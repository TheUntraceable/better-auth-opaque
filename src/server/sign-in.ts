import { server } from "@serenity-kit/opaque";
import { APIError } from "better-auth";
import { createAuthEndpoint, sendVerificationEmailFn } from "better-auth/api";
import { generateRandomString } from "better-auth/crypto";
import { parseUserOutput } from "better-auth/db";
import * as z from "zod";
import { OPAQUE_ERROR_CODES } from "../error-codes";
import {
	fakeCredentialId,
	findOpaqueAccount,
	type LoginIdentity,
	loginIdentity,
	matchesLoginIdentity,
} from "./account";
import {
	enforceMinimumDuration,
	loginRequest,
	loginResult,
	normalizeEmail,
	type Shared,
	state,
} from "./shared";
import { PURPOSE } from "./state";

export const signInEndpoints = (shared: Shared) => {
	const {
		options,
		issueState,
		consumeState,
		runHook,
		finishLogin,
		issueSession,
		floorMs,
	} = shared;

	return {
		opaqueSignInChallenge: createAuthEndpoint(
			"/opaque/sign-in/challenge",
			{
				method: "POST",
				body: z.object({
					email: z.email(),
					loginRequest,
				}),
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Start OPAQUE login. Always returns a well-formed challenge, whether or not the account exists.",
					},
				},
			},
			async (ctx) => {
				const started = performance.now();
				try {
					const email = normalizeEmail(ctx.body.email);
					const found = await ctx.context.internalAdapter.findUserByEmail(
						email,
					);
					// A random id on the missing branch keeps the query count the same.
					const account = await findOpaqueAccount(
						ctx,
						found?.user.id ?? generateRandomString(32),
					);
					const record = account?.registrationRecord ?? null;
					// A null record makes the library simulate a registered user; the
					// fake id keeps repeated attempts for one email consistent. A 2.x
					// record needs the email as sent, so not the normalised one.
					const identity: LoginIdentity =
						account && record
							? await loginIdentity(account, record, ctx.body.email)
							: {
									credentialId: await fakeCredentialId(shared.serverSetup, email),
								};

					const { loginResponse, serverLoginState } = server.startLogin({
						serverSetup: shared.serverSetup,
						userIdentifier: identity.credentialId,
						registrationRecord: record,
						startLoginRequest: ctx.body.loginRequest,
					});
					const encrypted = await issueState(ctx, {
						purpose: PURPOSE.signIn,
						serverLoginState,
						userId: found?.user.id ?? null,
						...identity,
					});
					return { challenge: loginResponse, state: encrypted };
				} finally {
					await enforceMinimumDuration(started, floorMs);
				}
			},
		),

		opaqueSignInComplete: createAuthEndpoint(
			"/opaque/sign-in/complete",
			{
				method: "POST",
				body: z.object({
					loginResult,
					state,
					rememberMe: z.boolean().optional(),
					callbackURL: z.string().optional(),
				}),
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Finish OPAQUE login with the client's proof. Creates a session on success.",
					},
				},
			},
			async (ctx) => {
				const decoded = await consumeState(ctx, ctx.body.state, PURPOSE.signIn);
				const sessionKey = finishLogin(
					ctx.body.loginResult,
					decoded.serverLoginState,
					OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD,
				);
				// A proof can only verify against a real record, so userId is set
				// here in practice; the check keeps the fake path airtight.
				const user = decoded.userId
					? await ctx.context.internalAdapter.findUserById(decoded.userId)
					: null;
				const account = user
					? await findOpaqueAccount(ctx, user.id)
					: undefined;
				if (!user || !(await matchesLoginIdentity(account, decoded))) {
					// Also covers a challenge minted before a password change.
					throw APIError.from(
						"UNAUTHORIZED",
						OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD,
					);
				}

				if (shared.requireVerification && !user.emailVerified) {
					const emailVerification = ctx.context.options.emailVerification;
					if (
						emailVerification?.sendOnSignIn &&
						emailVerification.sendVerificationEmail
					) {
						await runHook(ctx, () => sendVerificationEmailFn(ctx, user));
					}
					throw APIError.from(
						"FORBIDDEN",
						OPAQUE_ERROR_CODES.EMAIL_NOT_VERIFIED,
					);
				}

				const session = await issueSession(
					ctx,
					user,
					ctx.body.rememberMe === false,
				);
				await runHook(ctx, () =>
					options.onSessionKey?.({ user, session, sessionKey }, ctx),
				);
				// Never a redirect, unlike signIn.email: better-auth's client follows
				// one inside the fetch, before the action hands the app its export
				// key. callbackURL only feeds the verification email link.
				return {
					redirect: false,
					token: session.token,
					user: parseUserOutput(ctx.context.options, user),
				};
			},
		),
	};
};
