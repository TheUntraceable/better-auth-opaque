import { server } from "@serenity-kit/opaque";
import { APIError } from "better-auth";
import {
	createAuthEndpoint,
	createEmailVerificationToken,
} from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { generateRandomString } from "better-auth/crypto";
import { parseUserOutput } from "better-auth/db";
import * as z from "zod";
import { OPAQUE_ERROR_CODES } from "../error-codes";
import {
	credentialIdFor,
	fakeCredentialId,
	findOpaqueAccount,
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
		requireSetup,
		issueState,
		consumeState,
		runHook,
		finishLoginOrThrow,
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
					const setup = requireSetup();
					const email = normalizeEmail(ctx.body.email);
					const found = await ctx.context.internalAdapter.findUserByEmail(
						email,
					);

					let userId: string | null = null;
					let credentialId: string;
					let record: string | null = null;
					if (found) {
						const account = await findOpaqueAccount(ctx, found.user.id);
						userId = found.user.id;
						credentialId = credentialIdFor(account, email);
						record = account?.registrationRecord ?? null;
					} else {
						// Same query count as the real branch, then a deterministic
						// fake identifier so repeated attempts look consistent. A null
						// record makes the library simulate a registered user.
						await findOpaqueAccount(ctx, generateRandomString(32));
						credentialId = await fakeCredentialId(ctx.context.secret, email);
					}

					const { loginResponse, serverLoginState } = server.startLogin({
						serverSetup: setup,
						userIdentifier: credentialId,
						registrationRecord: record,
						startLoginRequest: ctx.body.loginRequest,
					});
					const encrypted = await issueState(ctx, {
						purpose: PURPOSE.signIn,
						serverLoginState,
						userId,
						credentialId,
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
				if (!decoded.serverLoginState) {
					throw APIError.from(
						"BAD_REQUEST",
						OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE,
					);
				}
				finishLoginOrThrow(
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
				if (
					!user ||
					!account ||
					credentialIdFor(account, user.email) !== decoded.credentialId
				) {
					// Also covers a challenge minted before a password change.
					throw APIError.from(
						"UNAUTHORIZED",
						OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD,
					);
				}

				const requireVerification =
					options.requireEmailVerification ??
					ctx.context.options.emailAndPassword?.requireEmailVerification;
				if (requireVerification && !user.emailVerified) {
					const emailVerification = ctx.context.options.emailVerification;
					if (
						emailVerification?.sendOnSignIn &&
						emailVerification.sendVerificationEmail
					) {
						const token = await createEmailVerificationToken(
							ctx.context.secret,
							user.email,
							undefined,
							emailVerification.expiresIn,
						);
						const url = `${ctx.context.baseURL}/verify-email?token=${token}&callbackURL=${encodeURIComponent(ctx.body.callbackURL || "/")}`;
						const sendVerificationEmail = emailVerification.sendVerificationEmail;
						await runHook(ctx, () =>
							sendVerificationEmail({ user, url, token }, ctx.request),
						);
					}
					throw APIError.from(
						"FORBIDDEN",
						OPAQUE_ERROR_CODES.EMAIL_NOT_VERIFIED,
					);
				}

				const dontRememberMe = ctx.body.rememberMe === false;
				const session = await ctx.context.internalAdapter.createSession(
					user.id,
					dontRememberMe,
				);
				if (!session) {
					throw APIError.from(
						"INTERNAL_SERVER_ERROR",
						OPAQUE_ERROR_CODES.FAILED_TO_CREATE_SESSION,
					);
				}
				await setSessionCookie(ctx, { session, user }, dontRememberMe);
				return {
					token: session.token,
					user: parseUserOutput(ctx.context.options, user),
				};
			},
		),
	};
};
