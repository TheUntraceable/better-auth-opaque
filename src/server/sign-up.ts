import { server } from "@serenity-kit/opaque";
import { APIError, type User } from "better-auth";
import {
	createAuthEndpoint,
	createEmailVerificationToken,
} from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { generateRandomString } from "better-auth/crypto";
import { parseUserInput } from "better-auth/db";
import * as z from "zod";
import { OPAQUE_ERROR_CODES } from "../error-codes";
import { assertValidRegistrationRecord } from "./account";
import {
	enforceMinimumDuration,
	normalizeEmail,
	registrationRecord,
	registrationRequest,
	type Shared,
	state,
} from "./shared";
import { PURPOSE } from "./state";

export const signUpEndpoints = (shared: Shared) => {
	const { options, requireSetup, issueState, consumeState, runHook, floorMs } =
		shared;

	return {
		opaqueSignUpChallenge: createAuthEndpoint(
			"/opaque/sign-up/challenge",
			{
				method: "POST",
				body: z.object({
					email: z.email(),
					registrationRequest,
				}),
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Start OPAQUE registration. Returns the registration challenge and an encrypted state to pass to the complete step.",
					},
				},
			},
			async (ctx) => {
				const setup = requireSetup();
				const email = normalizeEmail(ctx.body.email);
				// No lookup here: the challenge does not depend on whether the
				// account exists, so there is nothing to hide.
				const credentialId = generateRandomString(32);
				const { registrationResponse } = server.createRegistrationResponse({
					serverSetup: setup,
					userIdentifier: credentialId,
					registrationRequest: ctx.body.registrationRequest,
				});
				const encrypted = await issueState(ctx, {
					purpose: PURPOSE.signUp,
					email,
					credentialId,
				});
				return { challenge: registrationResponse, state: encrypted };
			},
		),

		opaqueSignUpComplete: createAuthEndpoint(
			"/opaque/sign-up/complete",
			{
				method: "POST",
				body: z
					.object({
						email: z.email(),
						name: z.string().min(1).max(100),
						image: z.string().optional(),
						registrationRecord,
						state,
						callbackURL: z.string().optional(),
					})
					.and(z.record(z.string(), z.any())),
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Finish OPAQUE registration. Responds identically whether or not the email was already registered.",
					},
				},
			},
			async (ctx) => {
				const started = performance.now();
				try {
					const setup = requireSetup();
					const {
						email: rawEmail,
						name,
						image,
						registrationRecord: record,
						state: encrypted,
						callbackURL,
						...rest
					} = ctx.body;
					const email = normalizeEmail(rawEmail);
					const decoded = await consumeState(ctx, encrypted, PURPOSE.signUp);
					if (decoded.email !== email || !decoded.credentialId) {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.EMAIL_MISMATCH,
						);
					}
					await assertValidRegistrationRecord(
						setup,
						decoded.credentialId,
						record,
					);

					const existing = await ctx.context.internalAdapter.findUserByEmail(
						email,
					);
					if (existing) {
						await runHook(ctx, () =>
							options.onExistingUserSignUp?.({ user: existing.user }, ctx.request),
						);
						return { status: true, token: null };
					}

					const additionalFields = parseUserInput(
						ctx.context.options,
						rest,
						"create",
					);
					let user: User;
					try {
						user = await ctx.context.internalAdapter.createUser(
							{
								email,
								name,
								image,
								...additionalFields,
								emailVerified: false,
							},
							{ method: "opaque" },
						);
					} catch (error) {
						if (error instanceof APIError) throw error;
						ctx.context.logger.error("Failed to create user", error);
						throw APIError.from(
							"UNPROCESSABLE_ENTITY",
							OPAQUE_ERROR_CODES.FAILED_TO_CREATE_USER,
						);
					}
					await ctx.context.internalAdapter.createAccount({
						providerId: "opaque",
						accountId: user.id,
						userId: user.id,
						registrationRecord: record,
						credentialId: decoded.credentialId,
					} as Parameters<
						typeof ctx.context.internalAdapter.createAccount
					>[0]);

					const emailVerification = ctx.context.options.emailVerification;
					const requireVerification =
						options.requireEmailVerification ??
						ctx.context.options.emailAndPassword?.requireEmailVerification;
					if (
						(emailVerification?.sendOnSignUp || requireVerification) &&
						emailVerification?.sendVerificationEmail
					) {
						const token = await createEmailVerificationToken(
							ctx.context.secret,
							user.email,
							undefined,
							emailVerification.expiresIn,
						);
						const url = `${ctx.context.baseURL}/verify-email?token=${token}&callbackURL=${encodeURIComponent(callbackURL || "/")}`;
						const sendVerificationEmail = emailVerification.sendVerificationEmail;
						await runHook(ctx, () =>
							sendVerificationEmail({ user, url, token }, ctx.request),
						);
					}

					if (options.insecureCreateSessionOnRegister) {
						const session = await ctx.context.internalAdapter.createSession(
							user.id,
							false,
						);
						if (session) {
							await setSessionCookie(ctx, { session, user });
							return { status: true, token: session.token };
						}
					}
					return { status: true, token: null };
				} finally {
					await enforceMinimumDuration(started, floorMs);
				}
			},
		),
	};
};
