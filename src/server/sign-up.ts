import { APIError, generateId, type User } from "better-auth";
import { createAuthEndpoint, sendVerificationEmailFn } from "better-auth/api";
import { parseUserInput } from "better-auth/db";
import * as z from "zod";
import { OPAQUE_ERROR_CODES } from "../error-codes";
import { assertValidRegistrationRecord } from "./account";
import {
	emailAddress,
	enforceMinimumDuration,
	normalizeEmail,
	registrationRecord,
	registrationRequest,
	type Shared,
	state,
} from "./shared";
import { PURPOSE } from "./state";

const MAX_NAME_LENGTH = 100;

export const signUpEndpoints = (shared: Shared) => {
	const {
		options,
		issueState,
		consumeState,
		runHook,
		issueSession,
		createRegistrationResponse,
	} = shared;

	return {
		opaqueSignUpChallenge: createAuthEndpoint(
			"/opaque/sign-up/challenge",
			{
				method: "POST",
				body: z.object({
					email: emailAddress,
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
				const email = normalizeEmail(ctx.body.email);
				// No lookup here: the challenge does not depend on whether the
				// account exists, so there is nothing to hide.
				const credentialId = generateId();
				const challenge = createRegistrationResponse({
					userIdentifier: credentialId,
					registrationRequest: ctx.body.registrationRequest,
				});
				const encrypted = await issueState(ctx, {
					purpose: PURPOSE.signUp,
					email,
					credentialId,
				});
				return { challenge, state: encrypted };
			},
		),

		opaqueSignUpComplete: createAuthEndpoint(
			"/opaque/sign-up/complete",
			{
				method: "POST",
				body: z
					.object({
						email: emailAddress,
						name: z.string().min(1).max(MAX_NAME_LENGTH),
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
					if (decoded.email !== email) {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.EMAIL_MISMATCH,
						);
					}
					assertValidRegistrationRecord(
						shared.serverSetup,
						decoded.credentialId,
						record,
					);

					// Parsed before the lookup so a disallowed or missing field is
					// rejected the same way whether or not the email is registered.
					const additionalFields = parseUserInput(
						ctx.context.options,
						rest,
						"create",
					);
					const existing = await ctx.context.internalAdapter.findUserByEmail(
						email,
					);
					if (existing) {
						await runHook(ctx, () =>
							options.onExistingUserSignUp?.(
								{ user: existing.user },
								ctx.request,
							),
						);
						return { status: true, token: null };
					}

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
					});

					const emailVerification = ctx.context.options.emailVerification;
					if (
						(emailVerification?.sendOnSignUp ?? shared.requireVerification) &&
						emailVerification?.sendVerificationEmail
					) {
						await runHook(ctx, () => sendVerificationEmailFn(ctx, user));
					}

					if (
						options.insecureCreateSessionOnRegister &&
						!shared.requireVerification
					) {
						const session = await issueSession(ctx, user, false);
						return { status: true, token: session.token };
					}
					return { status: true, token: null };
				} finally {
					await enforceMinimumDuration(started, options.timingSafeResponseMs);
				}
			},
		),
	};
};
