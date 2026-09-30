/** `/sign-up/opaque/*` and `/sign-in/opaque/*`. */
import { runWithTransaction } from "@better-auth/core/context";
import { APIError } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { parseUserInput } from "better-auth/db";
import * as z from "zod";
import {
	FINISH_LOGIN_REQUEST_LENGTH,
	LOGIN_REQUEST_LENGTH,
	normalizeEmail,
	OPAQUE_ERROR_CODES,
	REGISTRATION_REQUEST_LENGTH,
	validateBase64Length,
} from "../utils.js";
import {
	assertRecordUnchanged,
	assertStorableRegistrationRecord,
	consumeChallengeState,
	createOpaqueAccount,
	findOpaqueAccount,
	finishLoginOr401,
	HIDDEN_FROM_CLIENT,
	issueChallengeState,
	type OpaqueDeps,
	opaqueIdentifier,
	phantomUserId,
	recordDigest,
	registrationResponseOr400,
	requiresEmailVerification,
	sendVerificationEmail,
	startLoginSafely,
} from "./shared.js";

export function signUpEndpoints(deps: OpaqueDeps) {
	return {
		/** `{ email, registrationRequest }` → `{ challenge }`. Same answer whether or not the email exists. */
		opaqueSignUpChallenge: createAuthEndpoint(
			"/sign-up/opaque/challenge",
			{
				method: "POST",
				body: z.object({
					email: z.string().email(),
					registrationRequest: z.string().base64url(),
				}),
				metadata: HIDDEN_FROM_CLIENT,
			},
			async (ctx) => {
				const email = normalizeEmail(ctx.body.email);
				const { registrationRequest } = ctx.body;
				validateBase64Length(
					registrationRequest,
					REGISTRATION_REQUEST_LENGTH,
					OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
				);
				const challenge = registrationResponseOr400(
					deps,
					ctx.context.logger,
					email,
					registrationRequest,
				);
				return { challenge };
			},
		),

		/**
		 * `{ email, name, registrationRecord, image?, callbackURL?, ...additionalFields }`
		 * → 201 `{ success, message }`, whether or not the email already existed
		 * (nothing is written for an existing one). Additional user fields are
		 * parsed as core's `/sign-up/email` does (a missing required field is
		 * 400 MISSING_FIELD, whatever the email).
		 */
		opaqueSignUpComplete: createAuthEndpoint(
			"/sign-up/opaque/complete",
			{
				method: "POST",
				body: z
					.object({
						email: z.string().email(),
						name: z.string().min(1).max(100),
						registrationRecord: z.string().base64url(),
						image: z.string().optional(),
						/** Where the verification email's link lands (as core's `/sign-up/email`). Default "/". */
						callbackURL: z.string().optional(),
					})
					.and(z.record(z.string(), z.any())),
				metadata: HIDDEN_FROM_CLIENT,
			},
			async (ctx) => {
				const {
					email: rawEmail,
					name,
					registrationRecord,
					image,
					callbackURL,
					...rest
				} = ctx.body;
				const email = normalizeEmail(rawEmail);
				// Never store a record that would later make login throw.
				assertStorableRegistrationRecord(deps, registrationRecord);
				const additionalFields = parseUserInput(ctx.context.options, rest, "create");

				const existing = await ctx.context.internalAdapter.findUserByEmail(email);
				if (!existing) {
					// User and account together, or neither.
					const user = await runWithTransaction(ctx.context.adapter, async () => {
						const created = await ctx.context.internalAdapter.createUser(
							{ ...additionalFields, email, name, image },
							{ method: "email-password" },
						);
						try {
							await createOpaqueAccount(ctx, created.id, { registrationRecord, identifier: email });
						} catch (error) {
							// Adapters without transactions: never leave a user
							// that has no password.
							await ctx.context.internalAdapter.deleteUser(created.id).catch(() => {});
							throw error;
						}
						return created;
					});

					// As core's `/sign-up/email`: only for a newly created user.
					if (
						ctx.context.options.emailVerification?.sendOnSignUp ??
						requiresEmailVerification(deps, ctx)
					) {
						await sendVerificationEmail(ctx, user, callbackURL);
					}

					// Never sign in a user who may not log in yet (as core, which
					// skips auto sign-in when email verification is required).
					if (
						deps.options.raw.insecureCreateSessionOnRegister &&
						!requiresEmailVerification(deps, ctx)
					) {
						const session = await ctx.context.internalAdapter.createSession(user.id, false);
						if (session) await setSessionCookie(ctx, { session, user });
					}
				}

				// Same answer for new and existing emails (no enumeration).
				// (`ctx.json(body, { status })` is ignored by Better Auth; setStatus is not.)
				ctx.setStatus(201);
				return ctx.json({ success: true, message: "User registered successfully" });
			},
		),
	};
}

export function signInEndpoints(deps: OpaqueDeps) {
	return {
		/**
		 * `{ email, loginRequest }` → `{ challenge, state }`. Known and unknown
		 * emails, and users without an OPAQUE account, cost the same work and
		 * the same queries (one per table) and get the same shape.
		 */
		opaqueSignInChallenge: createAuthEndpoint(
			"/sign-in/opaque/challenge",
			{
				method: "POST",
				body: z.object({
					email: z.string().email(),
					loginRequest: z.string().base64url(),
				}),
				metadata: HIDDEN_FROM_CLIENT,
			},
			async (ctx) => {
				const email = normalizeEmail(ctx.body.email);
				const { loginRequest } = ctx.body;
				validateBase64Length(
					loginRequest,
					LOGIN_REQUEST_LENGTH,
					OPAQUE_ERROR_CODES.INVALID_LOGIN_REQUEST,
				);

				const found = await ctx.context.internalAdapter.findUserByEmail(email);
				// An unknown email gets an id no user has (so completion fails)
				// and the same account lookup as a known one.
				const userId = found?.user.id ?? phantomUserId(ctx);
				const account = await findOpaqueAccount(ctx, userId);
				const registrationRecord = account?.registrationRecord ?? null;
				const userIdentifier = opaqueIdentifier(account, email);

				const { loginResponse, serverLoginState } = startLoginSafely(
					deps,
					ctx.context.logger,
					{ userIdentifier, startLoginRequest: loginRequest, registrationRecord },
					OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD,
				);
				const state = await issueChallengeState(
					ctx,
					"login",
					userId,
					serverLoginState,
					await recordDigest(ctx, registrationRecord, userIdentifier),
				);
				return { challenge: loginResponse, state };
			},
		),

		/**
		 * `{ loginResult, encryptedServerState, dontRememberMe?, callbackURL? }`
		 * → `{ token, success, user: { id } }` + session cookie. The user is
		 * taken from the state, never from the body.
		 */
		opaqueSignInComplete: createAuthEndpoint(
			"/sign-in/opaque/complete",
			{
				method: "POST",
				body: z.object({
					// Accepted for backwards compatibility; the user is taken from the state.
					email: z.string().email().optional(),
					loginResult: z.string().base64url(),
					encryptedServerState: z.string(),
					dontRememberMe: z.boolean().optional(),
					/** Where a (re-sent) verification email's link lands, as core's `/sign-in/email`. Default "/". */
					callbackURL: z.string().optional(),
				}),
				metadata: HIDDEN_FROM_CLIENT,
			},
			async (ctx) => {
				const { loginResult, encryptedServerState } = ctx.body;
				const dontRememberMe = ctx.body.dontRememberMe === true;
				const credentialError = OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD;
				validateBase64Length(
					loginResult,
					FINISH_LOGIN_REQUEST_LENGTH,
					OPAQUE_ERROR_CODES.INVALID_LOGIN_RESULT,
				);

				const state = await consumeChallengeState(
					ctx,
					encryptedServerState,
					"login",
					credentialError,
				);
				finishLoginOr401(ctx.context.logger, state.serverLoginState, loginResult, credentialError);
				const user = await ctx.context.internalAdapter.findUserById(state.userId);
				if (!user) throw APIError.from("UNAUTHORIZED", credentialError);
				// The proof verified against the record the challenge was issued
				// for; refuse it if that record has been replaced since.
				await assertRecordUnchanged(ctx, state, user, credentialError);

				// Only after the password proof verified (as core's
				// `/sign-in/email`): a wrong password never gets here.
				if (requiresEmailVerification(deps, ctx) && !user.emailVerified) {
					if (ctx.context.options.emailVerification?.sendOnSignIn) {
						await sendVerificationEmail(ctx, user, ctx.body.callbackURL);
					}
					throw APIError.from("FORBIDDEN", OPAQUE_ERROR_CODES.EMAIL_NOT_VERIFIED);
				}

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

				return ctx.json({ token: session.token, success: true, user: { id: user.id } });
			},
		),
	};
}
