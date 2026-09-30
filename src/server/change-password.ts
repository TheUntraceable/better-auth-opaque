/** `/opaque/change-password/*`: a logged-in user replaces their OPAQUE password. */
import { runWithTransaction } from "@better-auth/core/context";
import { APIError } from "better-auth";
import { createAuthEndpoint, sensitiveSessionMiddleware } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import * as z from "zod";
import {
	FINISH_LOGIN_REQUEST_LENGTH,
	LOGIN_REQUEST_LENGTH,
	OPAQUE_ERROR_CODES,
	REGISTRATION_REQUEST_LENGTH,
	validateBase64Length,
} from "../utils.js";
import {
	assertRecordUnchanged,
	assertStorableRegistrationRecord,
	consumeChallengeState,
	findOpaqueAccount,
	finishLoginOr401,
	HIDDEN_FROM_CLIENT,
	issueChallengeState,
	type OpaqueDeps,
	opaqueIdentifier,
	purgeOutstandingCredentials,
	recordDigest,
	registrationResponseOr400,
	startLoginSafely,
	updateOpaqueRecord,
} from "./shared.js";

export function changePasswordEndpoints(deps: OpaqueDeps) {
	return {
		/**
		 * `{ loginRequest, registrationRequest }` → `{ loginChallenge,
		 * registrationChallenge, state }`: a login against the current
		 * password plus a registration of the new one. A user without an
		 * OPAQUE account is 400 OPAQUE_ACCOUNT_NOT_FOUND (the caller is
		 * authenticated: nothing to hide).
		 */
		opaqueChangePasswordChallenge: createAuthEndpoint(
			"/opaque/change-password/challenge",
			{
				method: "POST",
				requireHeaders: true,
				body: z.object({
					loginRequest: z.string().base64url(),
					registrationRequest: z.string().base64url(),
				}),
				// Authoritative session read (bypasses the cookie cache), like core's /change-password.
				use: [sensitiveSessionMiddleware],
				metadata: HIDDEN_FROM_CLIENT,
			},
			async (ctx) => {
				const { loginRequest, registrationRequest } = ctx.body;
				const sessionUser = ctx.context.session.user;
				validateBase64Length(
					loginRequest,
					LOGIN_REQUEST_LENGTH,
					OPAQUE_ERROR_CODES.INVALID_LOGIN_REQUEST,
				);
				validateBase64Length(
					registrationRequest,
					REGISTRATION_REQUEST_LENGTH,
					OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
				);

				const account = await findOpaqueAccount(ctx, sessionUser.id);
				if (!account) {
					throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_NOT_FOUND);
				}
				const registrationRecord = account.registrationRecord ?? null;
				// The new record is registered under the same identifier.
				const userIdentifier = opaqueIdentifier(account, sessionUser.email);

				const { loginResponse, serverLoginState } = startLoginSafely(
					deps,
					ctx.context.logger,
					{ userIdentifier, startLoginRequest: loginRequest, registrationRecord },
					OPAQUE_ERROR_CODES.INVALID_CURRENT_PASSWORD,
				);
				const registrationChallenge = registrationResponseOr400(
					deps,
					ctx.context.logger,
					userIdentifier,
					registrationRequest,
				);
				const state = await issueChallengeState(
					ctx,
					"change-password",
					sessionUser.id,
					serverLoginState,
					await recordDigest(ctx, registrationRecord, userIdentifier),
				);
				return { loginChallenge: loginResponse, registrationChallenge, state };
			},
		),

		/**
		 * `{ loginResult, registrationRecord, encryptedServerState,
		 * revokeOtherSessions? }` → `{ success, message }`. Replaces the
		 * record, invalidates every outstanding challenge and reset credential,
		 * and rotates the caller's session (a new token; other sessions are
		 * revoked unless `revokeOtherSessions: false`).
		 */
		opaqueChangePasswordComplete: createAuthEndpoint(
			"/opaque/change-password/complete",
			{
				method: "POST",
				requireHeaders: true,
				body: z.object({
					loginResult: z.string().base64url(),
					registrationRecord: z.string().base64url(),
					encryptedServerState: z.string(),
					/** Revoke every other session of the user. Default: true. */
					revokeOtherSessions: z.boolean().optional(),
				}),
				// Authoritative session read (bypasses the cookie cache), like core's /change-password.
				use: [sensitiveSessionMiddleware],
				metadata: HIDDEN_FROM_CLIENT,
			},
			async (ctx) => {
				const { loginResult, registrationRecord, encryptedServerState } = ctx.body;
				const revokeOtherSessions = ctx.body.revokeOtherSessions ?? true;
				const currentSession = ctx.context.session;
				const credentialError = OPAQUE_ERROR_CODES.INVALID_CURRENT_PASSWORD;

				validateBase64Length(
					loginResult,
					FINISH_LOGIN_REQUEST_LENGTH,
					OPAQUE_ERROR_CODES.INVALID_LOGIN_RESULT,
				);
				assertStorableRegistrationRecord(deps, registrationRecord);

				// The state must belong to the authenticated user.
				const state = await consumeChallengeState(
					ctx,
					encryptedServerState,
					"change-password",
					credentialError,
					currentSession.user.id,
				);
				finishLoginOr401(ctx.context.logger, state.serverLoginState, loginResult, credentialError);
				const user = await ctx.context.internalAdapter.findUserById(currentSession.user.id);
				if (!user) throw APIError.from("UNAUTHORIZED", credentialError);
				// The current password was proven against the record (and
				// identifier) the challenge was issued for; refuse if it has been
				// replaced since (e.g. by a reset).
				const account = await assertRecordUnchanged(ctx, state, user, credentialError);
				if (!account) {
					throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_NOT_FOUND);
				}
				const credential = {
					registrationRecord,
					identifier: opaqueIdentifier(account, user.email),
				};

				// The caller's "don't remember me" choice carries over.
				const dontRememberMe = !!(await ctx.getSignedCookie(
					ctx.context.authCookies.dontRememberToken.name,
					ctx.context.secret,
				));
				const newSession = await runWithTransaction(ctx.context.adapter, async () => {
					await updateOpaqueRecord(ctx, account.id, credential);
					await purgeOutstandingCredentials(ctx, user);
					// Rotate the caller's session (a new token for a new password):
					// the session that made the request is always deleted, and with
					// `revokeOtherSessions` (default) every other session is too.
					if (revokeOtherSessions) {
						await ctx.context.internalAdapter.deleteUserSessions(user.id);
					} else {
						await ctx.context.internalAdapter.deleteSession(currentSession.session.token);
					}
					return await ctx.context.internalAdapter.createSession(user.id, dontRememberMe);
				});
				if (!newSession) {
					throw APIError.from(
						"INTERNAL_SERVER_ERROR",
						OPAQUE_ERROR_CODES.FAILED_TO_CREATE_SESSION,
					);
				}
				// Fresh cookies (session token + cookie cache rebuilt from the
				// current DB state) for the new session.
				await setSessionCookie(ctx, { session: newSession, user }, dontRememberMe);

				return ctx.json({ success: true, message: "Password changed successfully" });
			},
		),
	};
}
