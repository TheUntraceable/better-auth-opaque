import { APIError, generateId } from "better-auth";
import {
	createAuthEndpoint,
	freshSessionMiddleware,
	sensitiveSessionMiddleware,
} from "better-auth/api";
import { parseUserOutput } from "better-auth/db";
import * as z from "zod";
import { OPAQUE_ERROR_CODES } from "../error-codes";
import {
	assertValidRegistrationRecord,
	findOpaqueAccount,
	loginIdentity,
	matchesLoginIdentity,
	upsertOpaqueAccount,
} from "./account";
import {
	loginRequest,
	loginResult,
	registrationRecord,
	registrationRequest,
	type Shared,
	state,
} from "./shared";
import { PURPOSE } from "./state";

// sensitiveSessionMiddleware re-reads the session from the store but ignores
// session.freshAge; freshSessionMiddleware then applies core's freshness
// check to the session the first one put on the context.
const freshSensitiveSession = [
	sensitiveSessionMiddleware,
	freshSessionMiddleware,
];

export const passwordEndpoints = (shared: Shared) => {
	const {
		issueState,
		consumeState,
		startLogin,
		createRegistrationResponse,
		finishLogin,
		issueSession,
	} = shared;

	return {
		opaqueChangePasswordChallenge: createAuthEndpoint(
			"/opaque/change-password/challenge",
			{
				method: "POST",
				requireHeaders: true,
				body: z.object({
					loginRequest,
					registrationRequest,
				}),
				use: freshSensitiveSession,
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Start an OPAQUE password change: a login challenge for the current password and a registration challenge for the new one.",
					},
				},
			},
			async (ctx) => {
				const { user } = ctx.context.session;
				const account = await findOpaqueAccount(ctx, user.id);
				if (!account?.registrationRecord) {
					throw APIError.from(
						"BAD_REQUEST",
						OPAQUE_ERROR_CODES.NO_OPAQUE_ACCOUNT,
					);
				}
				// No email in this request, so a 2.x record gets the stored one, as
				// 2.x itself used; one registered in mixed case needs a reset.
				const identity = await loginIdentity(
					account,
					account.registrationRecord,
					user.email,
				);
				const newCredentialId = generateId();

				const { loginResponse, serverLoginState } = startLogin({
					userIdentifier: identity.credentialId,
					registrationRecord: account.registrationRecord,
					startLoginRequest: ctx.body.loginRequest,
				});
				const registrationResponse = createRegistrationResponse({
					userIdentifier: newCredentialId,
					registrationRequest: ctx.body.registrationRequest,
				});
				const encrypted = await issueState(ctx, {
					purpose: PURPOSE.changePassword,
					serverLoginState,
					userId: user.id,
					...identity,
					newCredentialId,
				});
				return {
					loginChallenge: loginResponse,
					registrationChallenge: registrationResponse,
					state: encrypted,
				};
			},
		),

		opaqueChangePasswordComplete: createAuthEndpoint(
			"/opaque/change-password/complete",
			{
				method: "POST",
				requireHeaders: true,
				body: z.object({
					loginResult,
					registrationRecord,
					state,
					revokeOtherSessions: z.boolean().optional(),
				}),
				use: freshSensitiveSession,
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Finish an OPAQUE password change. Verifies the current password, stores the new record, and by default revokes every other session.",
					},
				},
			},
			async (ctx) => {
				const { user, session } = ctx.context.session;
				const decoded = await consumeState(
					ctx,
					ctx.body.state,
					PURPOSE.changePassword,
				);
				if (decoded.userId !== user.id) {
					throw APIError.from(
						"UNAUTHORIZED",
						OPAQUE_ERROR_CODES.USER_MISMATCH,
					);
				}
				const account = await findOpaqueAccount(ctx, user.id);
				if (!(await matchesLoginIdentity(account, decoded))) {
					throw APIError.from(
						"BAD_REQUEST",
						OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE,
					);
				}
				finishLogin(
					ctx.body.loginResult,
					decoded.serverLoginState,
					OPAQUE_ERROR_CODES.INVALID_PASSWORD,
				);
				assertValidRegistrationRecord(
					shared.serverSetup,
					decoded.newCredentialId,
					ctx.body.registrationRecord,
				);
				const revokeOtherSessions = ctx.body.revokeOtherSessions !== false;
				// Revoked before the write, as core does: a revoke failing after it
				// would leave old sessions alive under the new password.
				if (revokeOtherSessions) {
					await ctx.context.internalAdapter.deleteUserSessions(user.id);
				}
				await upsertOpaqueAccount(ctx, account, {
					userId: user.id,
					registrationRecord: ctx.body.registrationRecord,
					credentialId: decoded.newCredentialId,
				});
				const token = revokeOtherSessions
					? (await issueSession(ctx, user, false)).token
					: session.token;
				return { token, user: parseUserOutput(ctx.context.options, user) };
			},
		),

		opaqueSetPasswordChallenge: createAuthEndpoint(
			"/opaque/set-password/challenge",
			{
				method: "POST",
				requireHeaders: true,
				body: z.object({ registrationRequest }),
				use: freshSensitiveSession,
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Start setting an OPAQUE password on an account that has none (for example one created through a social provider).",
					},
				},
			},
			async (ctx) => {
				const { user } = ctx.context.session;
				const account = await findOpaqueAccount(ctx, user.id);
				if (account?.registrationRecord) {
					throw APIError.from(
						"BAD_REQUEST",
						OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_EXISTS,
					);
				}
				const newCredentialId = generateId();
				const challenge = createRegistrationResponse({
					userIdentifier: newCredentialId,
					registrationRequest: ctx.body.registrationRequest,
				});
				const encrypted = await issueState(ctx, {
					purpose: PURPOSE.setPassword,
					userId: user.id,
					newCredentialId,
				});
				return { challenge, state: encrypted };
			},
		),

		opaqueSetPasswordComplete: createAuthEndpoint(
			"/opaque/set-password/complete",
			{
				method: "POST",
				requireHeaders: true,
				body: z.object({ registrationRecord, state }),
				use: freshSensitiveSession,
				metadata: {
					isAction: false,
					openapi: {
						description: "Finish setting an OPAQUE password.",
					},
				},
			},
			async (ctx) => {
				const { user } = ctx.context.session;
				const decoded = await consumeState(
					ctx,
					ctx.body.state,
					PURPOSE.setPassword,
				);
				if (decoded.userId !== user.id) {
					throw APIError.from(
						"UNAUTHORIZED",
						OPAQUE_ERROR_CODES.USER_MISMATCH,
					);
				}
				assertValidRegistrationRecord(
					shared.serverSetup,
					decoded.newCredentialId,
					ctx.body.registrationRecord,
				);
				const existing = await findOpaqueAccount(ctx, user.id);
				if (existing?.registrationRecord) {
					throw APIError.from(
						"BAD_REQUEST",
						OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_EXISTS,
					);
				}
				await upsertOpaqueAccount(ctx, existing, {
					userId: user.id,
					registrationRecord: ctx.body.registrationRecord,
					credentialId: decoded.newCredentialId,
				});
				return { status: true };
			},
		),
	};
};
