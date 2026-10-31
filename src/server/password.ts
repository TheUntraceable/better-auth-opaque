import { server } from "@serenity-kit/opaque";
import { APIError } from "better-auth";
import {
	createAuthEndpoint,
	sensitiveSessionMiddleware,
} from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { generateRandomString } from "better-auth/crypto";
import { parseUserOutput } from "better-auth/db";
import * as z from "zod";
import { OPAQUE_ERROR_CODES } from "../error-codes";
import {
	assertValidRegistrationRecord,
	credentialIdFor,
	findOpaqueAccount,
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

export const passwordEndpoints = (shared: Shared) => {
	const { requireSetup, issueState, consumeState, finishLoginOrThrow } =
		shared;

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
				use: [sensitiveSessionMiddleware],
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Start an OPAQUE password change: a login challenge for the current password and a registration challenge for the new one.",
					},
				},
			},
			async (ctx) => {
				const setup = requireSetup();
				const user = ctx.context.session.user;
				const account = await findOpaqueAccount(ctx, user.id);
				if (!account?.registrationRecord) {
					throw APIError.from(
						"BAD_REQUEST",
						OPAQUE_ERROR_CODES.NO_OPAQUE_ACCOUNT,
					);
				}
				const credentialId = credentialIdFor(account, user.email);
				const newCredentialId = generateRandomString(32);

				const { loginResponse, serverLoginState } = server.startLogin({
					serverSetup: setup,
					userIdentifier: credentialId,
					registrationRecord: account.registrationRecord,
					startLoginRequest: ctx.body.loginRequest,
				});
				const { registrationResponse } = server.createRegistrationResponse({
					serverSetup: setup,
					userIdentifier: newCredentialId,
					registrationRequest: ctx.body.registrationRequest,
				});
				const encrypted = await issueState(ctx, {
					purpose: PURPOSE.changePassword,
					serverLoginState,
					userId: user.id,
					credentialId,
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
				use: [sensitiveSessionMiddleware],
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Finish an OPAQUE password change. Verifies the current password, stores the new record, and by default revokes every other session.",
					},
				},
			},
			async (ctx) => {
				const setup = requireSetup();
				const sessionUser = ctx.context.session.user;
				const decoded = await consumeState(
					ctx,
					ctx.body.state,
					PURPOSE.changePassword,
				);
				if (
					decoded.userId !== sessionUser.id ||
					!decoded.serverLoginState ||
					!decoded.newCredentialId
				) {
					throw APIError.from(
						"UNAUTHORIZED",
						OPAQUE_ERROR_CODES.USER_MISMATCH,
					);
				}
				const account = await findOpaqueAccount(ctx, sessionUser.id);
				if (
					!account ||
					credentialIdFor(account, sessionUser.email) !== decoded.credentialId
				) {
					throw APIError.from(
						"BAD_REQUEST",
						OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE,
					);
				}
				finishLoginOrThrow(
					ctx.body.loginResult,
					decoded.serverLoginState,
					OPAQUE_ERROR_CODES.INVALID_PASSWORD,
				);
				await assertValidRegistrationRecord(
					setup,
					decoded.newCredentialId,
					ctx.body.registrationRecord,
				);
				await ctx.context.internalAdapter.updateAccount(account.id, {
					registrationRecord: ctx.body.registrationRecord,
					credentialId: decoded.newCredentialId,
				} as Parameters<typeof ctx.context.internalAdapter.updateAccount>[1]);

				const user = await ctx.context.internalAdapter.findUserById(
					sessionUser.id,
				);
				if (!user) {
					throw APIError.from(
						"UNAUTHORIZED",
						OPAQUE_ERROR_CODES.USER_MISMATCH,
					);
				}
				if (ctx.body.revokeOtherSessions !== false) {
					await ctx.context.internalAdapter.deleteUserSessions(user.id);
					const session = await ctx.context.internalAdapter.createSession(
						user.id,
						false,
					);
					if (!session) {
						throw APIError.from(
							"INTERNAL_SERVER_ERROR",
							OPAQUE_ERROR_CODES.FAILED_TO_CREATE_SESSION,
						);
					}
					await setSessionCookie(ctx, { session, user });
					return {
						token: session.token,
						user: parseUserOutput(ctx.context.options, user),
					};
				}
				return {
					token: ctx.context.session.session.token,
					user: parseUserOutput(ctx.context.options, user),
				};
			},
		),

		opaqueSetPasswordChallenge: createAuthEndpoint(
			"/opaque/set-password/challenge",
			{
				method: "POST",
				requireHeaders: true,
				body: z.object({ registrationRequest }),
				use: [sensitiveSessionMiddleware],
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Start setting an OPAQUE password on an account that has none (for example one created through a social provider).",
					},
				},
			},
			async (ctx) => {
				const setup = requireSetup();
				const user = ctx.context.session.user;
				const account = await findOpaqueAccount(ctx, user.id);
				if (account?.registrationRecord) {
					throw APIError.from(
						"BAD_REQUEST",
						OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_EXISTS,
					);
				}
				const newCredentialId = generateRandomString(32);
				const { registrationResponse } = server.createRegistrationResponse({
					serverSetup: setup,
					userIdentifier: newCredentialId,
					registrationRequest: ctx.body.registrationRequest,
				});
				const encrypted = await issueState(ctx, {
					purpose: PURPOSE.setPassword,
					userId: user.id,
					newCredentialId,
				});
				return { challenge: registrationResponse, state: encrypted };
			},
		),

		opaqueSetPasswordComplete: createAuthEndpoint(
			"/opaque/set-password/complete",
			{
				method: "POST",
				requireHeaders: true,
				body: z.object({ registrationRecord, state }),
				use: [sensitiveSessionMiddleware],
				metadata: {
					isAction: false,
					openapi: {
						description: "Finish setting an OPAQUE password.",
					},
				},
			},
			async (ctx) => {
				const setup = requireSetup();
				const user = ctx.context.session.user;
				const decoded = await consumeState(
					ctx,
					ctx.body.state,
					PURPOSE.setPassword,
				);
				if (decoded.userId !== user.id || !decoded.newCredentialId) {
					throw APIError.from(
						"UNAUTHORIZED",
						OPAQUE_ERROR_CODES.USER_MISMATCH,
					);
				}
				await assertValidRegistrationRecord(
					setup,
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
				if (existing) {
					await ctx.context.internalAdapter.updateAccount(existing.id, {
						registrationRecord: ctx.body.registrationRecord,
						credentialId: decoded.newCredentialId,
					} as Parameters<typeof ctx.context.internalAdapter.updateAccount>[1]);
				} else {
					await ctx.context.internalAdapter.createAccount({
						providerId: "opaque",
						accountId: user.id,
						userId: user.id,
						registrationRecord: ctx.body.registrationRecord,
						credentialId: decoded.newCredentialId,
					} as Parameters<
						typeof ctx.context.internalAdapter.createAccount
					>[0]);
				}
				return { status: true };
			},
		),
	};
};
