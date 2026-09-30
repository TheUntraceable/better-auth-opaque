/**
 * `/opaque/set-password/*` (opt-in, `setPassword.enabled`): a logged-in user
 * without an OPAQUE account (e.g. social sign-in only) adds one.
 */
import { runWithTransaction } from "@better-auth/core/context";
import { APIError } from "better-auth";
import {
	createAuthEndpoint,
	freshSessionMiddleware,
	sensitiveSessionMiddleware,
} from "better-auth/api";
import * as z from "zod";
import {
	LOGIN_STATE_TTL_MS,
	normalizeEmail,
	OPAQUE_ERROR_CODES,
	REGISTRATION_REQUEST_LENGTH,
	setPasswordIdentifier,
	validateBase64Length,
} from "../utils.js";
import {
	assertStorableRegistrationRecord,
	convergeOpaqueAccounts,
	createOpaqueAccount,
	findOpaqueAccount,
	HIDDEN_FROM_CLIENT,
	type OpaqueDeps,
	purgeOutstandingCredentials,
	registrationResponseOr400,
} from "./shared.js";

const alreadyExists = () =>
	APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_ALREADY_EXISTS);

export function setPasswordEndpoints(deps: OpaqueDeps) {
	return {
		/**
		 * `{ registrationRequest }` → `{ challenge }`. Requires a fresh,
		 * DB-validated session. Reserves the single set-password slot (15
		 * minutes) that the complete step consumes.
		 */
		opaqueSetPasswordChallenge: createAuthEndpoint(
			"/opaque/set-password/challenge",
			{
				method: "POST",
				requireHeaders: true,
				body: z.object({
					registrationRequest: z.string().base64url(),
				}),
				// A stolen session must not be able to add a permanent
				// password to e.g. a social-only account: authoritative AND fresh.
				use: [sensitiveSessionMiddleware, freshSessionMiddleware],
				metadata: HIDDEN_FROM_CLIENT,
			},
			async (ctx) => {
				const { registrationRequest } = ctx.body;
				const sessionUser = ctx.context.session.user;
				validateBase64Length(
					registrationRequest,
					REGISTRATION_REQUEST_LENGTH,
					OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
				);
				if (await findOpaqueAccount(ctx, sessionUser.id)) throw alreadyExists();

				const challenge = registrationResponseOr400(
					deps,
					ctx.context.logger,
					normalizeEmail(sessionUser.email),
					registrationRequest,
				);

				const identifier = setPasswordIdentifier(sessionUser.id);
				await ctx.context.internalAdapter.deleteVerificationByIdentifier(identifier);
				await ctx.context.internalAdapter.createVerificationValue({
					identifier,
					// The OPAQUE identifier the challenge used.
					value: normalizeEmail(sessionUser.email),
					expiresAt: new Date(Date.now() + LOGIN_STATE_TTL_MS),
				});
				return { challenge };
			},
		),

		/**
		 * `{ registrationRecord }` → `{ status: true }`. Creates the `opaque`
		 * account; the session and cookies are left unchanged. 400
		 * OPAQUE_ACCOUNT_ALREADY_EXISTS if the user has one, 400
		 * SET_PASSWORD_CHALLENGE_REQUIRED without a live challenge.
		 */
		opaqueSetPasswordComplete: createAuthEndpoint(
			"/opaque/set-password/complete",
			{
				method: "POST",
				requireHeaders: true,
				body: z.object({
					registrationRecord: z.string().base64url(),
				}),
				use: [sensitiveSessionMiddleware, freshSessionMiddleware],
				metadata: HIDDEN_FROM_CLIENT,
			},
			async (ctx) => {
				const { registrationRecord } = ctx.body;
				const sessionUser = ctx.context.session.user;
				const userId = sessionUser.id;

				if (await findOpaqueAccount(ctx, userId)) throw alreadyExists();
				assertStorableRegistrationRecord(deps, registrationRecord);

				// Concurrency gate: the adapter cannot create "at most one
				// opaque account per user" atomically, but consuming a
				// verification row is atomic. The challenge left exactly one
				// slot row for this user; only one complete can take it.
				// Consumed outside the transaction, so that it really gates.
				const slot = await ctx.context.internalAdapter.consumeVerificationValue(
					setPasswordIdentifier(userId),
				);
				// The slot holds the identifier the challenge registered under: an
				// email change in between voids it.
				const identifier = normalizeEmail(sessionUser.email);
				if (!slot || slot.value !== identifier) {
					throw APIError.from(
						"BAD_REQUEST",
						OPAQUE_ERROR_CODES.SET_PASSWORD_CHALLENGE_REQUIRED,
					);
				}
				if (await findOpaqueAccount(ctx, userId)) throw alreadyExists();

				const credential = { registrationRecord, identifier };
				const created = await runWithTransaction(ctx.context.adapter, async () => {
					const account = await createOpaqueAccount(ctx, userId, credential);
					// Reset credentials issued before now were bound to "no password".
					await purgeOutstandingCredentials(ctx, sessionUser);
					return account;
				});
				// A concurrent password reset may have created one too.
				await convergeOpaqueAccounts(ctx, userId, created.id, credential);

				return ctx.json({ status: true });
			},
		),
	};
}
