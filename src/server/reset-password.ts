import { server } from "@serenity-kit/opaque";
import { APIError } from "better-auth";
import { createAuthEndpoint, originCheck } from "better-auth/api";
import { generateRandomString } from "better-auth/crypto";
import * as z from "zod";
import { OPAQUE_ERROR_CODES } from "../error-codes";
import {
	assertValidRegistrationRecord,
	findOpaqueAccount,
	saveOpaqueRecord,
} from "./account";
import {
	enforceMinimumDuration,
	normalizeEmail,
	registrationRecord,
	registrationRequest,
	type Shared,
	state,
} from "./shared";
import { PURPOSE } from "./state";

const resetIdentifier = (token: string) => `opaque-reset:${token}`;

export const resetPasswordEndpoints = (shared: Shared) => {
	const { options, issueState, consumeState, runHook, resetTtlMs, floorMs } =
		shared;

	return {
		opaqueRequestPasswordReset: createAuthEndpoint(
			"/opaque/reset-password/request",
			{
				method: "POST",
				body: z.object({
					email: z.email(),
					redirectTo: z.string().optional(),
				}),
				use: [originCheck((ctx) => ctx.body.redirectTo)],
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Email a password reset link. Responds identically whether or not the account exists.",
					},
				},
			},
			async (ctx) => {
				const started = performance.now();
				try {
					if (!options.sendResetPassword) {
						ctx.context.logger.error(
							"[better-auth-opaque] opaque.requestPasswordReset called but sendResetPassword is not configured",
						);
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.RESET_PASSWORD_NOT_CONFIGURED,
						);
					}
					const email = normalizeEmail(ctx.body.email);
					const found = await ctx.context.internalAdapter.findUserByEmail(
						email,
					);
					if (!found) {
						// Touch the verification table on this branch too so the
						// query pattern matches the real one. The real branch's
						// insert and mailer are what timingSafeResponseMs is for.
						await ctx.context.internalAdapter.findVerificationValue(
							resetIdentifier("dummy"),
						);
						return { status: true };
					}
					const token = generateRandomString(32);
					await ctx.context.internalAdapter.createVerificationValue({
						identifier: resetIdentifier(token),
						value: found.user.id,
						expiresAt: new Date(Date.now() + resetTtlMs),
					});
					const callbackURL = encodeURIComponent(ctx.body.redirectTo ?? "");
					const url = `${ctx.context.baseURL}/opaque/reset-password/${token}?callbackURL=${callbackURL}`;
					const sendResetPassword = options.sendResetPassword;
					await runHook(ctx, () =>
						sendResetPassword({ user: found.user, url, token }, ctx.request),
					);
					return { status: true };
				} finally {
					await enforceMinimumDuration(started, floorMs);
				}
			},
		),

		opaqueResetPasswordCallback: createAuthEndpoint(
			"/opaque/reset-password/:token",
			{
				method: "GET",
				query: z.object({ callbackURL: z.string().optional() }),
				use: [originCheck((ctx) => ctx.query.callbackURL)],
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Redirects the browser from the emailed link to your reset page with ?token=... (or ?error=INVALID_TOKEN).",
					},
				},
			},
			async (ctx) => {
				const { token } = ctx.params;
				const target = new URL(
					ctx.query.callbackURL || "/",
					ctx.context.baseURL,
				);
				const verification =
					await ctx.context.internalAdapter.findVerificationValue(
						resetIdentifier(token),
					);
				if (!verification || verification.expiresAt < new Date()) {
					target.searchParams.set("error", "INVALID_TOKEN");
				} else {
					target.searchParams.set("token", token);
				}
				throw ctx.redirect(target.toString());
			},
		),

		opaqueResetPasswordChallenge: createAuthEndpoint(
			"/opaque/reset-password/challenge",
			{
				method: "POST",
				body: z.object({
					token: z.string().min(1).max(256),
					registrationRequest,
				}),
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Start an OPAQUE password reset with the emailed token.",
					},
				},
			},
			async (ctx) => {
				const verification =
					await ctx.context.internalAdapter.findVerificationValue(
						resetIdentifier(ctx.body.token),
					);
				if (!verification || verification.expiresAt < new Date()) {
					throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
				}
				const newCredentialId = generateRandomString(32);
				const { registrationResponse } = server.createRegistrationResponse({
					serverSetup: shared.serverSetup,
					userIdentifier: newCredentialId,
					registrationRequest: ctx.body.registrationRequest,
				});
				const encrypted = await issueState(ctx, {
					purpose: PURPOSE.resetPassword,
					userId: verification.value,
					newCredentialId,
					token: ctx.body.token,
				});
				return { challenge: registrationResponse, state: encrypted };
			},
		),

		opaqueResetPasswordComplete: createAuthEndpoint(
			"/opaque/reset-password/complete",
			{
				method: "POST",
				body: z.object({
					token: z.string().min(1).max(256),
					registrationRecord,
					state,
				}),
				metadata: {
					isAction: false,
					openapi: {
						description:
							"Finish an OPAQUE password reset. Stores the new record, consumes the token and revokes every session.",
					},
				},
			},
			async (ctx) => {
				const decoded = await consumeState(
					ctx,
					ctx.body.state,
					PURPOSE.resetPassword,
				);
				const identifier = resetIdentifier(ctx.body.token);
				const verification =
					await ctx.context.internalAdapter.findVerificationValue(identifier);
				if (
					!verification ||
					verification.expiresAt < new Date() ||
					decoded.token !== ctx.body.token ||
					decoded.userId !== verification.value
				) {
					throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
				}
				const user = await ctx.context.internalAdapter.findUserById(
					verification.value,
				);
				if (!user) {
					throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
				}
				await assertValidRegistrationRecord(
					shared.serverSetup,
					decoded.newCredentialId,
					ctx.body.registrationRecord,
				);
				// Burned before the write, outside a transaction: joining the two needs
				// runWithTransaction from @better-auth/core, not a declared dependency.
				// If the write then fails the user needs a new reset email; burning
				// after it would let two resets racing on one link both write.
				if (
					!(await ctx.context.internalAdapter.consumeVerificationValue(
						identifier,
					))
				) {
					throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
				}
				await saveOpaqueRecord(ctx, await findOpaqueAccount(ctx, user.id), {
					userId: user.id,
					registrationRecord: ctx.body.registrationRecord,
					credentialId: decoded.newCredentialId,
				});
				await ctx.context.internalAdapter.deleteUserSessions(user.id);
				return { status: true };
			},
		),
	};
};
