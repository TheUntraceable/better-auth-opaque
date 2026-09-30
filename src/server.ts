/**
 * The `opaque()` Better Auth server plugin: option handling, startup checks,
 * rate limits and schema. The endpoints live in `./server/*`.
 */
import { ready, server } from "@serenity-kit/opaque";
import type { BetterAuthPlugin } from "better-auth";
import * as z from "zod";
import { changePasswordEndpoints } from "./server/change-password.js";
import { resolveOptions } from "./server/options.js";
import { signInEndpoints, signUpEndpoints } from "./server/register-login.js";
import { resetPasswordEndpoints } from "./server/reset-password.js";
import { setPasswordEndpoints } from "./server/set-password.js";
import type { OpaqueDeps } from "./server/shared.js";
import { assertValidServerSetup, OPAQUE_ERROR_CODES, type OpaqueOptions } from "./utils.js";

export { OPAQUE_ERROR_CODES } from "./utils.js";
export type { OpaqueErrorCode, OpaqueOptions } from "./utils.js";

function isProductionEnv(): boolean {
	return typeof process !== "undefined" && process.env?.NODE_ENV === "production";
}

export const opaque = (options?: OpaqueOptions) => {
	// Validates every option (and a provided key's format) synchronously.
	const resolved = resolveOptions(options);
	let serverSetup: string | undefined = resolved.raw.OPAQUE_SERVER_KEY;

	const deps: OpaqueDeps = {
		options: resolved,
		getServerSetup: () => {
			if (!serverSetup) {
				// Unreachable once `init` has run: Better Auth awaits plugin init
				// before handling any request.
				throw new Error("[better-auth-opaque] OPAQUE server setup is not initialised");
			}
			return serverSetup;
		},
	};

	return {
		id: "opaque",
		$ERROR_CODES: OPAQUE_ERROR_CODES,
		init: async (ctx) => {
			await ready;
			if (resolved.raw.OPAQUE_SERVER_KEY !== undefined) {
				assertValidServerSetup(resolved.raw.OPAQUE_SERVER_KEY);
			} else if (!serverSetup) {
				if (isProductionEnv()) {
					throw new Error(
						"[better-auth-opaque] OPAQUE_SERVER_KEY is required in production. Generate one with `npx @serenity-kit/opaque@latest create-server-setup` and keep it stable: changing it invalidates every registered password.",
					);
				}
				serverSetup = server.createSetup();
				ctx.logger.warn(
					"⚠️ [better-auth-opaque] OPAQUE_SERVER_KEY not provided. Generated a random one for DEVELOPMENT ONLY: all OPAQUE passwords become invalid when the process restarts. Generate a persistent key with `npx @serenity-kit/opaque@latest create-server-setup`.",
				);
			}
			if (resolved.raw.insecureCreateSessionOnRegister) {
				ctx.logger.warn(
					"⚠️ [better-auth-opaque] insecureCreateSessionOnRegister is enabled. This will automatically create a session upon registration, which could lead to user enumeration. Use with caution in production environments.",
				);
			}
			// Emails go out only for existing (or unverified) users: sent inline,
			// their latency tells an observer whether an email is registered.
			// Only the endpoints that really send an email with this
			// configuration are named.
			const requireVerification =
				resolved.raw.requireEmailVerification ??
				ctx.options.emailAndPassword?.requireEmailVerification ??
				false;
			const verification = ctx.options.emailVerification;
			const inlineEmailEndpoints = [
				...(resolved.raw.sendResetPassword || resolved.raw.sendResetPasswordOTP
					? ["/opaque/forget-password"]
					: []),
				...(verification?.sendVerificationEmail &&
				(verification.sendOnSignUp ?? requireVerification)
					? ["/sign-up/opaque/complete"]
					: []),
				...(verification?.sendVerificationEmail && requireVerification && verification.sendOnSignIn
					? ["/sign-in/opaque/complete"]
					: []),
			];
			if (inlineEmailEndpoints.length > 0 && !ctx.options.advanced?.backgroundTasks?.handler) {
				ctx.logger.warn(
					`⚠️ [better-auth-opaque] Emails (password reset / verification) are sent inline because \`advanced.backgroundTasks.handler\` is not configured. They are only sent for existing (or unverified) users, so the response timing of ${inlineEmailEndpoints.join(", ")} reveals whether an email is registered. Configure \`advanced.backgroundTasks\` (e.g. \`{ handler: waitUntil }\`).`,
				);
			}
			// A password change revokes other sessions server-side, but Better
			// Auth's cookie cache is validated statelessly (signature + token +
			// global `version` + maxAge); core has no per-user invalidation.
			const stateful = !!ctx.options.database || !!ctx.options.secondaryStorage;
			const cookieCache = ctx.options.session?.cookieCache;
			if (!stateful) {
				ctx.logger.warn(
					"⚠️ [better-auth-opaque] No `database` or `secondaryStorage` configured: sessions are stateless cookies, so a password change cannot revoke sessions on other devices (they stay valid until they expire).",
				);
			} else if (cookieCache?.enabled) {
				ctx.logger.info(
					`[better-auth-opaque] session.cookieCache is enabled: after a password change, revoked sessions on other devices are still accepted by /get-session and other non-sensitive endpoints for up to cookieCache.maxAge (${cookieCache.maxAge ?? 300}s).`,
				);
			}
		},
		// Better Auth applies the FIRST rule whose pathMatcher matches.
		rateLimit: [
			// Sends email: its own rule (default as core's /request-password-reset).
			{
				pathMatcher: (path: string) => path === "/opaque/forget-password",
				window: resolved.rateLimit.forgetPassword.window,
				max: resolved.rateLimit.forgetPassword.max,
			},
			// Every other OPAQUE endpoint (default as core's sign-in rule),
			// incl. /opaque/reset-password/* (the code also has its own
			// attempt budget) and /opaque/set-password/*.
			{
				pathMatcher: (path: string) =>
					path.startsWith("/sign-in/opaque/") ||
					path.startsWith("/sign-up/opaque/") ||
					path.startsWith("/opaque/"),
				window: resolved.rateLimit.window,
				max: resolved.rateLimit.max,
			},
		],
		schema: {
			account: {
				fields: {
					// Not `unique`: a unique index on a long string column fails on
					// MySQL / MSSQL, and records are random anyway.
					// Server-only: never accepted from, or returned in, API
					// input/output (e.g. core's /list-accounts). The plugin reads
					// and writes it through the adapter.
					registrationRecord: {
						type: "string",
						required: false,
						returned: false,
						input: false,
						validator: { input: z.string().base64url() },
					},
				},
			},
		},
		endpoints: {
			...signUpEndpoints(deps),
			...signInEndpoints(deps),
			...changePasswordEndpoints(deps),
			...resetPasswordEndpoints(deps),
			// Opt-in: when disabled the routes do not exist (404). Typed as
			// always present: optional keys (`{} | endpoints`) would defeat
			// Better Auth's `auth.api` filtering of hidden endpoints.
			...(resolved.setPasswordEnabled
				? setPasswordEndpoints(deps)
				: ({} as ReturnType<typeof setPasswordEndpoints>)),
		},
	} satisfies BetterAuthPlugin;
};
