import { server } from "@serenity-kit/opaque";
import { APIError, type AuthContext } from "better-auth";
import * as z from "zod";
import type { OpaqueOptions } from "./options";
import { createStateStore } from "./state";

// Sizes produced by @serenity-kit/opaque 0.9 (ristretto255, fixed-size
// outputs), expressed in unpadded base64url characters.
export const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
export const REGISTRATION_REQUEST_CHARS = 43; // 32 bytes
export const REGISTRATION_RECORD_CHARS = 256; // 192 bytes
export const LOGIN_REQUEST_CHARS = 128; // 96 bytes
export const LOGIN_RESULT_CHARS = 86; // 64 bytes
export const MAX_STATE_CHARS = 4096;

const base64url = (chars: number) =>
	z.string().length(chars).regex(BASE64URL_RE);

export const registrationRequest = base64url(REGISTRATION_REQUEST_CHARS);
export const registrationRecord = base64url(REGISTRATION_RECORD_CHARS);
export const loginRequest = base64url(LOGIN_REQUEST_CHARS);
export const loginResult = base64url(LOGIN_RESULT_CHARS);
export const state = z.string().min(1).max(MAX_STATE_CHARS);

const isProduction = () =>
	typeof process !== "undefined" && process.env?.NODE_ENV === "production";

export function normalizeEmail(email: string): string {
	return email.trim().toLowerCase();
}

export function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Pads a handler to a minimum duration. If the work already took longer
 * the real duration leaks, so this is a backstop, not a guarantee.
 */
export async function enforceMinimumDuration(
	startTime: number,
	targetMs: number | undefined,
): Promise<void> {
	if (!targetMs) return;
	const elapsed = performance.now() - startTime;
	if (elapsed < targetMs) {
		await sleep(targetMs - elapsed);
	}
}

export const createShared = (options: OpaqueOptions) => {
	let serverSetup = options.OPAQUE_SERVER_KEY;
	const challengeTtlMs = (options.challengeExpiresIn ?? 120) * 1000;
	const resetTtlMs = (options.resetPasswordTokenExpiresIn ?? 60 * 60) * 1000;
	const floorMs = options.timingSafeResponseMs;

	const requireSetup = () => {
		if (!serverSetup) {
			throw APIError.from("INTERNAL_SERVER_ERROR", {
				code: "OPAQUE_NOT_INITIALISED",
				message: "OPAQUE server key is not initialised",
			});
		}
		return serverSetup;
	};

	type HookCtx = {
		context: {
			runInBackgroundOrAwait: (promise: Promise<unknown>) => unknown;
		};
	};

	/**
	 * Runs an app-supplied hook (mailer, notification) without letting it
	 * change the HTTP response. Mailers fail; a 500 that only happens on the
	 * "account exists" branch would be an enumeration oracle, so better-auth's
	 * background runner logs the error and the endpoint answers as normal.
	 * Honours `advanced.backgroundTasks` like core does.
	 */
	const runHook = (ctx: HookCtx, hook: () => unknown) =>
		ctx.context.runInBackgroundOrAwait(Promise.resolve().then(hook));

	const finishLoginOrThrow = (
		finishLoginRequest: string,
		serverLoginState: string,
		code: { code: string; message: string },
	) => {
		try {
			const { sessionKey } = server.finishLogin({
				finishLoginRequest,
				serverLoginState,
			});
			if (!sessionKey) throw new Error("no session key");
			return sessionKey;
		} catch {
			// The library throws on a bad proof; surface it as an auth failure,
			// never as a 500.
			throw APIError.from("UNAUTHORIZED", code);
		}
	};

	const init = (ctx: AuthContext) => {
		if (!serverSetup) {
			if (isProduction()) {
				throw new Error(
					"[better-auth-opaque] OPAQUE_SERVER_KEY is required in production. Generate one with: import { server } from '@serenity-kit/opaque'; console.log(server.createSetup())",
				);
			}
			serverSetup = server.createSetup();
			ctx.logger.warn(
				"[better-auth-opaque] OPAQUE_SERVER_KEY not set. A temporary key was generated for this process; accounts registered now will stop working on restart. Generate a permanent key with: import { server } from '@serenity-kit/opaque'; server.createSetup()",
			);
		}
		try {
			server.getPublicKey(serverSetup);
		} catch {
			throw new Error(
				"[better-auth-opaque] OPAQUE_SERVER_KEY is not a valid server setup",
			);
		}
	};

	return {
		options,
		resetTtlMs,
		floorMs,
		init,
		requireSetup,
		runHook,
		...createStateStore(challengeTtlMs),
		finishLoginOrThrow,
	};
};

export type Shared = ReturnType<typeof createShared>;
