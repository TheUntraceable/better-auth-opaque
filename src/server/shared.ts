import { server } from "@serenity-kit/opaque";
import {
	APIError,
	type AuthContext,
	type GenericEndpointContext,
	isDevelopment,
	isTest,
	type User,
} from "better-auth";
import { setSessionCookie } from "better-auth/cookies";
import * as z from "zod";
import { OPAQUE_ERROR_CODES } from "../error-codes";
import type { OpaqueOptions } from "./options";
import { createStateStore } from "./state";

// Sizes produced by @serenity-kit/opaque 0.9 (ristretto255, fixed-size
// outputs), expressed in unpadded base64url characters.
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const REGISTRATION_REQUEST_CHARS = 43; // 32 bytes
const REGISTRATION_RECORD_CHARS = 256; // 192 bytes
const LOGIN_REQUEST_CHARS = 128; // 96 bytes
const LOGIN_RESULT_CHARS = 86; // 64 bytes
const MAX_STATE_CHARS = 4096;

const base64url = (chars: number) =>
	z.string().length(chars).regex(BASE64URL_RE);

export const registrationRequest = base64url(REGISTRATION_REQUEST_CHARS);
export const registrationRecord = base64url(REGISTRATION_RECORD_CHARS);
export const loginRequest = base64url(LOGIN_REQUEST_CHARS);
export const loginResult = base64url(LOGIN_RESULT_CHARS);
export const state = z.string().min(1).max(MAX_STATE_CHARS);

export function normalizeEmail(email: string): string {
	return email.trim().toLowerCase();
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
	const remaining = targetMs - (performance.now() - startTime);
	if (remaining > 0) {
		await new Promise((resolve) => setTimeout(resolve, remaining));
	}
}

const GENERATE_HINT =
	"Generate one with: npx @serenity-kit/opaque@latest create-server-setup";

export const createShared = (options: OpaqueOptions) => {
	const shared = {
		options,
		resetTtlMs: (options.resetPasswordTokenExpiresIn ?? 60 * 60) * 1000,
		floorMs: options.timingSafeResponseMs,
		// Both assigned by init, which better-auth runs before serving any request.
		serverSetup: "",
		requireVerification: false,

		init: (ctx: AuthContext) => {
			const configured = options.serverSetup ?? options.OPAQUE_SERVER_KEY;
			if (configured) {
				try {
					server.getPublicKey(configured);
				} catch {
					throw new Error(
						"[better-auth-opaque] serverSetup is not a valid OPAQUE server setup",
					);
				}
				shared.serverSetup = configured;
			} else if (isDevelopment() || isTest()) {
				shared.serverSetup = server.createSetup();
				ctx.logger.warn(
					`[better-auth-opaque] serverSetup not set. A temporary key was generated for this process; accounts registered now will stop working on restart. ${GENERATE_HINT}`,
				);
			} else {
				throw new Error(
					`[better-auth-opaque] serverSetup is required unless NODE_ENV is development or test. ${GENERATE_HINT}`,
				);
			}
			shared.requireVerification =
				options.requireEmailVerification ??
				ctx.options.emailAndPassword?.requireEmailVerification ??
				false;
		},

		/**
		 * Runs an app-supplied hook (mailer, notification) without letting it
		 * change the HTTP response. Mailers fail; a 500 that only happens on the
		 * "account exists" branch would be an enumeration oracle, so better-auth's
		 * background runner logs the error and the endpoint answers as normal.
		 * Honours `advanced.backgroundTasks` like core does.
		 */
		runHook: (ctx: GenericEndpointContext, hook: () => unknown) =>
			ctx.context.runInBackgroundOrAwait(Promise.resolve().then(hook)),

		...createStateStore((options.challengeExpiresIn ?? 120) * 1000),

		finishLogin: (
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
		},

		issueSession: async (
			ctx: GenericEndpointContext,
			user: User,
			dontRememberMe: boolean,
		) => {
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
			return session;
		},
	};
	return shared;
};

export type Shared = ReturnType<typeof createShared>;
