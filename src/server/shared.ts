import { server } from "@serenity-kit/opaque";
import {
	APIError,
	type AuthContext,
	type GenericEndpointContext,
	generateId,
	isDevelopment,
	isTest,
	type User,
} from "better-auth";
import { setSessionCookie } from "better-auth/cookies";
import * as z from "zod";
import { OPAQUE_ERROR_CODES } from "../error-codes";
import type { OpaqueOptions } from "./options";
import {
	decryptState,
	encryptState,
	type Purpose,
	type StatePayload,
	stateIdentifier,
} from "./state";

// Sizes produced by @serenity-kit/opaque 0.9 (ristretto255, fixed-size
// outputs), expressed in unpadded base64url characters.
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const REGISTRATION_REQUEST_CHARS = 43; // 32 bytes
const REGISTRATION_RECORD_CHARS = 256; // 192 bytes
const LOGIN_REQUEST_CHARS = 128; // 96 bytes
const LOGIN_RESULT_CHARS = 86; // 64 bytes
const MAX_STATE_CHARS = 4096;
// The longest address SMTP can carry (RFC 5321). It also keeps every
// handshake state within its fixed padded size.
const MAX_EMAIL_LENGTH = 254;
const DEFAULT_CHALLENGE_EXPIRES_IN = 120;

const base64url = (chars: number) =>
	z.string().length(chars).regex(BASE64URL_RE);

export const emailAddress = z.email().max(MAX_EMAIL_LENGTH);
export const registrationRequest = base64url(REGISTRATION_REQUEST_CHARS);
export const registrationRecord = base64url(REGISTRATION_RECORD_CHARS);
export const loginRequest = base64url(LOGIN_REQUEST_CHARS);
export const loginResult = base64url(LOGIN_RESULT_CHARS);
export const state = z.string().min(1).max(MAX_STATE_CHARS);

export function normalizeEmail(email: string): string {
	return email.toLowerCase();
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

// The schemas check only length and alphabet, and the library throws on
// input that passes them but is not a valid group element. Both sign-in
// branches make the same call, so the 400 does not depend on whether the
// email exists.
function rejectMalformed<T>(run: () => T): T {
	try {
		return run();
	} catch {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_REQUEST);
	}
}

const GENERATE_HINT =
	"Generate one with: npx @serenity-kit/opaque@0.9 create-server-setup";

type WithoutSetup<T> = Omit<T, "serverSetup">;

export const createShared = (options: OpaqueOptions) => {
	const challengeTtlMs =
		(options.challengeExpiresIn ?? DEFAULT_CHALLENGE_EXPIRES_IN) * 1000;

	const shared = {
		options,
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

		// The encrypted blob alone is replayable; the marker row is what makes it single-use.
		issueState: async (ctx: GenericEndpointContext, data: StatePayload) => {
			const stateId = generateId();
			// Core purges expired rows only in findVerificationValue, not in
			// consumeVerificationValue, and abandoned challenges never reach complete;
			// looking up the fresh id runs that purge with its hooks and disableCleanup.
			await ctx.context.internalAdapter.findVerificationValue(
				stateIdentifier(stateId),
			);
			await ctx.context.internalAdapter.createVerificationValue({
				identifier: stateIdentifier(stateId),
				value: data.purpose,
				expiresAt: new Date(Date.now() + challengeTtlMs),
			});
			return encryptState(
				{ ...data, stateId, issuedAt: Date.now() },
				ctx.context.secretConfig,
			);
		},

		// consumeVerificationValue is atomic, so racing requests cannot both pass,
		// and it returns null for an expired row, hence no expiry check here.
		consumeState: async <P extends Purpose>(
			ctx: GenericEndpointContext,
			encrypted: string,
			purpose: P,
		) => {
			const decoded = await decryptState(
				encrypted,
				ctx.context.secretConfig,
				purpose,
				challengeTtlMs,
			);
			const marker = await ctx.context.internalAdapter.consumeVerificationValue(
				stateIdentifier(decoded.stateId),
			);
			if (!marker || marker.value !== purpose) {
				throw APIError.from(
					"BAD_REQUEST",
					OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE,
				);
			}
			return decoded;
		},

		startLogin: (
			params: WithoutSetup<Parameters<typeof server.startLogin>[0]>,
		) =>
			rejectMalformed(() =>
				server.startLogin({ ...params, serverSetup: shared.serverSetup }),
			),

		createRegistrationResponse: (
			params: WithoutSetup<
				Parameters<typeof server.createRegistrationResponse>[0]
			>,
		) =>
			rejectMalformed(() =>
				server.createRegistrationResponse({
					...params,
					serverSetup: shared.serverSetup,
				}),
			).registrationResponse,

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
