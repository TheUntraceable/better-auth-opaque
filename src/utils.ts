import { client, ready, server } from "@serenity-kit/opaque";
import { APIError, type User } from "better-auth";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";

/* -------------------------------------------------------------------------- */
/*                                   Options                                  */
/* -------------------------------------------------------------------------- */

export interface OpaqueOptions {
	/**
	 * The OPAQUE server setup, generated once with
	 * `import { server } from "@serenity-kit/opaque"; server.createSetup()`.
	 *
	 * Every registration record is bound to this value. Rotating it
	 * invalidates every password; losing it locks every user out.
	 * Required in production. In development a per-process key is generated
	 * and accounts do not survive a restart.
	 */
	OPAQUE_SERVER_KEY?: string | undefined;

	/**
	 * Create a session as soon as registration completes.
	 *
	 * Off by default because it turns the sign-up endpoint into an account
	 * existence oracle (an existing email cannot be issued a session). Only
	 * enable it if you accept that trade-off.
	 */
	insecureCreateSessionOnRegister?: boolean | undefined;

	/**
	 * Minimum response time, in milliseconds, for the endpoints whose work
	 * depends on whether an account exists (sign-in challenge, sign-up
	 * completion, reset-password request).
	 *
	 * Off by default. The plugin already performs matched work on both
	 * branches, which is the RFC 9807 approach and what better-auth core
	 * does. Enable this only as a backstop when your write path is much
	 * slower than your read path, and set it to roughly 2-3x your p99
	 * handler time. Requests that overrun the floor leak their real
	 * duration.
	 */
	timingSafeResponseMs?: number | undefined;

	/**
	 * Reject sign-in until the user's email is verified. Defaults to
	 * `emailAndPassword.requireEmailVerification` from your auth config.
	 */
	requireEmailVerification?: boolean | undefined;

	/**
	 * Called when someone tries to register with an email that already has
	 * an account. The response is identical either way; use this to email
	 * the real owner ("someone tried to sign up with your address, reset
	 * your password here").
	 */
	onExistingUserSignUp?:
		| ((data: { user: User }, request?: Request) => Promise<void> | void)
		| undefined;

	/**
	 * Deliver a password reset email. Required for `opaque.requestPasswordReset`.
	 * `url` points at the plugin's redirect endpoint, which forwards the
	 * browser to `redirectTo?token=...`.
	 */
	sendResetPassword?:
		| ((
				data: { user: User; url: string; token: string },
				request?: Request,
		  ) => Promise<void> | void)
		| undefined;

	/**
	 * Lifetime of a password reset token, in seconds. Default: 1 hour.
	 */
	resetPasswordTokenExpiresIn?: number | undefined;

	/**
	 * Lifetime of an in-flight challenge, in seconds. The client finishes a
	 * handshake in well under a second; the default is 120.
	 */
	challengeExpiresIn?: number | undefined;
}

/* -------------------------------------------------------------------------- */
/*                                 Error codes                                */
/* -------------------------------------------------------------------------- */

export { OPAQUE_ERROR_CODES, type OpaqueErrorCode } from "./error-codes";
import { OPAQUE_ERROR_CODES } from "./error-codes";

/* -------------------------------------------------------------------------- */
/*                               Wire-size checks                             */
/* -------------------------------------------------------------------------- */

// Sizes produced by @serenity-kit/opaque 0.9 (ristretto255, fixed-size
// outputs), expressed in unpadded base64url characters.
export const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
export const REGISTRATION_REQUEST_CHARS = 43; // 32 bytes
export const REGISTRATION_RECORD_CHARS = 256; // 192 bytes
export const LOGIN_REQUEST_CHARS = 128; // 96 bytes
export const LOGIN_RESULT_CHARS = 86; // 64 bytes
export const MAX_STATE_CHARS = 4096;

/* -------------------------------------------------------------------------- */
/*                               Encrypted state                              */
/* -------------------------------------------------------------------------- */

/**
 * Everything the server needs to finish a handshake lives in this blob,
 * handed to the client between the challenge and complete steps. It is
 * AEAD-encrypted under the auth secret, bound to a purpose so a sign-in
 * state cannot be replayed into change-password, and (via `stateId`)
 * consumed exactly once.
 */
export interface OpaqueState {
	purpose: string;
	stateId: string;
	issuedAt: number;
	serverLoginState?: string;
	userId?: string | null;
	email?: string;
	credentialId?: string;
	newCredentialId?: string;
	token?: string;
}

// Fixed-length ciphertext so the state's size never reveals which branch
// produced it. Large enough for every purpose above with headroom.
const STATE_PADDED_LENGTH = 1024;
const encoder = new TextEncoder();

function padToLength(input: string, length: number): string {
	const byteLength = encoder.encode(input).length;
	if (byteLength > length) {
		throw new Error(
			`Opaque state is ${byteLength} bytes, over the ${length} byte limit`,
		);
	}
	return input + " ".repeat(length - byteLength);
}

export async function encryptState(
	state: OpaqueState,
	secret: string,
): Promise<string> {
	return symmetricEncrypt({
		key: secret,
		data: padToLength(JSON.stringify(state), STATE_PADDED_LENGTH),
	});
}

export async function decryptState(
	encrypted: string,
	secret: string,
	expectedPurpose: string,
	maxAgeMs: number,
): Promise<OpaqueState> {
	let state: OpaqueState;
	try {
		state = JSON.parse(
			(await symmetricDecrypt({ key: secret, data: encrypted })).trimEnd(),
		);
	} catch {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE);
	}
	// Domain separation and expiry share one generic error so the response
	// does not say which check failed.
	if (
		!state ||
		typeof state !== "object" ||
		state.purpose !== expectedPurpose ||
		typeof state.stateId !== "string" ||
		typeof state.issuedAt !== "number" ||
		state.issuedAt + maxAgeMs < Date.now()
	) {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE);
	}
	return state;
}

/* -------------------------------------------------------------------------- */
/*                             Identifiers & records                          */
/* -------------------------------------------------------------------------- */

export function normalizeEmail(email: string): string {
	return email.trim().toLowerCase();
}

function toBase64Url(bytes: ArrayBuffer): string {
	let binary = "";
	for (const byte of new Uint8Array(bytes)) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * The OPAQUE credential identifier is server-chosen and stable; it must not
 * be the email, which better-auth lower-cases and lets users change. For
 * accounts that do not exist we still need an identifier that is the same
 * every time the same email is tried (otherwise a client reusing a blinded
 * request could tell the OPRF evaluations apart), so derive one from the
 * secret.
 */
export async function fakeCredentialId(
	secret: string,
	email: string,
): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sig = await crypto.subtle.sign(
		"HMAC",
		key,
		encoder.encode(`better-auth-opaque:fake-credential:${email}`),
	);
	return toBase64Url(sig);
}

let dummyLoginRequest: string | undefined;

/**
 * Checks that a client-supplied registration record deserialises and can
 * start a login under the given credential identifier. Without this a
 * malformed record would be persisted and every later login would crash.
 */
export async function assertValidRegistrationRecord(
	serverSetup: string,
	credentialId: string,
	registrationRecord: string,
): Promise<void> {
	await ready;
	dummyLoginRequest ??= client.startLogin({
		password: "record-validation",
	}).startLoginRequest;
	try {
		server.startLogin({
			serverSetup,
			userIdentifier: credentialId,
			registrationRecord,
			startLoginRequest: dummyLoginRequest,
		});
	} catch {
		throw APIError.from(
			"BAD_REQUEST",
			OPAQUE_ERROR_CODES.INVALID_REGISTRATION_RECORD,
		);
	}
}

export interface OpaqueAccount {
	id: string;
	userId: string;
	providerId: string;
	registrationRecord?: string | null;
	credentialId?: string | null;
	[key: string]: unknown;
}

export async function findOpaqueAccount(
	ctx: {
		context: {
			internalAdapter: { findAccounts: (userId: string) => Promise<unknown[]> };
		};
	},
	userId: string,
): Promise<OpaqueAccount | undefined> {
	const accounts = (await ctx.context.internalAdapter.findAccounts(
		userId,
	)) as OpaqueAccount[];
	return accounts.find((account) => account.providerId === "opaque");
}

/**
 * Records written by 2.x were bound to the (lower-cased) email rather than
 * a credential id. Fall back to that so those users keep working.
 */
export function credentialIdFor(
	account: OpaqueAccount | undefined,
	email: string,
): string {
	return account?.credentialId || email;
}

/* -------------------------------------------------------------------------- */
/*                                   Timing                                   */
/* -------------------------------------------------------------------------- */

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
