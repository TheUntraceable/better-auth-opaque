import { client, server } from "@serenity-kit/opaque";
import { APIError, type User } from "better-auth";
import {
	generateRandomString,
	makeSignature,
	symmetricDecrypt,
	symmetricEncrypt,
} from "better-auth/crypto";
import { OPAQUE_ERROR_CODES } from "./error-codes.js";

export { OPAQUE_ERROR_CODES, type OpaqueErrorCode } from "./error-codes.js";

/** Options of the `opaque()` server plugin. Invalid values throw at construction. */
export interface OpaqueOptions {
	/**
	 * The OPAQUE server setup (a base64url string of 128 bytes), e.g. the output of
	 * `npx @serenity-kit/opaque@latest create-server-setup`.
	 *
	 * If omitted, a random one is generated at startup for DEVELOPMENT ONLY: every
	 * restart then invalidates every registered password. Omitting it when
	 * `NODE_ENV === "production"` throws at startup.
	 */
	OPAQUE_SERVER_KEY?: string;
	/**
	 * Sign a NEWLY created user in when `/sign-up/opaque/complete` succeeds.
	 * Never for a duplicate registration, and never while email verification
	 * is required. The response still has the same body either way, but the
	 * presence of a session cookie tells a caller whether the email was new:
	 * this re-enables user enumeration through sign-up. Default `false`.
	 */
	insecureCreateSessionOnRegister?: boolean;
	/**
	 * Rate limits (per client IP and path) of the OPAQUE endpoints. Only
	 * enforced when Better Auth's rate limiter is enabled (`rateLimit.enabled`,
	 * on by default in production).
	 */
	rateLimit?: {
		/**
		 * Window, in seconds, of every OPAQUE endpoint except
		 * `/opaque/forget-password`. Default 10 (as core's sign-in rule).
		 */
		window?: number;
		/**
		 * Requests allowed per `window` on every OPAQUE endpoint except
		 * `/opaque/forget-password`. Default 3 (as core's sign-in rule).
		 */
		max?: number;
		/**
		 * Rule of `/opaque/forget-password` (which sends email). Independent of
		 * `window` / `max`. Default: 3 requests per 60 seconds, as core's
		 * `/request-password-reset`.
		 */
		forgetPassword?: {
			/** Seconds. Default 60. */
			window?: number;
			/** Default 3. */
			max?: number;
		};
	};
	/**
	 * Enables forgot/reset password by emailed LINK. Called for every existing
	 * user (with or without an OPAQUE account) who requests a reset; never for
	 * unknown emails. `url` points at `GET /opaque/reset-password/:token`,
	 * which redirects to the requested `redirectTo` with `?token=`.
	 *
	 * Configure `advanced.backgroundTasks` so that sending does not delay the
	 * response for existing users only (a timing side channel).
	 */
	sendResetPassword?: (
		data: { user: User; url: string; token: string },
		request?: Request,
	) => Promise<void> | void;
	/**
	 * Enables forgot/reset password by emailed one-time CODE. Called for every
	 * existing user who requests a reset; never for unknown emails.
	 *
	 * Configure `advanced.backgroundTasks` (see `sendResetPassword`).
	 */
	sendResetPasswordOTP?: (
		data: { user: User; otp: string },
		request?: Request,
	) => Promise<void> | void;
	/** Lifetime of a reset link token, in seconds. Must be > 0. Default 3600. */
	resetPasswordTokenExpiresIn?: number;
	/** The emailed reset code. */
	resetPasswordOTP?: {
		/** Lifetime of a code, in seconds. Must be > 0. Default 300. */
		expiresIn?: number;
		/** Number of digits, at least 4. Default 6. */
		length?: number;
		/**
		 * Wrong guesses (challenge and complete steps combined) after which
		 * the code is deleted; at least 1. Default 3.
		 */
		allowedAttempts?: number;
	};
	/**
	 * Refuse OPAQUE login (403 `EMAIL_NOT_VERIFIED`, after the password proof
	 * has been verified) until the user's email is verified. Defaults to Better
	 * Auth's `emailAndPassword.requireEmailVerification`.
	 */
	requireEmailVerification?: boolean;
	/**
	 * `/opaque/set-password/*`: lets a logged-in user WITHOUT an OPAQUE
	 * password (e.g. social sign-in only) add one. Requires a fresh session
	 * (`session.freshAge`). When disabled the endpoints do not exist (404).
	 */
	setPassword?: {
		/** Default `false`. */
		enabled?: boolean;
	};
}

export const DEFAULT_RESET_TOKEN_EXPIRES_IN = 3600;
export const DEFAULT_RESET_OTP_EXPIRES_IN = 300;
export const DEFAULT_RESET_OTP_LENGTH = 6;
export const DEFAULT_RESET_OTP_ALLOWED_ATTEMPTS = 3;
export const MIN_RESET_OTP_LENGTH = 4;

export const REGISTRATION_REQUEST_LENGTH = 32;
export const REGISTRATION_RECORD_MIN_LENGTH = 170;
export const REGISTRATION_RECORD_MAX_LENGTH = 200;
export const LOGIN_REQUEST_LENGTH = 96;
export const FINISH_LOGIN_REQUEST_LENGTH = 64;
export const SERVER_SETUP_LENGTH = 128;

/** Lifetime of a login / change-password / set-password challenge. */
export const LOGIN_STATE_TTL_MS = 15 * 60 * 1000;
/** The plaintext of the encrypted state is padded to a multiple of this many bytes. */
export const STATE_PADDING_BLOCK_SIZE = 256;
/** Upper bound for the client-supplied encrypted state, to bound decrypt work. */
export const ENCRYPTED_STATE_MAX_LENGTH = 8192;

/* ------------------------------------------------------------------------- */
/*                         Verification-table identifiers                    */
/* ------------------------------------------------------------------------- */

/**
 * Namespaced verification identifiers for single-use challenge nonces. The
 * row's `value` is the user id. No prefix contains a SQL `LIKE` wildcard
 * (`%`, `_`): rows are purged by `identifier LIKE '<prefix>%' AND value = ?`.
 */
export const NONCE_IDENTIFIER_PREFIX = {
	login: "opaque-login:",
	"change-password": "opaque-change-password:",
} as const;

export type LoginStatePurpose = keyof typeof NONCE_IDENTIFIER_PREFIX;

export function nonceIdentifier(purpose: LoginStatePurpose, nonce: string) {
	return `${NONCE_IDENTIFIER_PREFIX[purpose]}${nonce}`;
}

/**
 * Verification-table identifiers of the password-reset / set-password flows.
 * Deliberately distinct from core's `reset-password:` so an OPAQUE reset token
 * is never accepted (or burnt) by core's `/reset-password`.
 */
export const RESET_TOKEN_IDENTIFIER_PREFIX = "opaque-reset-password:";
export const RESET_OTP_IDENTIFIER_PREFIX = "opaque-reset-otp:";
export const SET_PASSWORD_IDENTIFIER_PREFIX = "opaque-set-password:";

export function setPasswordIdentifier(userId: string) {
	return `${SET_PASSWORD_IDENTIFIER_PREFIX}${userId}`;
}

/* ------------------------------------------------------------------------- */
/*                               Keyed hashing                               */
/* ------------------------------------------------------------------------- */

/**
 * Labels of the keys derived from Better Auth's `secret`: every use of the
 * secret gets its own key, so no two purposes ever share one.
 */
export const KEY_LABELS = {
	/** Encrypts the challenge state round-tripped through the client. */
	state: "opaque-state",
	/** Hashes reset link tokens into verification identifiers. */
	resetToken: "opaque-reset-token",
	/** Hashes reset codes, and emails into OTP verification identifiers. */
	resetOTP: "opaque-reset-otp",
	/** Digests of registration records, and reset-credential bindings. */
	recordDigest: "opaque-record-digest",
} as const;

export type KeyLabel = (typeof KEY_LABELS)[keyof typeof KEY_LABELS];

function toBase64Url(base64: string): string {
	return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const derivedKeys = new Map<string, Promise<string>>();

/**
 * `HMAC-SHA256(secret, "better-auth-opaque/" + label)`, base64url: a
 * per-purpose key derived from the auth secret (HMAC as a PRF / HKDF-Expand
 * with a single block). Memoised per (secret, label).
 */
export function deriveKey(secret: string, label: KeyLabel): Promise<string> {
	const cacheKey = `${label}\u0000${secret}`;
	let key = derivedKeys.get(cacheKey);
	if (!key) {
		if (derivedKeys.size >= 256) derivedKeys.clear();
		key = makeSignature(`better-auth-opaque/${label}`, secret).then(toBase64Url);
		derivedKeys.set(cacheKey, key);
	}
	return key;
}

/** base64url HMAC-SHA256 of `value` under `key`, domain-separated by `purpose`. */
export async function keyedHash(key: string, purpose: string, value: string): Promise<string> {
	return toBase64Url(await makeSignature(`${purpose}\u0000${value}`, key));
}

/**
 * Link tokens are stored hashed (under the `resetToken` key): a leaked
 * verification table does not yield usable reset links.
 */
export async function resetTokenIdentifier(key: string, token: string) {
	return `${RESET_TOKEN_IDENTIFIER_PREFIX}${await keyedHash(key, "token", token)}`;
}

/**
 * The OTP row of an email: a keyed hash of the normalised email (under the
 * `resetOTP` key), so the table holds no email and the identifier has a fixed
 * length (60 characters) whatever the email's.
 */
export async function resetOTPIdentifier(key: string, email: string) {
	return `${RESET_OTP_IDENTIFIER_PREFIX}${await keyedHash(key, "identifier", normalizeEmail(email))}`;
}

/** Keyed hash of an OTP, bound to the email it was issued for. */
export function hashResetOTP(key: string, email: string, otp: string) {
	return keyedHash(key, "code", `${normalizeEmail(email)}\u0000${otp}`);
}

export interface ResetOTPRecord {
	userId: string;
	otpHash: string;
	attempts: number;
	/** Binding of the code to the user's email and password record at issue time. */
	binding: string;
}

export function encodeResetOTPRecord(record: ResetOTPRecord): string {
	return JSON.stringify(record);
}

/** Parses a stored OTP record; `null` if it is malformed. Never throws. */
export function decodeResetOTPRecord(value: string): ResetOTPRecord | null {
	try {
		const data = JSON.parse(value) as Partial<ResetOTPRecord> | null;
		if (
			!data ||
			typeof data.userId !== "string" ||
			typeof data.otpHash !== "string" ||
			typeof data.binding !== "string" ||
			typeof data.attempts !== "number" ||
			!Number.isInteger(data.attempts) ||
			data.attempts < 0
		) {
			return null;
		}
		return {
			userId: data.userId,
			otpHash: data.otpHash,
			attempts: data.attempts,
			binding: data.binding,
		};
	} catch {
		return null;
	}
}

/** Separates the random part of a reset link token from its binding. */
export const RESET_TOKEN_SEPARATOR = ".";

/** A new link token: `<32 random alphanumerics>.<binding>`. */
export function createResetToken(binding: string): string {
	return `${generateRandomString(32, "a-z", "0-9", "A-Z")}${RESET_TOKEN_SEPARATOR}${binding}`;
}

/** The binding carried by a link token, or `null` if the token is malformed. */
export function resetTokenBinding(token: string): string | null {
	const i = token.indexOf(RESET_TOKEN_SEPARATOR);
	if (i <= 0 || i === token.length - 1) return null;
	return token.slice(i + 1);
}

/**
 * Whether a verification row has expired. `expiresAt` is a `Date` from a
 * database but an ISO string from `secondaryStorage`; an unreadable value
 * counts as expired.
 */
export function isExpired(row: { expiresAt: Date | string | number }): boolean {
	const expiresAt = new Date(row.expiresAt).getTime();
	return !Number.isFinite(expiresAt) || expiresAt < Date.now();
}

/* ------------------------------------------------------------------------- */
/*                               Misc helpers                                */
/* ------------------------------------------------------------------------- */

/**
 * A copy of the request for user callbacks (the original body has usually
 * been consumed by the time a callback runs). Mirrors core's `safeCloneRequest`.
 */
export function cloneRequest(request: Request | undefined): Request | undefined {
	if (!request) return undefined;
	try {
		return request.clone() as Request;
	} catch {
		return new Request(request.url, {
			headers: request.headers,
			method: request.method,
			redirect: request.redirect,
			referrer: request.referrer,
			referrerPolicy: request.referrerPolicy,
			signal: request.signal,
		});
	}
}

/**
 * The single normalisation used for the OPAQUE `userIdentifier` everywhere
 * (register, login, change password). Matches Better Auth core, which
 * lower-cases emails in `createUser` and `findUserByEmail`.
 */
export function normalizeEmail(email: string): string {
	return email.toLowerCase();
}

function bytesToBase64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return toBase64Url(btoa(binary));
}

/** 32 random bytes, base64url encoded. */
export function generateNonce(): string {
	return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export function base64UrlDecode(str: string): string {
	const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
	return atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
}

/**
 * Decoded byte length of a CANONICAL unpadded base64url string, or -1 if the
 * input is not one (bad characters, impossible length, or non-zero unused
 * bits in the last character, which the OPAQUE library rejects). Never throws.
 */
function decodedLength(base64: string): number {
	if (!/^[A-Za-z0-9_-]*$/.test(base64) || base64.length % 4 === 1) return -1;
	try {
		const decoded = base64UrlDecode(base64);
		if (toBase64Url(btoa(decoded)) !== base64) return -1;
		return decoded.length;
	} catch {
		return -1;
	}
}

type ErrorCodeEntry = { code: string; message: string };

/** 400 `error` unless `base64` is canonical base64url of exactly `expectedLength` bytes. */
export function validateBase64Length(
	base64: string,
	expectedLength: number,
	error: ErrorCodeEntry,
): void {
	if (decodedLength(base64) !== expectedLength) {
		throw APIError.from("BAD_REQUEST", error);
	}
}

/** 400 `error` unless `base64` is canonical base64url of `min`..`max` bytes. */
export function validateBase64LengthRange(
	base64: string,
	min: number,
	max: number,
	error: ErrorCodeEntry,
): void {
	if (!hasBase64LengthInRange(base64, min, max)) {
		throw APIError.from("BAD_REQUEST", error);
	}
}

export function hasBase64LengthInRange(base64: string, min: number, max: number): boolean {
	const length = decodedLength(base64);
	return length >= min && length <= max;
}

/**
 * Validates a server setup string at configuration time (format and length only;
 * the cryptographic check needs `ready` and is done by `assertValidServerSetup`).
 */
export function assertServerSetupFormat(serverSetup: unknown): asserts serverSetup is string {
	if (typeof serverSetup !== "string" || !/^[A-Za-z0-9_-]+$/.test(serverSetup)) {
		throw new Error(
			"[better-auth-opaque] OPAQUE_SERVER_KEY must be a base64url string (generate one with `npx @serenity-kit/opaque@latest create-server-setup`).",
		);
	}
	const length = decodedLength(serverSetup);
	if (length !== SERVER_SETUP_LENGTH) {
		throw new Error(
			`[better-auth-opaque] OPAQUE_SERVER_KEY has the wrong length: expected ${SERVER_SETUP_LENGTH} bytes, got ${length < 0 ? "undecodable input" : `${length} bytes`}.`,
		);
	}
}

/** Full validation of a server setup. Must be called after `await ready`. */
export function assertValidServerSetup(serverSetup: string): void {
	assertServerSetupFormat(serverSetup);
	try {
		server.getPublicKey(serverSetup);
	} catch (error) {
		throw new Error(
			`[better-auth-opaque] OPAQUE_SERVER_KEY is not a valid OPAQUE server setup: ${error instanceof Error ? error.message : String(error)}`,
		);
	}
}

/**
 * Parses an exception of `@serenity-kit/opaque`, which throws either
 * `Error('opaque protocol error at "<stage>"; ...')` (e.g. `deserialize
 * finishLoginRequest`, `finish server login`) or `Error('base64 decoding
 * failed at "<field>"; ...')`. Returns `null` for anything else.
 */
export function parseOpaqueError(
	error: unknown,
): { kind: "protocol" | "base64"; stage: string } | null {
	const message = error instanceof Error ? error.message : String(error);
	const protocol = /^opaque protocol error at "([^"]+)"/.exec(message);
	if (protocol?.[1]) return { kind: "protocol", stage: protocol[1] };
	const base64 = /^base64 decoding failed at "([^"]+)"/.exec(message);
	if (base64?.[1]) return { kind: "base64", stage: base64[1] };
	return null;
}

/**
 * The OPAQUE message a library error is about when the error means "this
 * input could not be decoded / deserialised" (e.g. `finishLoginRequest`);
 * `null` for any other error.
 */
export function undecodableInput(error: unknown): string | null {
	const parsed = parseOpaqueError(error);
	if (!parsed) return null;
	if (parsed.kind === "base64") return parsed.stage;
	return parsed.stage.startsWith("deserialize ")
		? parsed.stage.slice("deserialize ".length)
		: null;
}

/**
 * Checks that a client-supplied registration record deserialises, so that a
 * malformed record can never be stored and later make login throw.
 * Cheap: no key stretching is involved on either side.
 */
export function isDeserializableRegistrationRecord(
	registrationRecord: string,
	serverSetup: string,
): boolean {
	try {
		const { startLoginRequest } = client.startLogin({
			password: generateRandomString(16),
		});
		server.startLogin({
			serverSetup,
			userIdentifier: "registration-record-probe",
			registrationRecord,
			startLoginRequest,
		});
		return true;
	} catch {
		return false;
	}
}

/* ------------------------------------------------------------------------- */
/*                              Encrypted state                              */
/* ------------------------------------------------------------------------- */

export function padToLength(input: string, targetLength: number): string {
	const currentLength = new TextEncoder().encode(input).length;

	if (currentLength > targetLength) {
		throw new Error("Payload size exceeds target padding length.");
	}

	// Since the entire payload is encrypted, the padding character itself is
	// not security-sensitive.
	return input + " ".repeat(targetLength - currentLength);
}

/** Pads with spaces to the next multiple of `blockSize` bytes. Never throws. */
export function padToBlockSize(
	input: string,
	blockSize: number = STATE_PADDING_BLOCK_SIZE,
): string {
	const currentLength = new TextEncoder().encode(input).length;
	const target = Math.max(blockSize, Math.ceil(currentLength / blockSize) * blockSize);
	return padToLength(input, target);
}

export interface ServerLoginStatePayload {
	serverLoginState: string;
	userId: string;
	/** Names the single-use verification row of this challenge. */
	nonce: string;
	purpose: LoginStatePurpose;
	/**
	 * Keyed digest of the registration record the challenge was issued
	 * against: completing it after the record changed is refused.
	 */
	recordDigest: string;
	issuedAt: number;
}

/**
 * Encrypts the OPAQUE server login state for the round trip through the client.
 * Only the user id is embedded (never the user object) and the plaintext is
 * padded to a block size so its length does not depend on the user.
 *
 * `binding` is what the plugin always passes; it is optional only for the
 * stand-alone use of this helper (a random nonce, "login", no record).
 */
export async function encryptServerLoginState(
	serverLoginState: string,
	key: string,
	user: { id: string } | null,
	binding?: { nonce: string; purpose: LoginStatePurpose; recordDigest: string },
): Promise<string> {
	const payload: ServerLoginStatePayload = {
		serverLoginState,
		userId: user?.id ?? "",
		nonce: binding?.nonce ?? generateNonce(),
		purpose: binding?.purpose ?? "login",
		recordDigest: binding?.recordDigest ?? "",
		issuedAt: Date.now(),
	};
	return await symmetricEncrypt({
		data: padToBlockSize(JSON.stringify(payload)),
		key,
	});
}

/**
 * Decrypts and validates the encrypted state. Throws `APIError` BAD_REQUEST
 * (`INVALID_LOGIN_STATE` / `LOGIN_STATE_EXPIRED`); never anything else.
 */
export async function decryptServerLoginState(
	encryptedState: string,
	key: string,
): Promise<ServerLoginStatePayload> {
	let data: unknown;
	try {
		if (encryptedState.length > ENCRYPTED_STATE_MAX_LENGTH) throw new Error();
		const decrypted = await symmetricDecrypt({ key, data: encryptedState });
		data = JSON.parse(decrypted);
	} catch {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE);
	}
	const payload = data as Partial<ServerLoginStatePayload> | null;
	if (
		typeof payload !== "object" ||
		payload === null ||
		typeof payload.serverLoginState !== "string" ||
		typeof payload.userId !== "string" ||
		typeof payload.nonce !== "string" ||
		typeof payload.purpose !== "string" ||
		!Object.hasOwn(NONCE_IDENTIFIER_PREFIX, payload.purpose) ||
		typeof payload.recordDigest !== "string" ||
		typeof payload.issuedAt !== "number"
	) {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE);
	}
	if (payload.issuedAt + LOGIN_STATE_TTL_MS < Date.now()) {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.LOGIN_STATE_EXPIRED);
	}
	return payload as ServerLoginStatePayload;
}
