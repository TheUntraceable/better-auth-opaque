import { client, server } from "@serenity-kit/opaque";
import { type Account, APIError, type User } from "better-auth";
import {
	constantTimeEqual,
	generateRandomString,
	makeSignature,
	symmetricDecrypt,
	symmetricEncrypt,
} from "better-auth/crypto";
import { OPAQUE_ERROR_CODES } from "./error-codes";

export { OPAQUE_ERROR_CODES, type OpaqueErrorCode } from "./error-codes";

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
	// Purposely make this long and verbose to discourage the use of it.
	// People who use it should understand the risks.
	insecureCreateSessionOnRegister?: boolean;
	/**
	 * Rate limit applied to every OPAQUE endpoint (per IP, per path).
	 * Defaults to Better Auth's core sign-in rule: 3 requests per 10 seconds.
	 */
	rateLimit?: {
		window?: number;
		max?: number;
	};
	/**
	 * Enables forgot/reset password by emailed LINK. Called for every existing
	 * user (with or without an OPAQUE account) who requests a reset; never for
	 * unknown emails. `url` points at `GET /opaque/reset-password/:token`,
	 * which redirects to the requested `redirectTo` with `?token=`.
	 */
	sendResetPassword?: (
		data: { user: User; url: string; token: string },
		request?: Request,
	) => Promise<void> | void;
	/**
	 * Enables forgot/reset password by emailed one-time CODE. Called for every
	 * existing user who requests a reset; never for unknown emails.
	 */
	sendResetPasswordOTP?: (
		data: { user: User; otp: string },
		request?: Request,
	) => Promise<void> | void;
	/** Lifetime of a reset link token, in seconds. Default 3600. */
	resetPasswordTokenExpiresIn?: number;
	resetPasswordOTP?: {
		/** Lifetime of a reset code, in seconds. Default 300. */
		expiresIn?: number;
		/** Number of digits. Default 6. */
		length?: number;
		/** Wrong guesses (challenge and complete combined) before the code is locked. Default 3. */
		allowedAttempts?: number;
	};
	/**
	 * Refuse OPAQUE login (403 `EMAIL_NOT_VERIFIED`, after the password proof
	 * has been verified) until the user's email is verified. Defaults to Better
	 * Auth's `emailAndPassword.requireEmailVerification`.
	 */
	requireEmailVerification?: boolean;
}

export const DEFAULT_RESET_TOKEN_EXPIRES_IN = 3600;
export const DEFAULT_RESET_OTP_EXPIRES_IN = 300;
export const DEFAULT_RESET_OTP_LENGTH = 6;
export const DEFAULT_RESET_OTP_ALLOWED_ATTEMPTS = 3;

export const REGISTRATION_REQUEST_LENGTH = 32;
export const REGISTRATION_RECORD_MIN_LENGTH = 170;
export const REGISTRATION_RECORD_MAX_LENGTH = 200;
export const LOGIN_REQUEST_LENGTH = 96;
export const FINISH_LOGIN_REQUEST_LENGTH = 64;
export const SERVER_SETUP_LENGTH = 128;

/** Lifetime of a login / change-password challenge (encrypted state + nonce row). */
export const LOGIN_STATE_TTL_MS = 15 * 60 * 1000;
/** The plaintext of the encrypted state is padded to a multiple of this many bytes. */
export const STATE_PADDING_BLOCK_SIZE = 256;
/** Upper bound for the client-supplied encrypted state, to bound decrypt work. */
export const ENCRYPTED_STATE_MAX_LENGTH = 8192;


/** Namespaced verification identifiers for single-use challenge nonces. */
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

/** base64url HMAC-SHA256 of `value` under `secret`, domain-separated by `purpose`. */
export async function keyedHash(
	secret: string,
	purpose: string,
	value: string,
): Promise<string> {
	const signature = await makeSignature(`${purpose}\u0000${value}`, secret);
	return signature.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Link tokens are stored hashed (keyed by the auth secret): a leaked
 * verification table does not yield usable reset links.
 */
export async function resetTokenIdentifier(secret: string, token: string) {
	return `${RESET_TOKEN_IDENTIFIER_PREFIX}${await keyedHash(secret, "opaque-reset-token", token)}`;
}

export function resetOTPIdentifier(email: string) {
	return `${RESET_OTP_IDENTIFIER_PREFIX}${normalizeEmail(email)}`;
}

export function setPasswordIdentifier(userId: string) {
	return `${SET_PASSWORD_IDENTIFIER_PREFIX}${userId}`;
}

/** Keyed hash of an OTP, bound to the email it was issued for. */
export function hashResetOTP(secret: string, email: string, otp: string) {
	return keyedHash(secret, "opaque-reset-otp", `${normalizeEmail(email)}:${otp}`);
}

export interface ResetOTPRecord {
	userId: string;
	otpHash: string;
	attempts: number;
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
			typeof data.attempts !== "number" ||
			!Number.isInteger(data.attempts) ||
			data.attempts < 0
		) {
			return null;
		}
		return { userId: data.userId, otpHash: data.otpHash, attempts: data.attempts };
	} catch {
		return null;
	}
}

export function timingSafeEqualString(a: string, b: string): boolean {
	return constantTimeEqual(a, b);
}

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
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** 32 random bytes, base64url encoded. */
export function generateNonce(): string {
	return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export function base64UrlDecode(str: string): string {
	const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
	return atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
}

/** Decoded byte length, or -1 if the input is not decodable. Never throws. */
function decodedLength(base64: string): number {
	try {
		return base64UrlDecode(base64).length;
	} catch {
		return -1;
	}
}

type ErrorCodeEntry = { code: string; message: string };

function toErrorEntry(error: ErrorCodeEntry | string): ErrorCodeEntry {
	return typeof error === "string"
		? { code: "INVALID_INPUT", message: `Invalid ${error}` }
		: error;
}

export function validateBase64Length(
	base64: string,
	expectedLength: number,
	error: ErrorCodeEntry | string,
): void {
	if (decodedLength(base64) !== expectedLength) {
		throw APIError.from("BAD_REQUEST", toErrorEntry(error));
	}
}

export function validateBase64LengthRange(
	base64: string,
	min: number,
	max: number,
	error: ErrorCodeEntry | string,
): void {
	const length = decodedLength(base64);
	if (length < min || length > max) {
		throw APIError.from("BAD_REQUEST", toErrorEntry(error));
	}
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
 * `@serenity-kit/opaque` throws `Error('opaque protocol error at "<stage>"; ...')`.
 * Returns the stage (e.g. `deserialize finishLoginRequest`, `finish server login`).
 */
export function getOpaqueErrorStage(error: unknown): string | null {
	const message = error instanceof Error ? error.message : String(error);
	const match = /opaque protocol error at "([^"]+)"/.exec(message);
	return match?.[1] ?? null;
}

export async function createDummyRegistrationRecord(): Promise<string> {
	const tempServerSetup = server.createSetup(); // Use a temporary key

	const userId = generateRandomString(12);
	const password = generateRandomString(24);

	const { registrationRequest, clientRegistrationState } =
		client.startRegistration({
			password,
		});

	const { registrationResponse } = server.createRegistrationResponse({
		registrationRequest,
		serverSetup: tempServerSetup,
		userIdentifier: userId,
	});

	const { registrationRecord } = client.finishRegistration({
		clientRegistrationState,
		registrationResponse,
		password,
	});

	return registrationRecord;
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
	nonce: string;
	purpose: LoginStatePurpose;
	issuedAt: number;
}

/**
 * Encrypts the OPAQUE server login state for the round trip through the client.
 * Only the user id is embedded (never the user object) and the plaintext is
 * padded to a block size so its length does not depend on the user.
 */
export async function encryptServerLoginState(
	serverLoginState: string,
	secret: string,
	user: { id: string } | null,
	options?: { nonce?: string; purpose?: LoginStatePurpose },
): Promise<string> {
	const payload: ServerLoginStatePayload = {
		serverLoginState,
		userId: user?.id ?? "",
		nonce: options?.nonce ?? generateNonce(),
		purpose: options?.purpose ?? "login",
		issuedAt: Date.now(),
	};
	return await symmetricEncrypt({
		data: padToBlockSize(JSON.stringify(payload)),
		key: secret,
	});
}

/**
 * Decrypts and validates the encrypted state. Throws `APIError` BAD_REQUEST
 * (`INVALID_LOGIN_STATE` / `LOGIN_STATE_EXPIRED`); never anything else.
 */
export async function decryptServerLoginState(
	encryptedState: string,
	secret: string,
): Promise<ServerLoginStatePayload> {
	let data: unknown;
	try {
		if (encryptedState.length > ENCRYPTED_STATE_MAX_LENGTH) throw new Error();
		const decrypted = await symmetricDecrypt({
			key: secret,
			data: encryptedState,
		});
		data = JSON.parse(decrypted);
	} catch {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE);
	}
	if (
		typeof data !== "object" ||
		data === null ||
		typeof (data as ServerLoginStatePayload).serverLoginState !== "string" ||
		typeof (data as ServerLoginStatePayload).userId !== "string" ||
		typeof (data as ServerLoginStatePayload).nonce !== "string" ||
		!Object.hasOwn(NONCE_IDENTIFIER_PREFIX, (data as ServerLoginStatePayload).purpose) ||
		typeof (data as ServerLoginStatePayload).issuedAt !== "number"
	) {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE);
	}
	const payload = data as ServerLoginStatePayload;
	if (payload.issuedAt + LOGIN_STATE_TTL_MS < Date.now()) {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.LOGIN_STATE_EXPIRED);
	}
	return payload;
}

export async function findOpaqueAccount(
	ctx: {
		context: {
			internalAdapter: { findAccounts: (userId: string) => Promise<Account[]> };
		};
	},
	userId: string,
): Promise<(Account & { registrationRecord: string }) | undefined> {
	const accounts = await ctx.context.internalAdapter.findAccounts(userId);
	return accounts.find((account: Account) => account.providerId === "opaque") as
		| (Account & { registrationRecord: string })
		| undefined;
}

export async function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
