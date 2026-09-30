/*
 * Shared by the server plugin and the browser client, so importing it must
 * never pull in server code: the only import is Better Auth core's error-code
 * table (`@better-auth/core/error`, which the client imports as well).
 */
import { BASE_ERROR_CODES } from "@better-auth/core/error";

/**
 * Stable error codes returned by the OPAQUE endpoints, in Better Auth's
 * `{ code, message }` convention (usable with `APIError.from`).
 *
 * Codes that mean the same thing as one of Better Auth core's are core's own
 * entries (same code, same message), so an app can handle both the same way.
 */
export const OPAQUE_ERROR_CODES = {
	/** Wrong password, unknown user, replayed/unknown/stale challenge. Deliberately generic. Core's entry. */
	INVALID_EMAIL_OR_PASSWORD: BASE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD,
	/** Change password: current password did not verify, or the challenge was replayed or is stale. */
	INVALID_CURRENT_PASSWORD: {
		code: "INVALID_CURRENT_PASSWORD",
		message: "Invalid current password",
	},
	INVALID_REGISTRATION_REQUEST: {
		code: "INVALID_REGISTRATION_REQUEST",
		message: "Invalid registration request",
	},
	INVALID_REGISTRATION_RECORD: {
		code: "INVALID_REGISTRATION_RECORD",
		message: "Invalid registration record",
	},
	INVALID_LOGIN_REQUEST: {
		code: "INVALID_LOGIN_REQUEST",
		message: "Invalid login request",
	},
	INVALID_LOGIN_RESULT: {
		code: "INVALID_LOGIN_RESULT",
		message: "Invalid login result",
	},
	/** The encrypted challenge state is malformed, tampered with, or belongs to another flow. */
	INVALID_LOGIN_STATE: {
		code: "INVALID_LOGIN_STATE",
		message: "Invalid login state",
	},
	LOGIN_STATE_EXPIRED: {
		code: "LOGIN_STATE_EXPIRED",
		message: "Login state has expired",
	},
	/** Change password for a user that has no OPAQUE account (e.g. social-only). */
	OPAQUE_ACCOUNT_NOT_FOUND: {
		code: "OPAQUE_ACCOUNT_NOT_FOUND",
		message: "No OPAQUE account found for this user",
	},
	/** Core's entry. */
	FAILED_TO_CREATE_SESSION: BASE_ERROR_CODES.FAILED_TO_CREATE_SESSION,
	/**
	 * Reset password: unknown, expired, used, locked (too many wrong codes) or
	 * superseded link token / code, or not exactly one credential. Core's entry.
	 */
	INVALID_TOKEN: BASE_ERROR_CODES.INVALID_TOKEN,
	/** Forgot password: the requested delivery method (link / otp) is not configured on the server. */
	RESET_PASSWORD_METHOD_NOT_CONFIGURED: {
		code: "RESET_PASSWORD_METHOD_NOT_CONFIGURED",
		message: "This password reset method is not configured",
	},
	/** Set password: the user already has an OPAQUE password (use change password instead). */
	OPAQUE_ACCOUNT_ALREADY_EXISTS: {
		code: "OPAQUE_ACCOUNT_ALREADY_EXISTS",
		message: "An OPAQUE password is already set for this user",
	},
	/** Set password: complete without a live challenge (none, expired, or already used). */
	SET_PASSWORD_CHALLENGE_REQUIRED: {
		code: "SET_PASSWORD_CHALLENGE_REQUIRED",
		message: "Request a set-password challenge first",
	},
	/** Login: correct password, but the email is not verified (requireEmailVerification). Core's entry. */
	EMAIL_NOT_VERIFIED: BASE_ERROR_CODES.EMAIL_NOT_VERIFIED,
} as const;

export type OpaqueErrorCode = keyof typeof OPAQUE_ERROR_CODES;
