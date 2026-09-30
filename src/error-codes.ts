/*
 * Dependency-free on purpose: shared by the server plugin and the browser
 * client, so importing it must never pull in server code.
 */

/**
 * Stable error codes returned by the OPAQUE endpoints, in Better Auth's
 * `{ code, message }` convention (usable with `APIError.from`).
 */
export const OPAQUE_ERROR_CODES = {
	/** Wrong password, unknown user, replayed/unknown challenge. Deliberately generic. */
	INVALID_EMAIL_OR_PASSWORD: {
		code: "INVALID_EMAIL_OR_PASSWORD",
		message: "Invalid email or password",
	},
	/** Change password: current password did not verify, or the challenge was replayed. */
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
	FAILED_TO_CREATE_SESSION: {
		code: "FAILED_TO_CREATE_SESSION",
		message: "Failed to create session",
	},
	/** Reset password: unknown, expired, used or wrong link token / code (or not exactly one credential). */
	INVALID_TOKEN: {
		code: "INVALID_TOKEN",
		message: "Invalid token",
	},
	/** Reset password: the code was guessed wrong too many times; request a new one. */
	TOO_MANY_ATTEMPTS: {
		code: "TOO_MANY_ATTEMPTS",
		message: "Too many attempts",
	},
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
	/** Login: correct password, but the email is not verified (requireEmailVerification). */
	EMAIL_NOT_VERIFIED: {
		code: "EMAIL_NOT_VERIFIED",
		message: "Email not verified",
	},
} as const;

export type OpaqueErrorCode = keyof typeof OPAQUE_ERROR_CODES;
