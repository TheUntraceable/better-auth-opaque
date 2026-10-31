// Kept free of imports so the client bundle can use it without pulling in
// server-side code.

const defineCodes = <const T extends Record<string, string>>(codes: T) =>
	Object.fromEntries(
		Object.entries(codes).map(([code, message]) => [code, { code, message }]),
	) as { [K in keyof T & string]: { code: K; message: T[K] } };

export const OPAQUE_ERROR_CODES = defineCodes({
	INVALID_EMAIL_OR_PASSWORD: "Invalid email or password",
	INVALID_PASSWORD: "Invalid password",
	INVALID_LOGIN_STATE: "Invalid or expired login state",
	INVALID_REGISTRATION_RECORD: "Invalid registration record",
	INVALID_REQUEST: "Invalid OPAQUE request",
	INVALID_TOKEN: "Invalid or expired token",
	EMAIL_NOT_VERIFIED: "Email not verified",
	EMAIL_MISMATCH: "Email does not match the challenge",
	USER_MISMATCH: "User does not match the authenticated session",
	NO_OPAQUE_ACCOUNT: "No OPAQUE password is set for this account",
	OPAQUE_ACCOUNT_EXISTS: "An OPAQUE password is already set for this account",
	RESET_PASSWORD_NOT_CONFIGURED:
		"Password reset is not configured. Provide sendResetPassword to the opaque plugin",
	FAILED_TO_CREATE_USER: "Failed to create user",
	FAILED_TO_CREATE_SESSION: "Failed to create session",
	SERVER_KEY_MISMATCH:
		"The server's OPAQUE public key does not match the pinned key",
	CHALLENGE_FAILED: "Failed to obtain a challenge from the server",
});

export type OpaqueErrorCode = keyof typeof OPAQUE_ERROR_CODES;
