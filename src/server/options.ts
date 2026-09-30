import {
	assertServerSetupFormat,
	DEFAULT_RESET_OTP_ALLOWED_ATTEMPTS,
	DEFAULT_RESET_OTP_EXPIRES_IN,
	DEFAULT_RESET_OTP_LENGTH,
	DEFAULT_RESET_TOKEN_EXPIRES_IN,
	MIN_RESET_OTP_LENGTH,
	type OpaqueOptions,
} from "../utils.js";

/** `OpaqueOptions` with every default applied, validated. */
export interface ResolvedOpaqueOptions {
	/** The options as passed (callbacks, flags). */
	raw: OpaqueOptions;
	rateLimit: {
		window: number;
		max: number;
		forgetPassword: { window: number; max: number };
	};
	/** Seconds. */
	resetTokenExpiresIn: number;
	resetOTP: { expiresIn: number; length: number; allowedAttempts: number };
	setPasswordEnabled: boolean;
}

function invalid(name: string, requirement: string, value: unknown): never {
	throw new Error(
		`[better-auth-opaque] Invalid option ${name}: must be ${requirement} (got ${JSON.stringify(value)}).`,
	);
}

function positive(name: string, value: number | undefined, fallback: number): number {
	if (value === undefined) return fallback;
	if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
		invalid(name, "a number > 0", value);
	}
	return value;
}

function integerAtLeast(
	name: string,
	value: number | undefined,
	min: number,
	fallback: number,
): number {
	if (value === undefined) return fallback;
	if (typeof value !== "number" || !Number.isInteger(value) || value < min) {
		invalid(name, `an integer >= ${min}`, value);
	}
	return value;
}

/**
 * Applies defaults and validates, synchronously at construction: a bad value
 * (e.g. a 0-digit code, or a rate limit of 0) throws a descriptive Error
 * instead of silently weakening or disabling a flow.
 */
export function resolveOptions(options: OpaqueOptions = {}): ResolvedOpaqueOptions {
	if (options.OPAQUE_SERVER_KEY !== undefined) {
		assertServerSetupFormat(options.OPAQUE_SERVER_KEY);
	}
	const rateLimit = options.rateLimit ?? {};
	const forget = rateLimit.forgetPassword ?? {};
	const otp = options.resetPasswordOTP ?? {};
	return {
		raw: options,
		rateLimit: {
			window: positive("rateLimit.window", rateLimit.window, 10),
			max: integerAtLeast("rateLimit.max", rateLimit.max, 1, 3),
			forgetPassword: {
				window: positive("rateLimit.forgetPassword.window", forget.window, 60),
				max: integerAtLeast("rateLimit.forgetPassword.max", forget.max, 1, 3),
			},
		},
		resetTokenExpiresIn: positive(
			"resetPasswordTokenExpiresIn",
			options.resetPasswordTokenExpiresIn,
			DEFAULT_RESET_TOKEN_EXPIRES_IN,
		),
		resetOTP: {
			expiresIn: positive(
				"resetPasswordOTP.expiresIn",
				otp.expiresIn,
				DEFAULT_RESET_OTP_EXPIRES_IN,
			),
			length: integerAtLeast(
				"resetPasswordOTP.length",
				otp.length,
				MIN_RESET_OTP_LENGTH,
				DEFAULT_RESET_OTP_LENGTH,
			),
			allowedAttempts: integerAtLeast(
				"resetPasswordOTP.allowedAttempts",
				otp.allowedAttempts,
				1,
				DEFAULT_RESET_OTP_ALLOWED_ATTEMPTS,
			),
		},
		setPasswordEnabled: options.setPassword?.enabled === true,
	};
}
