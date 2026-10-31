import type { User } from "better-auth";

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
