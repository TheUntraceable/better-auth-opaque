import { ready, server } from "@serenity-kit/opaque";
import {
	APIError,
	type BetterAuthPlugin,
	type GenericEndpointContext,
	type User,
} from "better-auth";
import {
	createAuthEndpoint,
	createEmailVerificationToken,
	freshSessionMiddleware,
	originCheck,
	sensitiveSessionMiddleware,
} from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { generateRandomString } from "better-auth/crypto";
import * as z from "zod";
import {
	assertServerSetupFormat,
	assertValidServerSetup,
	cloneRequest,
	createDummyRegistrationRecord,
	DEFAULT_RESET_OTP_ALLOWED_ATTEMPTS,
	DEFAULT_RESET_OTP_EXPIRES_IN,
	DEFAULT_RESET_OTP_LENGTH,
	DEFAULT_RESET_TOKEN_EXPIRES_IN,
	decodeResetOTPRecord,
	decryptServerLoginState,
	encodeResetOTPRecord,
	encryptServerLoginState,
	FINISH_LOGIN_REQUEST_LENGTH,
	findOpaqueAccount,
	generateNonce,
	getOpaqueErrorStage,
	hashResetOTP,
	isDeserializableRegistrationRecord,
	LOGIN_REQUEST_LENGTH,
	LOGIN_STATE_TTL_MS,
	type LoginStatePurpose,
	nonceIdentifier,
	normalizeEmail,
	OPAQUE_ERROR_CODES,
	type OpaqueOptions,
	REGISTRATION_RECORD_MAX_LENGTH,
	REGISTRATION_RECORD_MIN_LENGTH,
	REGISTRATION_REQUEST_LENGTH,
	resetOTPIdentifier,
	resetTokenIdentifier,
	setPasswordIdentifier,
	timingSafeEqualString,
	validateBase64Length,
	validateBase64LengthRange,
} from "./utils";

export { OPAQUE_ERROR_CODES } from "./utils";

type ErrorEntry = { code: string; message: string };

type Logger = {
	error: (message: string, ...args: unknown[]) => void;
};

/**
 * Maps an exception thrown by `@serenity-kit/opaque` to an `APIError`.
 * Deserialisation failures of client input are 400s, a failed credential check
 * is a 401 with `credentialError`. Nothing a client sends can produce a 500.
 */
function toOpaqueAPIError(
	error: unknown,
	logger: Logger,
	credentialError: ErrorEntry,
	fallbackStatus: "UNAUTHORIZED" | "BAD_REQUEST" = "UNAUTHORIZED",
): APIError {
	if (error instanceof APIError) return error;
	const stage = getOpaqueErrorStage(error);
	switch (stage) {
		case "finish server login":
			return APIError.from("UNAUTHORIZED", credentialError);
		case "deserialize finishLoginRequest":
			return APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_LOGIN_RESULT);
		case "deserialize startLoginRequest":
			return APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_LOGIN_REQUEST);
		case "deserialize registrationRequest":
			return APIError.from(
				"BAD_REQUEST",
				OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
			);
		case "deserialize serverLoginState":
			return APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE);
		default:
			// Unknown stage (e.g. a corrupt server setup). Never reveal details.
			logger.error("[better-auth-opaque] Unexpected OPAQUE error", error);
			return APIError.from(fallbackStatus, credentialError);
	}
}

/**
 * `server.startLogin`, falling back to the dummy record if the stored record
 * cannot be deserialised (a corrupt/legacy row must not turn into a 500 or be
 * distinguishable from "wrong password").
 */
function startLoginSafely(
	params: {
		serverSetup: string;
		userIdentifier: string;
		startLoginRequest: string;
		registrationRecord: string;
		dummyRecord: string;
	},
	logger: Logger,
	credentialError: ErrorEntry,
) {
	const { dummyRecord, ...rest } = params;
	try {
		return server.startLogin(rest);
	} catch (error) {
		if (
			getOpaqueErrorStage(error) === "deserialize registrationRecord" &&
			rest.registrationRecord !== dummyRecord
		) {
			logger.error(
				"[better-auth-opaque] Stored registration record could not be deserialised; treating as invalid credentials",
			);
			try {
				return server.startLogin({ ...rest, registrationRecord: dummyRecord });
			} catch (retryError) {
				throw toOpaqueAPIError(retryError, logger, credentialError);
			}
		}
		throw toOpaqueAPIError(error, logger, credentialError);
	}
}

function isProductionEnv(): boolean {
	return (
		typeof process !== "undefined" && process.env?.NODE_ENV === "production"
	);
}

export const opaque = (options?: OpaqueOptions) => {
	// Validate a provided key synchronously, at configuration time.
	if (options?.OPAQUE_SERVER_KEY !== undefined) {
		assertServerSetupFormat(options.OPAQUE_SERVER_KEY);
	}
	let serverSetup: string | undefined = options?.OPAQUE_SERVER_KEY;

	const getServerSetup = (): string => {
		if (!serverSetup) {
			// Unreachable once `init` has run: Better Auth awaits plugin init
			// before handling any request.
			throw new Error("[better-auth-opaque] OPAQUE server setup is not initialised");
		}
		return serverSetup;
	};

	/**
	 * Creates the single-use nonce row and the encrypted state for a challenge.
	 * Also triggers Better Auth core's opportunistic cleanup of expired
	 * verification rows (`findVerificationValue` deletes expired rows unless
	 * `verification.disableCleanup` is set), since `consumeVerificationValue`
	 * does not.
	 */
	const issueChallengeState = async (
		ctx: {
			context: {
				secret: string;
				internalAdapter: {
					findVerificationValue: (identifier: string) => Promise<unknown>;
					createVerificationValue: (data: {
						identifier: string;
						value: string;
						expiresAt: Date;
					}) => Promise<unknown>;
				};
			};
		},
		purpose: LoginStatePurpose,
		userId: string,
		serverLoginState: string,
	) => {
		const nonce = generateNonce();
		const identifier = nonceIdentifier(purpose, nonce);
		await ctx.context.internalAdapter.findVerificationValue(identifier);
		await ctx.context.internalAdapter.createVerificationValue({
			identifier,
			value: userId,
			expiresAt: new Date(Date.now() + LOGIN_STATE_TTL_MS),
		});
		return await encryptServerLoginState(
			serverLoginState,
			ctx.context.secret,
			{ id: userId },
			{ nonce, purpose },
		);
	};

	const rateLimitWindow = options?.rateLimit?.window ?? 10;
	const rateLimitMax = options?.rateLimit?.max ?? 3;

	const resetTokenExpiresIn =
		options?.resetPasswordTokenExpiresIn ?? DEFAULT_RESET_TOKEN_EXPIRES_IN;
	const resetOTP = {
		expiresIn: options?.resetPasswordOTP?.expiresIn ?? DEFAULT_RESET_OTP_EXPIRES_IN,
		length: options?.resetPasswordOTP?.length ?? DEFAULT_RESET_OTP_LENGTH,
		allowedAttempts:
			options?.resetPasswordOTP?.allowedAttempts ??
			DEFAULT_RESET_OTP_ALLOWED_ATTEMPTS,
	};

	/** Plugin option if set, else core's `emailAndPassword.requireEmailVerification`. */
	const requiresEmailVerification = (ctx: GenericEndpointContext): boolean =>
		options?.requireEmailVerification ??
		ctx.context.options.emailAndPassword?.requireEmailVerification ??
		false;

	/**
	 * Sends core's verification email exactly as core's `/sign-up/email` and
	 * `/sign-in/email` do (same token helper, same URL). No-op when
	 * `emailVerification.sendVerificationEmail` is not configured.
	 */
	const sendVerificationEmail = async (
		ctx: GenericEndpointContext,
		user: User,
		callbackURL: string | undefined,
	) => {
		const send = ctx.context.options.emailVerification?.sendVerificationEmail;
		if (!send) return;
		const token = await createEmailVerificationToken(
			ctx.context.secret,
			user.email,
			undefined,
			ctx.context.options.emailVerification?.expiresIn,
		);
		const url = `${ctx.context.baseURL}/verify-email?token=${token}&callbackURL=${encodeURIComponent(callbackURL || "/")}`;
		await ctx.context.runInBackgroundOrAwait(
			send({ user, url, token }, cloneRequest(ctx.request)),
		);
	};

	type ResetCredential =
		| { kind: "token"; token: string }
		| { kind: "otp"; email: string; otp: string };

	/** Exactly one of `{ token }` or `{ email, otp }`; anything else is INVALID_TOKEN. */
	const parseResetCredential = (body: {
		token?: string;
		email?: string;
		otp?: string;
	}): ResetCredential => {
		const { token, email, otp } = body;
		if (token && email === undefined && otp === undefined) {
			return { kind: "token", token };
		}
		if (token === undefined && email && otp) {
			return { kind: "otp", email: normalizeEmail(email), otp };
		}
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
	};

	/**
	 * Checks a reset credential and returns the user id it was issued for.
	 *
	 * Link token: looked up by its keyed hash; consumed (atomically) only when
	 * `consume` is set.
	 *
	 * OTP: the stored row is taken with an atomic consume, which serialises
	 * concurrent guesses (a racer finds nothing and is rejected). A wrong code
	 * puts the row back with one more attempt counted; a correct code puts it
	 * back unchanged unless `consume` is set. A row whose attempts are used up
	 * stays deleted (TOO_MANY_ATTEMPTS), like core's email-otp plugin.
	 */
	const verifyResetCredential = async (
		ctx: GenericEndpointContext,
		credential: ResetCredential,
		consume: boolean,
	): Promise<string> => {
		const adapter = ctx.context.internalAdapter;
		if (credential.kind === "token") {
			const identifier = await resetTokenIdentifier(
				ctx.context.secret,
				credential.token,
			);
			const row = consume
				? await adapter.consumeVerificationValue(identifier)
				: await adapter.findVerificationValue(identifier);
			if (!row || row.expiresAt < new Date()) {
				throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
			}
			return row.value;
		}

		const identifier = resetOTPIdentifier(credential.email);
		// Hash first so a missing row costs the same as a present one.
		const submittedHash = await hashResetOTP(
			ctx.context.secret,
			credential.email,
			credential.otp,
		);
		const row = await adapter.consumeVerificationValue(identifier);
		if (!row) {
			throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
		}
		const record = decodeResetOTPRecord(row.value);
		if (!record) {
			throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
		}
		if (record.attempts >= resetOTP.allowedAttempts) {
			throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.TOO_MANY_ATTEMPTS);
		}
		const restore = (attempts: number) =>
			adapter.createVerificationValue({
				identifier,
				value: encodeResetOTPRecord({ ...record, attempts }),
				expiresAt: row.expiresAt,
			});
		if (!timingSafeEqualString(record.otpHash, submittedHash)) {
			await restore(record.attempts + 1);
			throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
		}
		if (!consume) await restore(record.attempts);
		return record.userId;
	};

	/** The user a reset credential was issued for (and, for an OTP, still has that email). */
	const findResetUser = async (
		ctx: GenericEndpointContext,
		credential: ResetCredential,
		userId: string,
	): Promise<User> => {
		const user = await ctx.context.internalAdapter.findUserById(userId);
		if (
			!user ||
			(credential.kind === "otp" && normalizeEmail(user.email) !== credential.email)
		) {
			throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
		}
		return user;
	};

	/** 400 INVALID_REGISTRATION_RECORD unless the record has a valid length and deserialises. */
	const assertStorableRegistrationRecord = (registrationRecord: string) => {
		validateBase64LengthRange(
			registrationRecord,
			REGISTRATION_RECORD_MIN_LENGTH,
			REGISTRATION_RECORD_MAX_LENGTH,
			OPAQUE_ERROR_CODES.INVALID_REGISTRATION_RECORD,
		);
		if (!isDeserializableRegistrationRecord(registrationRecord, getServerSetup())) {
			throw APIError.from(
				"BAD_REQUEST",
				OPAQUE_ERROR_CODES.INVALID_REGISTRATION_RECORD,
			);
		}
	};

	const opaqueAccountsOf = async (ctx: GenericEndpointContext, userId: string) =>
		(await ctx.context.internalAdapter.findAccounts(userId)).filter(
			(account) => account.providerId === "opaque",
		);

	const createOpaqueAccount = (
		ctx: GenericEndpointContext,
		userId: string,
		registrationRecord: string,
	) => {
		const now = new Date();
		return ctx.context.internalAdapter.createAccount({
			accountId: ctx.context.generateId({ model: "account" }) || userId,
			providerId: "opaque",
			userId,
			registrationRecord,
			createdAt: now,
			updatedAt: now,
		});
	};

	/** 400 RESET_PASSWORD_METHOD_NOT_CONFIGURED unless the delivery callback exists. */
	const resolveResetMethod = (requested: "link" | "otp" | undefined) => {
		const method = requested ?? (options?.sendResetPassword ? "link" : "otp");
		const configured =
			method === "link" ? !!options?.sendResetPassword : !!options?.sendResetPasswordOTP;
		if (!configured) {
			throw APIError.from(
				"BAD_REQUEST",
				OPAQUE_ERROR_CODES.RESET_PASSWORD_METHOD_NOT_CONFIGURED,
			);
		}
		return method;
	};

	return {
		id: "opaque",
		$ERROR_CODES: OPAQUE_ERROR_CODES,
		init: async (ctx) => {
			await ready;
			if (options?.OPAQUE_SERVER_KEY !== undefined) {
				assertValidServerSetup(options.OPAQUE_SERVER_KEY);
			} else if (!serverSetup) {
				if (isProductionEnv()) {
					throw new Error(
						"[better-auth-opaque] OPAQUE_SERVER_KEY is required in production. Generate one with `npx @serenity-kit/opaque@latest create-server-setup` and keep it stable: changing it invalidates every registered password.",
					);
				}
				serverSetup = server.createSetup();
				ctx.logger.warn(
					"⚠️ [better-auth-opaque] OPAQUE_SERVER_KEY not provided. Generated a random one for DEVELOPMENT ONLY: all OPAQUE passwords become invalid when the process restarts. Generate a persistent key with `npx @serenity-kit/opaque@latest create-server-setup`.",
				);
			}
			if (options?.insecureCreateSessionOnRegister) {
				ctx.logger.warn(
					"⚠️ [better-auth-opaque] insecureCreateSessionOnRegister is enabled. This will automatically create a session upon registration, which could lead to user enumeration. Use with caution in production environments.",
				);
			}
			// A password change revokes other sessions server-side, but Better
			// Auth's cookie cache is validated statelessly (signature + token +
			// global `version` + maxAge); core has no per-user invalidation.
			const stateful = !!ctx.options.database || !!ctx.options.secondaryStorage;
			const cookieCache = ctx.options.session?.cookieCache;
			if (!stateful) {
				ctx.logger.warn(
					"⚠️ [better-auth-opaque] No `database` or `secondaryStorage` configured: sessions are stateless cookies, so a password change cannot revoke sessions on other devices (they stay valid until they expire).",
				);
			} else if (cookieCache?.enabled) {
				ctx.logger.info(
					`[better-auth-opaque] session.cookieCache is enabled: after a password change, revoked sessions on other devices are still accepted by /get-session and other non-sensitive endpoints for up to cookieCache.maxAge (${cookieCache.maxAge ?? 300}s).`,
				);
			}
		},
		rateLimit: [
			// Sends email: core's rule for /request-password-reset (3 per 60s).
			{
				pathMatcher: (path: string) => path === "/opaque/forget-password",
				window: options?.rateLimit?.window ?? 60,
				max: rateLimitMax,
			},
			// Every other OPAQUE endpoint, incl. /opaque/reset-password/* (the
			// OTP also has its own attempt counter) and /opaque/setPassword/*.
			{
				pathMatcher: (path: string) =>
					path.startsWith("/sign-in/opaque/") ||
					path.startsWith("/sign-up/opaque/") ||
					path.startsWith("/opaque/"),
				window: rateLimitWindow,
				max: rateLimitMax,
			},
		],
		schema: {
			account: {
				fields: {
					registrationRecord: {
						type: "string",
						required: false,
						unique: true,
						validator: { input: z.string().base64url() },
					},
				},
			},
		},
		endpoints: {
			getRegisterChallenge: createAuthEndpoint(
				"/sign-up/opaque/challenge",
				{
					method: "POST",
					body: z.object({
						email: z.string().email(),
						registrationRequest: z.string().base64url(),
					}),
				},
				async (ctx) => {
					const email = normalizeEmail(ctx.body.email);
					const { registrationRequest } = ctx.body;

					validateBase64Length(
						registrationRequest,
						REGISTRATION_REQUEST_LENGTH,
						OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
					);

					const startTime = performance.now();

					// CRITICAL: Check if user exists to ensure timing consistency
					// Even though we don't use this information here, checking ensures
					// both new and existing user registrations hit the database similarly
					const existingUser =
						await ctx.context.internalAdapter.findUserByEmail(email);

					ctx.context.logger.debug(
						`[CHALLENGE] ${email.substring(0, 20)}... - User exists: ${!!existingUser} - DB lookup: ${(performance.now() - startTime).toFixed(2)}ms`,
					);

					let registrationResponse: string;
					try {
						({ registrationResponse } = server.createRegistrationResponse({
							userIdentifier: email,
							registrationRequest,
							serverSetup: getServerSetup(),
						}));
					} catch (error) {
						throw toOpaqueAPIError(
							error,
							ctx.context.logger,
							OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
							"BAD_REQUEST",
						);
					}

					ctx.context.logger.debug(
						`[CHALLENGE] Total time: ${(performance.now() - startTime).toFixed(2)}ms`,
					);
					return { challenge: registrationResponse };
				},
			),
			completeRegistration: createAuthEndpoint(
				"/sign-up/opaque/complete",
				{
					method: "POST",
					body: z.object({
						email: z.string().email(),
						name: z.string().min(1).max(100),
						registrationRecord: z.string().base64url(),
						/** Where the verification email's link lands (as core's `/sign-up/email`). Default "/". */
						callbackURL: z.string().optional(),
					}),
				},
				async (ctx) => {
					const email = normalizeEmail(ctx.body.email);
					const { name, registrationRecord } = ctx.body;

					validateBase64LengthRange(
						registrationRecord,
						REGISTRATION_RECORD_MIN_LENGTH,
						REGISTRATION_RECORD_MAX_LENGTH,
						OPAQUE_ERROR_CODES.INVALID_REGISTRATION_RECORD,
					);
					// Never store a record that would later make login throw.
					if (
						!isDeserializableRegistrationRecord(
							registrationRecord,
							getServerSetup(),
						)
					) {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.INVALID_REGISTRATION_RECORD,
						);
					}

					const startTime = performance.now();
					const now = new Date();

					const existingUser =
						await ctx.context.internalAdapter.findUserByEmail(email);

					ctx.context.logger.debug(
						`[COMPLETE] ${email.substring(0, 20)}... - User exists: ${!!existingUser} - DB lookup: ${(performance.now() - startTime).toFixed(2)}ms`,
					);

					if (!existingUser) {
						// User doesn't exist - proceed with actual creation
						const user = await ctx.context.internalAdapter.createUser(
							{
								email,
								name,
								createdAt: now,
								updatedAt: now,
							},
							{ method: "email-password" },
						);

						const accountId =
							ctx.context.generateId({ model: "account" }) || user.id;

						await ctx.context.internalAdapter.createAccount({
							accountId,
							providerId: "opaque",
							userId: user.id,
							registrationRecord,
							createdAt: now,
							updatedAt: now,
						});

						// As core's `/sign-up/email`: only for a newly created user.
						if (
							ctx.context.options.emailVerification?.sendOnSignUp ??
							requiresEmailVerification(ctx)
						) {
							await sendVerificationEmail(ctx, user, ctx.body.callbackURL);
						}

						// Never sign in a user who may not log in yet (as core, which
						// skips auto sign-in when email verification is required).
						if (
							options?.insecureCreateSessionOnRegister &&
							!requiresEmailVerification(ctx)
						) {
							const session = await ctx.context.internalAdapter.createSession(
								user.id,
								false,
							);
							if (session) {
								await setSessionCookie(ctx, { session, user });
							}
						}

						ctx.context.logger.debug(
							`[COMPLETE] User created - Total time: ${(performance.now() - startTime).toFixed(2)}ms`,
						);
					} else {
						ctx.context.logger.debug(
							`[COMPLETE] User exists - Total time: ${(performance.now() - startTime).toFixed(2)}ms`,
						);
					}

					// Always return success (whether user was created or already existed)
					// This prevents user enumeration through registration attempts.
					// (`ctx.json(body, { status })` is ignored by Better Auth; setStatus is not.)
					ctx.setStatus(201);
					return ctx.json({
						success: true,
						message: "User registered successfully",
					});
				},
			),

			getLoginChallenge: createAuthEndpoint(
				"/sign-in/opaque/challenge",
				{
					method: "POST",
					body: z.object({
						email: z.string().email(),
						loginRequest: z.string().base64url(),
					}),
				},
				async (ctx) => {
					const email = normalizeEmail(ctx.body.email);
					const { loginRequest } = ctx.body;

					validateBase64Length(
						loginRequest,
						LOGIN_REQUEST_LENGTH,
						OPAQUE_ERROR_CODES.INVALID_LOGIN_REQUEST,
					);

					// CRITICAL: Always generate a dummy record for timing attack resistance
					// Both code paths (user exists/doesn't exist) must perform the same expensive operations.
					// Accounts are joined into the user lookup so both paths do one query.
					const [dummyRecord, found] = await Promise.all([
						createDummyRegistrationRecord(),
						ctx.context.internalAdapter.findUserByEmail(email, {
							includeAccounts: true,
						}),
					]);

					let registrationRecord = dummyRecord;
					let userId: string;

					if (!found) {
						// User doesn't exist - use the dummy record and a random id.
						// The random id never matches a user, so completion fails.
						userId =
							ctx.context.generateId({ model: "user" }) ||
							generateRandomString(32);
					} else {
						userId = found.user.id;
						const opaqueAccount = found.accounts.find(
							(account) => account.providerId === "opaque",
						) as { registrationRecord?: string | null } | undefined;
						if (opaqueAccount?.registrationRecord) {
							registrationRecord = opaqueAccount.registrationRecord;
						}
					}

					const { loginResponse, serverLoginState } = startLoginSafely(
						{
							userIdentifier: email,
							startLoginRequest: loginRequest,
							serverSetup: getServerSetup(),
							registrationRecord,
							dummyRecord,
						},
						ctx.context.logger,
						OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD,
					);

					// Both paths persist a single-use nonce (timing consistency).
					const encryptedServerState = await issueChallengeState(
						ctx,
						"login",
						userId,
						serverLoginState,
					);

					return { challenge: loginResponse, state: encryptedServerState };
				},
			),

			completeLogin: createAuthEndpoint(
				"/sign-in/opaque/complete",
				{
					method: "POST",
					body: z.object({
						// Accepted for backwards compatibility; the user is taken from the state.
						email: z.string().email().optional(),
						loginResult: z.string().base64url(),
						encryptedServerState: z.string(),
						dontRememberMe: z.boolean().optional(),
						/** Where a (re-sent) verification email's link lands, as core's `/sign-in/email`. Default "/". */
						callbackURL: z.string().optional(),
					}),
				},
				async (ctx) => {
					const { loginResult, encryptedServerState } = ctx.body;
					const dontRememberMe = ctx.body.dontRememberMe === true;

					validateBase64Length(
						loginResult,
						FINISH_LOGIN_REQUEST_LENGTH,
						OPAQUE_ERROR_CODES.INVALID_LOGIN_RESULT,
					);

					const state = await decryptServerLoginState(
						encryptedServerState,
						ctx.context.secret,
					);
					if (state.purpose !== "login") {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE,
						);
					}

					// Single use: consume the nonce BEFORE verifying credentials.
					const nonceRow =
						await ctx.context.internalAdapter.consumeVerificationValue(
							nonceIdentifier("login", state.nonce),
						);
					if (!nonceRow || nonceRow.value !== state.userId) {
						throw APIError.from(
							"UNAUTHORIZED",
							OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD,
						);
					}

					try {
						server.finishLogin({
							finishLoginRequest: loginResult,
							serverLoginState: state.serverLoginState,
						});
					} catch (error) {
						throw toOpaqueAPIError(
							error,
							ctx.context.logger,
							OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD,
						);
					}

					// Build the session from current DB state.
					const user = await ctx.context.internalAdapter.findUserById(
						state.userId,
					);
					if (!user) {
						throw APIError.from(
							"UNAUTHORIZED",
							OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD,
						);
					}

					// Only after the password proof verified (as core's
					// `/sign-in/email`): a wrong password never gets here.
					if (requiresEmailVerification(ctx) && !user.emailVerified) {
						if (ctx.context.options.emailVerification?.sendOnSignIn) {
							await sendVerificationEmail(ctx, user, ctx.body.callbackURL);
						}
						throw APIError.from(
							"FORBIDDEN",
							OPAQUE_ERROR_CODES.EMAIL_NOT_VERIFIED,
						);
					}

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

					return ctx.json({
						token: session.token,
						success: true,
						user: {
							id: user.id,
						},
					});
				},
			),

			getChangePasswordChallenge: createAuthEndpoint(
				"/opaque/changePassword/challenge",
				{
					method: "POST",
					requireHeaders: true,
					body: z.object({
						loginRequest: z.string().base64url(),
						registrationRequest: z.string().base64url(),
					}),
					// Authoritative session read (bypasses the cookie cache), like core's /change-password.
					use: [sensitiveSessionMiddleware],
				},
				async (ctx) => {
					const { loginRequest, registrationRequest } = ctx.body;
					const sessionUser = ctx.context.session.user;
					const email = normalizeEmail(sessionUser.email);
					validateBase64Length(
						loginRequest,
						LOGIN_REQUEST_LENGTH,
						OPAQUE_ERROR_CODES.INVALID_LOGIN_REQUEST,
					);
					validateBase64Length(
						registrationRequest,
						REGISTRATION_REQUEST_LENGTH,
						OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
					);

					const startTime = performance.now();

					// Always perform the same OPAQUE operations whether or not the
					// user has an OPAQUE account (dummy record otherwise).
					const [dummyRecord, opaqueAccount] = await Promise.all([
						createDummyRegistrationRecord(),
						findOpaqueAccount(ctx, sessionUser.id),
					]);
					const registrationRecord =
						opaqueAccount?.registrationRecord || dummyRecord;

					// Step 1: Verify old password with login challenge (real or dummy)
					const { loginResponse, serverLoginState } = startLoginSafely(
						{
							userIdentifier: email,
							startLoginRequest: loginRequest,
							serverSetup: getServerSetup(),
							registrationRecord,
							dummyRecord,
						},
						ctx.context.logger,
						OPAQUE_ERROR_CODES.INVALID_CURRENT_PASSWORD,
					);

					// Step 2: Generate new password challenge
					let registrationResponse: string;
					try {
						({ registrationResponse } = server.createRegistrationResponse({
							userIdentifier: email,
							registrationRequest,
							serverSetup: getServerSetup(),
						}));
					} catch (error) {
						throw toOpaqueAPIError(
							error,
							ctx.context.logger,
							OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
							"BAD_REQUEST",
						);
					}

					const encryptedServerState = await issueChallengeState(
						ctx,
						"change-password",
						sessionUser.id,
						serverLoginState,
					);

					ctx.context.logger.debug(
						`[CHANGE_PASSWORD] Total time: ${(performance.now() - startTime).toFixed(2)}ms`,
					);

					return {
						loginChallenge: loginResponse,
						registrationChallenge: registrationResponse,
						state: encryptedServerState,
					};
				},
			),

			completeChangePassword: createAuthEndpoint(
				"/opaque/changePassword/complete",
				{
					method: "POST",
					requireHeaders: true,
					body: z.object({
						loginResult: z.string().base64url(),
						registrationRecord: z.string().base64url(),
						encryptedServerState: z.string(),
						/** Revoke every other session of the user. Default: true. */
						revokeOtherSessions: z.boolean().optional(),
					}),
					// Authoritative session read (bypasses the cookie cache), like core's /change-password.
					use: [sensitiveSessionMiddleware],
				},
				async (ctx) => {
					const { loginResult, registrationRecord, encryptedServerState } =
						ctx.body;
					const revokeOtherSessions = ctx.body.revokeOtherSessions ?? true;
					const currentSession = ctx.context.session;

					validateBase64Length(
						loginResult,
						FINISH_LOGIN_REQUEST_LENGTH,
						OPAQUE_ERROR_CODES.INVALID_LOGIN_RESULT,
					);
					validateBase64LengthRange(
						registrationRecord,
						REGISTRATION_RECORD_MIN_LENGTH,
						REGISTRATION_RECORD_MAX_LENGTH,
						OPAQUE_ERROR_CODES.INVALID_REGISTRATION_RECORD,
					);
					if (
						!isDeserializableRegistrationRecord(
							registrationRecord,
							getServerSetup(),
						)
					) {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.INVALID_REGISTRATION_RECORD,
						);
					}

					const state = await decryptServerLoginState(
						encryptedServerState,
						ctx.context.secret,
					);
					if (state.purpose !== "change-password") {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE,
						);
					}

					// CRITICAL: the state must belong to the authenticated user.
					// Checked before consuming so another user cannot burn it.
					if (state.userId !== currentSession.user.id) {
						throw APIError.from(
							"UNAUTHORIZED",
							OPAQUE_ERROR_CODES.INVALID_CURRENT_PASSWORD,
						);
					}

					// Single use: consume the nonce BEFORE verifying credentials.
					const nonceRow =
						await ctx.context.internalAdapter.consumeVerificationValue(
							nonceIdentifier("change-password", state.nonce),
						);
					if (!nonceRow || nonceRow.value !== state.userId) {
						throw APIError.from(
							"UNAUTHORIZED",
							OPAQUE_ERROR_CODES.INVALID_CURRENT_PASSWORD,
						);
					}

					const opaqueAccount = await findOpaqueAccount(
						ctx,
						currentSession.user.id,
					);
					if (!opaqueAccount) {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_NOT_FOUND,
						);
					}

					// Verify the old password
					try {
						server.finishLogin({
							finishLoginRequest: loginResult,
							serverLoginState: state.serverLoginState,
						});
					} catch (error) {
						throw toOpaqueAPIError(
							error,
							ctx.context.logger,
							OPAQUE_ERROR_CODES.INVALID_CURRENT_PASSWORD,
						);
					}

					const user = await ctx.context.internalAdapter.findUserById(
						currentSession.user.id,
					);
					if (!user) {
						throw APIError.from(
							"UNAUTHORIZED",
							OPAQUE_ERROR_CODES.INVALID_CURRENT_PASSWORD,
						);
					}

					// Old password verified, now update to new password
					await ctx.context.internalAdapter.updateAccount(opaqueAccount.id, {
						registrationRecord,
						updatedAt: new Date(),
					} as Partial<typeof opaqueAccount>);

					// Rotate the caller's session (a new token for a new password):
					// the session that made the request is always deleted, and with
					// `revokeOtherSessions` (default) every other session is too.
					// The caller's "don't remember me" choice carries over.
					const dontRememberMe = !!(await ctx.getSignedCookie(
						ctx.context.authCookies.dontRememberToken.name,
						ctx.context.secret,
					));
					if (revokeOtherSessions) {
						await ctx.context.internalAdapter.deleteUserSessions(user.id);
					} else {
						await ctx.context.internalAdapter.deleteSession(
							currentSession.session.token,
						);
					}
					const newSession = await ctx.context.internalAdapter.createSession(
						user.id,
						dontRememberMe,
					);
					if (!newSession) {
						throw APIError.from(
							"INTERNAL_SERVER_ERROR",
							OPAQUE_ERROR_CODES.FAILED_TO_CREATE_SESSION,
						);
					}
					// Fresh cookies (session token + cookie cache rebuilt from the
					// current DB state) for the new session.
					await setSessionCookie(
						ctx,
						{ session: newSession, user },
						dontRememberMe,
					);

					ctx.context.logger.debug(
						`[CHANGE_PASSWORD] Password changed successfully for ${user.email.substring(0, 20)}...`,
					);

					return ctx.json({
						success: true,
						message: "Password changed successfully",
					});
				},
			),

			/* ------------------------- forgot / reset password ------------------------- */

			/**
			 * Sends a reset link (`sendResetPassword`) or code
			 * (`sendResetPasswordOTP`) to an existing user. Always 200 with the
			 * same body for unknown emails (nothing is sent).
			 */
			opaqueForgetPassword: createAuthEndpoint(
				"/opaque/forget-password",
				{
					method: "POST",
					body: z.object({
						email: z.string().email(),
						/** Default: "link" if `sendResetPassword` is configured, else "otp". */
						method: z.enum(["link", "otp"]).optional(),
						/** Link only: where the emailed link finally lands (with `?token=`). Default "/". */
						redirectTo: z.string().optional(),
					}),
					// As core's /request-password-reset (the router-level origin
					// check also rejects an untrusted `redirectTo`).
					use: [originCheck((ctx) => ctx.body.redirectTo)],
				},
				async (ctx) => {
					const method = resolveResetMethod(ctx.body.method);
					const email = normalizeEmail(ctx.body.email);
					const adapter = ctx.context.internalAdapter;
					const found = await adapter.findUserByEmail(email);
					const response = {
						status: true,
						message:
							method === "link"
								? "If this email exists in our system, check your email for the reset link"
								: "If this email exists in our system, check your email for the reset code",
					};

					if (method === "link") {
						const token = generateRandomString(32, "a-z", "0-9", "A-Z");
						const identifier = await resetTokenIdentifier(
							ctx.context.secret,
							token,
						);
						if (!found) {
							// Same token work plus a verification-table round trip, as core.
							await adapter.findVerificationValue(identifier);
							ctx.context.logger.debug("[FORGET_PASSWORD] User not found");
							return ctx.json(response);
						}
						await adapter.createVerificationValue({
							identifier,
							value: found.user.id,
							expiresAt: new Date(Date.now() + resetTokenExpiresIn * 1000),
						});
						const callbackURL = encodeURIComponent(ctx.body.redirectTo || "/");
						const url = `${ctx.context.baseURL}/opaque/reset-password/${token}?callbackURL=${callbackURL}`;
						await ctx.context.runInBackgroundOrAwait(
							options?.sendResetPassword?.(
								{ user: found.user, url, token },
								cloneRequest(ctx.request),
							),
						);
						return ctx.json(response);
					}

					const otp = generateRandomString(resetOTP.length, "0-9");
					const identifier = resetOTPIdentifier(email);
					const otpHash = await hashResetOTP(ctx.context.secret, email, otp);
					if (!found) {
						await adapter.findVerificationValue(identifier);
						ctx.context.logger.debug("[FORGET_PASSWORD] User not found");
						return ctx.json(response);
					}
					// One live code per email; a new code starts a new attempt budget.
					await adapter.deleteVerificationByIdentifier(identifier);
					await adapter.createVerificationValue({
						identifier,
						value: encodeResetOTPRecord({
							userId: found.user.id,
							otpHash,
							attempts: 0,
						}),
						expiresAt: new Date(Date.now() + resetOTP.expiresIn * 1000),
					});
					await ctx.context.runInBackgroundOrAwait(
						options?.sendResetPasswordOTP?.(
							{ user: found.user, otp },
							cloneRequest(ctx.request),
						),
					);
					return ctx.json(response);
				},
			),

			/**
			 * The emailed link. Mirrors core's GET /reset-password/:token:
			 * redirects to `callbackURL?token=...`, or `?error=INVALID_TOKEN`.
			 * Does not consume the token.
			 */
			opaqueResetPasswordCallback: createAuthEndpoint(
				"/opaque/reset-password/:token",
				{
					method: "GET",
					query: z.object({ callbackURL: z.string() }),
					use: [originCheck((ctx) => ctx.query.callbackURL)],
				},
				async (ctx) => {
					const { token } = ctx.params;
					const { callbackURL } = ctx.query;
					const redirectURL = (query: Record<string, string>) => {
						const url = new URL(callbackURL, ctx.context.baseURL);
						for (const [key, value] of Object.entries(query)) {
							url.searchParams.set(key, value);
						}
						return url.href;
					};
					if (!token) {
						throw ctx.redirect(redirectURL({ error: "INVALID_TOKEN" }));
					}
					const verification =
						await ctx.context.internalAdapter.findVerificationValue(
							await resetTokenIdentifier(ctx.context.secret, token),
						);
					if (!verification || verification.expiresAt < new Date()) {
						throw ctx.redirect(redirectURL({ error: "INVALID_TOKEN" }));
					}
					throw ctx.redirect(redirectURL({ token }));
				},
			),

			/** Step 1 of a reset: `{ token } | { email, otp }` + `registrationRequest` → `{ challenge }`. Does not consume the credential. */
			getResetPasswordChallenge: createAuthEndpoint(
				"/opaque/reset-password/challenge",
				{
					method: "POST",
					body: z.object({
						token: z.string().optional(),
						email: z.string().optional(),
						otp: z.string().optional(),
						registrationRequest: z.string().base64url(),
					}),
				},
				async (ctx) => {
					const credential = parseResetCredential(ctx.body);
					const { registrationRequest } = ctx.body;
					validateBase64Length(
						registrationRequest,
						REGISTRATION_REQUEST_LENGTH,
						OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
					);

					const userId = await verifyResetCredential(ctx, credential, false);
					const user = await findResetUser(ctx, credential, userId);

					let registrationResponse: string;
					try {
						({ registrationResponse } = server.createRegistrationResponse({
							userIdentifier: normalizeEmail(user.email),
							registrationRequest,
							serverSetup: getServerSetup(),
						}));
					} catch (error) {
						throw toOpaqueAPIError(
							error,
							ctx.context.logger,
							OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
							"BAD_REQUEST",
						);
					}
					return { challenge: registrationResponse };
				},
			),

			/**
			 * Step 2 of a reset: `{ token } | { email, otp }` + `registrationRecord`
			 * → `{ status: true }`. Consumes the credential, replaces (or creates)
			 * the OPAQUE account, marks the email verified, deletes every session
			 * of the user and sets no cookies.
			 */
			completeResetPassword: createAuthEndpoint(
				"/opaque/reset-password/complete",
				{
					method: "POST",
					body: z.object({
						token: z.string().optional(),
						email: z.string().optional(),
						otp: z.string().optional(),
						registrationRecord: z.string().base64url(),
					}),
				},
				async (ctx) => {
					const credential = parseResetCredential(ctx.body);
					const { registrationRecord } = ctx.body;
					// Before touching the credential: a malformed record neither
					// consumes it nor counts as an OTP attempt.
					assertStorableRegistrationRecord(registrationRecord);

					const userId = await verifyResetCredential(ctx, credential, true);
					const user = await findResetUser(ctx, credential, userId);
					const adapter = ctx.context.internalAdapter;

					const existing = await opaqueAccountsOf(ctx, user.id);
					let keepId: string;
					if (existing[0]) {
						keepId = existing[0].id;
						await adapter.updateAccount(keepId, {
							registrationRecord,
							updatedAt: new Date(),
						} as Record<string, unknown>);
					} else {
						keepId = (await createOpaqueAccount(ctx, user.id, registrationRecord))
							.id;
					}
					// The reset is authoritative: it leaves exactly its own record
					// (e.g. over a set-password racing with it).
					for (const account of await opaqueAccountsOf(ctx, user.id)) {
						if (account.id !== keepId) await adapter.deleteAccount(account.id);
					}

					// Following the emailed link/code proved control of the mailbox.
					if (!user.emailVerified) {
						await adapter.updateUser(user.id, { emailVerified: true });
					}
					await adapter.deleteUserSessions(user.id);

					ctx.context.logger.debug(
						`[RESET_PASSWORD] Password reset for ${user.email.substring(0, 20)}...`,
					);
					return ctx.json({ status: true });
				},
			),

			/* ------------------------------ set password ------------------------------ */

			/**
			 * Step 1 of adding an OPAQUE password to a logged-in user without
			 * one: `{ registrationRequest }` → `{ challenge }`. Requires a fresh,
			 * DB-validated session. Reserves the single set-password slot the
			 * complete step consumes.
			 */
			getSetPasswordChallenge: createAuthEndpoint(
				"/opaque/setPassword/challenge",
				{
					method: "POST",
					requireHeaders: true,
					body: z.object({
						registrationRequest: z.string().base64url(),
					}),
					// A stolen session must not be able to add a permanent
					// password to e.g. a social-only account: authoritative AND fresh.
					use: [sensitiveSessionMiddleware, freshSessionMiddleware],
				},
				async (ctx) => {
					const { registrationRequest } = ctx.body;
					const sessionUser = ctx.context.session.user;
					validateBase64Length(
						registrationRequest,
						REGISTRATION_REQUEST_LENGTH,
						OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
					);
					if (await findOpaqueAccount(ctx, sessionUser.id)) {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_ALREADY_EXISTS,
						);
					}

					let registrationResponse: string;
					try {
						({ registrationResponse } = server.createRegistrationResponse({
							userIdentifier: normalizeEmail(sessionUser.email),
							registrationRequest,
							serverSetup: getServerSetup(),
						}));
					} catch (error) {
						throw toOpaqueAPIError(
							error,
							ctx.context.logger,
							OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
							"BAD_REQUEST",
						);
					}

					const identifier = setPasswordIdentifier(sessionUser.id);
					await ctx.context.internalAdapter.deleteVerificationByIdentifier(
						identifier,
					);
					await ctx.context.internalAdapter.createVerificationValue({
						identifier,
						value: sessionUser.id,
						expiresAt: new Date(Date.now() + LOGIN_STATE_TTL_MS),
					});
					return { challenge: registrationResponse };
				},
			),

			/**
			 * Step 2: `{ registrationRecord }` → `{ status: true }`. Creates the
			 * `opaque` account; the session and cookies are left unchanged.
			 */
			completeSetPassword: createAuthEndpoint(
				"/opaque/setPassword/complete",
				{
					method: "POST",
					requireHeaders: true,
					body: z.object({
						registrationRecord: z.string().base64url(),
					}),
					use: [sensitiveSessionMiddleware, freshSessionMiddleware],
				},
				async (ctx) => {
					const { registrationRecord } = ctx.body;
					const userId = ctx.context.session.user.id;
					const alreadyExists = () =>
						APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_ALREADY_EXISTS,
						);

					if (await findOpaqueAccount(ctx, userId)) throw alreadyExists();
					assertStorableRegistrationRecord(registrationRecord);

					// Concurrency gate: the adapter cannot create "at most one
					// opaque account per user" atomically, but consuming a
					// verification row is atomic. The challenge left exactly one
					// slot row for this user; only one complete can take it, every
					// racer (or a complete without a challenge) is refused.
					const slot = await ctx.context.internalAdapter.consumeVerificationValue(
						setPasswordIdentifier(userId),
					);
					if (!slot || slot.value !== userId) throw alreadyExists();
					if (await findOpaqueAccount(ctx, userId)) throw alreadyExists();

					const created = await createOpaqueAccount(ctx, userId, registrationRecord);
					// Belt and braces against a concurrent password reset creating
					// an account in between: never leave two OPAQUE accounts.
					const accounts = await opaqueAccountsOf(ctx, userId);
					if (accounts.some((account) => account.id !== created.id)) {
						await ctx.context.internalAdapter.deleteAccount(created.id);
						throw alreadyExists();
					}

					return ctx.json({ status: true });
				},
			),
		},
	} satisfies BetterAuthPlugin;
};
