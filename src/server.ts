import { ready, server } from "@serenity-kit/opaque";
import { APIError, type BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint, sensitiveSessionMiddleware } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { generateRandomString } from "better-auth/crypto";
import * as z from "zod";
import {
	assertServerSetupFormat,
	assertValidServerSetup,
	createDummyRegistrationRecord,
	decryptServerLoginState,
	encryptServerLoginState,
	FINISH_LOGIN_REQUEST_LENGTH,
	findOpaqueAccount,
	generateNonce,
	getOpaqueErrorStage,
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

						if (options?.insecureCreateSessionOnRegister) {
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

					if (revokeOtherSessions) {
						// Mirrors core's /revoke-other-sessions: keep the caller's session.
						const otherSessions = (
							await ctx.context.internalAdapter.listSessions(user.id)
						).filter(
							(session) => session.token !== currentSession.session.token,
						);
						await Promise.all(
							otherSessions.map((session) =>
								ctx.context.internalAdapter.deleteSession(session.token),
							),
						);
					}

					// Fresh cookies for the caller (session token + cookie cache
					// rebuilt from current DB state), preserving "don't remember me".
					const dontRememberMe = !!(await ctx.getSignedCookie(
						ctx.context.authCookies.dontRememberToken.name,
						ctx.context.secret,
					));
					await setSessionCookie(
						ctx,
						{ session: currentSession.session, user },
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
		},
	} satisfies BetterAuthPlugin;
};
