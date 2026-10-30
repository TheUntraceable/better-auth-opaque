import { ready, server } from "@serenity-kit/opaque";
import { APIError, type BetterAuthPlugin, type User } from "better-auth";
import {
	createAuthEndpoint,
	createEmailVerificationToken,
	originCheck,
	sensitiveSessionMiddleware,
} from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { generateRandomString } from "better-auth/crypto";
import { parseUserInput, parseUserOutput } from "better-auth/db";
import * as z from "zod";
import {
	assertValidRegistrationRecord,
	BASE64URL_RE,
	credentialIdFor,
	decryptState,
	encryptState,
	enforceMinimumDuration,
	fakeCredentialId,
	findOpaqueAccount,
	LOGIN_REQUEST_CHARS,
	LOGIN_RESULT_CHARS,
	MAX_STATE_CHARS,
	normalizeEmail,
	OPAQUE_ERROR_CODES,
	type OpaqueOptions,
	type OpaqueState,
	REGISTRATION_RECORD_CHARS,
	REGISTRATION_REQUEST_CHARS,
} from "./utils";

export { OPAQUE_ERROR_CODES, type OpaqueOptions } from "./utils";

const base64url = (chars: number) =>
	z.string().length(chars).regex(BASE64URL_RE);

const registrationRequest = base64url(REGISTRATION_REQUEST_CHARS);
const registrationRecord = base64url(REGISTRATION_RECORD_CHARS);
const loginRequest = base64url(LOGIN_REQUEST_CHARS);
const loginResult = base64url(LOGIN_RESULT_CHARS);
const state = z.string().min(1).max(MAX_STATE_CHARS);

const PURPOSE = {
	signUp: "sign-up",
	signIn: "sign-in",
	changePassword: "change-password",
	setPassword: "set-password",
	resetPassword: "reset-password",
} as const;

const stateIdentifier = (stateId: string) => `opaque-state:${stateId}`;
const resetIdentifier = (token: string) => `opaque-reset:${token}`;

const isProduction = () =>
	typeof process !== "undefined" && process.env?.NODE_ENV === "production";

export const opaque = (options: OpaqueOptions = {}) => {
	let serverSetup = options.OPAQUE_SERVER_KEY;
	const challengeTtlMs = (options.challengeExpiresIn ?? 120) * 1000;
	const resetTtlMs = (options.resetPasswordTokenExpiresIn ?? 60 * 60) * 1000;
	const floorMs = options.timingSafeResponseMs;

	const requireSetup = () => {
		if (!serverSetup) {
			throw APIError.from("INTERNAL_SERVER_ERROR", {
				code: "OPAQUE_NOT_INITIALISED",
				message: "OPAQUE server key is not initialised",
			});
		}
		return serverSetup;
	};

	/* ------------------------------ state helpers ----------------------------- */

	type Ctx = {
		context: {
			secret: string;
			internalAdapter: {
				createVerificationValue: (data: {
					identifier: string;
					value: string;
					expiresAt: Date;
				}) => Promise<unknown>;
				findVerificationValue: (
					identifier: string,
				) => Promise<{ value: string; expiresAt: Date } | null | undefined>;
				deleteVerificationByIdentifier: (identifier: string) => Promise<void>;
			};
		};
	};

	// Issue a one-time, purpose-bound state. The stateId is recorded so the
	// complete step can consume it exactly once.
	const issueState = async (
		ctx: Ctx,
		data: Omit<OpaqueState, "stateId" | "issuedAt">,
	) => {
		const stateId = generateRandomString(32);
		await ctx.context.internalAdapter.createVerificationValue({
			identifier: stateIdentifier(stateId),
			value: data.purpose,
			expiresAt: new Date(Date.now() + challengeTtlMs),
		});
		return encryptState(
			{ ...data, stateId, issuedAt: Date.now() },
			ctx.context.secret,
		);
	};

	const consumeState = async (ctx: Ctx, encrypted: string, purpose: string) => {
		const decoded = await decryptState(
			encrypted,
			ctx.context.secret,
			purpose,
			challengeTtlMs,
		);
		const identifier = stateIdentifier(decoded.stateId);
		const record = await ctx.context.internalAdapter.findVerificationValue(
			identifier,
		);
		if (!record || record.value !== purpose || record.expiresAt < new Date()) {
			throw APIError.from(
				"BAD_REQUEST",
				OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE,
			);
		}
		await ctx.context.internalAdapter.deleteVerificationByIdentifier(
			identifier,
		);
		return decoded;
	};

	const finishLoginOrThrow = (
		finishLoginRequest: string,
		serverLoginState: string,
		code: { code: string; message: string },
	) => {
		try {
			const { sessionKey } = server.finishLogin({
				finishLoginRequest,
				serverLoginState,
			});
			if (!sessionKey) throw new Error("no session key");
			return sessionKey;
		} catch {
			// The library throws on a bad proof; surface it as an auth failure,
			// never as a 500.
			throw APIError.from("UNAUTHORIZED", code);
		}
	};

	return {
		id: "opaque",
		init: async (ctx) => {
			await ready;
			if (!serverSetup) {
				if (isProduction()) {
					throw new Error(
						"[better-auth-opaque] OPAQUE_SERVER_KEY is required in production. Generate one with: import { server } from '@serenity-kit/opaque'; console.log(server.createSetup())",
					);
				}
				serverSetup = server.createSetup();
				ctx.logger.warn(
					"[better-auth-opaque] OPAQUE_SERVER_KEY not set. A temporary key was generated for this process; accounts registered now will stop working on restart. Generate a permanent key with: import { server } from '@serenity-kit/opaque'; server.createSetup()",
				);
			}
			try {
				server.getPublicKey(serverSetup);
			} catch {
				throw new Error(
					"[better-auth-opaque] OPAQUE_SERVER_KEY is not a valid server setup",
				);
			}
			if (options.insecureCreateSessionOnRegister) {
				ctx.logger.warn(
					"[better-auth-opaque] insecureCreateSessionOnRegister is enabled: the sign-up endpoint can now reveal whether an email is registered.",
				);
			}
			if (ctx.options.emailAndPassword?.enabled) {
				ctx.logger.warn(
					"[better-auth-opaque] emailAndPassword is enabled alongside OPAQUE. Core /reset-password and /set-password create a server-side password hash next to the OPAQUE record. Use opaque.requestPasswordReset / opaque.setPassword instead, or disable emailAndPassword.",
				);
			}
		},
		schema: {
			account: {
				fields: {
					registrationRecord: {
						type: "string",
						required: false,
						returned: false,
						input: false,
					},
					credentialId: {
						type: "string",
						required: false,
						returned: false,
						input: false,
					},
				},
			},
		},
		rateLimit: [
			{
				pathMatcher: (path) => path.startsWith("/opaque/"),
				window: 10,
				max: 5,
			},
		],
		endpoints: {
			/* ------------------------------- sign-up ------------------------------ */

			opaqueSignUpChallenge: createAuthEndpoint(
				"/opaque/sign-up/challenge",
				{
					method: "POST",
					body: z.object({
						email: z.email(),
						registrationRequest,
					}),
					metadata: {
						isAction: false,
						openapi: {
							description:
								"Start OPAQUE registration. Returns the registration challenge and an encrypted state to pass to the complete step.",
						},
					},
				},
				async (ctx) => {
					const setup = requireSetup();
					const email = normalizeEmail(ctx.body.email);
					// No lookup here: the challenge does not depend on whether the
					// account exists, so there is nothing to hide.
					const credentialId = generateRandomString(32);
					const { registrationResponse } = server.createRegistrationResponse({
						serverSetup: setup,
						userIdentifier: credentialId,
						registrationRequest: ctx.body.registrationRequest,
					});
					const encrypted = await encryptState(
						{
							purpose: PURPOSE.signUp,
							stateId: generateRandomString(32),
							issuedAt: Date.now(),
							email,
							credentialId,
						},
						ctx.context.secret,
					);
					return { challenge: registrationResponse, state: encrypted };
				},
			),

			opaqueSignUpComplete: createAuthEndpoint(
				"/opaque/sign-up/complete",
				{
					method: "POST",
					body: z
						.object({
							email: z.email(),
							name: z.string().min(1).max(100),
							image: z.string().optional(),
							registrationRecord,
							state,
							callbackURL: z.string().optional(),
						})
						.and(z.record(z.string(), z.any())),
					metadata: {
						isAction: false,
						openapi: {
							description:
								"Finish OPAQUE registration. Responds identically whether or not the email was already registered.",
						},
					},
				},
				async (ctx) => {
					const started = performance.now();
					try {
						const setup = requireSetup();
						const {
							email: rawEmail,
							name,
							image,
							registrationRecord: record,
							state: encrypted,
							callbackURL,
							...rest
						} = ctx.body;
						const email = normalizeEmail(rawEmail);
						const decoded = await decryptState(
							encrypted,
							ctx.context.secret,
							PURPOSE.signUp,
							challengeTtlMs,
						);
						if (decoded.email !== email || !decoded.credentialId) {
							throw APIError.from(
								"BAD_REQUEST",
								OPAQUE_ERROR_CODES.EMAIL_MISMATCH,
							);
						}
						await assertValidRegistrationRecord(
							setup,
							decoded.credentialId,
							record,
						);

						const existing = await ctx.context.internalAdapter.findUserByEmail(
							email,
						);
						if (existing) {
							await options.onExistingUserSignUp?.(
								{ user: existing.user },
								ctx.request,
							);
							return { status: true, token: null };
						}

						const additionalFields = parseUserInput(
							ctx.context.options,
							rest,
							"create",
						);
						let user: User;
						try {
							user = await ctx.context.internalAdapter.createUser(
								{
									email,
									name,
									image,
									...additionalFields,
									emailVerified: false,
								},
								{ method: "opaque" },
							);
						} catch (error) {
							if (error instanceof APIError) throw error;
							ctx.context.logger.error("Failed to create user", error);
							throw APIError.from(
								"UNPROCESSABLE_ENTITY",
								OPAQUE_ERROR_CODES.FAILED_TO_CREATE_USER,
							);
						}
						await ctx.context.internalAdapter.createAccount({
							providerId: "opaque",
							accountId: user.id,
							userId: user.id,
							registrationRecord: record,
							credentialId: decoded.credentialId,
						} as Parameters<
							typeof ctx.context.internalAdapter.createAccount
						>[0]);

						const emailVerification = ctx.context.options.emailVerification;
						const requireVerification =
							options.requireEmailVerification ??
							ctx.context.options.emailAndPassword?.requireEmailVerification;
						if (
							(emailVerification?.sendOnSignUp || requireVerification) &&
							emailVerification?.sendVerificationEmail
						) {
							const token = await createEmailVerificationToken(
								ctx.context.secret,
								user.email,
								undefined,
								emailVerification.expiresIn,
							);
							const url = `${ctx.context.baseURL}/verify-email?token=${token}&callbackURL=${encodeURIComponent(callbackURL || "/")}`;
							await ctx.context.runInBackgroundOrAwait(
								emailVerification.sendVerificationEmail(
									{ user, url, token },
									ctx.request,
								),
							);
						}

						if (options.insecureCreateSessionOnRegister) {
							const session = await ctx.context.internalAdapter.createSession(
								user.id,
								false,
							);
							if (session) {
								await setSessionCookie(ctx, { session, user });
								return { status: true, token: session.token };
							}
						}
						return { status: true, token: null };
					} finally {
						await enforceMinimumDuration(started, floorMs);
					}
				},
			),

			/* ------------------------------- sign-in ------------------------------ */

			opaqueSignInChallenge: createAuthEndpoint(
				"/opaque/sign-in/challenge",
				{
					method: "POST",
					body: z.object({
						email: z.email(),
						loginRequest,
					}),
					metadata: {
						isAction: false,
						openapi: {
							description:
								"Start OPAQUE login. Always returns a well-formed challenge, whether or not the account exists.",
						},
					},
				},
				async (ctx) => {
					const started = performance.now();
					try {
						const setup = requireSetup();
						const email = normalizeEmail(ctx.body.email);
						const found = await ctx.context.internalAdapter.findUserByEmail(
							email,
						);

						let userId: string | null = null;
						let credentialId: string;
						let record: string | null = null;
						if (found) {
							const account = await findOpaqueAccount(ctx, found.user.id);
							userId = found.user.id;
							credentialId = credentialIdFor(account, email);
							record = account?.registrationRecord ?? null;
						} else {
							// Same query count as the real branch, then a deterministic
							// fake identifier so repeated attempts look consistent. A null
							// record makes the library simulate a registered user.
							await findOpaqueAccount(ctx, generateRandomString(32));
							credentialId = await fakeCredentialId(ctx.context.secret, email);
						}

						const { loginResponse, serverLoginState } = server.startLogin({
							serverSetup: setup,
							userIdentifier: credentialId,
							registrationRecord: record,
							startLoginRequest: ctx.body.loginRequest,
						});
						const encrypted = await issueState(ctx, {
							purpose: PURPOSE.signIn,
							serverLoginState,
							userId,
							credentialId,
						});
						return { challenge: loginResponse, state: encrypted };
					} finally {
						await enforceMinimumDuration(started, floorMs);
					}
				},
			),

			opaqueSignInComplete: createAuthEndpoint(
				"/opaque/sign-in/complete",
				{
					method: "POST",
					body: z.object({
						loginResult,
						state,
						rememberMe: z.boolean().optional(),
						callbackURL: z.string().optional(),
					}),
					metadata: {
						isAction: false,
						openapi: {
							description:
								"Finish OPAQUE login with the client's proof. Creates a session on success.",
						},
					},
				},
				async (ctx) => {
					const decoded = await consumeState(ctx, ctx.body.state, PURPOSE.signIn);
					if (!decoded.serverLoginState) {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE,
						);
					}
					finishLoginOrThrow(
						ctx.body.loginResult,
						decoded.serverLoginState,
						OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD,
					);
					// A proof can only verify against a real record, so userId is set
					// here in practice; the check keeps the fake path airtight.
					const user = decoded.userId
						? await ctx.context.internalAdapter.findUserById(decoded.userId)
						: null;
					const account = user
						? await findOpaqueAccount(ctx, user.id)
						: undefined;
					if (
						!user ||
						!account ||
						credentialIdFor(account, user.email) !== decoded.credentialId
					) {
						// Also covers a challenge minted before a password change.
						throw APIError.from(
							"UNAUTHORIZED",
							OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD,
						);
					}

					const requireVerification =
						options.requireEmailVerification ??
						ctx.context.options.emailAndPassword?.requireEmailVerification;
					if (requireVerification && !user.emailVerified) {
						const emailVerification = ctx.context.options.emailVerification;
						if (
							emailVerification?.sendOnSignIn &&
							emailVerification.sendVerificationEmail
						) {
							const token = await createEmailVerificationToken(
								ctx.context.secret,
								user.email,
								undefined,
								emailVerification.expiresIn,
							);
							const url = `${ctx.context.baseURL}/verify-email?token=${token}&callbackURL=${encodeURIComponent(ctx.body.callbackURL || "/")}`;
							await ctx.context.runInBackgroundOrAwait(
								emailVerification.sendVerificationEmail(
									{ user, url, token },
									ctx.request,
								),
							);
						}
						throw APIError.from(
							"FORBIDDEN",
							OPAQUE_ERROR_CODES.EMAIL_NOT_VERIFIED,
						);
					}

					const dontRememberMe = ctx.body.rememberMe === false;
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
					return {
						token: session.token,
						user: parseUserOutput(ctx.context.options, user),
					};
				},
			),

			/* --------------------------- change password -------------------------- */

			opaqueChangePasswordChallenge: createAuthEndpoint(
				"/opaque/change-password/challenge",
				{
					method: "POST",
					requireHeaders: true,
					body: z.object({
						loginRequest,
						registrationRequest,
					}),
					use: [sensitiveSessionMiddleware],
					metadata: {
						isAction: false,
						openapi: {
							description:
								"Start an OPAQUE password change: a login challenge for the current password and a registration challenge for the new one.",
						},
					},
				},
				async (ctx) => {
					const setup = requireSetup();
					const user = ctx.context.session.user;
					const account = await findOpaqueAccount(ctx, user.id);
					if (!account?.registrationRecord) {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.NO_OPAQUE_ACCOUNT,
						);
					}
					const credentialId = credentialIdFor(account, user.email);
					const newCredentialId = generateRandomString(32);

					const { loginResponse, serverLoginState } = server.startLogin({
						serverSetup: setup,
						userIdentifier: credentialId,
						registrationRecord: account.registrationRecord,
						startLoginRequest: ctx.body.loginRequest,
					});
					const { registrationResponse } = server.createRegistrationResponse({
						serverSetup: setup,
						userIdentifier: newCredentialId,
						registrationRequest: ctx.body.registrationRequest,
					});
					const encrypted = await issueState(ctx, {
						purpose: PURPOSE.changePassword,
						serverLoginState,
						userId: user.id,
						credentialId,
						newCredentialId,
					});
					return {
						loginChallenge: loginResponse,
						registrationChallenge: registrationResponse,
						state: encrypted,
					};
				},
			),

			opaqueChangePasswordComplete: createAuthEndpoint(
				"/opaque/change-password/complete",
				{
					method: "POST",
					requireHeaders: true,
					body: z.object({
						loginResult,
						registrationRecord,
						state,
						revokeOtherSessions: z.boolean().optional(),
					}),
					use: [sensitiveSessionMiddleware],
					metadata: {
						isAction: false,
						openapi: {
							description:
								"Finish an OPAQUE password change. Verifies the current password, stores the new record, and by default revokes every other session.",
						},
					},
				},
				async (ctx) => {
					const setup = requireSetup();
					const sessionUser = ctx.context.session.user;
					const decoded = await consumeState(
						ctx,
						ctx.body.state,
						PURPOSE.changePassword,
					);
					if (
						decoded.userId !== sessionUser.id ||
						!decoded.serverLoginState ||
						!decoded.newCredentialId
					) {
						throw APIError.from(
							"UNAUTHORIZED",
							OPAQUE_ERROR_CODES.USER_MISMATCH,
						);
					}
					const account = await findOpaqueAccount(ctx, sessionUser.id);
					if (
						!account ||
						credentialIdFor(account, sessionUser.email) !== decoded.credentialId
					) {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE,
						);
					}
					finishLoginOrThrow(
						ctx.body.loginResult,
						decoded.serverLoginState,
						OPAQUE_ERROR_CODES.INVALID_PASSWORD,
					);
					await assertValidRegistrationRecord(
						setup,
						decoded.newCredentialId,
						ctx.body.registrationRecord,
					);
					await ctx.context.internalAdapter.updateAccount(account.id, {
						registrationRecord: ctx.body.registrationRecord,
						credentialId: decoded.newCredentialId,
					} as Parameters<typeof ctx.context.internalAdapter.updateAccount>[1]);

					const user = await ctx.context.internalAdapter.findUserById(
						sessionUser.id,
					);
					if (!user) {
						throw APIError.from(
							"UNAUTHORIZED",
							OPAQUE_ERROR_CODES.USER_MISMATCH,
						);
					}
					if (ctx.body.revokeOtherSessions !== false) {
						await ctx.context.internalAdapter.deleteUserSessions(user.id);
						const session = await ctx.context.internalAdapter.createSession(
							user.id,
							false,
						);
						if (!session) {
							throw APIError.from(
								"INTERNAL_SERVER_ERROR",
								OPAQUE_ERROR_CODES.FAILED_TO_CREATE_SESSION,
							);
						}
						await setSessionCookie(ctx, { session, user });
						return {
							token: session.token,
							user: parseUserOutput(ctx.context.options, user),
						};
					}
					return {
						token: ctx.context.session.session.token,
						user: parseUserOutput(ctx.context.options, user),
					};
				},
			),

			/* ----------------------------- set password --------------------------- */

			opaqueSetPasswordChallenge: createAuthEndpoint(
				"/opaque/set-password/challenge",
				{
					method: "POST",
					requireHeaders: true,
					body: z.object({ registrationRequest }),
					use: [sensitiveSessionMiddleware],
					metadata: {
						isAction: false,
						openapi: {
							description:
								"Start setting an OPAQUE password on an account that has none (for example one created through a social provider).",
						},
					},
				},
				async (ctx) => {
					const setup = requireSetup();
					const user = ctx.context.session.user;
					const account = await findOpaqueAccount(ctx, user.id);
					if (account?.registrationRecord) {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_EXISTS,
						);
					}
					const newCredentialId = generateRandomString(32);
					const { registrationResponse } = server.createRegistrationResponse({
						serverSetup: setup,
						userIdentifier: newCredentialId,
						registrationRequest: ctx.body.registrationRequest,
					});
					const encrypted = await issueState(ctx, {
						purpose: PURPOSE.setPassword,
						userId: user.id,
						newCredentialId,
					});
					return { challenge: registrationResponse, state: encrypted };
				},
			),

			opaqueSetPasswordComplete: createAuthEndpoint(
				"/opaque/set-password/complete",
				{
					method: "POST",
					requireHeaders: true,
					body: z.object({ registrationRecord, state }),
					use: [sensitiveSessionMiddleware],
					metadata: {
						isAction: false,
						openapi: {
							description: "Finish setting an OPAQUE password.",
						},
					},
				},
				async (ctx) => {
					const setup = requireSetup();
					const user = ctx.context.session.user;
					const decoded = await consumeState(
						ctx,
						ctx.body.state,
						PURPOSE.setPassword,
					);
					if (decoded.userId !== user.id || !decoded.newCredentialId) {
						throw APIError.from(
							"UNAUTHORIZED",
							OPAQUE_ERROR_CODES.USER_MISMATCH,
						);
					}
					await assertValidRegistrationRecord(
						setup,
						decoded.newCredentialId,
						ctx.body.registrationRecord,
					);
					const existing = await findOpaqueAccount(ctx, user.id);
					if (existing?.registrationRecord) {
						throw APIError.from(
							"BAD_REQUEST",
							OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_EXISTS,
						);
					}
					if (existing) {
						await ctx.context.internalAdapter.updateAccount(existing.id, {
							registrationRecord: ctx.body.registrationRecord,
							credentialId: decoded.newCredentialId,
						} as Parameters<typeof ctx.context.internalAdapter.updateAccount>[1]);
					} else {
						await ctx.context.internalAdapter.createAccount({
							providerId: "opaque",
							accountId: user.id,
							userId: user.id,
							registrationRecord: ctx.body.registrationRecord,
							credentialId: decoded.newCredentialId,
						} as Parameters<
							typeof ctx.context.internalAdapter.createAccount
						>[0]);
					}
					return { status: true };
				},
			),

			/* ---------------------------- reset password -------------------------- */

			opaqueRequestPasswordReset: createAuthEndpoint(
				"/opaque/reset-password/request",
				{
					method: "POST",
					body: z.object({
						email: z.email(),
						redirectTo: z.string().optional(),
					}),
					use: [originCheck((ctx) => ctx.body.redirectTo)],
					metadata: {
						isAction: false,
						openapi: {
							description:
								"Email a password reset link. Responds identically whether or not the account exists.",
						},
					},
				},
				async (ctx) => {
					const started = performance.now();
					try {
						if (!options.sendResetPassword) {
							ctx.context.logger.error(
								"[better-auth-opaque] opaque.requestPasswordReset called but sendResetPassword is not configured",
							);
							throw APIError.from(
								"BAD_REQUEST",
								OPAQUE_ERROR_CODES.RESET_PASSWORD_NOT_CONFIGURED,
							);
						}
						const email = normalizeEmail(ctx.body.email);
						const found = await ctx.context.internalAdapter.findUserByEmail(
							email,
						);
						if (!found) {
							// Match the real branch's write so the two look alike.
							await ctx.context.internalAdapter.findVerificationValue(
								resetIdentifier("dummy"),
							);
							return { status: true };
						}
						const token = generateRandomString(32);
						await ctx.context.internalAdapter.createVerificationValue({
							identifier: resetIdentifier(token),
							value: found.user.id,
							expiresAt: new Date(Date.now() + resetTtlMs),
						});
						const callbackURL = encodeURIComponent(ctx.body.redirectTo ?? "");
						const url = `${ctx.context.baseURL}/opaque/reset-password/${token}?callbackURL=${callbackURL}`;
						await ctx.context.runInBackgroundOrAwait(
							options.sendResetPassword(
								{ user: found.user, url, token },
								ctx.request,
							),
						);
						return { status: true };
					} finally {
						await enforceMinimumDuration(started, floorMs);
					}
				},
			),

			opaqueResetPasswordCallback: createAuthEndpoint(
				"/opaque/reset-password/:token",
				{
					method: "GET",
					query: z.object({ callbackURL: z.string().optional() }),
					use: [originCheck((ctx) => ctx.query.callbackURL)],
					metadata: {
						isAction: false,
						openapi: {
							description:
								"Redirects the browser from the emailed link to your reset page with ?token=... (or ?error=INVALID_TOKEN).",
						},
					},
				},
				async (ctx) => {
					const { token } = ctx.params;
					const target = new URL(
						ctx.query.callbackURL || "/",
						ctx.context.baseURL,
					);
					const verification = await ctx.context.internalAdapter.findVerificationValue(
						resetIdentifier(token),
					);
					if (!verification || verification.expiresAt < new Date()) {
						target.searchParams.set("error", "INVALID_TOKEN");
					} else {
						target.searchParams.set("token", token);
					}
					throw ctx.redirect(target.toString());
				},
			),

			opaqueResetPasswordChallenge: createAuthEndpoint(
				"/opaque/reset-password/challenge",
				{
					method: "POST",
					body: z.object({
						token: z.string().min(1).max(256),
						registrationRequest,
					}),
					metadata: {
						isAction: false,
						openapi: {
							description:
								"Start an OPAQUE password reset with the emailed token.",
						},
					},
				},
				async (ctx) => {
					const setup = requireSetup();
					const verification = await ctx.context.internalAdapter.findVerificationValue(
						resetIdentifier(ctx.body.token),
					);
					if (!verification || verification.expiresAt < new Date()) {
						throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
					}
					const newCredentialId = generateRandomString(32);
					const { registrationResponse } = server.createRegistrationResponse({
						serverSetup: setup,
						userIdentifier: newCredentialId,
						registrationRequest: ctx.body.registrationRequest,
					});
					const encrypted = await issueState(ctx, {
						purpose: PURPOSE.resetPassword,
						userId: verification.value,
						newCredentialId,
						token: ctx.body.token,
					});
					return { challenge: registrationResponse, state: encrypted };
				},
			),

			opaqueResetPasswordComplete: createAuthEndpoint(
				"/opaque/reset-password/complete",
				{
					method: "POST",
					body: z.object({
						token: z.string().min(1).max(256),
						registrationRecord,
						state,
					}),
					metadata: {
						isAction: false,
						openapi: {
							description:
								"Finish an OPAQUE password reset. Stores the new record, consumes the token and revokes every session.",
						},
					},
				},
				async (ctx) => {
					const setup = requireSetup();
					const decoded = await consumeState(
						ctx,
						ctx.body.state,
						PURPOSE.resetPassword,
					);
					const identifier = resetIdentifier(ctx.body.token);
					const verification = await ctx.context.internalAdapter.findVerificationValue(
						identifier,
					);
					if (
						!verification ||
						verification.expiresAt < new Date() ||
						decoded.token !== ctx.body.token ||
						decoded.userId !== verification.value ||
						!decoded.newCredentialId
					) {
						throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
					}
					const user = await ctx.context.internalAdapter.findUserById(
						verification.value,
					);
					if (!user) {
						throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);
					}
					await assertValidRegistrationRecord(
						setup,
						decoded.newCredentialId,
						ctx.body.registrationRecord,
					);
					const account = await findOpaqueAccount(ctx, user.id);
					if (account) {
						await ctx.context.internalAdapter.updateAccount(account.id, {
							registrationRecord: ctx.body.registrationRecord,
							credentialId: decoded.newCredentialId,
						} as Parameters<typeof ctx.context.internalAdapter.updateAccount>[1]);
					} else {
						await ctx.context.internalAdapter.createAccount({
							providerId: "opaque",
							accountId: user.id,
							userId: user.id,
							registrationRecord: ctx.body.registrationRecord,
							credentialId: decoded.newCredentialId,
						} as Parameters<
							typeof ctx.context.internalAdapter.createAccount
						>[0]);
					}
					await ctx.context.internalAdapter.deleteVerificationByIdentifier(
						identifier,
					);
					await ctx.context.internalAdapter.deleteUserSessions(user.id);
					return { status: true };
				},
			),
		},
		$ERROR_CODES: OPAQUE_ERROR_CODES,
	} satisfies BetterAuthPlugin;
};
