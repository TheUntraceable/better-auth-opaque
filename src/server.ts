import { ready, server } from "@serenity-kit/opaque";
import { APIError, type BetterAuthPlugin, type User } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { generateRandomString } from "better-auth/crypto";
import * as z from "zod";
import {
	createDummyRegistrationRecord,
	decryptServerLoginState,
	encryptServerLoginState,
	findOpaqueAccount,
	LOGIN_REQUEST_LENGTH,
	type OpaqueOptions,
	REGISTRATION_RECORD_MAX_LENGTH,
	REGISTRATION_RECORD_MIN_LENGTH,
	REGISTRATION_REQUEST_LENGTH,
	sleep,
	validateBase64Length,
	validateBase64LengthRange,
} from "./utils";

export const opaque = (options?: OpaqueOptions) => {
	let OPAQUE_SERVER_KEY: string;

	if (options?.OPAQUE_SERVER_KEY) {
		OPAQUE_SERVER_KEY = options.OPAQUE_SERVER_KEY;
	} else {
		ready.then(() => {
			OPAQUE_SERVER_KEY = server.createSetup();
			console.log(
				`OPAQUE_SERVER_KEY not provided. Generated a new one for development purposes: ${OPAQUE_SERVER_KEY}`,
			);
		});
	}

	return {
		id: "opaque",
		init: async () => {
			await ready;
		},
		schema: {
			account: {
				fields: {
					registrationRecord: {
						type: "string",
						required: false,
						unique: true,
						validator: { input: z.base64url() },
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
						email: z.email(),
						registrationRequest: z.base64url(),
					}),
				},
				async (ctx) => {
					const { email, registrationRequest } = ctx.body;

					validateBase64Length(
						registrationRequest,
						REGISTRATION_REQUEST_LENGTH,
						"registration request",
					);

					const { registrationResponse } = server.createRegistrationResponse({
						userIdentifier: email,
						registrationRequest,
						serverSetup: OPAQUE_SERVER_KEY,
					});
					return { challenge: registrationResponse };
				},
			),
			completeRegistration: createAuthEndpoint(
				"/sign-up/opaque/complete",
				{
					method: "POST",
					body: z.object({
						email: z.email(),
						name: z.string().min(1).max(100),
						registrationRecord: z.base64url(),
					}),
				},
				async (ctx) => {
					const { email, name, registrationRecord } = ctx.body;

					validateBase64LengthRange(
						registrationRecord,
						REGISTRATION_RECORD_MIN_LENGTH,
						REGISTRATION_RECORD_MAX_LENGTH,
						"registration record",
					);

					const now = new Date();

					const existingUser =
						await ctx.context.internalAdapter.findUserByEmail(email);

					const approximateDbWriteTimeMs = 120;

					if (existingUser) {
						// Simulate 2 database writes with independent jitter
						for (let i = 0; i < 2; i++) {
							const jitter = Math.random() * 50;
							await sleep(approximateDbWriteTimeMs + jitter);
						}

						const fakeUserId = ctx.context.generateId({ model: "user" });

						if (!fakeUserId) {
							throw new Error("Failed to generate fake user ID");
						}

						const fakeAccountId = ctx.context.generateId({ model: "account" });

						if (!fakeAccountId) {
							throw new Error("Failed to generate fake account ID");
						}


						return ctx.json(
							{
								success: true,
								message: "User registered successfully",
							},
							{
								status: 201,
							},
						);
					}

					const user = await ctx.context.internalAdapter.createUser({
						email,
						name,
						createdAt: now,
						updatedAt: now,
					});

					const accountId = ctx.context.generateId({
						model: "account",
					});

					if (!accountId) {
						throw new Error("Failed to generate account ID");
					}

					await ctx.context.internalAdapter.createAccount({
						accountId,
						providerId: "opaque",
						userId: user.id,
						registrationRecord,
						createdAt: now,
						updatedAt: now,
					});

					return ctx.json(
						{
							success: true,
							message: "User registered successfully",
						},
						{
							status: 201,
						},
					);
				},
			),

			getLoginChallenge: createAuthEndpoint(
				"/sign-in/opaque/challenge",
				{
					method: "POST",
					body: z.object({
						email: z.email(),
						loginRequest: z.base64url(),
					}),
				},
				async (ctx) => {
					const { email, loginRequest } = ctx.body;

					validateBase64Length(
						loginRequest,
						LOGIN_REQUEST_LENGTH,
						"login request",
					);

					const user = await ctx.context.internalAdapter.findUserByEmail(email);

					let registrationRecord: string;
					let userToEncrypt: {
						id: string;
						email: string;
						name: string;
						[key: string]: unknown;
					} | null = null;

					if (!user) {
						registrationRecord = await createDummyRegistrationRecord();
						userToEncrypt = {
							id: generateRandomString(12),
							email,
							name: generateRandomString(24),
						};
					} else {
						userToEncrypt = user.user;
						const opaqueAccount = await findOpaqueAccount(ctx, user.user.id);
						registrationRecord =
							opaqueAccount?.registrationRecord ||
							(await createDummyRegistrationRecord());
					}

					const { loginResponse, serverLoginState } = server.startLogin({
						userIdentifier: email,
						startLoginRequest: loginRequest,
						serverSetup: OPAQUE_SERVER_KEY,
						registrationRecord,
					});

					const encryptedServerState = await encryptServerLoginState(
						serverLoginState,
						ctx.context.secret,
						userToEncrypt,
					);

					return { challenge: loginResponse, state: encryptedServerState };
				},
			),

			completeLogin: createAuthEndpoint(
				"/sign-in/opaque/complete",
				{
					method: "POST",
					body: z.object({
						email: z.email(),
						loginResult: z.base64url(),
						encryptedServerState: z.string(),
						dontRememberMe: z.boolean().optional(),
					}),
				},
				async (ctx) => {
					const { loginResult, encryptedServerState, dontRememberMe } =
						ctx.body;
					let serverLoginState: string;
					let user: User | null;

					try {
						({ serverLoginState, user } = await decryptServerLoginState(
							encryptedServerState,
							ctx.context.secret,
						));
					} catch {
						throw new APIError("BAD_REQUEST", {
							message: "Invalid login state",
						});
					}

					const { sessionKey } = server.finishLogin({
						finishLoginRequest: loginResult,
						serverLoginState: serverLoginState,
					});

					if (!sessionKey) {
						throw new APIError("UNAUTHORIZED", {
							message: "Login failed",
						});
					}

					// If user is null, it means the user didn't exist during challenge phase
					// This shouldn't happen with valid OPAQUE flow, but we check for safety
					if (!user) {
						throw new APIError("UNAUTHORIZED", {
							message: "Login failed",
						});
					}

					const session = await ctx.context.internalAdapter.createSession(
						user.id,
						ctx,
						dontRememberMe || false,
					);
					if (!session) {
						throw new APIError("INTERNAL_SERVER_ERROR", {
							message: "Failed to create session",
						});
					}

					await setSessionCookie(ctx, { session, user: user as User });

					return ctx.json({
						token: session.token,
						success: true,
						user: {
							id: user.id,
						},
					});
				},
			),
		},
	} satisfies BetterAuthPlugin;
};
