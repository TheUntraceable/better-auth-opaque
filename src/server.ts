import { ready, server } from "@serenity-kit/opaque";
import {
	APIError,
	type BetterAuthPlugin,
	type User
} from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import {
	generateRandomString
} from "better-auth/crypto";
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

					if (existingUser) {
						// const approximateDbWriteTimeMs = 150;

						// // Simulate 3 database writes with independent jitter
						// for (let i = 0; i < 3; i++) {
						// 	const jitter = Math.random() * 50;
						// 	await sleep(approximateDbWriteTimeMs + jitter)
						// }

						// const fakeUserId = ctx.context.generateId({ model: "user" });

						// if (!fakeUserId) {
						// 	throw new Error("Failed to generate fake user ID");
						// }

						// const fakeSessionId = ctx.context.generateId({ model: "session" });

						// if (!fakeSessionId) {
						// 	throw new Error("Failed to generate fake session ID");
						// }

						// const session = {
						// 	token: generateRandomString(48),
						// 	createdAt: now,
						// 	expiresAt: new Date(now.getTime() + 1000 * 60 * 60), // 1 hour
						// 	id: fakeSessionId,
						// 	updatedAt: now,
						// 	userId: fakeUserId,
						// };

						// const fakeUser: User = {
						// 	id: fakeUserId,
						// 	email,
						// 	name,
						// 	createdAt: now,
						// 	updatedAt: now,
						// 	emailVerified: false,
						// };

						// setSessionCookie(ctx, {
						// 	session,
						// 	user: fakeUser,
						// });

						// return ctx.json(
						// 	{
						// 		success: true,
						// 		message: "User registered successfully",
						// 		token: session.token,
						// 		user: {
						// 			id: fakeUser.id,
						// 		},
						// 	},
						// 	{
						// 		status: 201,
						// 	},
						// );
						
						// The code above is meant to mitigate timing attacks during registration by simulating
						// database operations even when the user already exists. However, it is currently
						// commented out because I'm not sure how I want to handle this. The current flow will
						// cause UX issues for real users who are trying to register with an existing email.
						// Maybe this UX issue is worth it for the security, but I can't think of a good way to
						// get around it.
						
						throw new APIError("CONFLICT", {
							message: "User with this email already exists",
						});
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

					const session = await ctx.context.internalAdapter.createSession(
						user.id,
						ctx,
						false,
					);

					if (!session) {
						throw new APIError("INTERNAL_SERVER_ERROR", {
							message: "Failed to create session",
						});
					}

					await setSessionCookie(ctx, { session, user });

					return ctx.json(
						{
							success: true,
							message: "User registered successfully",
							token: session.token,
							user: {
								id: user.id,
							},
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

					const { serverLoginState, user } = await decryptServerLoginState(
						encryptedServerState,
						ctx.context.secret,
					);

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
