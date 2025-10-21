import { client, ready, server } from "@serenity-kit/opaque";
import {
	type Account,
	APIError,
	type BetterAuthPlugin,
	type User,
} from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import {
	generateRandomString,
	symmetricDecrypt,
	symmetricEncrypt,
} from "better-auth/crypto";
import * as z from "zod";

interface OpaqueOptions {
	OPAQUE_SERVER_KEY: string;
}

const REGISTRATION_REQUEST_LENGTH = 32;
const REGISTRATION_RECORD_MIN_LENGTH = 170;
const REGISTRATION_RECORD_MAX_LENGTH = 200;
const LOGIN_REQUEST_LENGTH = 96;

function base64UrlDecode(str: string): string {
	const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
	return atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
}

function validateBase64Length(
	base64: string,
	expectedLength: number,
	fieldName: string,
): void {
	const bytes = base64UrlDecode(base64);
	if (bytes.length !== expectedLength) {
		throw new APIError("BAD_REQUEST", {
			message: `Invalid ${fieldName}`,
		});
	}
}

function validateBase64LengthRange(
	base64: string,
	min: number,
	max: number,
	fieldName: string,
): void {
	const bytes = base64UrlDecode(base64);
	if (bytes.length < min || bytes.length > max) {
		throw new APIError("BAD_REQUEST", {
			message: `Invalid ${fieldName}`,
		});
	}
}

async function encryptServerLoginState(
	serverLoginState: string,
	secret: string,
	user: {
		id: string;
		email: string;
		name: string;
		[key: string]: unknown;
	} | null,
): Promise<string> {
	return await symmetricEncrypt({
		data: JSON.stringify({ serverLoginState, user }),
		key: secret,
	});
}

async function decryptServerLoginState(
	encryptedState: string,
	secret: string,
): Promise<{
	serverLoginState: string;
	user: {
		id: string;
		email: string;
		name: string;
		[key: string]: unknown;
	} | null;
}> {
	const decrypted = await symmetricDecrypt({
		key: secret,
		data: encryptedState,
	});
	return JSON.parse(decrypted);
}

async function findOpaqueAccount(
	ctx: {
		context: {
			internalAdapter: { findAccounts: (userId: string) => Promise<Account[]> };
		};
	},
	userId: string,
): Promise<(Account & { registrationRecord: string }) | undefined> {
	const accounts = await ctx.context.internalAdapter.findAccounts(userId);
	return accounts.find((account: Account) => account.providerId === "opaque") as
		| (Account & { registrationRecord: string })
		| undefined;
}

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
		})
	}
	let dummyRegistrationRecord: string;

	return {
		id: "opaque",
		init: async () => {
			await ready;

			const tempServerSetup = server.createSetup(); // Use a temporary key

			const userId = generateRandomString(12);
			const password = generateRandomString(24);

			const { registrationRequest, clientRegistrationState } =
				client.startRegistration({
					password,
				});

			const { registrationResponse } = server.createRegistrationResponse({
				registrationRequest,
				serverSetup: tempServerSetup,
				userIdentifier: userId,
			});

			const { registrationRecord } = client.finishRegistration({
				clientRegistrationState,
				registrationResponse,
				password,
			});

			dummyRegistrationRecord = registrationRecord;
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

					// Determine registration record (use dummy for non-existent users to prevent enumeration)
					let registrationRecord: string;
					let userToEncrypt: {
						id: string;
						email: string;
						name: string;
						[key: string]: unknown;
					} | null = null;

					if (!user) {
						registrationRecord = dummyRegistrationRecord;
					} else {
						userToEncrypt = user.user;
						const opaqueAccount = await findOpaqueAccount(ctx, user.user.id);
						registrationRecord =
							opaqueAccount?.registrationRecord || dummyRegistrationRecord;
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
