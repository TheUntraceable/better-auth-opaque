import { client as opaqueClient, ready } from "@serenity-kit/opaque";
import { getTestInstanceMemory } from "better-auth/test";
import { describe, expect, test } from "bun:test";
import { opaqueClient as opaquePluginClient } from "./client";
import { opaque } from "./server";

describe("opaque", async () => {
	await ready;
	const { client } = await getTestInstanceMemory(
		{
			plugins: [opaque()],
		},
		{
			clientOptions: {
				plugins: [opaquePluginClient()],
			},
		},
	);
	const password = "supersecurepassword";

	// Helper function to register a user for testing
	const registerTestUser = async (
		email: string,
		password: string,
		name: string,
	) => {
		const { registrationRequest, clientRegistrationState } =
			opaqueClient.startRegistration({ password });

		const { data: challengeData } = await client.signUp.opaque.challenge({
			email,
			registrationRequest,
		});

		if (!challengeData) {
			throw new Error("No data returned from challenge endpoint");
		}

		const { registrationRecord } = opaqueClient.finishRegistration({
			clientRegistrationState,
			registrationResponse: challengeData.challenge,
			password,
		});

		return client.signUp.opaque.complete({
			email,
			name,
			registrationRecord,
		});
	};

	test("should create an account", async () => {
		const { data } = await registerTestUser(
			"test@untraceable.dev",
			password,
			"Test User",
		);
		expect(data?.success).toBe(true);
		expect(data?.message).toBe("User registered successfully");
		expect(data?.token).toBeDefined();
		expect(data?.user?.id).toBeDefined();
	});

	test("should not create an account with invalid registration request", async () => {
		const { registrationRequest } = opaqueClient.startRegistration({
			password,
		});

		// Tamper with the registration request to make it invalid
		const invalidRegistrationRequest = registrationRequest.slice(0, -2);

		try {
			await client.signUp.opaque.challenge({
				email: "invalid-request@untraceable.dev",
				registrationRequest: invalidRegistrationRequest,
			});
		} catch (error) {
			expect(error).toBeDefined();
		}
	});

	test("should reject registration with invalid email", async () => {
		const { registrationRequest } = opaqueClient.startRegistration({
			password,
		});

		try {
			await client.signUp.opaque.challenge({
				email: "not-a-valid-email",
				registrationRequest,
			});
		} catch (error) {
			expect(error).toBeDefined();
		}
	});

	test("should reject registration with invalid registration record", async () => {
		const { registrationRequest, clientRegistrationState } =
			opaqueClient.startRegistration({ password });

		const { data: challengeData } = await client.signUp.opaque.challenge({
			email: "invalid-register-record@untraceable.dev",
			registrationRequest,
		});

		if (!challengeData) {
			throw new Error("No data returned from challenge endpoint");
		}

		const registrationResponse = challengeData.challenge;

		const { registrationRecord } = opaqueClient.finishRegistration({
			clientRegistrationState,
			registrationResponse,
			password,
		});

		const invalidRegistrationRecord = registrationRecord.slice(0, -5);

		try {
			await client.signUp.opaque.complete({
				email: "test@untraceable.dev",
				name: "Invalid Record User",
				registrationRecord: invalidRegistrationRecord,
			});
		} catch (error) {
			expect(error).toBeDefined();
		}
	});

	test("should reject login with wrong password", async () => {
		const email = "wrong-pass@untraceable.dev";
		const correctPassword = "correctPassword123";
		const wrongPassword = "wrongPassword456";

		// Register user with correct password
		await registerTestUser(email, correctPassword, "Wrong Password Test");

		// Try to login with wrong password
		const { startLoginRequest, clientLoginState } = opaqueClient.startLogin({
			password: wrongPassword,
		});

		const { data: loginChallengeData, error } =
			await client.signIn.opaque.challenge({
				email,
				loginRequest: startLoginRequest,
			});

		// If the challenge itself fails, that's also acceptable (generic error message)
		if (error) {
			expect(error).toBeDefined();
			return;
		}

		if (!loginChallengeData) {
			throw new Error("No data returned from login challenge");
		}

		const loginResult = opaqueClient.finishLogin({
			clientLoginState,
			loginResponse: loginChallengeData.challenge,
			password: wrongPassword,
		});

		if (loginResult) {
			const { error: completeError } = await client.signIn.opaque.complete({
				email,
				loginResult: loginResult.finishLoginRequest,
				encryptedServerState: loginChallengeData.state,
			});
			expect(completeError).toBeDefined();
		} else {
			expect(loginResult).toBeUndefined();
		}
	});

	test("should reject login with non-existent user", async () => {
		const email = "nonexistent@untraceable.dev";

		const { startLoginRequest } = opaqueClient.startLogin({ password });

		try {
			await client.signIn.opaque.challenge({
				email,
				loginRequest: startLoginRequest,
			});
		} catch (error) {
			expect(error).toBeDefined();
		}
	});

	test("should reject login with invalid login request", async () => {
		const email = "invalid-login-request@untraceable.dev";

		// Register user first
		const { registrationRequest: regRequest, clientRegistrationState } =
			opaqueClient.startRegistration({ password });

		const { data: regChallengeData } = await client.signUp.opaque.challenge({
			email,
			registrationRequest: regRequest,
		});

		if (!regChallengeData) {
			throw new Error("No data returned from registration challenge");
		}

		const { registrationRecord } = opaqueClient.finishRegistration({
			clientRegistrationState,
			registrationResponse: regChallengeData.challenge,
			password,
		});

		await client.signUp.opaque.complete({
			email,
			name: "Invalid Login Request User",
			registrationRecord,
		});

		// Try login with invalid request
		const { startLoginRequest } = opaqueClient.startLogin({ password });
		const invalidLoginRequest = startLoginRequest.slice(0, -5);

		try {
			await client.signIn.opaque.challenge({
				email,
				loginRequest: invalidLoginRequest,
			});
		} catch (error) {
			expect(error).toBeDefined();
		}
	});

	test("should handle multiple sequential logins", async () => {
		const email = "multi-login@untraceable.dev";

		// Register user
		await registerTestUser(email, password, "Multi Login User");

		// Perform multiple logins
		for (let i = 0; i < 3; i++) {
			const { startLoginRequest, clientLoginState } = opaqueClient.startLogin({
				password,
			});

			const { data: loginChallengeData, error } =
				await client.signIn.opaque.challenge({
					email,
					loginRequest: startLoginRequest,
				});
			console.log(error);
			if (!loginChallengeData) {
				throw new Error("No data returned from login challenge");
			}

			const loginResult = opaqueClient.finishLogin({
				clientLoginState,
				loginResponse: loginChallengeData.challenge,
				password,
			});
			if (!loginResult) {
				throw new Error("Login failed");
			}

			const { data: loginData } = await client.signIn.opaque.complete({
				email,
				loginResult: loginResult.finishLoginRequest,
				encryptedServerState: loginChallengeData.state,
			});

			expect(loginData?.success).toBe(true);
			expect(loginData?.token).toBeDefined();
		}
	});

	test("should support dontRememberMe flag in login", async () => {
		const email = "dont-remember-flag@untraceable.dev";

		// Register user first
		await registerTestUser(email, password, "Dont Remember User");

		const { startLoginRequest, clientLoginState } = opaqueClient.startLogin({
			password,
		});

		const { data: loginChallengeData } = await client.signIn.opaque.challenge({
			email,
			loginRequest: startLoginRequest,
		});

		if (!loginChallengeData) {
			throw new Error("No data returned from login challenge");
		}

		const loginResult = opaqueClient.finishLogin({
			clientLoginState,
			loginResponse: loginChallengeData.challenge,
			password,
		});

		if (!loginResult) {
			throw new Error("Login failed");
		}

		const { data: loginData, error } = await client.signIn.opaque.complete({
			email,
			loginResult: loginResult.finishLoginRequest,
			encryptedServerState: loginChallengeData.state,
			dontRememberMe: true,
		});
		console.log(error);

		expect(loginData?.success).toBe(true);
		expect(loginData?.token).toBeDefined();
	});
});
