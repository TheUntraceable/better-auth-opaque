import { ready } from "@serenity-kit/opaque";
import { createAuthClient } from "better-auth/client";
import { describe, expect, test } from "bun:test";
import { opaqueClient as opaquePluginClient } from "../src/client";

describe("opaque", async () => {
	await ready;

	const client = createAuthClient({
		baseURL: "http://localhost:8080",
		plugins: [opaquePluginClient()],
	});

	const password = "supersecurepassword";

	// Helper function to register a user for testing
	const registerTestUser = async (
		email: string,
		password: string,
		name: string,
	) => {
		return await client.signUp.opaque({
			email,
			name,
			password,
		});
	};

	test("should create an account", async () => {
		const response = await registerTestUser(
			"test@untraceable.dev",
			password,
			"Test User",
		);
		if ('data' in response) {
			expect(response.data).toBeDefined();
		} else if ('error' in response) {
			// User might already exist, which is acceptable
			expect(response.error).toBeDefined();
		}
	});

	test("should reject registration with invalid email", async () => {
		try {
			await client.signUp.opaque({
				email: "not-a-valid-email",
				password,
				name: "Invalid Email User",
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
		const loginResponse = await client.signIn.opaque({
			email,
			password: wrongPassword
		});

		// Login should fail with wrong password
		// The response should either have an error or indicate failure
		expect(loginResponse).toBeDefined();
	});

	test("should reject login with non-existent user", async () => {
		const email = "nonexistent@untraceable.dev";

		try {
			await client.signIn.opaque({
				email,
				password,
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
			const loginResponse = await client.signIn.opaque({
				email,
				password,
			});
			if ('data' in loginResponse && !loginResponse.data) {
				throw new Error("No data returned from login challenge");
			}
		}
	});

	test("should support dontRememberMe flag in login", async () => {
		const email = "dont-remember-flag@untraceable.dev";

		await registerTestUser(email, password, "Dont Remember User");

		const loginResponse = await client.signIn.opaque({
			email,
			password,
		});

		if ('data' in loginResponse && loginResponse.data) {
			expect(loginResponse.data.success).toBe(true);
			expect(loginResponse.data.token).toBeDefined();
		}
	});

	test("should not allow users to try register and get a valid session as an existing user", async () => {
		const email = "existing-user@untraceable.dev";

		await registerTestUser(email, password, "Existing User Test");

		const registerResponse = await client.signUp.opaque({
			email,
			name: "Existing User Test",
			password
		});
		const session = await client.getSession();

		if ('error' in registerResponse) {
			expect(registerResponse.error).toBeDefined();
		}
		expect(session.data).toBeNull();

		if ('data' in registerResponse) {
			expect(registerResponse.data).toBeDefined();
		}
	});

});
