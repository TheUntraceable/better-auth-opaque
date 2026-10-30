import { client as opaqueCrypto, ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test, vi } from "vitest";
import { createOpaqueTestInstance } from "../helpers";

// Each test here runs 50 to 200 full handshakes (client Argon2 included), far
// past the suite's 60s default; budget accordingly.
vi.setConfig({ testTimeout: 15 * 60_000 });

describe.skipIf(!process.env.OPAQUE_TIMING_TESTS)("timing attack resistance", async () => {
	await ready;

	const { client, server } = await createOpaqueTestInstance();
	afterAll(() => server.close());

	const existingUserEmail = "timing-test-existing@untraceable.dev";
	const nonExistentUserEmail = "timing-test-nonexistent@untraceable.dev";
	const testPassword = "supersecurepassword123";
	const testName = "Timing Test User";

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

	beforeAll(async () => {
		try {
			await registerTestUser(existingUserEmail, testPassword, testName);
		} catch {
			// User might already exist, that's fine
			console.log("User already exists or creation failed");
		}
	});

	test("registration timing attack - existing vs non-existent user", async () => {
		const iterations = 10;
		const existingUserTimes: number[] = [];
		const nonExistentUserTimes: number[] = [];

		for (let i = 0; i < iterations; i++) {
			const start = performance.now();
			try {
				await registerTestUser(existingUserEmail, testPassword, testName);
			} catch {
				// Expected to fail or return success (timing protection)
			}
			const duration = performance.now() - start;
			existingUserTimes.push(duration);
		}

		// Test with non-existent user (each with unique email to avoid conflicts)
		for (let i = 0; i < iterations; i++) {
			const start = performance.now();
			try {
				await registerTestUser(
					`timing-new-${Date.now()}-${i}@untraceable.dev`,
					testPassword,
					testName,
				);
			} catch {
				// May fail for various reasons
			}
			const duration = performance.now() - start;
			nonExistentUserTimes.push(duration);
		}

		const avgExisting =
			existingUserTimes.reduce((a, b) => a + b, 0) / existingUserTimes.length;
		const avgNonExistent =
			nonExistentUserTimes.reduce((a, b) => a + b, 0) /
			nonExistentUserTimes.length;

		const stdDevExisting = Math.sqrt(
			existingUserTimes.reduce(
				(sum, time) => sum + (time - avgExisting) ** 2,
				0,
			) / existingUserTimes.length,
		);

		const stdDevNonExistent = Math.sqrt(
			nonExistentUserTimes.reduce(
				(sum, time) => sum + (time - avgNonExistent) ** 2,
				0,
			) / nonExistentUserTimes.length,
		);

		const timeDifference = Math.abs(avgExisting - avgNonExistent);
		const combinedStdDev = Math.sqrt(
			(stdDevExisting ** 2 + stdDevNonExistent ** 2) / 2,
		);

		console.log("\n=== Registration Timing Attack Test ===");
		console.log(`Existing user average: ${avgExisting.toFixed(2)}ms`);
		console.log(`Existing user std dev: ${stdDevExisting.toFixed(2)}ms`);
		console.log(`Non-existent user average: ${avgNonExistent.toFixed(2)}ms`);
		console.log(`Non-existent user std dev: ${stdDevNonExistent.toFixed(2)}ms`);
		console.log(`Time difference: ${timeDifference.toFixed(2)}ms`);
		console.log(`Combined std dev: ${combinedStdDev.toFixed(2)}ms`);

		// The time difference should be within ~3 standard deviations
		// This is a statistical test - timing should be indistinguishable
		// Allow for 3 sigma (99.7% confidence interval)
		const threshold = 3 * combinedStdDev;

		console.log(`Threshold (3σ): ${threshold.toFixed(2)}ms`);
		console.log(
			`Test ${timeDifference <= threshold ? "PASSED" : "FAILED"}: Time difference is ${timeDifference <= threshold ? "within" : "outside"} acceptable range`,
		);

		// The timing difference should be relatively small compared to the standard deviation
		// This indicates the server is successfully hiding whether a user exists
		expect(timeDifference).toBeLessThanOrEqual(threshold);
	});

	test("login timing attack - existing vs non-existent user (challenge phase)", async () => {
		const iterations = 10;
		const existingUserTimes: number[] = [];
		const nonExistentUserTimes: number[] = [];

		// Time the challenge endpoint alone: the full signIn flow only sends the second
		// request when the local finishLogin succeeds, which happens for the existing
		// user but not the missing one, so it would measure request count, not the server.
		for (let i = 0; i < iterations; i++) {
			const { startLoginRequest } = opaqueCrypto.startLogin({ password: testPassword });
			const start = performance.now();
			await client.$fetch("/opaque/sign-in/challenge", {
				method: "POST",
				body: { email: existingUserEmail, loginRequest: startLoginRequest },
			});
			existingUserTimes.push(performance.now() - start);
		}

		for (let i = 0; i < iterations; i++) {
			const { startLoginRequest } = opaqueCrypto.startLogin({ password: testPassword });
			const start = performance.now();
			await client.$fetch("/opaque/sign-in/challenge", {
				method: "POST",
				body: { email: nonExistentUserEmail, loginRequest: startLoginRequest },
			});
			nonExistentUserTimes.push(performance.now() - start);
		}

		const avgExisting =
			existingUserTimes.reduce((a, b) => a + b, 0) / existingUserTimes.length;
		const avgNonExistent =
			nonExistentUserTimes.reduce((a, b) => a + b, 0) /
			nonExistentUserTimes.length;

		const stdDevExisting = Math.sqrt(
			existingUserTimes.reduce(
				(sum, time) => sum + (time - avgExisting) ** 2,
				0,
			) / existingUserTimes.length,
		);

		const stdDevNonExistent = Math.sqrt(
			nonExistentUserTimes.reduce(
				(sum, time) => sum + (time - avgNonExistent) ** 2,
				0,
			) / nonExistentUserTimes.length,
		);

		const timeDifference = Math.abs(avgExisting - avgNonExistent);
		const combinedStdDev = Math.sqrt(
			(stdDevExisting ** 2 + stdDevNonExistent ** 2) / 2,
		);

		console.log("\n=== Login Challenge Timing Attack Test ===");
		console.log(`Existing user average: ${avgExisting.toFixed(2)}ms`);
		console.log(`Existing user std dev: ${stdDevExisting.toFixed(2)}ms`);
		console.log(`Non-existent user average: ${avgNonExistent.toFixed(2)}ms`);
		console.log(`Non-existent user std dev: ${stdDevNonExistent.toFixed(2)}ms`);
		console.log(`Time difference: ${timeDifference.toFixed(2)}ms`);
		console.log(`Combined std dev: ${combinedStdDev.toFixed(2)}ms`);

		const threshold = 3 * combinedStdDev;

		console.log(`Threshold (3σ): ${threshold.toFixed(2)}ms`);
		console.log(
			`Test ${timeDifference <= threshold ? "PASSED" : "FAILED"}: Time difference is ${timeDifference <= threshold ? "within" : "outside"} acceptable range`,
		);

		// For login challenge, the timing should be very similar
		// because both paths generate a response (real or dummy)
		expect(timeDifference).toBeLessThanOrEqual(threshold);
	});

	test("statistical analysis of timing consistency", async () => {
		const iterations = 20;
		const existingUserTimes: number[] = [];

		for (let i = 0; i < iterations; i++) {
			const start = performance.now();
			try {
				await registerTestUser(existingUserEmail, testPassword, testName);
			} catch {
				// Expected
			}
			const duration = performance.now() - start;
			existingUserTimes.push(duration);
		}

		const avg = existingUserTimes.reduce((a, b) => a + b, 0) / iterations;
		const stdDev = Math.sqrt(
			existingUserTimes.reduce((sum, time) => sum + (time - avg) ** 2, 0) /
			iterations,
		);

		const coefficientOfVariation = (stdDev / avg) * 100;

		console.log("\n=== Timing Consistency Analysis ===");
		console.log(`Average time: ${avg.toFixed(2)}ms`);
		console.log(`Standard deviation: ${stdDev.toFixed(2)}ms`);
		console.log(
			`Coefficient of variation: ${coefficientOfVariation.toFixed(2)}%`,
		);
		console.log(
			"Sample times:",
			existingUserTimes.map((t) => t.toFixed(2)),
		);

		expect(coefficientOfVariation).toBeLessThan(50);
	});
});
