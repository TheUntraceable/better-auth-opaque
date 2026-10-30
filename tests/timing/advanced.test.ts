import { client as opaqueCrypto, ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test, vi } from "vitest";
import { createOpaqueTestInstance } from "../helpers";

// Each test here runs 50 to 200 full handshakes (client Argon2 included), far
// past the suite's 60s default; budget accordingly.
vi.setConfig({ testTimeout: 15 * 60_000 });

describe.skipIf(!process.env.OPAQUE_TIMING_TESTS)("advanced timing attack resistance", async () => {
	await ready;

	const { client, server } = await createOpaqueTestInstance();
	afterAll(() => server.close());

	const existingUserEmail = "advanced-timing-existing@untraceable.dev";
	const nonExistentUserEmail = "advanced-timing-nonexistent@untraceable.dev";
	const testPassword = "supersecurepassword123";
	const testName = "Advanced Timing Test User";

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
			console.log("User already exists or creation failed");
		}
	});

	test("extreme sample size - registration timing (100 iterations)", async () => {
		const iterations = 100;
		const existingUserTimes: number[] = [];
		const nonExistentUserTimes: number[] = [];

		console.log("\n🔬 Running extreme sample size test with 100 iterations...");

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

		for (let i = 0; i < iterations; i++) {
			const start = performance.now();
			try {
				await registerTestUser(
					`extreme-new-${Date.now()}-${i}@untraceable.dev`,
					testPassword,
					testName,
				);
			} catch {
				// Expected
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

		console.log("\n=== Extreme Sample Size Registration Test ===");
		console.log(`Iterations: ${iterations}`);
		console.log(`Existing user average: ${avgExisting.toFixed(2)}ms`);
		console.log(`Existing user std dev: ${stdDevExisting.toFixed(2)}ms`);
		console.log(`Non-existent user average: ${avgNonExistent.toFixed(2)}ms`);
		console.log(`Non-existent user std dev: ${stdDevNonExistent.toFixed(2)}ms`);
		console.log(`Time difference: ${timeDifference.toFixed(2)}ms`);
		console.log(`Combined std dev: ${combinedStdDev.toFixed(2)}ms`);

		// With more samples, we can be more strict (use 2.5σ instead of 3σ)
		const threshold = 2.5 * combinedStdDev;
		console.log(`Threshold (2.5σ): ${threshold.toFixed(2)}ms`);

		expect(timeDifference).toBeLessThanOrEqual(threshold);
	});

	test("kolmogorov-smirnov test - distribution similarity", async () => {
		const iterations = 50;
		const existingUserTimes: number[] = [];
		const nonExistentUserTimes: number[] = [];

		console.log("\n🔬 Running Kolmogorov-Smirnov distribution test...");

		for (let i = 0; i < iterations; i++) {
			const start1 = performance.now();
			try {
				await registerTestUser(existingUserEmail, testPassword, testName);
			} catch { }
			existingUserTimes.push(performance.now() - start1);

			const start2 = performance.now();
			try {
				await registerTestUser(
					`ks-new-${Date.now()}-${i}@untraceable.dev`,
					testPassword,
					testName,
				);
			} catch { }
			nonExistentUserTimes.push(performance.now() - start2);
		}

		const sorted1 = [...existingUserTimes].sort((a, b) => a - b);
		const sorted2 = [...nonExistentUserTimes].sort((a, b) => a - b);

		// Calculate empirical CDFs and find maximum difference
		let maxDiff = 0;
		const allPoints = [...new Set([...sorted1, ...sorted2])].sort(
			(a, b) => a - b,
		);

		for (const point of allPoints) {
			const cdf1 = sorted1.filter((x) => x <= point).length / sorted1.length;
			const cdf2 = sorted2.filter((x) => x <= point).length / sorted2.length;
			const diff = Math.abs(cdf1 - cdf2);
			if (diff > maxDiff) maxDiff = diff;
		}

		// Critical value for KS test at α=0.05 for n=50
		const criticalValue = 1.36 / Math.sqrt(iterations);

		console.log("\n=== Kolmogorov-Smirnov Test ===");
		console.log(`Max CDF difference (D): ${maxDiff.toFixed(4)}`);
		console.log(`Critical value (α=0.05): ${criticalValue.toFixed(4)}`);
		console.log(
			`Distributions are ${maxDiff < criticalValue ? "SIMILAR" : "DIFFERENT"}`,
		);

		// If D < critical value, distributions are statistically similar (good!)
		expect(maxDiff).toBeLessThan(criticalValue);
	});

	test("mann-whitney u test - median comparison", async () => {
		const iterations = 40;
		const existingUserTimes: number[] = [];
		const nonExistentUserTimes: number[] = [];

		console.log("\n🔬 Running Mann-Whitney U test...");

		for (let i = 0; i < iterations; i++) {
			const start1 = performance.now();
			try {
				await registerTestUser(existingUserEmail, testPassword, testName);
			} catch { }
			existingUserTimes.push(performance.now() - start1);

			const start2 = performance.now();
			try {
				await registerTestUser(
					`mw-new-${Date.now()}-${i}@untraceable.dev`,
					testPassword,
					testName,
				);
			} catch { }
			nonExistentUserTimes.push(performance.now() - start2);
		}

		const combined = [
			...existingUserTimes.map((t) => ({ time: t, group: 1 })),
			...nonExistentUserTimes.map((t) => ({ time: t, group: 2 })),
		].sort((a, b) => a.time - b.time);

		// Rank = 1-based position in the sorted combined sample
		const group1Ranks = combined
			.map((item, i) => (item.group === 1 ? i + 1 : 0))
			.filter((r) => r > 0);

		const R1 = group1Ranks.reduce((a, b) => a + b, 0);
		const n1 = existingUserTimes.length;
		const n2 = nonExistentUserTimes.length;

		const U1 = R1 - (n1 * (n1 + 1)) / 2;
		const U2 = n1 * n2 - U1;
		const U = Math.min(U1, U2);

		const meanU = (n1 * n2) / 2;
		const stdU = Math.sqrt((n1 * n2 * (n1 + n2 + 1)) / 12);
		const z = (U - meanU) / stdU;

		console.log("\n=== Mann-Whitney U Test ===");
		console.log(`U statistic: ${U.toFixed(2)}`);
		console.log(`Expected U: ${meanU.toFixed(2)}`);
		console.log(`Z-score: ${z.toFixed(4)}`);
		console.log(`|Z| < 1.96: ${Math.abs(z) < 1.96 ? "PASS" : "FAIL"} (α=0.05)`);

		// |Z| < 1.96 means no significant difference at α=0.05
		expect(Math.abs(z)).toBeLessThan(1.96);
	});

	test("percentile analysis - tail behavior", async () => {
		const iterations = 50;
		const existingUserTimes: number[] = [];
		const nonExistentUserTimes: number[] = [];

		console.log("\n🔬 Running percentile analysis...");

		for (let i = 0; i < iterations; i++) {
			const start1 = performance.now();
			try {
				await registerTestUser(existingUserEmail, testPassword, testName);
			} catch { }
			existingUserTimes.push(performance.now() - start1);

			const start2 = performance.now();
			try {
				await registerTestUser(
					`percentile-new-${Date.now()}-${i}@untraceable.dev`,
					testPassword,
					testName,
				);
			} catch { }
			nonExistentUserTimes.push(performance.now() - start2);
		}

		const percentile = (arr: number[], p: number) => {
			const sorted = [...arr].sort((a, b) => a - b);
			const index = (p / 100) * (sorted.length - 1);
			const lower = Math.floor(index);
			const upper = Math.ceil(index);
			const weight = index % 1;
			return (sorted[lower] ?? 0) * (1 - weight) + (sorted[upper] ?? 0) * weight;
		};

		const percentiles = [10, 25, 50, 75, 90, 95, 99];
		console.log("\n=== Percentile Analysis ===");
		console.log("Percentile | Existing | New User | Difference");
		console.log("-----------|----------|----------|------------");

		for (const p of percentiles) {
			const p1 = percentile(existingUserTimes, p);
			const p2 = percentile(nonExistentUserTimes, p);
			const diff = Math.abs(p1 - p2);
			console.log(
				`P${p.toString().padStart(2)}        | ${p1.toFixed(2).padStart(8)} | ${p2.toFixed(2).padStart(8)} | ${diff.toFixed(2).padStart(10)}`,
			);

			// Percentile differences should be relatively small
			// Allow 15% difference in timing at each percentile
			const avgPercentile = (p1 + p2) / 2;
			expect(diff).toBeLessThan(avgPercentile * 0.15);
		}
	});

	test("interleaved timing - prevent caching artifacts", async () => {
		const iterations = 30;
		const existingUserTimes: number[] = [];
		const nonExistentUserTimes: number[] = [];

		console.log("\n🔬 Running interleaved timing test...");

		// Interleave requests to prevent any caching or warm-up effects
		for (let i = 0; i < iterations; i++) {
			// Randomly decide which to test first
			const testExistingFirst = Math.random() > 0.5;

			if (testExistingFirst) {
				const start1 = performance.now();
				try {
					await registerTestUser(existingUserEmail, testPassword, testName);
				} catch { }
				existingUserTimes.push(performance.now() - start1);

				const start2 = performance.now();
				try {
					await registerTestUser(
						`interleaved-new-${Date.now()}-${i}@untraceable.dev`,
						testPassword,
						testName,
					);
				} catch { }
				nonExistentUserTimes.push(performance.now() - start2);
			} else {
				const start2 = performance.now();
				try {
					await registerTestUser(
						`interleaved-new-${Date.now()}-${i}@untraceable.dev`,
						testPassword,
						testName,
					);
				} catch { }
				nonExistentUserTimes.push(performance.now() - start2);

				const start1 = performance.now();
				try {
					await registerTestUser(existingUserEmail, testPassword, testName);
				} catch { }
				existingUserTimes.push(performance.now() - start1);
			}
		}

		const avgExisting =
			existingUserTimes.reduce((a, b) => a + b, 0) / existingUserTimes.length;
		const avgNonExistent =
			nonExistentUserTimes.reduce((a, b) => a + b, 0) /
			nonExistentUserTimes.length;

		const timeDifference = Math.abs(avgExisting - avgNonExistent);

		console.log("\n=== Interleaved Timing Test ===");
		console.log(`Existing user average: ${avgExisting.toFixed(2)}ms`);
		console.log(`Non-existent user average: ${avgNonExistent.toFixed(2)}ms`);
		console.log(`Time difference: ${timeDifference.toFixed(2)}ms`);

		// Should be within 5% of each other
		const avgOverall = (avgExisting + avgNonExistent) / 2;
		const maxDiff = avgOverall * 0.05;

		console.log(`Maximum acceptable difference (5%): ${maxDiff.toFixed(2)}ms`);
		expect(timeDifference).toBeLessThan(maxDiff);
	});

	test("login challenge - extreme sample size (100 iterations)", async () => {
		const iterations = 100;
		const existingUserTimes: number[] = [];
		const nonExistentUserTimes: number[] = [];

		console.log("\n🔬 Running extreme login challenge test...");

		// Time the challenge endpoint alone: the full signIn flow only sends the second
		// request when the local finishLogin succeeds, which happens for the existing
		// user but not the missing one, so it would measure request count, not the server.
		for (let i = 0; i < iterations; i++) {
			const { startLoginRequest: existingRequest } = opaqueCrypto.startLogin({ password: testPassword });
			const start1 = performance.now();
			await client.$fetch("/opaque/sign-in/challenge", {
				method: "POST",
				body: { email: existingUserEmail, loginRequest: existingRequest },
			});
			existingUserTimes.push(performance.now() - start1);

			const { startLoginRequest: missingRequest } = opaqueCrypto.startLogin({ password: testPassword });
			const start2 = performance.now();
			await client.$fetch("/opaque/sign-in/challenge", {
				method: "POST",
				body: { email: nonExistentUserEmail, loginRequest: missingRequest },
			});
			nonExistentUserTimes.push(performance.now() - start2);
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

		console.log("\n=== Extreme Login Challenge Test ===");
		console.log(`Iterations: ${iterations}`);
		console.log(`Existing user average: ${avgExisting.toFixed(2)}ms`);
		console.log(`Existing user std dev: ${stdDevExisting.toFixed(2)}ms`);
		console.log(`Non-existent user average: ${avgNonExistent.toFixed(2)}ms`);
		console.log(`Non-existent user std dev: ${stdDevNonExistent.toFixed(2)}ms`);
		console.log(`Time difference: ${timeDifference.toFixed(2)}ms`);
		console.log(`Combined std dev: ${combinedStdDev.toFixed(2)}ms`);

		const threshold = 2.5 * combinedStdDev;
		console.log(`Threshold (2.5σ): ${threshold.toFixed(2)}ms`);

		expect(timeDifference).toBeLessThanOrEqual(threshold);
	});

	test("autocorrelation test - detect timing leak patterns", async () => {
		const iterations = 50;
		const existingTimes: number[] = [];
		const newUserTimes: number[] = [];

		console.log("\n🔬 Running autocorrelation test...");

		for (let i = 0; i < iterations; i++) {
			if (i % 2 === 0) {
				const start = performance.now();
				try {
					await registerTestUser(existingUserEmail, testPassword, testName);
				} catch { }
				existingTimes.push(performance.now() - start);
			} else {
				const start = performance.now();
				try {
					await registerTestUser(
						`autocorr-new-${Date.now()}-${i}@untraceable.dev`,
						testPassword,
						testName,
					);
				} catch { }
				newUserTimes.push(performance.now() - start);
			}
		}

		// If there's a timing leak, existing users would be consistently faster or slower
		const minLength = Math.min(existingTimes.length, newUserTimes.length);
		const differences: number[] = [];

		for (let i = 0; i < minLength; i++) {
			differences.push((existingTimes[i] ?? 0) - (newUserTimes[i] ?? 0));
		}

		const meanDiff =
			differences.reduce((a, b) => a + b, 0) / differences.length;
		const stdDiff = Math.sqrt(
			differences.reduce((sum, d) => sum + (d - meanDiff) ** 2, 0) /
			differences.length,
		);

		console.log("\n=== Autocorrelation Test ===");
		console.log(`Mean difference (existing - new): ${meanDiff.toFixed(2)}ms`);
		console.log(`Std dev of differences: ${stdDiff.toFixed(2)}ms`);
		console.log(
			`Mean / Std dev ratio: ${Math.abs(meanDiff / stdDiff).toFixed(4)}`,
		);
		console.log(
			`Expected: ratio < 0.5 (differences are just noise, no systematic pattern)`,
		);

		// If there's a timing leak, mean difference would be large relative to std dev
		// Ratio < 0.5 means the timing differences are just random noise
		const ratio = Math.abs(meanDiff / stdDiff);
		expect(ratio).toBeLessThan(0.5);
	});
});
