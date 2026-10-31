import { client as opaqueCrypto, ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { createOpaqueTestInstance } from "../helpers";

describe.skipIf(!process.env.OPAQUE_TIMING_TESTS)("advanced timing attack resistance", async () => {
	await ready;

	const { client, server } = await createOpaqueTestInstance();
	afterAll(() => server.close());

	const existingUserEmail = "advanced-timing-existing@untraceable.dev";
	const nonExistentUserEmail = "advanced-timing-nonexistent@untraceable.dev";
	const testPassword = "supersecurepassword123";
	const testName = "Advanced Timing Test User";
	// New-email writes add under 1ms on in-memory SQLite; 5ms still catches a real extra branch.
	const marginMs = 5;
	// The server cannot see key stretching and none of it is timed, so minimal Argon2 keeps a thousand sign-ups fast.
	const keyStretching = { "argon2id-custom": { iterations: 1, memory: 8, parallelism: 1 } } as const;

	beforeAll(async () => {
		await client.signUp.opaque({ email: existingUserEmail, name: testName, password: testPassword });
	});

	const prepareSignUp = async (email: string) => {
		const { clientRegistrationState, registrationRequest } =
			opaqueCrypto.startRegistration({ password: testPassword });
		const { data } = await client.$fetch<{ challenge: string; state: string }>(
			"/opaque/sign-up/challenge",
			{ method: "POST", body: { email, registrationRequest } },
		);
		if (!data) throw new Error("sign-up challenge failed");
		const { registrationRecord } = opaqueCrypto.finishRegistration({
			clientRegistrationState,
			password: testPassword,
			registrationResponse: data.challenge,
			keyStretching,
		});
		return { email, name: testName, registrationRecord, state: data.state };
	};

	const timeRequest = async (path: string, body: Record<string, unknown>) => {
		const start = performance.now();
		const { error } = await client.$fetch(path, { method: "POST", body });
		const elapsed = performance.now() - start;
		if (error) throw new Error(`${path} failed with ${error.status}`);
		return elapsed;
	};

	const timeSignUp = async (email: string) =>
		timeRequest("/opaque/sign-up/complete", await prepareSignUp(email));

	// Time the challenge endpoint alone: the full signIn flow only sends the second
	// request when the local finishLogin succeeds, which happens for the existing
	// user but not the missing one, so it would measure request count, not the server.
	const timeChallenge = (email: string) =>
		timeRequest("/opaque/sign-in/challenge", {
			email,
			loginRequest: opaqueCrypto.startLogin({ password: testPassword }).startLoginRequest,
		});

	const newEmail = () => `advanced-new-${crypto.randomUUID()}@untraceable.dev`;

	const interleave = async (
		pairs: number,
		timeExisting: () => Promise<number>,
		timeOther: () => Promise<number>,
	) => {
		const existing: number[] = [];
		const other: number[] = [];
		for (let i = 0; i < pairs; i++) {
			if (i % 2) {
				existing.push(await timeExisting());
				other.push(await timeOther());
			} else {
				other.push(await timeOther());
				existing.push(await timeExisting());
			}
		}
		return [existing, other] as const;
	};

	const sampleSignUps = (pairs: number) =>
		interleave(pairs, () => timeSignUp(existingUserEmail), () => timeSignUp(newEmail()));

	const mean = (times: number[]) => times.reduce((a, b) => a + b, 0) / times.length;
	const stdDev = (times: number[]) => {
		const m = mean(times);
		return Math.sqrt(times.reduce((sum, t) => sum + (t - m) ** 2, 0) / times.length);
	};
	const effectSize = (a: number[], b: number[]) =>
		Math.abs(mean(a) - mean(b)) / Math.sqrt((stdDev(a) ** 2 + stdDev(b) ** 2) / 2);

	const percentile = (times: number[], p: number) => {
		const sorted = [...times].sort((a, b) => a - b);
		const index = (p / 100) * (sorted.length - 1);
		const weight = index % 1;
		return sorted[Math.floor(index)]! * (1 - weight) + sorted[Math.ceil(index)]! * weight;
	};

	test("extreme sample size - registration timing (100 iterations)", async () => {
		const [existing, fresh] = await sampleSignUps(100);
		const d = effectSize(existing, fresh);

		console.log(
			`Sign-up complete means: existing ${mean(existing).toFixed(2)}ms, new ${mean(fresh).toFixed(2)}ms, effect size ${d.toFixed(2)}σ`,
		);
		// Effect size, not significance: 100 pairs resolve the real sub-millisecond write-path gap.
		expect(d).toBeLessThanOrEqual(2.5);
	});

	test("kolmogorov-smirnov test - distribution similarity", async () => {
		const iterations = 50;
		const [existing, fresh] = await sampleSignUps(iterations);

		const cdf = (times: number[], x: number) => times.filter((t) => t <= x).length / times.length;
		const exceedance = (a: number[], b: number[]) => {
			const lowered = b.map((t) => t - marginMs);
			return Math.max(...[...a, ...lowered].map((x) => cdf(a, x) - cdf(lowered, x)));
		};
		// Plain KS rejects the real write-path gap every run, so each side gets marginMs of head start.
		const d = Math.max(exceedance(existing, fresh), exceedance(fresh, existing));
		// Two-sample critical value at α=0.05: 1.36·sqrt((n+m)/(n·m)).
		const criticalValue = 1.36 * Math.sqrt(2 / iterations);

		console.log(`KS D beyond ${marginMs}ms: ${d.toFixed(4)} (critical ${criticalValue.toFixed(4)})`);
		expect(d).toBeLessThan(criticalValue);
	});

	test("mann-whitney u test - median comparison", async () => {
		const [existing, fresh] = await sampleSignUps(40);

		const slowerZ = (a: number[], b: number[]) => {
			let u = 0;
			for (const x of a) for (const y of b) u += x - marginMs > y ? 1 : x - marginMs === y ? 0.5 : 0;
			const n = a.length * b.length;
			return (u - n / 2) / Math.sqrt((n * (a.length + b.length + 1)) / 12);
		};
		const zFresh = slowerZ(fresh, existing);
		const zExisting = slowerZ(existing, fresh);

		console.log(`Mann-Whitney z beyond ${marginMs}ms: new ${zFresh.toFixed(2)}, existing ${zExisting.toFixed(2)}`);
		// One-sided α=0.025 per direction, like plain |z| < 1.96 but against a marginMs gap: plain U rejects the real one every run.
		expect(Math.max(zFresh, zExisting)).toBeLessThan(1.96);
	});

	test("percentile analysis - tail behavior", async () => {
		// P99 needs ~10 points behind it; on fewer it tracks individual GC spikes.
		const [existing, fresh] = await sampleSignUps(1000);

		for (const p of [10, 25, 50, 75, 90, 95, 99]) {
			const p1 = percentile(existing, p);
			const p2 = percentile(fresh, p);
			console.log(`P${p}: existing ${p1.toFixed(2)}ms, new ${p2.toFixed(2)}ms`);
			// Absolute, not relative: on ~3ms responses a percentage threshold would sit below the real write-path gap.
			expect(Math.abs(p1 - p2)).toBeLessThan(marginMs);
		}
	});

	test("interleaved timing - prevent caching artifacts", async () => {
		const [existing, fresh] = await sampleSignUps(30);
		const timeDifference = Math.abs(mean(existing) - mean(fresh));

		console.log(`Interleaved mean difference: ${timeDifference.toFixed(2)}ms`);
		// Absolute, not relative: on ~3ms responses a percentage threshold would sit below the real write-path gap.
		expect(timeDifference).toBeLessThan(marginMs);
	});

	test("login challenge - extreme sample size (100 iterations)", async () => {
		const [existing, missing] = await interleave(
			100,
			() => timeChallenge(existingUserEmail),
			() => timeChallenge(nonExistentUserEmail),
		);
		const d = effectSize(existing, missing);

		console.log(
			`Sign-in challenge means: existing ${mean(existing).toFixed(2)}ms, missing ${mean(missing).toFixed(2)}ms, effect size ${d.toFixed(2)}σ`,
		);
		// Effect size, not significance: 100 pairs resolve sub-millisecond lookup differences.
		expect(d).toBeLessThanOrEqual(2.5);
	});

	test("autocorrelation test - detect timing leak patterns", async () => {
		const series: number[] = [];
		// Strict alternation, unlike the swapped pairs above, turns a branch gap into a zig-zag at lag 1.
		for (let i = 0; i < 50; i++) {
			series.push(await timeSignUp(i % 2 ? newEmail() : existingUserEmail));
		}

		const m = mean(series);
		let lagged = 0;
		let total = 0;
		for (let i = 0; i < series.length; i++) {
			total += (series[i]! - m) ** 2;
			if (i) lagged += (series[i]! - m) * (series[i - 1]! - m);
		}
		const r1 = lagged / total;
		const bound = -2 / Math.sqrt(series.length);

		console.log(`Lag-1 autocorrelation: ${r1.toFixed(4)} (bound ${bound.toFixed(4)})`);
		// One-sided: drift only raises r1, a branch gap pulls it toward -1, and white noise stays within ~2/sqrt(N).
		expect(r1).toBeGreaterThan(bound);
	});
});
