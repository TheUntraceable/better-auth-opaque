import { client as opaqueCrypto, ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
	createOpaqueTestInstance,
	type OpaqueTestInstance,
	uniqueEmail,
} from "./helpers";

// Deterministic checks on the enumeration defences. The statistical timing
// tests live in tests/timing and are opt-in (OPAQUE_TIMING_TESTS=1).

describe("enumeration defences", () => {
	let t: OpaqueTestInstance;
	const password = "supersecurepassword";

	beforeAll(async () => {
		await ready;
		t = await createOpaqueTestInstance({ timingSafeResponseMs: 100 });
	});
	afterAll(() => t.server.close());

	test("the sign-in challenge for a missing account is a real, well-formed challenge", async () => {
		const { startLoginRequest } = opaqueCrypto.startLogin({ password });
		const ghost = await t.client.$fetch<{ challenge: string; state: string }>(
			"/opaque/sign-in/challenge",
			{
				method: "POST",
				body: { email: uniqueEmail("ghost"), loginRequest: startLoginRequest },
			},
		);
		expect(ghost.error).toBeNull();
		expect(ghost.data?.challenge).toMatch(/^[A-Za-z0-9_-]{427}$/);
	});

	test("the same missing email always gets the same OPRF evaluation", async () => {
		// Reusing one blinded request must yield identical evaluations, as it
		// would for a real account; otherwise the fake path is distinguishable.
		const email = uniqueEmail("stable");
		const { startLoginRequest } = opaqueCrypto.startLogin({ password });
		const post = () =>
			t.client.$fetch<{ challenge: string }>("/opaque/sign-in/challenge", {
				method: "POST",
				body: { email, loginRequest: startLoginRequest },
			});
		const [a, b] = await Promise.all([post(), post()]);
		// The evaluated element is the first 32 bytes of the response. 42 base64url
		// chars cover 252 of those bits; the 43rd char already mixes in the random
		// masking nonce.
		expect(a.data?.challenge.slice(0, 42)).toBe(b.data?.challenge.slice(0, 42));
	});

	test("timingSafeResponseMs pads the existence-dependent endpoints", async () => {
		const { startLoginRequest } = opaqueCrypto.startLogin({ password });
		const started = performance.now();
		await t.client.$fetch("/opaque/sign-in/challenge", {
			method: "POST",
			body: { email: uniqueEmail("floor"), loginRequest: startLoginRequest },
		});
		expect(performance.now() - started).toBeGreaterThanOrEqual(95);
	});
});
