import {
	client as opaqueCrypto,
	server as opaqueServer,
	ready,
} from "@serenity-kit/opaque";
import { makeSignature } from "better-auth/crypto";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
	createOpaqueTestInstance,
	type OpaqueTestInstance,
	uniqueEmail,
} from "./helpers";
import { TEST_OPAQUE_SERVER_KEY } from "./test-key";

// Deterministic checks on the enumeration defences. The statistical timing
// tests live in tests/timing and are opt-in (OPAQUE_TIMING_TESTS=1).

// The evaluated element is the first 32 bytes of the response. 42 base64url
// chars cover 252 of those bits; the 43rd char already mixes in the random
// masking nonce.
const evaluation = (challenge: string | undefined) => challenge?.slice(0, 42);

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
		expect(evaluation(a.data?.challenge)).toBe(evaluation(b.data?.challenge));
	});

	test("emails without an OPAQUE record are evaluated under the setup-keyed fake id", async () => {
		const coreOnly = uniqueEmail("core-only");
		await t.auth.api.signUpEmail({
			body: { email: coreOnly, name: "Core", password: "core-password-123" },
		});
		const { startLoginRequest } = opaqueCrypto.startLogin({ password });
		for (const email of [coreOnly, uniqueEmail("nobody")]) {
			const response = await t.client.$fetch<{ challenge: string }>(
				"/opaque/sign-in/challenge",
				{ method: "POST", body: { email, loginRequest: startLoginRequest } },
			);
			// Computed without the auth secret, so rotating it cannot move these.
			const expected = opaqueServer.startLogin({
				serverSetup: TEST_OPAQUE_SERVER_KEY,
				userIdentifier: await makeSignature(
					`better-auth-opaque:fake-credential:${email}`,
					TEST_OPAQUE_SERVER_KEY,
				),
				registrationRecord: null,
				startLoginRequest,
			}).loginResponse;
			expect(evaluation(response.data?.challenge)).toBe(evaluation(expected));
		}
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
