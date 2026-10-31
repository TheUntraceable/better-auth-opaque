import { client as opaqueCrypto, ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test, vi } from "vitest";
import {
	createOpaqueTestInstance,
	errorCode,
	type OpaqueTestInstance,
	password,
	uniqueEmail,
} from "./helpers";

describe("opaque: sign-up and sign-in", () => {
	let t: OpaqueTestInstance;
	const onExistingUserSignUp = vi.fn();

	beforeAll(async () => {
		await ready;
		t = await createOpaqueTestInstance({ onExistingUserSignUp });
	});
	afterAll(() => t.server.close());

	test("registers, logs in, and hands the client its export and session keys", async () => {
		const email = uniqueEmail("basic");
		const signUp = await t.client.signUp.opaque({ email, name: "Basic", password });
		expect(signUp.error).toBeNull();
		expect(signUp.data?.status).toBe(true);
		expect(signUp.data?.token).toBeNull();
		expect(signUp.data?.exportKey).toHaveLength(86);

		const signIn = await t.client.signIn.opaque({ email, password });
		expect(signIn.error).toBeNull();
		expect(signIn.data?.token).toBeTruthy();
		expect(signIn.data?.user.email).toBe(email);
		expect(signIn.data?.sessionKey).toHaveLength(86);
		// The export key is a stable function of the password and record.
		expect(signIn.data?.exportKey).toBe(signUp.data?.exportKey);

		const again = await t.client.signIn.opaque({ email, password });
		expect(again.data?.exportKey).toBe(signUp.data?.exportKey);
		expect(again.data?.sessionKey).not.toBe(signIn.data?.sessionKey);
	});

	test("rejects a wrong password on the client without a server round trip", async () => {
		const email = uniqueEmail("wrong");
		await t.client.signUp.opaque({ email, name: "Wrong", password });
		const result = await t.client.signIn.opaque({ email, password: "nope-nope-nope" });
		expect(result.data).toBeNull();
		expect(result.error?.code).toBe("INVALID_EMAIL_OR_PASSWORD");
		expect(result.error?.status).toBe(401);
	});

	test("non-existent and existing accounts get identical challenge shapes and errors", async () => {
		const email = uniqueEmail("exists");
		await t.client.signUp.opaque({ email, name: "Exists", password });
		const { startLoginRequest } = opaqueCrypto.startLogin({ password });

		const real = await t.client.$fetch<{ challenge: string; state: string }>(
			"/opaque/sign-in/challenge",
			{ method: "POST", body: { email, loginRequest: startLoginRequest } },
		);
		const fake = await t.client.$fetch<{ challenge: string; state: string }>(
			"/opaque/sign-in/challenge",
			{
				method: "POST",
				body: { email: uniqueEmail("ghost"), loginRequest: startLoginRequest },
			},
		);
		expect(real.data?.challenge).toHaveLength(fake.data!.challenge.length);
		expect(real.data?.state).toHaveLength(fake.data!.state.length);

		const missing = await t.client.signIn.opaque({
			email: uniqueEmail("ghost"),
			password,
		});
		expect(missing.error?.code).toBe("INVALID_EMAIL_OR_PASSWORD");
	});

	test("a forged proof is an auth failure, not a server error", async () => {
		const email = uniqueEmail("forged");
		await t.client.signUp.opaque({ email, name: "Forged", password });
		const { startLoginRequest } = opaqueCrypto.startLogin({ password });
		const challenge = await t.client.$fetch<{ challenge: string; state: string }>(
			"/opaque/sign-in/challenge",
			{ method: "POST", body: { email, loginRequest: startLoginRequest } },
		);
		const garbage = "A".repeat(86);
		const result = await t.client.$fetch("/opaque/sign-in/complete", {
			method: "POST",
			body: { loginResult: garbage, state: challenge.data!.state },
		});
		expect(result.error?.status).toBe(401);
		expect(errorCode(result)).toBe("INVALID_EMAIL_OR_PASSWORD");
	});

	test("email casing does not matter", async () => {
		const email = `Case-${crypto.randomUUID()}@Untraceable.DEV`;
		await t.client.signUp.opaque({ email, name: "Case", password });
		const lower = await t.client.signIn.opaque({
			email: email.toLowerCase(),
			password,
		});
		expect(lower.error).toBeNull();
		const upper = await t.client.signIn.opaque({
			email: email.toUpperCase(),
			password,
		});
		expect(upper.error).toBeNull();
	});

	test("re-registering an existing email looks like success but changes nothing", async () => {
		const email = uniqueEmail("dupe");
		await t.client.signUp.opaque({ email, name: "Dupe", password });
		onExistingUserSignUp.mockClear();

		const second = await t.client.signUp.opaque({
			email,
			name: "Impostor",
			password: "a-different-password",
		});
		expect(second.error).toBeNull();
		expect(second.data?.status).toBe(true);
		expect(onExistingUserSignUp).toHaveBeenCalledTimes(1);
		expect(onExistingUserSignUp.mock.calls[0]?.[0]?.user?.email).toBe(email);

		expect((await t.client.signIn.opaque({ email, password })).error).toBeNull();
		expect(
			(await t.client.signIn.opaque({ email, password: "a-different-password" }))
				.error?.code,
		).toBe("INVALID_EMAIL_OR_PASSWORD");
	});

	test("a login state can be used exactly once", async () => {
		const email = uniqueEmail("replay");
		await t.client.signUp.opaque({ email, name: "Replay", password });
		const { clientLoginState, startLoginRequest } = opaqueCrypto.startLogin({
			password,
		});
		const challenge = await t.client.$fetch<{ challenge: string; state: string }>(
			"/opaque/sign-in/challenge",
			{ method: "POST", body: { email, loginRequest: startLoginRequest } },
		);
		const login = opaqueCrypto.finishLogin({
			clientLoginState,
			loginResponse: challenge.data!.challenge,
			password,
		});
		const body = {
			loginResult: login!.finishLoginRequest,
			state: challenge.data!.state,
		};
		const first = await t.client.$fetch<{ token: string }>(
			"/opaque/sign-in/complete",
			{ method: "POST", body },
		);
		expect(first.data?.token).toBeTruthy();
		const replay = await t.client.$fetch("/opaque/sign-in/complete", {
			method: "POST",
			body,
		});
		expect(replay.error?.status).toBe(400);
		expect(errorCode(replay)).toBe("INVALID_LOGIN_STATE");
	});

	test("a sign-up state can be used exactly once", async () => {
		const email = uniqueEmail("signup-replay");
		const { clientRegistrationState, registrationRequest } =
			opaqueCrypto.startRegistration({ password });
		const challenge = await t.client.$fetch<{ challenge: string; state: string }>(
			"/opaque/sign-up/challenge",
			{ method: "POST", body: { email, registrationRequest } },
		);
		const { registrationRecord } = opaqueCrypto.finishRegistration({
			clientRegistrationState,
			password,
			registrationResponse: challenge.data!.challenge,
		});
		const body = { email, name: "Replay", registrationRecord, state: challenge.data!.state };
		const first = await t.client.$fetch<{ status: boolean }>(
			"/opaque/sign-up/complete",
			{ method: "POST", body },
		);
		expect(first.data?.status).toBe(true);
		const replay = await t.client.$fetch("/opaque/sign-up/complete", {
			method: "POST",
			body,
		});
		expect(replay.error?.status).toBe(400);
		expect(errorCode(replay)).toBe("INVALID_LOGIN_STATE");
	});

	test("concurrent completes with the same state yield at most one session", async () => {
		const email = uniqueEmail("race");
		await t.client.signUp.opaque({ email, name: "Race", password });
		const { clientLoginState, startLoginRequest } = opaqueCrypto.startLogin({
			password,
		});
		const challenge = await t.client.$fetch<{ challenge: string; state: string }>(
			"/opaque/sign-in/challenge",
			{ method: "POST", body: { email, loginRequest: startLoginRequest } },
		);
		const login = opaqueCrypto.finishLogin({
			clientLoginState,
			loginResponse: challenge.data!.challenge,
			password,
		});
		const body = {
			loginResult: login!.finishLoginRequest,
			state: challenge.data!.state,
		};
		const results = await Promise.all(
			Array.from({ length: 4 }, () =>
				t.client.$fetch<{ token: string }>("/opaque/sign-in/complete", {
					method: "POST",
					body,
				}),
			),
		);
		const sessions = results.filter((r) => r.data?.token);
		expect(sessions).toHaveLength(1);
		for (const r of results.filter((r) => !r.data?.token)) {
			expect(errorCode(r)).toBe("INVALID_LOGIN_STATE");
		}
	});

	test("rejects a malformed registration record before storing it", async () => {
		const email = uniqueEmail("badrecord");
		const { registrationRequest } = opaqueCrypto.startRegistration({ password });
		const challenge = await t.client.$fetch<{ challenge: string; state: string }>(
			"/opaque/sign-up/challenge",
			{ method: "POST", body: { email, registrationRequest } },
		);
		const result = await t.client.$fetch("/opaque/sign-up/complete", {
			method: "POST",
			body: {
				email,
				name: "Bad",
				registrationRecord: "A".repeat(256),
				state: challenge.data!.state,
			},
		});
		expect(result.error?.status).toBe(400);
		expect(errorCode(result)).toBe("INVALID_REGISTRATION_RECORD");
	});

	test("rememberMe: false issues a session-only cookie", async () => {
		const email = uniqueEmail("remember");
		await t.client.signUp.opaque({ email, name: "Remember", password });
		const { clientLoginState, startLoginRequest } = opaqueCrypto.startLogin({
			password,
		});
		const challenge = await t.client.$fetch<{ challenge: string; state: string }>(
			"/opaque/sign-in/challenge",
			{ method: "POST", body: { email, loginRequest: startLoginRequest } },
		);
		const login = opaqueCrypto.finishLogin({
			clientLoginState,
			loginResponse: challenge.data!.challenge,
			password,
		});
		let setCookies: string[] = [];
		const result = await t.client.$fetch("/opaque/sign-in/complete", {
			method: "POST",
			body: {
				loginResult: login!.finishLoginRequest,
				state: challenge.data!.state,
				rememberMe: false,
			},
			onResponse(context) {
				setCookies = context.response.headers.getSetCookie();
			},
		});
		expect(result.error).toBeNull();
		expect(setCookies.join("\n")).toContain("dont_remember");
	});

	test("forwards fetchOptions to every request of a flow", async () => {
		const email = uniqueEmail("fetchopts");
		await t.client.signUp.opaque({ email, name: "Fetch", password });
		const seen: string[] = [];
		const signIn = await t.client.signIn.opaque(
			{ email, password },
			{
				headers: { "x-opaque-test": "1" },
				onResponse: ({ response }) => {
					seen.push(new URL(response.url).pathname);
				},
			},
		);
		expect(signIn.error).toBeNull();
		expect(seen).toEqual([
			"/api/auth/opaque/sign-in/challenge",
			"/api/auth/opaque/sign-in/complete",
		]);
	});

	test("accepts additional user fields on sign-up", async () => {
		const scoped = await createOpaqueTestInstance(
			{},
			{
				user: {
					additionalFields: {
						nickname: { type: "string", required: false },
					},
				},
			},
		);
		try {
			const email = uniqueEmail("fields");
			await scoped.client.signUp.opaque({
				email,
				name: "Fields",
				password,
				nickname: "fieldsy",
			});
			const signIn = await scoped.client.signIn.opaque({ email, password });
			expect((signIn.data?.user as { nickname?: string }).nickname).toBe("fieldsy");
		} finally {
			await scoped.server.close();
		}
	});

});

describe("opaque: pinned server key", () => {
	test("refuses to talk to a server whose key does not match the pin", async () => {
		const t = await createOpaqueTestInstance({}, {}, { serverPublicKey: "nope" });
		try {
			const result = await t.client.signUp.opaque({
				email: uniqueEmail("pin"),
				name: "Pin",
				password,
			});
			expect(result.error?.code).toBe("SERVER_KEY_MISMATCH");
		} finally {
			await t.server.close();
		}
	});

	test("accepts a server whose key matches the pin", async () => {
		const { TEST_OPAQUE_PUBLIC_KEY } = await import("./helpers");
		const t = await createOpaqueTestInstance(
			{},
			{},
			{ serverPublicKey: TEST_OPAQUE_PUBLIC_KEY() },
		);
		try {
			const email = uniqueEmail("pin-ok");
			const signUp = await t.client.signUp.opaque({ email, name: "Pin", password });
			expect(signUp.error).toBeNull();
			expect(signUp.data?.serverPublicKey).toBe(TEST_OPAQUE_PUBLIC_KEY());
			const signIn = await t.client.signIn.opaque({ email, password });
			expect(signIn.error).toBeNull();
		} finally {
			await t.server.close();
		}
	});
});
