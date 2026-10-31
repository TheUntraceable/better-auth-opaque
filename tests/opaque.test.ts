import { client as opaqueCrypto, ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test, vi } from "vitest";
import {
	createOpaqueTestInstance,
	errorCode,
	type OpaqueTestInstance,
	uniqueEmail,
} from "./helpers";

const password = "supersecurepassword";

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

describe("opaque: authenticated password operations", () => {
	let t: OpaqueTestInstance;

	beforeAll(async () => {
		await ready;
		t = await createOpaqueTestInstance();
	});
	afterAll(() => t.server.close());

	test("changes the password, rotates keys, and revokes other sessions", async () => {
		const email = uniqueEmail("change");
		const newPassword = "brandNewPassword789";
		await t.client.signUp.opaque({ email, name: "Change", password });

		const device = t.createSessionClient();
		const otherDevice = t.createSessionClient();
		const login = await device.signIn.opaque({ email, password });
		await otherDevice.signIn.opaque({ email, password });
		expect((await otherDevice.getSession()).data?.user.email).toBe(email);

		const change = await device.opaque.changePassword({
			currentPassword: password,
			newPassword,
		});
		expect(change.error).toBeNull();
		expect(change.data?.token).toBeTruthy();
		expect(change.data?.token).not.toBe(login.data?.token);
		expect(change.data?.previousExportKey).toBe(login.data?.exportKey);
		expect(change.data?.exportKey).not.toBe(login.data?.exportKey);

		// Current device stays logged in, the other one is out.
		expect((await device.getSession()).data?.user.email).toBe(email);
		expect((await otherDevice.getSession()).data).toBeNull();

		expect(
			(await t.client.signIn.opaque({ email, password })).error?.code,
		).toBe("INVALID_EMAIL_OR_PASSWORD");
		const fresh = await t.client.signIn.opaque({ email, password: newPassword });
		expect(fresh.error).toBeNull();
		expect(fresh.data?.exportKey).toBe(change.data?.exportKey);
	});

	test("refuses to change the password without the current one", async () => {
		const email = uniqueEmail("change-wrong");
		await t.client.signUp.opaque({ email, name: "ChangeWrong", password });
		const device = t.createSessionClient();
		await device.signIn.opaque({ email, password });
		const change = await device.opaque.changePassword({
			currentPassword: "not-the-password",
			newPassword: "whatever-whatever",
		});
		expect(change.data).toBeNull();
		expect(change.error?.code).toBe("INVALID_PASSWORD");
		expect((await t.client.signIn.opaque({ email, password })).error).toBeNull();
	});

	test("a challenge minted before a password change cannot complete afterwards", async () => {
		const email = uniqueEmail("stale");
		await t.client.signUp.opaque({ email, name: "Stale", password });
		const device = t.createSessionClient();
		await device.signIn.opaque({ email, password });

		const { clientLoginState, startLoginRequest } = opaqueCrypto.startLogin({
			password,
		});
		const stale = await t.client.$fetch<{ challenge: string; state: string }>(
			"/opaque/sign-in/challenge",
			{ method: "POST", body: { email, loginRequest: startLoginRequest } },
		);
		const proof = opaqueCrypto.finishLogin({
			clientLoginState,
			loginResponse: stale.data!.challenge,
			password,
		});
		await device.opaque.changePassword({
			currentPassword: password,
			newPassword: "rotated-rotated",
		});
		const result = await t.client.$fetch("/opaque/sign-in/complete", {
			method: "POST",
			body: { loginResult: proof!.finishLoginRequest, state: stale.data!.state },
		});
		expect(result.error?.status).toBe(401);
	});

	test("rejects a state minted for another flow", async () => {
		const email = uniqueEmail("cross");
		await t.client.signUp.opaque({ email, name: "Cross", password });
		const device = t.createSessionClient();
		await device.signIn.opaque({ email, password });

		const { clientLoginState, startLoginRequest } = opaqueCrypto.startLogin({
			password,
		});
		const { registrationRequest } = opaqueCrypto.startRegistration({ password });
		const challenge = await device.$fetch<{
			loginChallenge: string;
			state: string;
		}>("/opaque/change-password/challenge", {
			method: "POST",
			body: { loginRequest: startLoginRequest, registrationRequest },
		});
		const proof = opaqueCrypto.finishLogin({
			clientLoginState,
			loginResponse: challenge.data!.loginChallenge,
			password,
		});
		const crossed = await device.$fetch("/opaque/sign-in/complete", {
			method: "POST",
			body: { loginResult: proof!.finishLoginRequest, state: challenge.data!.state },
		});
		expect(crossed.error?.status).toBe(400);
		expect(errorCode(crossed)).toBe("INVALID_LOGIN_STATE");
	});

	test("sets an OPAQUE password on an account that has none", async () => {
		const email = uniqueEmail("social");
		// Stand-in for a social-login user: created with core email/password.
		await t.auth.api.signUpEmail({
			body: { email, name: "Social", password: "core-password-123" },
		});
		const device = t.createSessionClient();
		await device.signIn.email({ email, password: "core-password-123" });

		const noAccount = await device.opaque.changePassword({
			currentPassword: "x",
			newPassword: "y",
		});
		expect(noAccount.error?.code).toBe("NO_OPAQUE_ACCOUNT");

		const set = await device.opaque.setPassword({ password });
		expect(set.error).toBeNull();
		expect(set.data?.exportKey).toHaveLength(86);

		const signIn = await t.client.signIn.opaque({ email, password });
		expect(signIn.error).toBeNull();
		expect(signIn.data?.exportKey).toBe(set.data?.exportKey);

		const again = await device.opaque.setPassword({ password: "another" });
		expect(again.error?.code).toBe("OPAQUE_ACCOUNT_EXISTS");
	});

	test("never returns the registration record through list-accounts", async () => {
		const email = uniqueEmail("leak");
		await t.client.signUp.opaque({ email, name: "Leak", password });
		const device = t.createSessionClient();
		await device.signIn.opaque({ email, password });
		const accounts = await device.listAccounts();
		const opaqueAccount = accounts.data?.find((a) => a.providerId === "opaque");
		expect(opaqueAccount).toBeDefined();
		expect(JSON.stringify(accounts.data)).not.toContain("registrationRecord");
		expect(JSON.stringify(accounts.data)).not.toContain("credentialId");
	});
});

describe("opaque: password reset", () => {
	let t: OpaqueTestInstance;
	const sent: { email: string; token: string; url: string }[] = [];

	beforeAll(async () => {
		await ready;
		t = await createOpaqueTestInstance({
			sendResetPassword: async ({ user, token, url }) => {
				sent.push({ email: user.email, token, url });
			},
		});
	});
	afterAll(() => t.server.close());

	test("resets the password with an emailed token and revokes sessions", async () => {
		const email = uniqueEmail("reset");
		await t.client.signUp.opaque({ email, name: "Reset", password });
		const device = t.createSessionClient();
		await device.signIn.opaque({ email, password });

		const request = await t.client.opaque.requestPasswordReset({
			email,
			redirectTo: "/reset",
		});
		expect(request.error).toBeNull();
		const mail = sent.find((m) => m.email === email);
		expect(mail).toBeDefined();
		expect(mail!.url).toContain(`/opaque/reset-password/${mail!.token}`);

		const redirect = await fetch(mail!.url, { redirect: "manual" });
		expect(redirect.status).toBeGreaterThanOrEqual(300);
		expect(redirect.headers.get("location")).toContain(`token=${mail!.token}`);

		const reset = await t.client.opaque.resetPassword({
			token: mail!.token,
			newPassword: "after-reset-password",
		});
		expect(reset.error).toBeNull();
		expect(reset.data?.exportKey).toHaveLength(86);

		expect((await device.getSession()).data).toBeNull();
		expect(
			(await t.client.signIn.opaque({ email, password })).error?.code,
		).toBe("INVALID_EMAIL_OR_PASSWORD");
		const fresh = await t.client.signIn.opaque({
			email,
			password: "after-reset-password",
		});
		expect(fresh.error).toBeNull();
		expect(fresh.data?.exportKey).toBe(reset.data?.exportKey);

		const reuse = await t.client.opaque.resetPassword({
			token: mail!.token,
			newPassword: "third-password-xx",
		});
		expect(reuse.error?.code).toBe("INVALID_TOKEN");
	});

	test("responds identically for unknown emails", async () => {
		const before = sent.length;
		const result = await t.client.opaque.requestPasswordReset({
			email: uniqueEmail("nobody"),
		});
		expect(result.error).toBeNull();
		expect(result.data?.status).toBe(true);
		expect(sent.length).toBe(before);
	});

	test("rejects an unknown token", async () => {
		const result = await t.client.opaque.resetPassword({
			token: "not-a-real-token",
			newPassword: "whatever-whatever",
		});
		expect(result.error?.code).toBe("INVALID_TOKEN");
	});
});

describe("opaque: hooks that throw", () => {
	let t: OpaqueTestInstance;

	beforeAll(async () => {
		await ready;
		t = await createOpaqueTestInstance({
			onExistingUserSignUp: () => {
				throw new Error("mailer down");
			},
			sendResetPassword: async () => {
				throw new Error("mailer down");
			},
		});
	});
	afterAll(() => t.server.close());

	test("never change the response, so a failing mailer is not an existence oracle", async () => {
		const email = uniqueEmail("hooks");
		expect((await t.client.signUp.opaque({ email, name: "Hooks", password })).error).toBeNull();

		const duplicate = await t.client.signUp.opaque({ email, name: "Hooks", password });
		expect(duplicate.error).toBeNull();
		expect(duplicate.data?.status).toBe(true);

		const known = await t.client.opaque.requestPasswordReset({ email });
		const unknown = await t.client.opaque.requestPasswordReset({
			email: uniqueEmail("nobody"),
		});
		expect(known.error).toBeNull();
		expect(unknown.error).toBeNull();
		expect(known.data).toEqual(unknown.data);
	});
});

describe("opaque: email verification", () => {
	let t: OpaqueTestInstance;
	const verificationEmails: { email: string; url: string }[] = [];

	beforeAll(async () => {
		await ready;
		t = await createOpaqueTestInstance(
			{ requireEmailVerification: true },
			{
				emailVerification: {
					sendOnSignUp: true,
					sendVerificationEmail: async ({ user, url }) => {
						verificationEmails.push({ email: user.email, url });
					},
				},
			},
		);
	});
	afterAll(() => t.server.close());

	test("sends a verification email on sign-up and blocks sign-in until verified", async () => {
		const email = uniqueEmail("verify");
		await t.client.signUp.opaque({ email, name: "Verify", password });
		const mail = verificationEmails.find((m) => m.email === email);
		expect(mail).toBeDefined();

		const blocked = await t.client.signIn.opaque({ email, password });
		expect(blocked.error?.status).toBe(403);
		expect(blocked.error?.code).toBe("EMAIL_NOT_VERIFIED");

		await fetch(mail!.url, { redirect: "manual" });
		const allowed = await t.client.signIn.opaque({ email, password });
		expect(allowed.error).toBeNull();
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
