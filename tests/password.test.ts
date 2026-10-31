import { client as opaqueCrypto, ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test, vi } from "vitest";
import {
	createOpaqueTestInstance,
	errorCode,
	type OpaqueTestInstance,
	password,
	uniqueEmail,
	writeV2Record,
} from "./helpers";

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

	test("a 2.x account can change its password and leaves the email fallback", async () => {
		const email = uniqueEmail("legacy-change");
		await t.client.signUp.opaque({ email, name: "Legacy", password });
		const { exportKey, accountId } = await writeV2Record(t, email, password);
		const device = t.createSessionClient();
		await device.signIn.opaque({ email, password });

		const change = await device.opaque.changePassword({
			currentPassword: password,
			newPassword: "post-legacy-password",
		});
		expect(change.error).toBeNull();
		expect(change.data?.previousExportKey).toBe(exportKey);
		const { adapter } = await t.auth.$context;
		const account = await adapter.findOne<{ credentialId: string | null }>({
			model: "account",
			where: [{ field: "id", value: accountId }],
		});
		expect(account?.credentialId).toBeTruthy();
		const signIn = await t.client.signIn.opaque({
			email,
			password: "post-legacy-password",
		});
		expect(signIn.data?.exportKey).toBe(change.data?.exportKey);
	});

	test("setting the same password again still rotates the export key", async () => {
		const email = uniqueEmail("same");
		await t.client.signUp.opaque({ email, name: "Same", password });
		const device = t.createSessionClient();
		await device.signIn.opaque({ email, password });
		const change = await device.opaque.changePassword({
			currentPassword: password,
			newPassword: password,
		});
		expect(change.error).toBeNull();
		expect(change.data?.exportKey).not.toBe(change.data?.previousExportKey);
		const signIn = await t.client.signIn.opaque({ email, password });
		expect(signIn.data?.exportKey).toBe(change.data?.exportKey);
	});

	test("revokeOtherSessions: false keeps every session", async () => {
		const email = uniqueEmail("keep");
		await t.client.signUp.opaque({ email, name: "Keep", password });
		const device = t.createSessionClient();
		const otherDevice = t.createSessionClient();
		const login = await device.signIn.opaque({ email, password });
		await otherDevice.signIn.opaque({ email, password });
		const change = await device.opaque.changePassword({
			currentPassword: password,
			newPassword: "kept-sessions-password",
			revokeOtherSessions: false,
		});
		expect(change.error).toBeNull();
		expect(change.data?.token).toBe(login.data?.token);
		expect((await device.getSession()).data?.user.email).toBe(email);
		expect((await otherDevice.getSession()).data?.user.email).toBe(email);
	});

	test("rejects a change-password state submitted by another user", async () => {
		const [aliceEmail, malloryEmail] = [uniqueEmail("alice"), uniqueEmail("mallory")];
		const alice = t.createSessionClient();
		const mallory = t.createSessionClient();
		for (const [client, email] of [
			[alice, aliceEmail],
			[mallory, malloryEmail],
		] as const) {
			await t.client.signUp.opaque({ email, name: "User", password });
			await client.signIn.opaque({ email, password });
		}
		const challenge = await alice.$fetch<{ state: string }>(
			"/opaque/change-password/challenge",
			{
				method: "POST",
				body: {
					loginRequest: opaqueCrypto.startLogin({ password }).startLoginRequest,
					registrationRequest: opaqueCrypto.startRegistration({ password })
						.registrationRequest,
				},
			},
		);
		const stolen = await mallory.$fetch("/opaque/change-password/complete", {
			method: "POST",
			body: {
				loginResult: "A".repeat(86),
				registrationRecord: "A".repeat(256),
				state: challenge.data!.state,
			},
		});
		expect(stolen.error?.status).toBe(401);
		expect(errorCode(stolen)).toBe("USER_MISMATCH");
		expect((await t.client.signIn.opaque({ email: aliceEmail, password })).error).toBeNull();
	});

	test("change and set password refuse a server whose key does not match the pin", async () => {
		const email = uniqueEmail("pin-ops");
		await t.auth.api.signUpEmail({
			body: { email, name: "Pin", password: "core-password-123" },
		});
		const device = t.createSessionClient({ serverPublicKey: "nope" });
		await device.signIn.email({ email, password: "core-password-123" });

		const set = await device.opaque.setPassword({ password });
		expect(set.error?.code).toBe("SERVER_KEY_MISMATCH");

		// The pin is a client check, so a raw handshake still sets a password
		// for change-password to work against.
		const { clientRegistrationState, registrationRequest } =
			opaqueCrypto.startRegistration({ password });
		const challenge = await device.$fetch<{ challenge: string; state: string }>(
			"/opaque/set-password/challenge",
			{ method: "POST", body: { registrationRequest } },
		);
		const { registrationRecord } = opaqueCrypto.finishRegistration({
			clientRegistrationState,
			password,
			registrationResponse: challenge.data!.challenge,
		});
		await device.$fetch("/opaque/set-password/complete", {
			method: "POST",
			body: { registrationRecord, state: challenge.data!.state },
		});

		const change = await device.opaque.changePassword({
			currentPassword: password,
			newPassword: "never-applied-password",
		});
		expect(change.error?.code).toBe("SERVER_KEY_MISMATCH");
		expect((await t.client.signIn.opaque({ email, password })).error).toBeNull();
	});
});

describe("opaque: session freshness", () => {
	test("change and set password reject a session older than freshAge", async () => {
		await ready;
		const t = await createOpaqueTestInstance({}, { session: { freshAge: 60 } });
		try {
			const email = uniqueEmail("stale-session");
			await t.client.signUp.opaque({ email, name: "Stale", password });
			const device = t.createSessionClient();
			await device.signIn.opaque({ email, password });
			// Date only: faking timers would stall the in-process HTTP server.
			vi.setSystemTime(Date.now() + 120_000);

			const change = await device.opaque.changePassword({
				currentPassword: password,
				newPassword: "never-applied-password",
			});
			expect(change.error?.status).toBe(403);
			expect(change.error?.code).toBe("SESSION_NOT_FRESH");
			// Fails before the handler, which would answer OPAQUE_ACCOUNT_EXISTS.
			const set = await device.opaque.setPassword({ password });
			expect(set.error?.status).toBe(403);
			expect(set.error?.code).toBe("SESSION_NOT_FRESH");
		} finally {
			vi.useRealTimers();
			await t.server.close();
		}
	});
});
