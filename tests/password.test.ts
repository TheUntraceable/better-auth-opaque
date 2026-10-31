import { client as opaqueCrypto, ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
	createOpaqueTestInstance,
	errorCode,
	type OpaqueTestInstance,
	password,
	uniqueEmail,
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
