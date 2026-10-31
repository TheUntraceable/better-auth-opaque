import { ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
	createOpaqueTestInstance,
	type OpaqueTestInstance,
	password,
	uniqueEmail,
} from "./helpers";

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
