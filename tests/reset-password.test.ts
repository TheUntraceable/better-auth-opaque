import { client as opaqueCrypto, ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test, vi } from "vitest";
import {
	createOpaqueTestInstance,
	errorCode,
	type OpaqueTestInstance,
	password,
	slowVerificationDeletes,
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

	test("the emailed link sends an unknown or expired token to ?error=INVALID_TOKEN", async () => {
		const email = uniqueEmail("reset-link");
		await t.client.signUp.opaque({ email, name: "Link", password });
		await t.client.opaque.requestPasswordReset({ email, redirectTo: "/reset" });
		const mail = sent.find((m) => m.email === email)!;
		const follow = async (url: string) =>
			new URL((await fetch(url, { redirect: "manual" })).headers.get("location")!);

		const unknown = await follow(mail.url.replace(mail.token, "not-a-real-token"));
		expect(unknown.pathname).toBe("/reset");
		expect(unknown.searchParams.get("error")).toBe("INVALID_TOKEN");
		expect(unknown.searchParams.has("token")).toBe(false);

		try {
			// Date only: faking timers would stall the in-process HTTP server.
			vi.setSystemTime(Date.now() + 2 * 60 * 60 * 1000);
			const expired = await follow(mail.url);
			expect(expired.searchParams.get("error")).toBe("INVALID_TOKEN");
			expect(expired.searchParams.has("token")).toBe(false);
		} finally {
			vi.useRealTimers();
		}
	});

	test("a sign-in challenge minted before a reset cannot complete afterwards", async () => {
		const email = uniqueEmail("reset-stale");
		await t.client.signUp.opaque({ email, name: "Stale", password });
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
		await t.client.opaque.requestPasswordReset({ email });
		const mail = sent.find((m) => m.email === email)!;
		const reset = await t.client.opaque.resetPassword({
			token: mail.token,
			newPassword: "post-reset-password",
		});
		expect(reset.error).toBeNull();

		const result = await t.client.$fetch("/opaque/sign-in/complete", {
			method: "POST",
			body: { loginResult: proof!.finishLoginRequest, state: stale.data!.state },
		});
		expect(result.error?.status).toBe(401);
		expect(errorCode(result)).toBe("INVALID_EMAIL_OR_PASSWORD");
	});

	test("refuses to reset against a server whose key does not match the pin", async () => {
		const email = uniqueEmail("reset-pin");
		await t.client.signUp.opaque({ email, name: "Pin", password });
		await t.client.opaque.requestPasswordReset({ email });
		const mail = sent.find((m) => m.email === email)!;
		const pinned = t.createSessionClient({ serverPublicKey: "nope" });
		const reset = await pinned.opaque.resetPassword({
			token: mail.token,
			newPassword: "never-applied-password",
		});
		expect(reset.error?.code).toBe("SERVER_KEY_MISMATCH");
		expect((await t.client.signIn.opaque({ email, password })).error).toBeNull();
	});

	test("notifies the session signal only when a reset succeeds", async () => {
		const tokens: string[] = [];
		const scoped = await createOpaqueTestInstance(
			{
				sendResetPassword: async ({ token }) => {
					tokens.push(token);
				},
			},
			slowVerificationDeletes,
		);
		let notified = 0;
		const unlisten = scoped.client.$store.atoms.$sessionSignal!.listen(() => {
			notified++;
		});
		try {
			const email = uniqueEmail("reset-signal");
			await scoped.client.signUp.opaque({ email, name: "Signal", password });
			await scoped.client.opaque.requestPasswordReset({ email });
			// The challenge does not consume the token, so both calls pass it and
			// the loser fails at complete, where the client decides to notify.
			const failedPaths: string[] = [];
			const results = await Promise.all(
				["signal-password-a", "signal-password-b"].map((newPassword) =>
					scoped.client.opaque.resetPassword(
						{ token: tokens[0]!, newPassword },
						{ onError: ({ request }) => void failedPaths.push(String(request.url)) },
					),
				),
			);
			expect(results.filter((r) => r.error === null)).toHaveLength(1);
			const failed = results.filter((r) => r.error !== null);
			expect(failed).toHaveLength(1);
			expect(failed[0]!.error?.code).toBe("INVALID_TOKEN");
			expect(failedPaths).toHaveLength(1);
			expect(failedPaths[0]).toMatch(/\/opaque\/reset-password\/complete$/);
			expect(notified).toBe(1);
		} finally {
			unlisten();
			await scoped.server.close();
		}
	});

	test("concurrent completes on one reset token let exactly one through", async () => {
		const tokens: string[] = [];
		const scoped = await createOpaqueTestInstance(
			{
				sendResetPassword: async ({ token }) => {
					tokens.push(token);
				},
			},
			slowVerificationDeletes,
		);
		try {
			const email = uniqueEmail("reset-race");
			await scoped.client.signUp.opaque({ email, name: "Race", password });
			await scoped.client.opaque.requestPasswordReset({ email });
			const token = tokens[0]!;
			const bodies = [];
			for (let i = 0; i < 4; i++) {
				const { clientRegistrationState, registrationRequest } =
					opaqueCrypto.startRegistration({ password: `race-password-${i}` });
				const challenge = await scoped.client.$fetch<{
					challenge: string;
					state: string;
				}>("/opaque/reset-password/challenge", {
					method: "POST",
					body: { token, registrationRequest },
				});
				const { registrationRecord } = opaqueCrypto.finishRegistration({
					clientRegistrationState,
					password: `race-password-${i}`,
					registrationResponse: challenge.data!.challenge,
				});
				bodies.push({ token, registrationRecord, state: challenge.data!.state });
			}
			const results = await Promise.all(
				bodies.map((body) =>
					scoped.client.$fetch<{ status: boolean }>(
						"/opaque/reset-password/complete",
						{ method: "POST", body },
					),
				),
			);
			const winner = results.findIndex((r) => r.data?.status);
			expect(results.filter((r) => r.data?.status)).toHaveLength(1);
			for (const r of results.filter((r) => !r.data?.status)) {
				expect(errorCode(r)).toBe("INVALID_TOKEN");
			}
			const signIn = await scoped.client.signIn.opaque({
				email,
				password: `race-password-${winner}`,
			});
			expect(signIn.error).toBeNull();
		} finally {
			await scoped.server.close();
		}
	});
});

describe("opaque: password reset without a mailer", () => {
	test("reports RESET_PASSWORD_NOT_CONFIGURED", async () => {
		await ready;
		const t = await createOpaqueTestInstance();
		try {
			const result = await t.client.opaque.requestPasswordReset({
				email: uniqueEmail("no-mailer"),
			});
			expect(result.error?.status).toBe(400);
			expect(result.error?.code).toBe("RESET_PASSWORD_NOT_CONFIGURED");
		} finally {
			await t.server.close();
		}
	});
});
