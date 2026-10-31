import { ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
	createOpaqueTestInstance,
	type OpaqueTestInstance,
	password,
	uniqueEmail,
} from "./helpers";

describe.each(["sync", "async"] as const)("opaque: hooks that throw (%s)", (mode) => {
	let t: OpaqueTestInstance;
	const calls = { existingUser: 0, resetPassword: 0 };
	const sessionKeys: { sessionKey: string; token: string; email: string }[] = [];
	const fail = () => {
		if (mode === "sync") throw new Error("mailer down");
		return Promise.reject(new Error("mailer down"));
	};

	beforeAll(async () => {
		await ready;
		t = await createOpaqueTestInstance({
			onExistingUserSignUp: () => {
				calls.existingUser++;
				return fail();
			},
			sendResetPassword: () => {
				calls.resetPassword++;
				return fail();
			},
			onSessionKey: ({ user, session, sessionKey }) => {
				sessionKeys.push({ sessionKey, token: session.token, email: user.email });
				return fail();
			},
		});
	});
	afterAll(() => t.server.close());

	test("onSessionKey gets the key the client derived and cannot fail the sign-in", async () => {
		const email = uniqueEmail("session-key");
		await t.client.signUp.opaque({ email, name: "Keys", password });
		const signIn = await t.client.signIn.opaque({ email, password });
		expect(signIn.error).toBeNull();
		expect(sessionKeys).toEqual([
			{ sessionKey: signIn.data?.sessionKey, token: signIn.data?.token, email },
		]);
	});

	test("never change the response, so a failing mailer is not an existence oracle", async () => {
		const email = uniqueEmail("hooks");
		const fresh = await t.client.signUp.opaque({ email, name: "Hooks", password });
		expect(fresh.error).toBeNull();
		expect(fresh.data?.status).toBe(true);
		expect(calls.existingUser).toBe(0);

		const duplicate = await t.client.signUp.opaque({ email, name: "Hooks", password });
		expect(calls.existingUser).toBe(1);
		expect(duplicate.error).toBeNull();
		expect(duplicate.data?.status).toBe(fresh.data?.status);
		expect(duplicate.data?.token).toBe(fresh.data?.token);

		const known = await t.client.opaque.requestPasswordReset({ email });
		expect(calls.resetPassword).toBe(1);
		const unknown = await t.client.opaque.requestPasswordReset({
			email: uniqueEmail("nobody"),
		});
		expect(calls.resetPassword).toBe(1);
		expect(known.error).toBeNull();
		expect(unknown.error).toBeNull();
		expect(known.data).toEqual(unknown.data);
	});
});

describe("opaque: verification mailer that throws", () => {
	let t: OpaqueTestInstance;
	let calls = 0;

	beforeAll(async () => {
		await ready;
		t = await createOpaqueTestInstance(
			{ requireEmailVerification: true },
			{
				emailVerification: {
					sendOnSignUp: true,
					sendOnSignIn: true,
					sendVerificationEmail: () => {
						calls++;
						throw new Error("mailer down");
					},
				},
			},
		);
	});
	afterAll(() => t.server.close());

	test("does not change the sign-up or unverified sign-in response", async () => {
		const email = uniqueEmail("verify-throws");
		const signUp = await t.client.signUp.opaque({ email, name: "Verify", password });
		expect(signUp.error).toBeNull();
		expect(signUp.data?.status).toBe(true);
		expect(calls).toBe(1);

		const blocked = await t.client.signIn.opaque({ email, password });
		expect(blocked.error?.status).toBe(403);
		expect(blocked.error?.code).toBe("EMAIL_NOT_VERIFIED");
		expect(calls).toBe(2);
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

	test("an explicit sendOnSignUp: false wins over requireEmailVerification", async () => {
		const sent: { email: string; url: string }[] = [];
		const scoped = await createOpaqueTestInstance(
			{ requireEmailVerification: true },
			{
				emailVerification: {
					sendOnSignUp: false,
					sendOnSignIn: true,
					sendVerificationEmail: async ({ user, url }) => {
						sent.push({ email: user.email, url });
					},
				},
			},
		);
		try {
			const email = uniqueEmail("no-signup-mail");
			await scoped.client.signUp.opaque({ email, name: "Quiet", password });
			expect(sent).toHaveLength(0);

			const blocked = await scoped.client.signIn.opaque({
				email,
				password,
				callbackURL: "/welcome",
			});
			expect(blocked.error?.code).toBe("EMAIL_NOT_VERIFIED");
			expect(sent).toHaveLength(1);
			expect(sent[0]!.email).toBe(email);
			expect(sent[0]!.url).toContain(
				`callbackURL=${encodeURIComponent("/welcome")}`,
			);
		} finally {
			await scoped.server.close();
		}
	});
});
