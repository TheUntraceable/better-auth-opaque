import { ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
	createOpaqueTestInstance,
	type OpaqueTestInstance,
	password,
	uniqueEmail,
} from "./helpers";

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
