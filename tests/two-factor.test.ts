import { ready } from "@serenity-kit/opaque";
import type { BetterAuthPlugin } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
	createOpaqueTestInstance,
	type OpaqueTestInstance,
	password,
	uniqueEmail,
} from "./helpers";

const enableTwoFactor = async (t: OpaqueTestInstance, email: string) => {
	const { internalAdapter } = await t.auth.$context;
	const found = await internalAdapter.findUserByEmail(email);
	await internalAdapter.updateUser(found!.user.id, {
		twoFactorEnabled: true,
	} as never);
};

describe("opaque: with the twoFactor plugin", () => {
	let t: OpaqueTestInstance;
	const codes: string[] = [];

	beforeAll(async () => {
		await ready;
		t = await createOpaqueTestInstance(
			{},
			{
				plugins: [
					twoFactor({
						otpOptions: {
							sendOTP: ({ otp }) => {
								codes.push(otp);
							},
						},
					}),
				],
			},
		);
	});
	afterAll(() => t.server.close());

	test("a sign-in stops for the second factor and finishes once it is given", async () => {
		const email = uniqueEmail("two-factor");
		const signUp = await t.client.signUp.opaque({ email, name: "Two", password });
		await enableTwoFactor(t, email);

		const device = t.createSessionClient();
		const signIn = await device.signIn.opaque({ email, password });
		expect(signIn.error).toBeNull();
		expect(signIn.data).toMatchObject({ twoFactorRedirect: true });
		expect(signIn.data?.token).toBeUndefined();
		// The password was proved, so the keys are the client's to have.
		expect(signIn.data?.exportKey).toBe(signUp.data?.exportKey);
		expect((await device.getSession()).data).toBeNull();

		const sent = await device.$fetch("/two-factor/send-otp", {
			method: "POST",
			body: {},
		});
		expect(sent.error).toBeNull();
		const wrong = await device.$fetch("/two-factor/verify-otp", {
			method: "POST",
			body: { code: codes.at(-1) === "000000" ? "111111" : "000000" },
		});
		expect(wrong.error).not.toBeNull();
		expect((await device.getSession()).data).toBeNull();

		const verified = await device.$fetch("/two-factor/verify-otp", {
			method: "POST",
			body: { code: codes.at(-1) },
		});
		expect(verified.error).toBeNull();
		expect((await device.getSession()).data?.user.email).toBe(email);
	});

	test("a wrong password never reaches the second factor", async () => {
		const email = uniqueEmail("two-factor-wrong");
		await t.client.signUp.opaque({ email, name: "Two", password });
		await enableTwoFactor(t, email);
		const before = codes.length;

		const device = t.createSessionClient();
		const signIn = await device.signIn.opaque({
			email,
			password: "not-the-password",
		});
		expect(signIn.error?.code).toBe("INVALID_EMAIL_OR_PASSWORD");
		const sent = await device.$fetch("/two-factor/send-otp", {
			method: "POST",
			body: {},
		});
		expect(sent.error).not.toBeNull();
		expect(codes.length).toBe(before);
	});

	test("a user without two-factor signs in as usual", async () => {
		const email = uniqueEmail("one-factor");
		await t.client.signUp.opaque({ email, name: "One", password });
		const device = t.createSessionClient();
		const signIn = await device.signIn.opaque({ email, password });
		expect(signIn.error).toBeNull();
		expect(signIn.data?.token).toBeTruthy();
		expect((await device.getSession()).data?.user.email).toBe(email);
	});
});

describe("opaque: with a twoFactor plugin it cannot hook into", () => {
	test("refuses two-factor users instead of skipping the second factor", async () => {
		await ready;
		const warnings: string[] = [];
		// Same id and user field as the real plugin, without its sign-in hook.
		const hookless = {
			id: "two-factor",
			schema: {
				user: {
					fields: {
						twoFactorEnabled: {
							type: "boolean",
							required: false,
							defaultValue: false,
							input: false,
						},
					},
				},
			},
		} satisfies BetterAuthPlugin;
		const t = await createOpaqueTestInstance(
			{},
			{
				plugins: [hookless],
				logger: {
					level: "warn",
					log: (level, message) => {
						if (level === "warn") warnings.push(message);
					},
				},
			},
		);
		try {
			const email = uniqueEmail("hookless");
			await t.client.signUp.opaque({ email, name: "Hookless", password });
			expect(warnings).toEqual(
				expect.arrayContaining([expect.stringContaining("sign-in hook")]),
			);
			const open = t.createSessionClient();
			expect((await open.signIn.opaque({ email, password })).error).toBeNull();

			await enableTwoFactor(t, email);
			const device = t.createSessionClient();
			const signIn = await device.signIn.opaque({ email, password });
			expect(signIn.error).toMatchObject({
				code: "TWO_FACTOR_UNSUPPORTED",
				status: 403,
			});
			expect((await device.getSession()).data).toBeNull();
		} finally {
			await t.server.close();
		}
	});
});
