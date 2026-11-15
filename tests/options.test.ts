import { client as opaqueCrypto, ready } from "@serenity-kit/opaque";
import { beforeAll, describe, expect, test, vi } from "vitest";
import { opaque } from "../src/server";
import {
	createOpaqueTestInstance,
	password,
	TEST_OPAQUE_PUBLIC_KEY,
	uniqueEmail,
} from "./helpers";
import { TEST_OPAQUE_SERVER_KEY } from "./test-key";

// init only reads these two fields of the auth context.
const initContext = () => ({ logger: { warn: vi.fn() }, options: {} });

beforeAll(async () => {
	await ready;
});

describe("opaque: server setup", () => {
	test("still accepts the deprecated OPAQUE_SERVER_KEY name", async () => {
		const t = await createOpaqueTestInstance(
			{ serverSetup: undefined, OPAQUE_SERVER_KEY: TEST_OPAQUE_SERVER_KEY },
			{},
			{ serverPublicKey: TEST_OPAQUE_PUBLIC_KEY() },
		);
		try {
			const signUp = await t.client.signUp.opaque({
				email: uniqueEmail("alias"),
				name: "Alias",
				password,
			});
			expect(signUp.error).toBeNull();
			expect(signUp.data?.serverPublicKey).toBe(TEST_OPAQUE_PUBLIC_KEY());
		} finally {
			await t.server.close();
		}
	});

	test("generates a working temporary key when NODE_ENV is test", async () => {
		const warnings: string[] = [];
		const t = await createOpaqueTestInstance(
			{ serverSetup: undefined },
			{
				logger: {
					level: "warn",
					log: (level, message) => {
						if (level === "warn") warnings.push(message);
					},
				},
			},
		);
		try {
			const email = uniqueEmail("temporary");
			const signUp = await t.client.signUp.opaque({
				email,
				name: "Temporary",
				password,
			});
			// Creating the instance does not wait for plugin init; serving a
			// request does.
			expect(warnings).toEqual(
				expect.arrayContaining([expect.stringContaining("temporary key")]),
			);
			expect(signUp.error).toBeNull();
			expect(signUp.data?.serverPublicKey).not.toBe(TEST_OPAQUE_PUBLIC_KEY());
			const signIn = await t.client.signIn.opaque({ email, password });
			expect(signIn.error).toBeNull();
			expect(signIn.data?.token).toBeTruthy();
			expect(signIn.data?.exportKey).toBe(signUp.data?.exportKey);
		} finally {
			await t.server.close();
		}
	});

	test("refuses to start without a key outside development and test", async () => {
		// better-auth reads NODE_ENV once at import, so swap the helpers instead.
		vi.resetModules();
		vi.doMock("better-auth", async (importOriginal) => ({
			...(await importOriginal<typeof import("better-auth")>()),
			isDevelopment: () => false,
			isTest: () => false,
		}));
		try {
			const { opaque: isolated } = await import("../src/server");
			await expect(isolated().init(initContext() as never)).rejects.toThrow(
				"serverSetup is required unless NODE_ENV is development or test",
			);
			await expect(
				isolated({ serverSetup: TEST_OPAQUE_SERVER_KEY }).init(
					initContext() as never,
				),
			).resolves.toBeUndefined();
		} finally {
			vi.doUnmock("better-auth");
			vi.resetModules();
		}
	});

	test("rejects a key that is not a server setup", async () => {
		await expect(
			opaque({ serverSetup: "not-a-setup" }).init(initContext() as never),
		).rejects.toThrow("not a valid OPAQUE server setup");
	});
});

describe("opaque: rate limits", () => {
	const ruleFor = (plugin: ReturnType<typeof opaque>, path: string) => {
		const rule = plugin.rateLimit.find((r) => r.pathMatcher(path));
		return rule && { window: rule.window, max: rule.max };
	};
	const flows = [
		"sign-up",
		"sign-in",
		"change-password",
		"set-password",
		"reset-password",
	];

	test("are tighter for the reset request and every challenge", () => {
		const plugin = opaque();
		expect(ruleFor(plugin, "/opaque/reset-password/request")).toEqual({
			window: 60,
			max: 3,
		});
		for (const flow of flows) {
			expect(ruleFor(plugin, `/opaque/${flow}/challenge`)).toEqual({
				window: 10,
				max: 3,
			});
			expect(ruleFor(plugin, `/opaque/${flow}/complete`)).toEqual({
				window: 10,
				max: 5,
			});
		}
		expect(ruleFor(plugin, "/opaque/reset-password/some-token")).toEqual({
			window: 10,
			max: 5,
		});
		expect(ruleFor(plugin, "/sign-in/email")).toBeUndefined();
	});

	test("the rateLimit option replaces every default", () => {
		const plugin = opaque({ rateLimit: { window: 30, max: 7 } });
		for (const path of [
			"/opaque/reset-password/request",
			"/opaque/sign-in/challenge",
			"/opaque/sign-in/complete",
		]) {
			expect(ruleFor(plugin, path)).toEqual({ window: 30, max: 7 });
		}
	});

	test("are enforced over HTTP", async () => {
		const t = await createOpaqueTestInstance({}, { rateLimit: { enabled: true } });
		try {
			const statuses: number[] = [];
			for (let i = 0; i < 4; i++) {
				const result = await t.client.$fetch("/opaque/sign-in/challenge", {
					method: "POST",
					body: {
						email: uniqueEmail("limited"),
						loginRequest: opaqueCrypto.startLogin({ password }).startLoginRequest,
					},
				});
				statuses.push(result.error?.status ?? 200);
			}
			expect(statuses).toEqual([200, 200, 200, 429]);
		} finally {
			await t.server.close();
		}
	});
});

describe("opaque: insecureCreateSessionOnRegister", () => {
	test("signs a new user in when verification is not required", async () => {
		const t = await createOpaqueTestInstance({
			insecureCreateSessionOnRegister: true,
		});
		try {
			const email = uniqueEmail("insecure");
			const device = t.createSessionClient();
			const signUp = await device.signUp.opaque({ email, name: "Insecure", password });
			expect(signUp.error).toBeNull();
			expect(signUp.data?.token).toBeTruthy();
			expect((await device.getSession()).data?.user.email).toBe(email);
		} finally {
			await t.server.close();
		}
	});

	test.each([
		["the plugin", { requireEmailVerification: true }, {}],
		[
			"emailAndPassword",
			{},
			{ emailAndPassword: { enabled: true, requireEmailVerification: true } },
		],
	] as const)(
		"issues no session while %s requires verification",
		async (_, pluginOptions, authOptions) => {
			const t = await createOpaqueTestInstance(
				{ insecureCreateSessionOnRegister: true, ...pluginOptions },
				authOptions,
			);
			try {
				const device = t.createSessionClient();
				const signUp = await device.signUp.opaque({
					email: uniqueEmail("insecure-unverified"),
					name: "Unverified",
					password,
				});
				expect(signUp.error).toBeNull();
				expect(signUp.data).toMatchObject({ status: true, token: null });
				expect((await device.getSession()).data).toBeNull();
			} finally {
				await t.server.close();
			}
		},
	);
});
