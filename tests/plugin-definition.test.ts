/**
 * The plugin object itself: endpoint naming and paths, schema, and the
 * startup checks on OPAQUE_SERVER_KEY.
 */
import { client as opaqueLib, ready, server as opaqueServer } from "@serenity-kit/opaque";
import { describe, expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { opaque } from "../src/server";
import { BASE_PATH, createTestHarness, type LogEntry, ORIGIN, randomBase64Url, uniqueEmail } from "./helpers/harness";

await ready;

const OPAQUE_SERVER_KEY = opaqueServer.createSetup();

describe("endpoints", () => {
	test("every endpoint key on opaque().endpoints starts with 'opaque'", () => {
		const keys = Object.keys(opaque({ OPAQUE_SERVER_KEY, setPassword: { enabled: true } }).endpoints);
		expect(keys.length).toBeGreaterThan(0);
		expect(keys.filter((k) => !k.startsWith("opaque"))).toEqual([]);
	});

	test("the camelCase paths /opaque/changePassword/* and /opaque/setPassword/* are gone (404); the kebab-case ones answer", async () => {
		const h = await createTestHarness({ emailAndPassword: true, plugin: { setPassword: { enabled: true } } });
		const email = uniqueEmail("paths");
		const device = await h.coreSignUp(email);
		const loginRequest = opaqueLib.startLogin({ password: "x" }).startLoginRequest;
		const registrationRequest = opaqueLib.startRegistration({ password: "x" }).registrationRequest;
		const bodies: Record<string, object> = {
			"change-password/challenge": { loginRequest, registrationRequest },
			"change-password/complete": {
				loginResult: randomBase64Url(64),
				registrationRecord: randomBase64Url(192),
				encryptedServerState: "x",
			},
			"set-password/challenge": { registrationRequest },
			"set-password/complete": { registrationRecord: randomBase64Url(192) },
		};

		for (const [kebab, body] of Object.entries(bodies)) {
			const camel = kebab.replace("change-password", "changePassword").replace("set-password", "setPassword");
			const old = await device.post(`/opaque/${camel}`, body);
			const now = await device.post(`/opaque/${kebab}`, body);
			expect({ path: camel, status: old.status }).toEqual({ path: camel, status: 404 });
			expect({ path: kebab, notFound: now.status === 404 }).toEqual({ path: kebab, notFound: false });
		}
	});
});

describe("schema", () => {
	test("account.registrationRecord is an optional string WITHOUT a unique constraint (a unique long string breaks MySQL/MSSQL)", () => {
		const field = opaque({ OPAQUE_SERVER_KEY }).schema.account.fields.registrationRecord as {
			type: unknown;
			required?: unknown;
			unique?: unknown;
		};
		expect(field.type).toBe("string");
		expect(field.required).toBe(false);
		expect(field.unique).toBeFalsy();
	});
});

describe("startup checks on OPAQUE_SERVER_KEY", () => {
	function authWith(pluginOptions: Parameters<typeof opaque>[0], logs?: LogEntry[]) {
		return betterAuth({
			database: memoryAdapter({}),
			baseURL: ORIGIN,
			basePath: BASE_PATH,
			secret: `test-secret-${randomBase64Url(32)}`,
			logger: { log: (level, message, ...args) => void logs?.push({ level, message, args }) },
			plugins: [opaque(pluginOptions)],
		});
	}

	test("NODE_ENV=production without a key: initialisation fails, naming OPAQUE_SERVER_KEY", async () => {
		const previous = process.env.NODE_ENV;
		process.env.NODE_ENV = "production";
		try {
			await expect(authWith({}).$context).rejects.toThrow(/OPAQUE_SERVER_KEY/);
		} finally {
			process.env.NODE_ENV = previous;
		}
	});

	test("outside production without a key: starts with a generated key and warns", async () => {
		const logs: LogEntry[] = [];
		await authWith({}, logs).$context;
		expect(logs.filter((l) => l.level === "warn" && l.message.includes("OPAQUE_SERVER_KEY"))).toHaveLength(1);
	});

	test.each([
		["not base64url", "not a key!"],
		["wrong length", randomBase64Url(64)],
	])("a malformed key (%s) throws at construction", (_label, key) => {
		expect(() => opaque({ OPAQUE_SERVER_KEY: key })).toThrow(/OPAQUE_SERVER_KEY/);
	});

	test("a key of the right format that is not a valid server setup fails at initialisation", async () => {
		const bogus = Buffer.alloc(128, 0xff).toString("base64url");
		await expect(authWith({ OPAQUE_SERVER_KEY: bogus }).$context).rejects.toThrow(/OPAQUE_SERVER_KEY/);
	});
});
