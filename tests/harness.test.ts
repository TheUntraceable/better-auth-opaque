/**
 * Sanity checks for the test harness itself. If these fail, every other
 * failure in the suite is suspect.
 */
import { describe, expect, test } from "bun:test";
import {
	CookieJar,
	createTestHarness,
	parseSetCookie,
	SESSION_DATA_COOKIE,
	SESSION_TOKEN_COOKIE,
	uniqueEmail,
} from "./helpers/harness";

const h = await createTestHarness();

describe("cookie jar", () => {
	test("parses Set-Cookie attributes", () => {
		const c = parseSetCookie("a.b=v%2Fx.sig; Max-Age=604800; Path=/; HttpOnly; SameSite=Lax");
		expect(c).toEqual({
			name: "a.b",
			value: "v%2Fx.sig",
			attributes: { "max-age": "604800", path: "/", httponly: true, samesite: "Lax" },
			raw: "a.b=v%2Fx.sig; Max-Age=604800; Path=/; HttpOnly; SameSite=Lax",
		});
	});

	test("stores, replays, filters and deletes cookies", () => {
		const jar = new CookieJar();
		jar.apply([parseSetCookie("x=1; Path=/"), parseSetCookie("y=2; Path=/")]);
		expect(jar.header()).toBe("x=1; y=2");
		expect(jar.header(["y"])).toBe("y=2");
		jar.apply([parseSetCookie("x=; Max-Age=0; Path=/")]);
		expect(jar.names()).toEqual(["y"]);
	});
});

describe("in-process harness", () => {
	test("login stores both the session token and the cookie-cache cookie, and both replay paths resolve the session", async () => {
		const email = uniqueEmail("harness");
		await h.register(email, "harness-password");
		const device = await h.loggedInDevice(email, "harness-password");

		expect(device.jar.has(SESSION_TOKEN_COOKIE)).toBe(true);
		expect(device.jar.has(SESSION_DATA_COOKIE)).toBe(true);

		const full = await device.whoami();
		expect(full.status).toBe(200);
		expect(full.session?.user.email).toBe(email);

		const tokenOnly = await device.whoami({ tokenOnly: true });
		expect(tokenOnly.status).toBe(200);
		expect(tokenOnly.session?.user.email).toBe(email);
		expect(tokenOnly.session?.session.token).toBe(device.sessionToken()!);

		// Client helper uses the same jar.
		const viaClient = await device.client.getSession();
		expect(viaClient.error).toBeNull();
		expect(viaClient.data?.user.email).toBe(email);
	});

	test("origin checks are live: cookie-bearing POST without Origin is 403 MISSING_OR_NULL_ORIGIN", async () => {
		const email = uniqueEmail("origin");
		await h.register(email, "origin-password");
		const device = await h.loggedInDevice(email, "origin-password");

		const res = await device.post(
			"/sign-in/opaque/challenge",
			{ email, loginRequest: "AAAA" },
			{ origin: null },
		);
		expect(res.status).toBe(403);
		expect(res.body.code).toBe("MISSING_OR_NULL_ORIGIN");
	});

	test("origin checks are live: untrusted Origin is 403 INVALID_ORIGIN", async () => {
		const email = uniqueEmail("origin");
		await h.register(email, "origin-password");
		const device = await h.loggedInDevice(email, "origin-password");

		const res = await device.post(
			"/sign-in/opaque/challenge",
			{ email, loginRequest: "AAAA" },
			{ origin: "https://evil.example" },
		);
		expect(res.status).toBe(403);
		expect(res.body.code).toBe("INVALID_ORIGIN");
	});

	test("token-only probes reflect the database; full-cookie requests are served from the cookie cache", async () => {
		const email = uniqueEmail("revoke");
		await h.register(email, "revoke-password");
		const device = await h.loggedInDevice(email, "revoke-password");
		const token = device.sessionToken()!;
		expect((await h.db.sessionsFor(email)).map((s) => s.token)).toEqual([token]);

		// Revoke directly in the database.
		await h.ctx.internalAdapter.deleteSession(token);
		expect(await h.db.sessionsFor(email)).toEqual([]);

		// The DB-side view sees the revocation...
		expect((await device.whoami({ tokenOnly: true })).session).toBeNull();
		// ...while the signed session_data cookie cache still vouches for it
		// (standard Better Auth behaviour within cookieCache.maxAge).
		expect((await device.whoami()).session?.user.email).toBe(email);
	});

	test("an unauthenticated device has no session", async () => {
		const device = h.device();
		const res = await device.whoami();
		expect(res.status).toBe(200);
		expect(res.session).toBeNull();
	});
});
