/**
 * Rate limiting of the OPAQUE endpoints, on harnesses with Better Auth's rate
 * limiter ENABLED. Better Auth's memory store is process-wide and keyed by
 * IP + path, so every test uses its own client IP.
 */
import { client as opaqueLib, ready } from "@serenity-kit/opaque";
import { afterEach, describe, expect, setSystemTime, test } from "bun:test";
import { createTestHarness, type TestHarness, uniqueEmail } from "./helpers/harness";

await ready;

afterEach(() => {
	setSystemTime(); // never leak a mocked clock into other tests
});

let ipCounter = 0;
/** A fresh client IP (TEST-NET-3) per call. */
function freshIp() {
	ipCounter += 1;
	return `203.0.113.${ipCounter}`;
}

const enabled = { rateLimit: { enabled: true } } as const;
/** Defaults. */
const hDefault = await createTestHarness({ resetLink: true, authOptions: enabled });
/** rateLimit.window / max set (to the defaults' values) — must not touch forget-password. */
const hWindow = await createTestHarness({ resetLink: true, plugin: { rateLimit: { window: 10, max: 3 } }, authOptions: enabled });
/** rateLimit.window / max tightened: they govern every other OPAQUE endpoint. */
const hTight = await createTestHarness({ resetLink: true, plugin: { rateLimit: { window: 20, max: 2 } }, authOptions: enabled });
/** forget-password's own rule. */
const hForget = await createTestHarness({
	resetLink: true,
	plugin: { rateLimit: { forgetPassword: { window: 1, max: 1 } } },
	authOptions: enabled,
});

function forget(h: TestHarness, ip: string) {
	return h.device({ ip }).post("/opaque/forget-password", { email: uniqueEmail("rl") });
}

function signInChallenge(h: TestHarness, ip: string) {
	return h.device({ ip }).post("/sign-in/opaque/challenge", {
		email: uniqueEmail("rl"),
		loginRequest: opaqueLib.startLogin({ password: "rate limited" }).startLoginRequest,
	});
}

async function statuses(n: number, send: () => Promise<{ status: number }>) {
	const out: number[] = [];
	for (let i = 0; i < n; i++) out.push((await send()).status);
	return out;
}

describe("sign-in challenge (rateLimit.window / max; default 3 per 10s)", () => {
	test("default: the 4th request within 10s is 429; after the window it is allowed again", async () => {
		const ip = freshIp();
		expect(await statuses(4, () => signInChallenge(hDefault, ip))).toEqual([200, 200, 200, 429]);
		setSystemTime(new Date(Date.now() + 11_000));
		expect((await signInChallenge(hDefault, ip)).status).toBe(200);
	});

	test("rateLimit: { window: 20, max: 2 } governs it: the 3rd request is 429, still 429 after 11s", async () => {
		const ip = freshIp();
		expect(await statuses(3, () => signInChallenge(hTight, ip))).toEqual([200, 200, 429]);
		setSystemTime(new Date(Date.now() + 11_000));
		expect((await signInChallenge(hTight, ip)).status).toBe(429);
	});
});

describe("forget-password (its own rule, rateLimit.forgetPassword; default 3 per 60s)", () => {
	test("default: the 4th request within 60s is 429, still 429 after 11s, allowed after 61s", async () => {
		const ip = freshIp();
		expect(await statuses(4, () => forget(hDefault, ip))).toEqual([200, 200, 200, 429]);
		setSystemTime(new Date(Date.now() + 11_000));
		expect((await forget(hDefault, ip)).status).toBe(429);
		setSystemTime(new Date(Date.now() + 61_000));
		expect((await forget(hDefault, ip)).status).toBe(200);
	});

	test("rateLimit: { window: 10, max: 3 } does NOT change it: the 4th request is 429 even after 11s", async () => {
		const ip = freshIp();
		expect(await statuses(3, () => forget(hWindow, ip))).toEqual([200, 200, 200]);
		setSystemTime(new Date(Date.now() + 11_000));
		expect((await forget(hWindow, ip)).status).toBe(429);
	});

	test("rateLimit: { window: 20, max: 2 } does NOT change it either: 3 requests are allowed", async () => {
		const ip = freshIp();
		expect(await statuses(4, () => forget(hTight, ip))).toEqual([200, 200, 200, 429]);
	});

	test("rateLimit.forgetPassword: { window: 1, max: 1 } is honoured", async () => {
		const ip = freshIp();
		expect(await statuses(2, () => forget(hForget, ip))).toEqual([200, 429]);
		setSystemTime(new Date(Date.now() + 1_500));
		expect((await forget(hForget, ip)).status).toBe(200);
	});
});
