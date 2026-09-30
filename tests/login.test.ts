import { afterEach, describe, expect, setSystemTime, test } from "bun:test";
import {
	createTestHarness,
	forgedLoginPayload,
	type LoginPayload,
	SESSION_DATA_COOKIE,
	SESSION_TOKEN_COOKIE,
	startLogin,
	UNDESERIALISABLE_RECORD,
	uniqueEmail,
	validLoginPayload,
} from "./helpers/harness";

const h = await createTestHarness();

const PASSWORD = "correct horse battery staple";

async function registeredUser(label = "login") {
	const email = uniqueEmail(label);
	await h.register(email, PASSWORD);
	const user = await h.db.user(email);
	if (!user) throw new Error("registration did not create a user");
	return { email, user };
}

function isClientError(status: number) {
	return status >= 400 && status < 500;
}

/** Complete a login over raw HTTP and assert that nothing session-like happened. */
async function expectRejectedWithoutSession(payload: LoginPayload) {
	const device = h.device();
	const sessionsBefore = await h.db.sessionCount();
	const res = await device.post("/sign-in/opaque/complete", payload);
	expect(res.ok).toBe(false);
	expect(res.setCookies.map((c) => c.name)).not.toContain(SESSION_TOKEN_COOKIE);
	expect(await h.db.sessionCount()).toBe(sessionsBefore);
	expect((await device.whoami()).session).toBeNull();
	return res;
}

afterEach(() => {
	setSystemTime(); // never leak a mocked clock into other tests
});

describe("login: happy path", () => {
	test("client login returns token + user id, sets session cookies and creates a DB session", async () => {
		const { email, user } = await registeredUser();
		const device = h.device();

		const res = await device.client.signIn.opaque({ email, password: PASSWORD });

		expect(res.error).toBeNull();
		expect(res.data).toEqual({ token: expect.any(String), success: true, user: { id: user.id } });
		const token = res.data!.token;

		// Cookies: signed session token (persistent) + cookie-cache data.
		expect(device.jar.has(SESSION_TOKEN_COOKIE)).toBe(true);
		expect(device.jar.has(SESSION_DATA_COOKIE)).toBe(true);
		expect(device.sessionToken()).toBe(token);
		const tokenCookie = device.lastSetCookies.find((c) => c.name === SESSION_TOKEN_COOKIE)!;
		expect(tokenCookie.attributes.httponly).toBe(true);
		expect(Number(tokenCookie.attributes["max-age"])).toBeGreaterThan(0);

		// Database side.
		const sessions = await h.db.sessionsFor(email);
		expect(sessions.map((s) => s.token)).toEqual([token]);
		expect(sessions[0]!.userId).toBe(user.id);

		// The session is usable, both through the cookie cache and the DB.
		const cached = await device.whoami();
		expect(cached.session?.user.email).toBe(email);
		const fromDb = await device.whoami({ tokenOnly: true });
		expect(fromDb.session?.user.id).toBe(user.id);
		expect(fromDb.session?.session.token).toBe(token);
	});

	test("raw login returns 200 with exactly { token, success, user: { id } }", async () => {
		const { email, user } = await registeredUser();
		const device = h.device();
		const res = await device.post("/sign-in/opaque/complete", await validLoginPayload(device, email, PASSWORD));
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ token: expect.any(String), success: true, user: { id: user.id } });
	});

	test("repeated logins each create a distinct session", async () => {
		const { email } = await registeredUser();
		const tokens = new Set<string>();
		for (let i = 0; i < 3; i++) {
			const res = await h.device().client.signIn.opaque({ email, password: PASSWORD });
			expect(res.error).toBeNull();
			tokens.add(res.data!.token);
		}
		expect(tokens.size).toBe(3);
		expect((await h.db.sessionsFor(email)).length).toBe(3);
	});
});

describe("login: failures", () => {
	test("wrong password via the client fails without a session", async () => {
		const { email } = await registeredUser();
		const device = h.device();
		const sessionsBefore = await h.db.sessionCount();

		const res = await device.client.signIn.opaque({ email, password: "wrong password" });

		expect(res.data).toBeNull();
		expect(res.error).not.toBeNull();
		expect(device.jar.has(SESSION_TOKEN_COOKIE)).toBe(false);
		expect(await h.db.sessionCount()).toBe(sessionsBefore);
	});

	test("wrong password at the server (unauthenticated KE3) is 401, not 500, and creates no session", async () => {
		const { email } = await registeredUser();
		const res = await expectRejectedWithoutSession(await forgedLoginPayload(h.device(), email));
		expect(res.status).toBe(401);
	});

	test("non-existent user fails identically (status and body) to a wrong password", async () => {
		const { email } = await registeredUser();
		const wrongPassword = await expectRejectedWithoutSession(await forgedLoginPayload(h.device(), email));
		const noSuchUser = await expectRejectedWithoutSession(
			await forgedLoginPayload(h.device(), uniqueEmail("ghost")),
		);

		expect(noSuchUser.status).toBe(401);
		expect(noSuchUser.status).toBe(wrongPassword.status);
		expect(noSuchUser.body).toEqual(wrongPassword.body);
	});

	test("non-existent user via the client returns the same error as a wrong password", async () => {
		const { email } = await registeredUser();
		const wrong = await h.device().client.signIn.opaque({ email, password: "wrong password" });
		const ghost = await h.device().client.signIn.opaque({ email: uniqueEmail("ghost"), password: PASSWORD });
		expect(wrong.data).toBeNull();
		expect(ghost.data).toBeNull();
		expect(ghost.error).toEqual(wrong.error!);
	});

	test("login challenge for a non-existent user is indistinguishable in shape from a real one", async () => {
		const { email } = await registeredUser();
		const real = await startLogin(h.device(), email, PASSWORD);
		const ghost = await startLogin(h.device(), uniqueEmail("ghost"), PASSWORD);
		expect(ghost.res.status).toBe(real.res.status);
		expect(Object.keys(ghost.res.body).sort()).toEqual(Object.keys(real.res.body).sort());
		expect(ghost.challenge.length).toBe(real.challenge.length);
		expect(ghost.state.length).toBe(real.state.length);
		// The client can't complete against a dummy record.
		expect(ghost.finish()).toBeUndefined();
	});

	test("malformed loginResult ('AAAA') is a 4xx, not 500, and creates no session", async () => {
		const { email } = await registeredUser();
		const payload = await validLoginPayload(h.device(), email, PASSWORD);
		const res = await expectRejectedWithoutSession({ ...payload, loginResult: "AAAA" });
		expect(isClientError(res.status)).toBe(true);
	});

	test("non-base64url loginResult is 400", async () => {
		const { email } = await registeredUser();
		const payload = await validLoginPayload(h.device(), email, PASSWORD);
		const res = await expectRejectedWithoutSession({ ...payload, loginResult: "!!not base64!!" });
		expect(res.status).toBe(400);
	});

	test("malformed loginRequest on the challenge step is 400", async () => {
		const res = await h.device().post("/sign-in/opaque/challenge", {
			email: uniqueEmail("badreq"),
			loginRequest: "AAAA",
		});
		expect(res.status).toBe(400);
	});

	test.each([
		["garbage", () => "definitely-not-an-encrypted-state"],
		["empty", () => ""],
		[
			"one character flipped",
			(state: string) => {
				const i = Math.floor(state.length / 2);
				const c = state[i] === "a" ? "b" : "a";
				return state.slice(0, i) + c + state.slice(i + 1);
			},
		],
		["truncated", (state: string) => state.slice(0, state.length - 8)],
	])("tampered encryptedServerState (%s) is 400 and creates no session", async (_label, tamper) => {
		const { email } = await registeredUser();
		const payload = await validLoginPayload(h.device(), email, PASSWORD);
		const tampered = tamper(payload.encryptedServerState);
		expect(tampered).not.toBe(payload.encryptedServerState);
		const res = await expectRejectedWithoutSession({ ...payload, encryptedServerState: tampered });
		expect(res.status).toBe(400);
	});

	test("an expired login state is rejected with 400 LOGIN_STATE_EXPIRED even when the KE3 is valid", async () => {
		const { email } = await registeredUser();
		const payload = await validLoginPayload(h.device(), email, PASSWORD);

		setSystemTime(new Date(Date.now() + 60 * 60 * 1000)); // one hour later
		const res = await expectRejectedWithoutSession(payload);
		expect(res.status).toBe(400);
		expect(res.body?.code).toBe("LOGIN_STATE_EXPIRED");
	});

	test("a corrupt stored registration record: the challenge still answers 200 and login fails with 401 (never 500), no session", async () => {
		const { email } = await registeredUser("login-corrupt");
		const account = (await h.db.opaqueAccount(email))!;
		await h.ctx.internalAdapter.updateAccount(account.id, { registrationRecord: UNDESERIALISABLE_RECORD } as Record<string, unknown>);
		expect(await h.db.registrationRecord(email)).toBe(UNDESERIALISABLE_RECORD);

		const started = await startLogin(h.device(), email, PASSWORD);
		expect(started.res.status).toBe(200);
		expect(started.finish()).toBeUndefined();
		const forged = await expectRejectedWithoutSession(await forgedLoginPayload(h.device(), email));
		expect({ status: forged.status, code: forged.body?.code }).toEqual({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });

		const viaClient = await h.device().client.signIn.opaque({ email, password: PASSWORD });
		expect(viaClient.data).toBeNull();
		expect(viaClient.error).toMatchObject({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });
	});
});

describe("login: dontRememberMe", () => {
	test("dontRememberMe: true yields session-lifetime cookies (no Max-Age / Expires)", async () => {
		const { email } = await registeredUser();
		const device = h.device();
		const payload = await validLoginPayload(device, email, PASSWORD);

		const res = await device.post("/sign-in/opaque/complete", { ...payload, dontRememberMe: true });

		expect(res.status).toBe(200);
		expect(res.body.success).toBe(true);
		const tokenCookie = res.setCookies.find((c) => c.name === SESSION_TOKEN_COOKIE);
		expect(tokenCookie).toBeDefined();
		expect(tokenCookie!.attributes["max-age"]).toBeUndefined();
		expect(tokenCookie!.attributes.expires).toBeUndefined();

		const dataCookie = res.setCookies.find((c) => c.name === SESSION_DATA_COOKIE);
		expect(dataCookie).toBeDefined();
		expect(dataCookie!.attributes["max-age"]).toBeUndefined();
		expect(dataCookie!.attributes.expires).toBeUndefined();

		// And the session works.
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
	});
});

describe("login: replay", () => {
	test("replaying the exact same /sign-in/opaque/complete payload is rejected", async () => {
		const { email } = await registeredUser();
		const payload = await validLoginPayload(h.device(), email, PASSWORD);

		const first = await h.device().post("/sign-in/opaque/complete", payload);
		expect(first.status).toBe(200);
		expect(await h.db.sessionsFor(email)).toHaveLength(1);

		const replay = await expectRejectedWithoutSession(payload);
		expect(isClientError(replay.status)).toBe(true);
		expect(await h.db.sessionsFor(email)).toHaveLength(1);
	});
});
