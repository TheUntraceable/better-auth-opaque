import { client as opaqueLib, ready } from "@serenity-kit/opaque";
import { describe, expect, test } from "bun:test";
import {
	createTestHarness,
	randomBase64Url,
	rawRegister,
	SESSION_TOKEN_COOKIE,
	uniqueEmail,
} from "./helpers/harness";

const h = await createTestHarness();
await ready;

const REGISTER_OK = { success: true, message: "User registered successfully" };

/**
 * `client.signUp.opaque` returns `{ error }` without a `data` key when the
 * challenge step fails (unlike signIn, which returns `data: null`); normalise
 * so the assertion is identical either way.
 */
function dataOf(res: object): unknown {
	return "data" in res ? (res.data ?? null) : null;
}

describe("register", () => {
	test("happy path: client returns the success body and the account is stored without creating a session", async () => {
		const email = uniqueEmail("reg");
		const device = h.device();
		const sessionsBefore = await h.db.sessionCount();

		const res = await device.client.signUp.opaque({ email, password: "pw-reg-1", name: "Reg User" });

		expect(res.error).toBeNull();
		expect(dataOf(res)).toEqual(REGISTER_OK);

		const user = await h.db.user(email);
		expect(user).not.toBeNull();
		expect(user!.email).toBe(email);
		expect(user!.name).toBe("Reg User");

		const account = await h.db.opaqueAccount(email);
		expect(account).not.toBeNull();
		expect(account!.providerId).toBe("opaque");
		expect(typeof account!.registrationRecord).toBe("string");

		// No session unless insecureCreateSessionOnRegister is enabled.
		expect(device.jar.has(SESSION_TOKEN_COOKIE)).toBe(false);
		expect(await h.db.sessionCount()).toBe(sessionsBefore);
	});

	test("happy path (raw): 201 with the success body and the exact registration record persisted", async () => {
		const email = uniqueEmail("reg-raw");
		const { challenge, complete, registrationRecord } = await rawRegister(h.device(), email, "pw-reg-raw");

		expect(challenge.status).toBe(200);
		expect(Object.keys(challenge.body)).toEqual(["challenge"]);
		expect(typeof challenge.body.challenge).toBe("string");

		expect(complete.status).toBe(201);
		expect(complete.body).toEqual(REGISTER_OK);
		expect(complete.setCookies.map((c) => c.name)).not.toContain(SESSION_TOKEN_COOKIE);

		expect(await h.db.registrationRecord(email)).toBe(registrationRecord);
	});

	test("duplicate email returns the identical 201 body and does not overwrite the existing record", async () => {
		const email = uniqueEmail("dup");
		const first = await rawRegister(h.device(), email, "original-password", "Original Name");
		expect(first.complete.status).toBe(201);
		const recordBefore = await h.db.registrationRecord(email);
		expect(recordBefore).toBe(first.registrationRecord);
		const usersBefore = await h.db.userCount();

		const second = await rawRegister(h.device(), email, "attacker-password", "Attacker Name");

		// Enumeration protection: indistinguishable from a fresh registration.
		expect(second.challenge.status).toBe(first.challenge.status);
		expect(second.complete.status).toBe(201);
		expect(second.complete.body).toEqual(first.complete.body);
		expect(second.complete.setCookies.map((c) => c.name)).not.toContain(SESSION_TOKEN_COOKIE);

		// Nothing was overwritten.
		expect(await h.db.userCount()).toBe(usersBefore);
		expect(await h.db.registrationRecord(email)).toBe(recordBefore);
		expect((await h.db.user(email))!.name).toBe("Original Name");

		// The original password still works; the attacker's does not.
		const good = await h.device().client.signIn.opaque({ email, password: "original-password" });
		expect(good.error).toBeNull();
		expect(good.data?.success).toBe(true);

		const bad = await h.device().client.signIn.opaque({ email, password: "attacker-password" });
		expect(bad.data).toBeNull();
		expect(bad.error).not.toBeNull();
	});

	test("invalid email is rejected with 400 on both steps and creates no user", async () => {
		const usersBefore = await h.db.userCount();

		const viaClient = await h.device().client.signUp.opaque({
			email: "not-a-valid-email",
			password: "pw",
			name: "Bad Email",
		});
		expect(dataOf(viaClient)).toBeNull();
		expect(viaClient.error).toMatchObject({ status: 400 });

		const { registrationRequest } = opaqueLib.startRegistration({ password: "pw" });
		const challenge = await h.device().post("/sign-up/opaque/challenge", {
			email: "not-a-valid-email",
			registrationRequest,
		});
		expect(challenge.status).toBe(400);

		const complete = await h.device().post("/sign-up/opaque/complete", {
			email: "not-a-valid-email",
			name: "Bad Email",
			registrationRecord: randomBase64Url(192),
		});
		expect(complete.status).toBe(400);

		expect(await h.db.userCount()).toBe(usersBefore);
	});

	test.each([
		["too short (16 bytes)", randomBase64Url(16)],
		["too long (33 bytes)", randomBase64Url(33)],
		["empty", ""],
		["not base64url", "!!!!not*base64!!!!"],
	])("registration request %s is rejected with 400", async (_label, registrationRequest) => {
		const res = await h.device().post("/sign-up/opaque/challenge", {
			email: uniqueEmail("badreq"),
			registrationRequest,
		});
		expect(res.status).toBe(400);
	});

	test.each([
		["too short (100 bytes)", randomBase64Url(100)],
		["too long (300 bytes)", randomBase64Url(300)],
		["not base64url", "!!!!not*base64!!!!"],
	])("registration record %s is rejected with 400 and creates no user", async (_label, registrationRecord) => {
		const email = uniqueEmail("badrec");
		const res = await h.device().post("/sign-up/opaque/complete", {
			email,
			name: "Bad Record",
			registrationRecord,
		});
		expect(res.status).toBe(400);
		expect(await h.db.user(email)).toBeNull();
	});

	test("name longer than 100 characters is rejected with 400 and creates no user", async () => {
		const email = uniqueEmail("longname");
		const res = await h.device().client.signUp.opaque({
			email,
			password: "pw-longname",
			name: "x".repeat(101),
		});
		expect(dataOf(res)).toBeNull();
		expect(res.error).toMatchObject({ status: 400 });
		expect(await h.db.user(email)).toBeNull();
	});

	test("empty name is rejected with 400 and creates no user", async () => {
		const email = uniqueEmail("noname");
		const res = await h.device().client.signUp.opaque({ email, password: "pw-noname", name: "" });
		expect(dataOf(res)).toBeNull();
		expect(res.error).toMatchObject({ status: 400 });
		expect(await h.db.user(email)).toBeNull();
	});
});
