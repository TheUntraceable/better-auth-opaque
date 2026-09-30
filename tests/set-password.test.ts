/**
 * Set an OPAQUE password for a logged-in user who has no OPAQUE account yet
 * (e.g. signed up with core email+password or a social provider).
 *
 *   POST /opaque/set-password/challenge { registrationRequest }  (fresh session required)
 *   POST /opaque/set-password/complete  { registrationRecord }   (fresh session required)
 *
 * Opt-in: `setPassword: { enabled: true }` (default false).
 */
import { client as opaqueLib, ready } from "@serenity-kit/opaque";
import { afterEach, describe, expect, setSystemTime, test } from "bun:test";
import {
	createTestHarness,
	type Device,
	FAST_KEY_STRETCHING,
	randomBase64Url,
	SESSION_TOKEN_COOKIE,
	startSetPassword,
	UNDESERIALISABLE_RECORD,
	uniqueEmail,
} from "./helpers/harness";

await ready;

const h = await createTestHarness({ emailAndPassword: true, plugin: { setPassword: { enabled: true } } });
/** Default options: set-password is NOT enabled. */
const hOff = await createTestHarness({ emailAndPassword: true });
/** Enabled, with sessions that stop being fresh after 60s. */
const hStale = await createTestHarness({
	emailAndPassword: true,
	plugin: { setPassword: { enabled: true } },
	authOptions: { session: { freshAge: 60 } },
});

afterEach(() => {
	setSystemTime(); // never leak a mocked clock into other tests
});

const CORE_PASSWORD = "core-password-123";
const OPAQUE_PASSWORD = "new opaque password";

/** A core email+password user (no OPAQUE account), logged in on the returned device. */
async function coreUser(label = "setpw") {
	const email = uniqueEmail(label);
	const device = await h.coreSignUp(email, CORE_PASSWORD);
	const user = (await h.db.user(email))!;
	return { email, user, device };
}

async function canLogIn(email: string, password: string) {
	const res = await h.device().client.signIn.opaque({ email, password });
	return res.error === null && res.data?.success === true;
}

function expectCode(res: { status: number; body: any }, status: number, code: string) {
	expect({ status: res.status, code: res.body?.code }).toEqual({ status, code });
}

/** Full raw set-password from `device`. */
async function rawSetPassword(device: Device, password = OPAQUE_PASSWORD) {
	const started = await startSetPassword(device, password);
	if (!started.registrationRecord) {
		throw new Error(`set-password challenge failed: ${started.res.status} ${started.res.text}`);
	}
	const complete = await device.post("/opaque/set-password/complete", {
		registrationRecord: started.registrationRecord,
	});
	return { challenge: started.res, complete, registrationRecord: started.registrationRecord };
}

/** A storable registration record (from a side-effect-free sign-up challenge). */
async function someRegistrationRecord(email: string, password = OPAQUE_PASSWORD) {
	const { clientRegistrationState, registrationRequest } = opaqueLib.startRegistration({ password });
	const ch = await h.device().post("/sign-up/opaque/challenge", { email, registrationRequest });
	expect(ch.status).toBe(200);
	return opaqueLib.finishRegistration({
		clientRegistrationState,
		password,
		registrationResponse: ch.body.challenge,
		keyStretching: FAST_KEY_STRETCHING, // only stored, never logged in with
	}).registrationRecord;
}

describe("set password: opt-in (setPassword.enabled, default false)", () => {
	test("default options: challenge and complete are 404 for an authenticated, fresh session (old and new paths); nothing is created", async () => {
		const email = uniqueEmail("setpw-off");
		const device = await hOff.coreSignUp(email, CORE_PASSWORD);
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
		const { registrationRequest } = opaqueLib.startRegistration({ password: OPAQUE_PASSWORD });
		const registrationRecord = await someRegistrationRecord(email);

		for (const base of ["/opaque/set-password", "/opaque/setPassword"]) {
			const challenge = await device.post(`${base}/challenge`, { registrationRequest });
			const complete = await device.post(`${base}/complete`, { registrationRecord });
			expect({ base, challenge: challenge.status, complete: complete.status }).toEqual({
				base,
				challenge: 404,
				complete: 404,
			});
		}
		expect(await hOff.db.opaqueAccounts(email)).toHaveLength(0);
	});

	test("default options: client.opaque.setPassword returns { data: null, error.status 404 }", async () => {
		const email = uniqueEmail("setpw-off-client");
		const device = await hOff.coreSignUp(email, CORE_PASSWORD);
		const res = await device.client.opaque.setPassword({ newPassword: OPAQUE_PASSWORD });
		expect(res.data).toBeNull();
		expect(res.error).toMatchObject({ status: 404 });
		expect(await hOff.db.opaqueAccounts(email)).toHaveLength(0);
	});

	test("enabled, but the session is no longer fresh (session.freshAge): 403 on both steps, nothing is created", async () => {
		const email = uniqueEmail("setpw-stale");
		const device = await hStale.coreSignUp(email, CORE_PASSWORD);
		const fresh = await startSetPassword(device, OPAQUE_PASSWORD);
		expect(fresh.res.status).toBe(200);

		setSystemTime(new Date(Date.now() + 120_000));

		const { registrationRequest } = opaqueLib.startRegistration({ password: OPAQUE_PASSWORD });
		expect((await device.post("/opaque/set-password/challenge", { registrationRequest })).status).toBe(403);
		const complete = await device.post("/opaque/set-password/complete", { registrationRecord: fresh.registrationRecord });
		expect(complete.status).toBe(403);
		expect(await hStale.db.opaqueAccounts(email)).toHaveLength(0);
	});
});

describe("set password: preconditions", () => {
	test("the fixture user really has no OPAQUE account and is logged in", async () => {
		const { email, device } = await coreUser("setpw-fixture");
		expect((await h.db.accounts(email)).map((a) => a.providerId)).toEqual(["credential"]);
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
	});
});

describe("set password: authentication", () => {
	test("unauthenticated challenge and complete are 401", async () => {
		const anon = h.device();
		const { registrationRequest } = opaqueLib.startRegistration({ password: OPAQUE_PASSWORD });
		expect((await anon.post("/opaque/set-password/challenge", { registrationRequest })).status).toBe(401);
		expect(
			(await anon.post("/opaque/set-password/complete", { registrationRecord: UNDESERIALISABLE_RECORD })).status,
		).toBe(401);
	});

	test("a session revoked in the database is rejected even while its cookie cache is valid", async () => {
		const { email, device } = await coreUser("setpw-revoked");
		await h.ctx.internalAdapter.deleteSession(device.sessionToken()!);
		expect((await device.whoami()).session?.user.email).toBe(email); // cookie cache still says yes

		const { registrationRequest } = opaqueLib.startRegistration({ password: OPAQUE_PASSWORD });
		expect((await device.post("/opaque/set-password/challenge", { registrationRequest })).status).toBe(401);
		expect(await h.db.opaqueAccounts(email)).toHaveLength(0);
	});
});

describe("set password: challenge", () => {
	test("logged-in user without an OPAQUE account: 200 { challenge }", async () => {
		const { device } = await coreUser();
		const { res } = await startSetPassword(device, OPAQUE_PASSWORD);
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ challenge: expect.any(String) });
	});

	test("registrationRequest of the wrong length: 400 INVALID_REGISTRATION_REQUEST", async () => {
		const { device } = await coreUser();
		const res = await device.post("/opaque/set-password/challenge", { registrationRequest: randomBase64Url(16) });
		expectCode(res, 400, "INVALID_REGISTRATION_REQUEST");
	});

	test("user who already has an OPAQUE account: 400 OPAQUE_ACCOUNT_ALREADY_EXISTS", async () => {
		const email = uniqueEmail("setpw-has");
		await h.register(email, "existing opaque password");
		const device = await h.loggedInDevice(email, "existing opaque password");
		const { res } = await startSetPassword(device, OPAQUE_PASSWORD);
		expectCode(res, 400, "OPAQUE_ACCOUNT_ALREADY_EXISTS");
	});
});

describe("set password: complete", () => {
	test("success: { status: true }, one 'opaque' account for the session user, and OPAQUE login works", async () => {
		const { email, user, device } = await coreUser();

		const { challenge, complete, registrationRecord } = await rawSetPassword(device);

		expect(challenge.status).toBe(200);
		expect(complete.status).toBe(200);
		expect(complete.body).toEqual({ status: true });
		const accounts = await h.db.opaqueAccounts(email);
		expect(accounts).toHaveLength(1);
		expect(accounts[0]!.userId).toBe(user.id);
		expect(accounts[0]!.providerId).toBe("opaque");
		expect((accounts[0] as { registrationRecord?: string }).registrationRecord).toBe(registrationRecord);

		const login = await h.device().client.signIn.opaque({ email, password: OPAQUE_PASSWORD });
		expect(login.error).toBeNull();
		expect(login.data?.user.id).toBe(user.id);
		expect(await canLogIn(email, "some other password")).toBe(false);
	});

	test("the caller's session stays valid and unchanged, other sessions and the core password are untouched", async () => {
		const { email, device } = await coreUser("setpw-keep");
		const other = h.device();
		expect((await other.post("/sign-in/email", { email, password: CORE_PASSWORD })).status).toBe(200);
		const tokenBefore = device.sessionToken();
		const sessionsBefore = (await h.db.sessionsFor(email)).map((s) => s.token).sort();

		const { complete } = await rawSetPassword(device);

		expect(complete.status).toBe(200);
		expect(device.sessionToken()).toBe(tokenBefore);
		expect(complete.setCookies.map((c) => c.name)).not.toContain(SESSION_TOKEN_COOKIE);
		expect((await h.db.sessionsFor(email)).map((s) => s.token).sort()).toEqual(sessionsBefore);
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
		expect((await other.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
		expect((await h.device().post("/sign-in/email", { email, password: CORE_PASSWORD })).status).toBe(200);
	});

	test("a second complete (account now exists): 400 OPAQUE_ACCOUNT_ALREADY_EXISTS, record unchanged", async () => {
		const { email, device } = await coreUser("setpw-twice");
		const first = await rawSetPassword(device);
		expect(first.complete.status).toBe(200);

		const second = await device.post("/opaque/set-password/complete", { registrationRecord: first.registrationRecord });
		expectCode(second, 400, "OPAQUE_ACCOUNT_ALREADY_EXISTS");
		expect(await h.db.opaqueAccounts(email)).toHaveLength(1);
		expect(await h.db.registrationRecord(email)).toBe(first.registrationRecord);
	});

	test("user registered with OPAQUE: 400 OPAQUE_ACCOUNT_ALREADY_EXISTS and the record is not overwritten", async () => {
		const email = uniqueEmail("setpw-opaque-user");
		await h.register(email, "existing opaque password");
		const device = await h.loggedInDevice(email, "existing opaque password");
		const recordBefore = await h.db.registrationRecord(email);

		// A record for a different password, obtained via a registration challenge.
		const { clientRegistrationState, registrationRequest } = opaqueLib.startRegistration({ password: OPAQUE_PASSWORD });
		const ch = await h.device().post("/sign-up/opaque/challenge", { email, registrationRequest });
		const { registrationRecord } = opaqueLib.finishRegistration({
			clientRegistrationState,
			password: OPAQUE_PASSWORD,
			registrationResponse: ch.body.challenge,
		});

		const res = await device.post("/opaque/set-password/complete", { registrationRecord });
		expectCode(res, 400, "OPAQUE_ACCOUNT_ALREADY_EXISTS");
		expect(await h.db.registrationRecord(email)).toBe(recordBefore);
		expect(await canLogIn(email, "existing opaque password")).toBe(true);
	});

	test.each([
		["undeserialisable (192 bytes)", UNDESERIALISABLE_RECORD],
		["too short (100 bytes)", randomBase64Url(100)],
	])("%s registrationRecord: 400 INVALID_REGISTRATION_RECORD and no account is created", async (_label, bad) => {
		const { email, device } = await coreUser("setpw-badrec");
		const res = await device.post("/opaque/set-password/complete", { registrationRecord: bad });
		expectCode(res, 400, "INVALID_REGISTRATION_RECORD");
		expect(await h.db.opaqueAccounts(email)).toHaveLength(0);

		// A proper attempt afterwards still works.
		expect((await rawSetPassword(device)).complete.status).toBe(200);
	});

	test("race: two concurrent completes → exactly one 200 and one 400, exactly one OPAQUE account (the winner's password)", async () => {
		const { email, device } = await coreUser("setpw-race");
		const pwA = "race password A";
		const pwB = "race password B";
		const a = await startSetPassword(device, pwA);
		const b = await startSetPassword(device, pwB);
		expect(a.res.status).toBe(200);
		expect(b.res.status).toBe(200);

		const [resA, resB] = await Promise.all([
			device.post("/opaque/set-password/complete", { registrationRecord: a.registrationRecord }),
			device.post("/opaque/set-password/complete", { registrationRecord: b.registrationRecord }),
		]);

		expect([resA.status, resB.status].sort()).toEqual([200, 400]);
		const loser = resA.status === 400 ? resA : resB;
		// The loser either found the winner's account or found no challenge slot left.
		expect(["OPAQUE_ACCOUNT_ALREADY_EXISTS", "SET_PASSWORD_CHALLENGE_REQUIRED"]).toContain(loser.body?.code);
		expect(await h.db.opaqueAccounts(email)).toHaveLength(1);
		const [winnerPw, loserPw] = resA.status === 200 ? [pwA, pwB] : [pwB, pwA];
		expect(await canLogIn(email, winnerPw)).toBe(true);
		expect(await canLogIn(email, loserPw)).toBe(false);
	});
});

describe("set password: the challenge is required", () => {
	test("complete without a prior challenge: 400 SET_PASSWORD_CHALLENGE_REQUIRED, no account", async () => {
		const { email, device } = await coreUser("setpw-nochallenge");
		const registrationRecord = await someRegistrationRecord(email);

		const res = await device.post("/opaque/set-password/complete", { registrationRecord });

		expectCode(res, 400, "SET_PASSWORD_CHALLENGE_REQUIRED");
		expect(await h.db.opaqueAccounts(email)).toHaveLength(0);
	});

	test("complete after the challenge expired (15 minutes): 400 SET_PASSWORD_CHALLENGE_REQUIRED, no account", async () => {
		const { email, device } = await coreUser("setpw-expired");
		const started = await startSetPassword(device, OPAQUE_PASSWORD);
		expect(started.res.status).toBe(200);

		setSystemTime(new Date(Date.now() + 16 * 60 * 1000));

		const res = await device.post("/opaque/set-password/complete", { registrationRecord: started.registrationRecord });
		expectCode(res, 400, "SET_PASSWORD_CHALLENGE_REQUIRED");
		expect(await h.db.opaqueAccounts(email)).toHaveLength(0);
	});

	test("a user who already has an OPAQUE account still gets OPAQUE_ACCOUNT_ALREADY_EXISTS, with or without a challenge", async () => {
		const email = uniqueEmail("setpw-has-nochallenge");
		await h.register(email, "existing opaque password");
		const device = await h.loggedInDevice(email, "existing opaque password");
		const res = await device.post("/opaque/set-password/complete", {
			registrationRecord: await someRegistrationRecord(email),
		});
		expectCode(res, 400, "OPAQUE_ACCOUNT_ALREADY_EXISTS");
	});
});

describe("set password: client", () => {
	test("authClient.opaque.setPassword({ newPassword }) → { data: { status: true }, error: null }, then OPAQUE login works", async () => {
		const { email, device } = await coreUser("setpw-client");
		const res = await device.client.opaque.setPassword({ newPassword: OPAQUE_PASSWORD });
		expect(res.error).toBeNull();
		expect(res.data).toEqual({ status: true });
		expect(await canLogIn(email, OPAQUE_PASSWORD)).toBe(true);
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
	});

	test("unauthenticated: { data: null, error.status 401 }", async () => {
		const res = await h.device().client.opaque.setPassword({ newPassword: OPAQUE_PASSWORD });
		expect(res.data).toBeNull();
		expect(res.error).toMatchObject({ status: 401 });
	});

	test("already has an OPAQUE account: error { status: 400, code: OPAQUE_ACCOUNT_ALREADY_EXISTS }", async () => {
		const email = uniqueEmail("setpw-client-has");
		await h.register(email, "existing opaque password");
		const device = await h.loggedInDevice(email, "existing opaque password");
		const res = await device.client.opaque.setPassword({ newPassword: OPAQUE_PASSWORD });
		expect(res.data).toBeNull();
		expect(res.error).toMatchObject({ status: 400, code: "OPAQUE_ACCOUNT_ALREADY_EXISTS" });
		expect(await canLogIn(email, "existing opaque password")).toBe(true);
	});
});
