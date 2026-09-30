/**
 * Regression tests for the security review findings (S1-S11) and the code
 * review's concurrency / storage findings (C1, C3, C4, C5). Each describe
 * names the finding it pins down.
 */
import { client as opaqueLib, ready, server as opaqueServer } from "@serenity-kit/opaque";
import { afterEach, describe, expect, setSystemTime, test } from "bun:test";
import type { SecondaryStorage } from "better-auth";
import { opaque } from "../src/server";
import {
	createTestHarness,
	type LogEntry,
	randomBase64Url,
	rawResetPassword,
	SESSION_TOKEN_COOKIE,
	sleep,
	startChangePassword,
	startLogin,
	startResetPassword,
	startSetPassword,
	type TestHarness,
	uniqueEmail,
	validLoginPayload,
} from "./helpers/harness";

await ready;

const OLD_PASSWORD = "old password s";
const NEW_PASSWORD = "new password s";

afterEach(() => {
	setSystemTime(); // never leak a mocked clock into other tests
});

/** Link + OTP reset, and core change-email that applies immediately for unverified users. */
const h = await createTestHarness({
	resetLink: true,
	resetOTP: true,
	authOptions: { user: { changeEmail: { enabled: true, updateEmailWithoutVerification: true } } },
});

/** Plain harness for database-footprint (S7, C3) and logging (S9) checks. */
const hDb = await createTestHarness();
const hLog = await createTestHarness();
/** OTP only (C4). */
const hOtp = await createTestHarness({ resetOTP: true });
// Slow account inserts (as a real database round trip would be) so that
// concurrent writers really interleave.
const hRace = await createTestHarness({
	resetLink: true,
	resetOTP: true,
	emailAndPassword: true,
	plugin: { setPassword: { enabled: true } },
	authOptions: {
		databaseHooks: {
			account: {
				create: {
					before: async () => {
						await sleep(30);
					},
					after: async () => {
						await sleep(30);
					},
				},
			},
		},
	},
});


function expectCode(res: { status: number; body: any }, status: number, code: string) {
	expect({ status: res.status, code: res.body?.code }).toEqual({ status, code });
}

const sessionTokenSet = (res: { setCookies: { name: string }[] }) =>
	res.setCookies.map((c) => c.name).includes(SESSION_TOKEN_COOKIE);

async function registered(hh: TestHarness, label: string, password = OLD_PASSWORD) {
	const email = uniqueEmail(label);
	await hh.register(email, password);
	return { email, user: (await hh.db.user(email))! };
}

async function canLogIn(hh: TestHarness, email: string, password: string) {
	const res = await hh.device().client.signIn.opaque({ email, password });
	return res.error === null && res.data?.success === true;
}

async function requestLink(hh: TestHarness, email: string) {
	const res = await hh.device().post("/opaque/forget-password", { email, method: "link" });
	expect(res.status).toBe(200);
	return hh.outbox.resetLinksFor(email).at(-1)!.token;
}

async function requestOTP(hh: TestHarness, email: string) {
	const res = await hh.device().post("/opaque/forget-password", { email, method: "otp" });
	expect(res.status).toBe(200);
	return hh.outbox.resetOTPsFor(email).at(-1)!.otp;
}

/** Complete a stale, fully valid login (computed before the record changed); asserts no session results. */
async function expectStaleLoginRejected(
	hh: TestHarness,
	attacker: ReturnType<TestHarness["device"]>,
	payload: { loginResult: string; encryptedServerState: string },
) {
	const sessionsBefore = await hh.db.sessionCount();
	const res = await attacker.post("/sign-in/opaque/complete", payload);
	expectCode(res, 401, "INVALID_EMAIL_OR_PASSWORD");
	expect(sessionTokenSet(res)).toBe(false);
	expect(await hh.db.sessionCount()).toBe(sessionsBefore);
	expect((await attacker.whoami({ tokenOnly: true })).session).toBeNull();
}

/** A login the attacker (who knows OLD_PASSWORD) prepares now and completes later. */
async function prepareStaleLogin(hh: TestHarness, email: string) {
	const attacker = hh.device();
	const started = await startLogin(attacker, email, OLD_PASSWORD);
	const loginResult = started.finish();
	expect(loginResult).toBeDefined();
	return { attacker, payload: { loginResult: loginResult!, encryptedServerState: started.state } };
}

/* ------------------------------------------------------------------------- */

describe("S1: a challenge issued before the password record changed cannot be completed", () => {
	test("(a) sign-in: stale challenge completed after a password RESET by link → 401 INVALID_EMAIL_OR_PASSWORD, no session", async () => {
		const { email } = await registered(h, "s1-reset");
		const { attacker, payload } = await prepareStaleLogin(h, email);

		const token = await requestLink(h, email);
		expect((await rawResetPassword(h.device(), { token }, NEW_PASSWORD)).complete.status).toBe(200);

		await expectStaleLoginRejected(h, attacker, payload);
	});

	test("(b) sign-in: stale challenge completed after opaque.changePassword (default revokeOtherSessions) → 401", async () => {
		const { email } = await registered(h, "s1-change");
		const { attacker, payload } = await prepareStaleLogin(h, email);

		const victim = await h.loggedInDevice(email, OLD_PASSWORD);
		const changed = await victim.client.opaque.changePassword({ currentPassword: OLD_PASSWORD, newPassword: NEW_PASSWORD });
		expect(changed.error).toBeNull();

		await expectStaleLoginRejected(h, attacker, payload);
	});

	test("(c) sign-in: stale challenge completed after opaque.changePassword with revokeOtherSessions: false → still 401 (the record changed)", async () => {
		const { email } = await registered(h, "s1-change-keep");
		const { attacker, payload } = await prepareStaleLogin(h, email);

		const victim = await h.loggedInDevice(email, OLD_PASSWORD);
		const changed = await victim.client.opaque.changePassword({
			currentPassword: OLD_PASSWORD,
			newPassword: NEW_PASSWORD,
			revokeOtherSessions: false,
		});
		expect(changed.error).toBeNull();

		await expectStaleLoginRejected(h, attacker, payload);
	});

	test("(d) change-password: a challenge obtained before a reset fails at complete with 401 INVALID_CURRENT_PASSWORD", async () => {
		const { email } = await registered(h, "s1-chpw");
		const device = await h.loggedInDevice(email, OLD_PASSWORD);
		const stale = await startChangePassword(device, OLD_PASSWORD, "attacker chosen password");
		expect(stale.loginResult).toBeDefined();

		const token = await requestLink(h, email);
		const reset = await rawResetPassword(h.device(), { token }, NEW_PASSWORD);
		expect(reset.complete.status).toBe(200);
		// The reset revoked every session: log the same device in again with
		// the NEW password, so the complete below is authenticated and only the
		// stale challenge is under test.
		expect((await device.client.signIn.opaque({ email, password: NEW_PASSWORD })).error).toBeNull();

		const res = await device.post("/opaque/change-password/complete", {
			loginResult: stale.loginResult,
			registrationRecord: stale.registrationRecord,
			encryptedServerState: stale.encryptedServerState,
		});

		expectCode(res, 401, "INVALID_CURRENT_PASSWORD");
		expect(await h.db.registrationRecord(email)).toBe(reset.registrationRecord);
		expect(await canLogIn(h, email, NEW_PASSWORD)).toBe(true);
		expect(await canLogIn(h, email, "attacker chosen password")).toBe(false);
	});

	test("(e) control: a challenge obtained AFTER the change, with the NEW password, completes", async () => {
		const { email } = await registered(h, "s1-control");
		const victim = await h.loggedInDevice(email, OLD_PASSWORD);
		expect(
			(await victim.client.opaque.changePassword({ currentPassword: OLD_PASSWORD, newPassword: NEW_PASSWORD })).error,
		).toBeNull();

		const device = h.device();
		const res = await device.post("/sign-in/opaque/complete", await validLoginPayload(device, email, NEW_PASSWORD));
		expect(res.status).toBe(200);
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
	});
});

/* ------------------------------------------------------------------------- */

/** Wall-clock of one client operation with the library-default key stretching (Argon2id). */
function calibrateKeyStretchingMs(serverSetup: string): number {
	const run = () => {
		const { clientRegistrationState, registrationRequest } = opaqueLib.startRegistration({ password: "calibrate" });
		const { registrationResponse } = opaqueServer.createRegistrationResponse({
			serverSetup,
			userIdentifier: "calibrate@example.test",
			registrationRequest,
		});
		const t = performance.now();
		opaqueLib.finishRegistration({ clientRegistrationState, registrationResponse, password: "calibrate" });
		return performance.now() - t;
	};
	run(); // warm-up
	return Math.min(run(), run());
}

describe("S2: sign-in challenges for unknown emails cost no key stretching", () => {
	test("(a) 20 parallel challenges for unknown emails all succeed, in less than 2x ONE default key-stretching operation", async () => {
		const single = calibrateKeyStretchingMs(h.serverSetup);
		const bodies = Array.from({ length: 20 }, () => ({
			email: uniqueEmail("s2-ghost"),
			loginRequest: opaqueLib.startLogin({ password: randomBase64Url(12) }).startLoginRequest,
		}));

		const t = performance.now();
		const responses = await Promise.all(bodies.map((body) => h.device().post("/sign-in/opaque/challenge", body)));
		const batch = performance.now() - t;

		expect(responses.map((r) => r.status)).toEqual(bodies.map(() => 200));
		expect({ batchMs: Math.round(batch), singleKsfMs: Math.round(single), underBound: batch < 2 * single }).toMatchObject({
			underBound: true,
		});
	});

	test("(b) a loginRequest of the right length that is not a valid group element is 400 INVALID_LOGIN_REQUEST, rejected before any expensive work", async () => {
		const invalid = Buffer.alloc(96, 0xff).toString("base64url");
		const single = calibrateKeyStretchingMs(h.serverSetup);

		const t = performance.now();
		const responses = await Promise.all(
			Array.from({ length: 10 }, () =>
				h.device().post("/sign-in/opaque/challenge", { email: uniqueEmail("s2-invalid"), loginRequest: invalid }),
			),
		);
		const batch = performance.now() - t;

		for (const res of responses) expectCode(res, 400, "INVALID_LOGIN_REQUEST");
		expect({ batchMs: Math.round(batch), singleKsfMs: Math.round(single), underBound: batch < 2 * single }).toMatchObject({
			underBound: true,
		});
	});

	test("(c) unknown- and known-email challenges have the same shape, and the client cannot finish against the unknown one", async () => {
		const { email } = await registered(h, "s2-known");
		const real = await startLogin(h.device(), email, OLD_PASSWORD);
		const ghost = await startLogin(h.device(), uniqueEmail("s2-ghost"), OLD_PASSWORD);

		expect(Object.keys(ghost.res.body).sort()).toEqual(Object.keys(real.res.body).sort());
		expect(ghost.challenge.length).toBe(real.challenge.length);
		expect(ghost.state.length).toBe(real.state.length);
		expect(real.finish()).toBeDefined();
		expect(ghost.finish()).toBeUndefined();
	});
});

/* ------------------------------------------------------------------------- */

describe("S3: a reset credential is bound to the email it was sent to", () => {
	async function changeEmail(device: ReturnType<TestHarness["device"]>, newEmail: string) {
		const res = await device.post("/change-email", { newEmail });
		expect(res.status).toBe(200);
	}

	test("link: after the account's email changed, the link is 400 INVALID_TOKEN at both steps; emailVerified stays false, the record is unchanged", async () => {
		const { email } = await registered(h, "s3-link");
		const device = await h.loggedInDevice(email, OLD_PASSWORD);
		const token = await requestLink(h, email);
		const newEmail = uniqueEmail("s3-link-new");
		await changeEmail(device, newEmail);
		expect((await h.db.user(newEmail))!.emailVerified).toBe(false);
		const recordBefore = await h.db.registrationRecord(newEmail);
		// A storable record for the complete step, from a legitimate (unused) challenge.
		const { registrationRecord } = await startResetPassword(h.device(), { token: await requestLink(h, newEmail) }, NEW_PASSWORD);
		expect(registrationRecord).toBeDefined();

		expectCode((await startResetPassword(h.device(), { token }, NEW_PASSWORD)).res, 400, "INVALID_TOKEN");
		expectCode(await h.device().post("/opaque/reset-password/complete", { token, registrationRecord }), 400, "INVALID_TOKEN");

		expect((await h.db.user(newEmail))!.emailVerified).toBe(false);
		expect(await h.db.registrationRecord(newEmail)).toBe(recordBefore);
		expect(await canLogIn(h, newEmail, OLD_PASSWORD)).toBe(true);
	});

	test("control: without an email change the link works and marks the email verified", async () => {
		const { email } = await registered(h, "s3-control");
		const token = await requestLink(h, email);
		expect((await rawResetPassword(h.device(), { token }, NEW_PASSWORD)).complete.status).toBe(200);
		expect((await h.db.user(email))!.emailVerified).toBe(true);
	});

	test("OTP (regression guard): after the email changed, the code is INVALID_TOKEN with the old and the new email", async () => {
		const { email } = await registered(h, "s3-otp");
		const device = await h.loggedInDevice(email, OLD_PASSWORD);
		const otp = await requestOTP(h, email);
		const newEmail = uniqueEmail("s3-otp-new");
		await changeEmail(device, newEmail);
		const recordBefore = await h.db.registrationRecord(newEmail);

		expectCode((await startResetPassword(h.device(), { email, otp }, NEW_PASSWORD)).res, 400, "INVALID_TOKEN");
		expectCode((await startResetPassword(h.device(), { email: newEmail, otp }, NEW_PASSWORD)).res, 400, "INVALID_TOKEN");
		expect((await h.db.user(newEmail))!.emailVerified).toBe(false);
		expect(await h.db.registrationRecord(newEmail)).toBe(recordBefore);
	});
});

/* ------------------------------------------------------------------------- */

describe("S6: a password change invalidates every outstanding reset credential", () => {
	test("link A, OTP, link B; reset with B → link A and the OTP are 400 INVALID_TOKEN at both steps", async () => {
		const { email } = await registered(h, "s6-reset");
		const linkA = await requestLink(h, email);
		const otp = await requestOTP(h, email);
		const linkB = await requestLink(h, email);

		const reset = await rawResetPassword(h.device(), { token: linkB }, NEW_PASSWORD);
		expect(reset.complete.status).toBe(200);

		expectCode((await startResetPassword(h.device(), { token: linkA }, "attacker 1")).res, 400, "INVALID_TOKEN");
		expectCode((await startResetPassword(h.device(), { email, otp }, "attacker 2")).res, 400, "INVALID_TOKEN");
		for (const credential of [{ token: linkA }, { email, otp }]) {
			const res = await h.device().post("/opaque/reset-password/complete", {
				...credential,
				registrationRecord: reset.registrationRecord,
			});
			expectCode(res, 400, "INVALID_TOKEN");
		}
		expect(await h.db.registrationRecord(email)).toBe(reset.registrationRecord);
		expect(await canLogIn(h, email, NEW_PASSWORD)).toBe(true);
	});

	test("after a successful opaque.changePassword, a previously issued link and OTP are 400 INVALID_TOKEN", async () => {
		const { email } = await registered(h, "s6-change");
		const link = await requestLink(h, email);
		const otp = await requestOTP(h, email);
		const device = await h.loggedInDevice(email, OLD_PASSWORD);
		expect(
			(await device.client.opaque.changePassword({ currentPassword: OLD_PASSWORD, newPassword: NEW_PASSWORD })).error,
		).toBeNull();
		const recordAfterChange = await h.db.registrationRecord(email);

		expectCode((await startResetPassword(h.device(), { token: link }, "attacker 1")).res, 400, "INVALID_TOKEN");
		expectCode((await startResetPassword(h.device(), { email, otp }, "attacker 2")).res, 400, "INVALID_TOKEN");
		expect(await h.db.registrationRecord(email)).toBe(recordAfterChange);
		expect(await canLogIn(h, email, NEW_PASSWORD)).toBe(true);
	});

	test("after a reset, a new forget-password issues a working link and code", async () => {
		const { email } = await registered(h, "s6-again");
		expect((await rawResetPassword(h.device(), { token: await requestLink(h, email) }, NEW_PASSWORD)).complete.status).toBe(
			200,
		);

		const again = await rawResetPassword(h.device(), { token: await requestLink(h, email) }, "third password");
		expect(again.complete.status).toBe(200);
		const viaOtp = await rawResetPassword(h.device(), { email, otp: await requestOTP(h, email) }, "fourth password");
		expect(viaOtp.complete.status).toBe(200);
		expect(await canLogIn(h, email, "fourth password")).toBe(true);
	});
});

/* ------------------------------------------------------------------------- */

describe("S7 / C3: the sign-in challenge touches the database identically for known and unknown emails", () => {
	async function challengeFootprint(email: string) {
		const loginRequest = opaqueLib.startLogin({ password: "footprint" }).startLoginRequest;
		let calls: Awaited<ReturnType<TestHarness["recordAdapterCalls"]>> = [];
		const reads = await hDb.db.countTableReads(async () => {
			calls = await hDb.recordAdapterCalls(async () => {
				const res = await hDb.device().post("/sign-in/opaque/challenge", { email, loginRequest });
				expect(res.status).toBe(200);
			});
		});
		return { reads, calls };
	}

	test("S7: same number of queries per table (user, account) for a known and an unknown email", async () => {
		const { email } = await registered(hDb, "s7-known");
		const known = await challengeFootprint(email);
		const unknown = await challengeFootprint(uniqueEmail("s7-ghost"));

		expect(known.reads.user).toBeGreaterThanOrEqual(1);
		expect({ user: unknown.reads.user, account: unknown.reads.account }).toEqual({
			user: known.reads.user,
			account: known.reads.account,
		});
		expect(unknown.calls.map((c) => `${c.method}:${c.model}`)).toEqual(known.calls.map((c) => `${c.method}:${c.model}`));
	});

	test("C3: no delete / deleteMany on the verification table (no table-wide cleanup on an unauthenticated endpoint)", async () => {
		const { email } = await registered(hDb, "c3-known");
		for (const target of [email, uniqueEmail("c3-ghost")]) {
			const { calls } = await challengeFootprint(target);
			const deletes = calls.filter((c) => c.model === "verification" && (c.method === "delete" || c.method === "deleteMany"));
			expect({ target, deletes }).toEqual({ target, deletes: [] });
		}
	});
});

/* ------------------------------------------------------------------------- */

describe("S8: invalid plugin options throw at construction", () => {
	const OPAQUE_SERVER_KEY = opaqueServer.createSetup();
	type Options = NonNullable<Parameters<typeof opaque>[0]>;

	test.each<[string, Partial<Options>]>([
		["resetPasswordOTP.length: 0", { resetPasswordOTP: { length: 0 } }],
		["resetPasswordOTP.length: 3", { resetPasswordOTP: { length: 3 } }],
		["resetPasswordOTP.allowedAttempts: 0", { resetPasswordOTP: { allowedAttempts: 0 } }],
		["resetPasswordOTP.expiresIn: 0", { resetPasswordOTP: { expiresIn: 0 } }],
		["resetPasswordTokenExpiresIn: -1", { resetPasswordTokenExpiresIn: -1 }],
		["rateLimit.max: 0", { rateLimit: { max: 0 } }],
	])("%s throws", (_label, invalid) => {
		expect(() => opaque({ OPAQUE_SERVER_KEY, ...invalid })).toThrow();
	});

	test.each<[string, Partial<Options>]>([
		["defaults", {}],
		["resetPasswordOTP.length: 4", { resetPasswordOTP: { length: 4 } }],
		["resetPasswordOTP.length: 10", { resetPasswordOTP: { length: 10 } }],
		["resetPasswordOTP.allowedAttempts: 1", { resetPasswordOTP: { allowedAttempts: 1 } }],
		["resetPasswordOTP.expiresIn: 1", { resetPasswordOTP: { expiresIn: 1 } }],
		["resetPasswordTokenExpiresIn: 1", { resetPasswordTokenExpiresIn: 1 }],
		["rateLimit: { window: 1, max: 1 }", { rateLimit: { window: 1, max: 1 } }],
	])("%s does not throw", (_label, valid) => {
		expect(() => opaque({ OPAQUE_SERVER_KEY, ...valid })).not.toThrow();
	});
});

/* ------------------------------------------------------------------------- */

describe("S9: attacker-controlled input never produces an error-level log", () => {
	async function errorLogsDuring(fn: () => Promise<unknown>): Promise<LogEntry[]> {
		const from = hLog.logs.length;
		await fn();
		return hLog.logs.slice(from).filter((l) => l.level === "error");
	}

	test("non-canonical base64url loginResult (right length, last char '_') → 400 INVALID_LOGIN_RESULT, no error log", async () => {
		const { email } = await registered(hLog, "s9-result");
		const payload = await validLoginPayload(hLog.device(), email, OLD_PASSWORD);
		const nonCanonical = `${payload.loginResult.slice(0, -1)}_`;
		expect(nonCanonical.length).toBe(payload.loginResult.length);
		let res: Awaited<ReturnType<ReturnType<TestHarness["device"]>["post"]>> | undefined;

		const errors = await errorLogsDuring(async () => {
			res = await hLog.device().post("/sign-in/opaque/complete", { ...payload, loginResult: nonCanonical });
		});

		expectCode(res!, 400, "INVALID_LOGIN_RESULT");
		expect(errors.map((l) => l.message)).toEqual([]);
	});

	test("non-canonical base64url registrationRequest (right length, last char '_') → 400 INVALID_REGISTRATION_REQUEST, no error log", async () => {
		const { registrationRequest } = opaqueLib.startRegistration({ password: "s9" });
		const nonCanonical = `${registrationRequest.slice(0, -1)}_`;
		let res: Awaited<ReturnType<ReturnType<TestHarness["device"]>["post"]>> | undefined;

		const errors = await errorLogsDuring(async () => {
			res = await hLog.device().post("/sign-up/opaque/challenge", {
				email: uniqueEmail("s9-req"),
				registrationRequest: nonCanonical,
			});
		});

		expectCode(res!, 400, "INVALID_REGISTRATION_REQUEST");
		expect(errors.map((l) => l.message)).toEqual([]);
	});

	test.each([
		["garbage", () => "definitely-not-an-encrypted-state"],
		["truncated", (s: string) => s.slice(0, -8)],
		["one character flipped", (s: string) => s.slice(0, 10) + (s[10] === "a" ? "b" : "a") + s.slice(11)],
	])("malformed encryptedServerState (%s) → 400 INVALID_LOGIN_STATE, no error log", async (_label, tamper) => {
		const { email } = await registered(hLog, "s9-state");
		const payload = await validLoginPayload(hLog.device(), email, OLD_PASSWORD);
		let res: Awaited<ReturnType<ReturnType<TestHarness["device"]>["post"]>> | undefined;

		const errors = await errorLogsDuring(async () => {
			res = await hLog.device().post("/sign-in/opaque/complete", {
				...payload,
				encryptedServerState: tamper(payload.encryptedServerState),
			});
		});

		expectCode(res!, 400, "INVALID_LOGIN_STATE");
		expect(errors.map((l) => l.message)).toEqual([]);
	});
});

/* ------------------------------------------------------------------------- */

describe("S10: init warns when reset emails are sent inline (no advanced.backgroundTasks)", () => {
	const isBackgroundWarning = (l: LogEntry) => l.level === "warn" && /background/i.test(l.message) && /timing/i.test(l.message);

	test("sendResetPassword configured, no backgroundTasks → exactly one warn mentioning timing and background tasks", async () => {
		const hWarn = await createTestHarness({ resetLink: true });
		expect(hWarn.logs.filter(isBackgroundWarning)).toHaveLength(1);
	});

	test("with advanced.backgroundTasks.handler configured → no such warning", async () => {
		const hQuiet = await createTestHarness({
			resetLink: true,
			authOptions: { advanced: { backgroundTasks: { handler: (promise) => void promise.catch(() => {}) } } },
		});
		expect(hQuiet.logs.filter(isBackgroundWarning)).toHaveLength(0);
		expect(hQuiet.logs.filter((l) => l.level === "warn" && /background/i.test(l.message))).toHaveLength(0);
	});
});

/* ------------------------------------------------------------------------- */

describe("C1: concurrent password writers converge on exactly one OPAQUE account", () => {
	/** The single stored record must be one of `candidates`, and its password must log in. */
	async function expectConverged(email: string, candidates: Array<{ record: string; password: string }>) {
		const accounts = await hRace.db.opaqueAccounts(email);
		expect(accounts).toHaveLength(1);
		const stored = (accounts[0] as { registrationRecord?: string }).registrationRecord;
		const winner = candidates.find((c) => c.record === stored);
		expect(winner).toBeDefined();
		expect(await canLogIn(hRace, email, winner!.password)).toBe(true);
	}

	test("two resets (link + OTP) of a user WITHOUT an OPAQUE account, completed concurrently", async () => {
		const email = uniqueEmail("c1-resets");
		await hRace.db.createUserWithoutOpaque(email);
		const token = await requestLink(hRace, email);
		const otp = await requestOTP(hRace, email);
		const viaLink = await startResetPassword(hRace.device(), { token }, "race link password");
		const viaOtp = await startResetPassword(hRace.device(), { email, otp }, "race otp password");
		expect(viaLink.res.status).toBe(200);
		expect(viaOtp.res.status).toBe(200);

		const [a, b] = await Promise.all([
			hRace.device().post("/opaque/reset-password/complete", { token, registrationRecord: viaLink.registrationRecord }),
			hRace.device().post("/opaque/reset-password/complete", { email, otp, registrationRecord: viaOtp.registrationRecord }),
		]);

		expect([a.status, b.status]).toContain(200);
		await expectConverged(email, [
			{ record: viaLink.registrationRecord!, password: "race link password" },
			{ record: viaOtp.registrationRecord!, password: "race otp password" },
		]);
	});

	test("set-password and a reset of the same user, completed concurrently", async () => {
		const email = uniqueEmail("c1-set-reset");
		const device = await hRace.coreSignUp(email);
		const set = await startSetPassword(device, "race set password");
		expect(set.res.status).toBe(200);
		const token = await requestLink(hRace, email);
		const reset = await startResetPassword(hRace.device(), { token }, "race reset password");
		expect(reset.res.status).toBe(200);

		const [a, b] = await Promise.all([
			device.post("/opaque/set-password/complete", { registrationRecord: set.registrationRecord }),
			hRace.device().post("/opaque/reset-password/complete", { token, registrationRecord: reset.registrationRecord }),
		]);

		expect([a.status, b.status]).toContain(200);
		await expectConverged(email, [
			{ record: set.registrationRecord!, password: "race set password" },
			{ record: reset.registrationRecord!, password: "race reset password" },
		]);
	});
});

/* ------------------------------------------------------------------------- */

describe("C4: OTP verification rows are keyed by a hash, not the raw email", () => {
	test("no verification row identifier contains the email", async () => {
		const { email } = await registered(hOtp, "c4-plain");
		await requestOTP(hOtp, email);
		const identifiers = hOtp.db.verificationRows().map((r) => r.identifier);
		expect(identifiers.length).toBeGreaterThan(0);
		for (const identifier of identifiers) {
			expect(identifier.toLowerCase()).not.toContain(email.toLowerCase());
			expect(identifier.toLowerCase()).not.toContain(email.split("@")[0]!.toLowerCase());
		}
	});

	test("identifiers stay within 255 characters for a 254-character email", async () => {
		const email = `${"l".repeat(64)}@${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(56)}.test`;
		expect(email.length).toBe(254);
		await hOtp.register(email, OLD_PASSWORD);
		await requestOTP(hOtp, email);

		const identifiers = hOtp.db.verificationRows().map((r) => r.identifier);
		for (const identifier of identifiers) {
			expect({ identifier, length: identifier.length, ok: identifier.length <= 255 }).toMatchObject({ ok: true });
		}
	});
});

/* ------------------------------------------------------------------------- */

describe("C5: with secondaryStorage, an expired reset link is rejected", () => {
	/**
	 * Map-backed secondary storage. TTLs are recorded but not enforced: a real
	 * store expires keys on its own clock, which a mocked clock does not move,
	 * and TTLs are coarse; the plugin must check `expiresAt` itself.
	 */
	function mapStorage(): SecondaryStorage {
		const store = new Map<string, string>();
		return {
			get: async (key) => store.get(key) ?? null,
			set: async (key, value) => {
				store.set(key, value);
			},
			delete: async (key) => {
				store.delete(key);
			},
			getAndDelete: async (key) => {
				const value = store.get(key) ?? null;
				store.delete(key);
				return value;
			},
		} as SecondaryStorage;
	}

	test("challenge and complete are 400 INVALID_TOKEN after the link's lifetime, and the record is unchanged", async () => {
		const hStore = await createTestHarness({ resetLink: true, authOptions: { secondaryStorage: mapStorage() } });
		const { email } = await registered(hStore, "c5");
		const recordBefore = await hStore.db.registrationRecord(email);
		const token = await requestLink(hStore, email);
		const started = await startResetPassword(hStore.device(), { token }, NEW_PASSWORD);
		expect(started.res.status).toBe(200);

		setSystemTime(new Date(Date.now() + 3_601_000)); // default lifetime is 3600s

		expectCode((await startResetPassword(hStore.device(), { token }, NEW_PASSWORD)).res, 400, "INVALID_TOKEN");
		const complete = await hStore
			.device()
			.post("/opaque/reset-password/complete", { token, registrationRecord: started.registrationRecord });
		expectCode(complete, 400, "INVALID_TOKEN");
		setSystemTime();
		expect(await hStore.db.registrationRecord(email)).toBe(recordBefore);
	});
});
