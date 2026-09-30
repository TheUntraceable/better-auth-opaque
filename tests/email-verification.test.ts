/**
 * Email verification with OPAQUE, mirroring Better Auth core's
 * `/sign-up/email` + `/sign-in/email` semantics:
 *  - sign-up sends a verification email iff `emailVerification.sendOnSignUp`
 *    (falling back to `requireEmailVerification` when unset), only for a
 *    newly created user;
 *  - with the plugin's `requireEmailVerification`, a login whose proof is
 *    VALID but whose email is unverified is 403 EMAIL_NOT_VERIFIED with no
 *    session, and re-sends the email iff `sendOnSignIn`. The proof is checked
 *    first: a wrong password is a plain 401 and sends nothing.
 */
import { ready } from "@serenity-kit/opaque";
import { describe, expect, test } from "bun:test";
import {
	BASE_PATH,
	createTestHarness,
	forgedLoginPayload,
	ORIGIN,
	rawRegister,
	rawResetPassword,
	SESSION_TOKEN_COOKIE,
	startChangePassword,
	startSetPassword,
	type TestHarness,
	uniqueEmail,
	validLoginPayload,
} from "./helpers/harness";

await ready;

const FLAGS = { sendOnSignUp: true, sendOnSignIn: true, autoSignInAfterVerification: false };

/** requireEmailVerification: true, send on sign-up and sign-in. */
const hReq = await createTestHarness({
	verification: FLAGS,
	plugin: { requireEmailVerification: true, setPassword: { enabled: true } },
	resetLink: true,
	emailAndPassword: true,
});
/** requireEmailVerification left at its default (false). */
const hOpt = await createTestHarness({ verification: FLAGS });
/** requireEmailVerification: true, but never send automatically. */
const hQuiet = await createTestHarness({
	verification: { sendOnSignUp: false, sendOnSignIn: false, autoSignInAfterVerification: false },
	plugin: { requireEmailVerification: true },
});
/** requireEmailVerification: true, sendOnSignUp unset (core falls back to requireEmailVerification). */
const hImplicit = await createTestHarness({ verification: {}, plugin: { requireEmailVerification: true } });
/** insecureCreateSessionOnRegister, but verification is required. */
const hAutoReq = await createTestHarness({
	verification: FLAGS,
	plugin: { requireEmailVerification: true, insecureCreateSessionOnRegister: true },
});

const PASSWORD = "verify me password";

function mails(h: TestHarness, email: string) {
	return h.outbox.verificationEmailsFor(email).length;
}

async function verifyWithToken(h: TestHarness, token: string) {
	return h.device().request(`/verify-email?token=${encodeURIComponent(token)}`, { method: "GET" });
}

/** Registers `email` and returns the verification mail sent for it (asserting exactly one). */
async function registerExpectingMail(h: TestHarness, label: string) {
	const email = uniqueEmail(label);
	const before = mails(h, email);
	await h.register(email, PASSWORD);
	const sent = h.outbox.verificationEmailsFor(email);
	expect(sent.length).toBe(before + 1);
	return { email, mail: sent[sent.length - 1]! };
}

/** Registers `email` (no expectation about sign-up mail); the user starts unverified. */
async function registerUser(h: TestHarness, label: string) {
	const email = uniqueEmail(label);
	await h.register(email, PASSWORD);
	expect((await h.db.user(email))!.emailVerified).toBe(false);
	return { email };
}

/** Raw login with the CORRECT password; returns the /sign-in/opaque/complete response. */
async function rawLogin(h: TestHarness, email: string, password = PASSWORD) {
	const device = h.device();
	const res = await device.post("/sign-in/opaque/complete", await validLoginPayload(device, email, password));
	return { device, res };
}

describe("email verification: on sign-up", () => {
	test("sendOnSignUp: new registration sends one email for the new user; its token verifies the email via core GET /verify-email", async () => {
		const { email, mail } = await registerExpectingMail(hReq, "ev-signup");
		const user = (await hReq.db.user(email))!;

		expect(user.emailVerified).toBe(false);
		expect(mail.user.id).toBe(user.id);
		expect(mail.user.email).toBe(email);
		expect(typeof mail.token).toBe("string");
		expect(mail.url.startsWith(`${ORIGIN}${BASE_PATH}/verify-email?token=${mail.token}`)).toBe(true);
		expect(mail.request).toBeInstanceOf(Request);

		const res = await verifyWithToken(hReq, mail.token);
		expect(res.status).toBe(200);
		expect((await hReq.db.user(email))!.emailVerified).toBe(true);
	});

	test("duplicate-email registration sends nothing (no enumeration)", async () => {
		const { email } = await registerExpectingMail(hReq, "ev-dup");
		const before = mails(hReq, email);

		const second = await rawRegister(hReq.device(), email, "other password");

		expect(second.complete.status).toBe(201);
		expect(mails(hReq, email)).toBe(before);
	});

	test("sendOnSignUp is independent of requireEmailVerification (sent with the default false too)", async () => {
		await registerExpectingMail(hOpt, "ev-opt-signup");
	});

	test("sendOnSignUp: false sends nothing", async () => {
		const email = uniqueEmail("ev-quiet-signup");
		await hQuiet.register(email, PASSWORD);
		expect(mails(hQuiet, email)).toBe(0);
	});

	test("sendOnSignUp unset falls back to requireEmailVerification (true → sent)", async () => {
		await registerExpectingMail(hImplicit, "ev-implicit");
	});
});

describe("email verification: callbackURL via the client", () => {
	test("signUp.opaque({ callbackURL }) sends it to the complete step and the verification link carries it", async () => {
		const email = uniqueEmail("ev-cb-signup");
		const device = hReq.device();
		const callbackURL = "/welcome?from=signup";

		const res = await device.client.signUp.opaque({ email, name: "Callback", password: PASSWORD, callbackURL });

		expect(res.error).toBeNull();
		expect(device.requestsTo("/sign-up/opaque/complete").at(-1)!.body.callbackURL).toBe(callbackURL);
		const mail = hReq.outbox.verificationEmailsFor(email).at(-1);
		expect(mail).toBeDefined();
		expect(new URL(mail!.url).searchParams.get("callbackURL")).toBe(callbackURL);
	});

	test("signIn.opaque({ callbackURL }) sends it to the complete step and the re-sent verification link carries it", async () => {
		const { email } = await registerUser(hReq, "ev-cb-signin");
		const device = hReq.device();
		const callbackURL = "/welcome?from=signin";
		const before = mails(hReq, email);

		const res = await device.client.signIn.opaque({ email, password: PASSWORD, callbackURL });

		expect(res.error).toMatchObject({ status: 403, code: "EMAIL_NOT_VERIFIED" });
		expect(device.requestsTo("/sign-in/opaque/complete").at(-1)!.body.callbackURL).toBe(callbackURL);
		expect(mails(hReq, email)).toBe(before + 1);
		const mail = hReq.outbox.verificationEmailsFor(email).at(-1)!;
		expect(new URL(mail.url).searchParams.get("callbackURL")).toBe(callbackURL);
	});

	test("without callbackURL the link's callbackURL is '/'", async () => {
		const { mail } = await registerExpectingMail(hReq, "ev-cb-default");
		expect(new URL(mail.url).searchParams.get("callbackURL")).toBe("/");
	});
});

describe("email verification: insecureCreateSessionOnRegister", () => {
	test("does not sign in a new user while verification is required", async () => {
		const email = uniqueEmail("ev-autosession");
		const device = hAutoReq.device();
		const sessionsBefore = await hAutoReq.db.sessionCount();

		const res = await device.client.signUp.opaque({ email, name: "Auto", password: PASSWORD });

		expect(res.error).toBeNull();
		expect(device.jar.has(SESSION_TOKEN_COOKIE)).toBe(false);
		expect(await hAutoReq.db.sessionCount()).toBe(sessionsBefore);
		expect(hAutoReq.outbox.verificationEmailsFor(email)).toHaveLength(1);
	});
});

describe("email verification: requireEmailVerification on sign-in", () => {
	test("unverified + correct password: 403 EMAIL_NOT_VERIFIED, no session, no cookies, and one email is sent (sendOnSignIn)", async () => {
		const { email } = await registerUser(hReq, "ev-block");
		const user = (await hReq.db.user(email))!;
		const before = mails(hReq, email);
		const sessionsBefore = await hReq.db.sessionCount();

		const { device, res } = await rawLogin(hReq, email);

		expect(res.status).toBe(403);
		expect(res.body?.code).toBe("EMAIL_NOT_VERIFIED");
		expect(res.setCookies.map((c) => c.name)).not.toContain(SESSION_TOKEN_COOKIE);
		expect(device.jar.has(SESSION_TOKEN_COOKIE)).toBe(false);
		expect(await hReq.db.sessionCount()).toBe(sessionsBefore);
		expect((await device.whoami()).session).toBeNull();

		const sent = hReq.outbox.verificationEmailsFor(email);
		expect(sent.length).toBe(before + 1);
		expect(sent[sent.length - 1]!.user.id).toBe(user.id);
	});

	test("the email sent on sign-in carries a working verification token", async () => {
		const { email } = await registerUser(hReq, "ev-signin-token");
		await rawLogin(hReq, email);
		const mail = hReq.outbox.verificationEmailsFor(email).at(-1);
		expect(mail).toBeDefined();
		expect((await verifyWithToken(hReq, mail!.token)).status).toBe(200);
		expect((await hReq.db.user(email))!.emailVerified).toBe(true);
		expect((await rawLogin(hReq, email)).res.status).toBe(200);
	});

	test("via the client: { data: null, error: { status: 403, code: EMAIL_NOT_VERIFIED } } and no session cookie", async () => {
		const { email } = await registerUser(hReq, "ev-block-client");
		const device = hReq.device();
		const res = await device.client.signIn.opaque({ email, password: PASSWORD });
		expect(res.data).toBeNull();
		expect(res.error).toMatchObject({ status: 403, code: "EMAIL_NOT_VERIFIED" });
		expect(device.jar.has(SESSION_TOKEN_COOKIE)).toBe(false);
	});

	test("unverified + WRONG password: 401 INVALID_EMAIL_OR_PASSWORD and NO email (proof is checked first)", async () => {
		const { email } = await registerUser(hReq, "ev-wrong");
		const before = mails(hReq, email);

		const res = await hReq.device().post("/sign-in/opaque/complete", await forgedLoginPayload(hReq.device(), email));
		expect(res.status).toBe(401);
		expect(res.body?.code).toBe("INVALID_EMAIL_OR_PASSWORD");

		const viaClient = await hReq.device().client.signIn.opaque({ email, password: "wrong password" });
		expect(viaClient.data).toBeNull();
		expect(viaClient.error).toMatchObject({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });

		expect(mails(hReq, email)).toBe(before);
	});

	test("after verifying, login succeeds and sends nothing", async () => {
		const { email } = await registerUser(hReq, "ev-after");
		await hReq.db.setEmailVerified(email, true);
		const before = mails(hReq, email);

		const { device, res } = await rawLogin(hReq, email);

		expect(res.status).toBe(200);
		expect(res.body?.success).toBe(true);
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
		expect(mails(hReq, email)).toBe(before);
	});

	test("sendOnSignIn: false → still 403 EMAIL_NOT_VERIFIED, but no email", async () => {
		const email = uniqueEmail("ev-quiet-signin");
		await hQuiet.register(email, PASSWORD);
		const { res } = await rawLogin(hQuiet, email);
		expect(res.status).toBe(403);
		expect(res.body?.code).toBe("EMAIL_NOT_VERIFIED");
		expect(mails(hQuiet, email)).toBe(0);
	});

	test("requireEmailVerification default (false): an unverified user logs in and nothing is sent on sign-in", async () => {
		const { email } = await registerUser(hOpt, "ev-opt");
		const before = mails(hOpt, email);

		const { device, res } = await rawLogin(hOpt, email);

		expect(res.status).toBe(200);
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
		expect(mails(hOpt, email)).toBe(before);
	});
});

describe("email verification: other flows are unaffected by verification state", () => {
	test("change password works for a session whose user is (now) unverified, and sends nothing", async () => {
		const { email } = await registerUser(hReq, "ev-chpw");
		await hReq.db.setEmailVerified(email, true);
		const device = await hReq.loggedInDevice(email, PASSWORD);
		await hReq.db.setEmailVerified(email, false);
		const before = mails(hReq, email);

		const started = await startChangePassword(device, PASSWORD, "changed password");
		const res = await device.post("/opaque/change-password/complete", {
			loginResult: started.loginResult,
			registrationRecord: started.registrationRecord,
			encryptedServerState: started.encryptedServerState,
		});

		expect(res.status).toBe(200);
		expect(mails(hReq, email)).toBe(before);
	});

	test("set password works for an unverified logged-in user", async () => {
		const email = uniqueEmail("ev-setpw");
		const device = await hReq.coreSignUp(email);
		expect((await hReq.db.user(email))!.emailVerified).toBe(false);

		const started = await startSetPassword(device, "set password");
		expect(started.res.status).toBe(200);
		const res = await device.post("/opaque/set-password/complete", { registrationRecord: started.registrationRecord });
		expect(res.status).toBe(200);
		expect(await hReq.db.opaqueAccounts(email)).toHaveLength(1);
	});

	test("forgot/reset password works for an unverified user", async () => {
		const { email } = await registerUser(hReq, "ev-reset");
		const forgot = await hReq.device().post("/opaque/forget-password", { email });
		expect(forgot.status).toBe(200);
		const link = hReq.outbox.resetLinksFor(email).at(-1);
		expect(link).toBeDefined();

		const { complete } = await rawResetPassword(hReq.device(), { token: link!.token }, "reset password");
		expect(complete.status).toBe(200);
	});
});
