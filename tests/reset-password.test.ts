/**
 * Forgot / reset password, by emailed link (token) or emailed one-time code
 * (OTP).
 *
 * Endpoints:
 *   POST /opaque/forget-password         { email, method?: "link" | "otp", redirectTo? }
 *   POST /opaque/reset-password/challenge { token | (email + otp), registrationRequest }
 *   POST /opaque/reset-password/complete  { token | (email + otp), registrationRecord }
 */
import { client as opaqueLib, ready } from "@serenity-kit/opaque";
import { afterEach, describe, expect, setSystemTime, test } from "bun:test";
import {
	BASE_PATH,
	createTestHarness,
	type Device,
	ORIGIN,
	randomBase64Url,
	rawResetPassword,
	SESSION_TOKEN_COOKIE,
	startResetPassword,
	type TestHarness,
	UNDESERIALISABLE_RECORD,
	uniqueEmail,
} from "./helpers/harness";

await ready;

/** Link only (default method "link"); core email+password on, to probe token isolation. */
const hLink = await createTestHarness({ resetLink: true, emailAndPassword: true });
/** Link only, 1 second token lifetime. */
const hLinkShort = await createTestHarness({ resetLink: true, plugin: { resetPasswordTokenExpiresIn: 1 } });
/** OTP only (default method "otp"), default OTP options. */
const hOTP = await createTestHarness({ resetOTP: true });
/** OTP only, custom OTP options. */
const hOTPCustom = await createTestHarness({
	resetOTP: true,
	plugin: { resetPasswordOTP: { length: 8, allowedAttempts: 1, expiresIn: 60 } },
});
/** Both delivery methods configured. */
const hBoth = await createTestHarness({ resetLink: true, resetOTP: true });
/** Neither configured. */
const hNone = await createTestHarness();

const OLD_PASSWORD = "old reset password";
const NEW_PASSWORD = "new reset password";

afterEach(() => {
	setSystemTime(); // never leak a mocked clock into other tests
});

/* --------------------------------- helpers -------------------------------- */

async function opaqueUser(h: TestHarness, label: string, loggedInDevices = 0) {
	const email = uniqueEmail(label);
	await h.register(email, OLD_PASSWORD);
	const user = (await h.db.user(email))!;
	const devices: Device[] = [];
	for (let i = 0; i < loggedInDevices; i++) devices.push(await h.loggedInDevice(email, OLD_PASSWORD));
	return { email, user, devices };
}

async function canLogIn(h: TestHarness, email: string, password: string) {
	const res = await h.device().client.signIn.opaque({ email, password });
	return res.error === null && res.data?.success === true;
}

function forget(h: TestHarness, body: { email: string; method?: "link" | "otp"; redirectTo?: string }) {
	return h.device().post("/opaque/forget-password", body);
}

/** Request a reset link; asserts 200 and exactly one new link mail for `email`. */
async function requestLink(h: TestHarness, email: string, redirectTo?: string) {
	const before = h.outbox.resetLinksFor(email).length;
	const res = await forget(h, { email, ...(redirectTo === undefined ? {} : { redirectTo }) });
	expect(res.status).toBe(200);
	const mails = h.outbox.resetLinksFor(email);
	expect(mails.length).toBe(before + 1);
	return { res, mail: mails[mails.length - 1]! };
}

/** Request a reset OTP; asserts 200 and exactly one new OTP mail for `email`. */
async function requestOTP(h: TestHarness, email: string, method?: "otp") {
	const before = h.outbox.resetOTPsFor(email).length;
	const res = await forget(h, { email, ...(method ? { method } : {}) });
	expect(res.status).toBe(200);
	const mails = h.outbox.resetOTPsFor(email);
	expect(mails.length).toBe(before + 1);
	return { res, otp: mails[mails.length - 1]!.otp, mail: mails[mails.length - 1]! };
}

function challenge(h: TestHarness, credential: object, registrationRequest?: string) {
	return h.device().post("/opaque/reset-password/challenge", {
		...credential,
		registrationRequest: registrationRequest ?? opaqueLib.startRegistration({ password: "irrelevant" }).registrationRequest,
	});
}

function complete(h: TestHarness, credential: object, registrationRecord: string) {
	return h.device().post("/opaque/reset-password/complete", { ...credential, registrationRecord });
}

function expectCode(res: { status: number; body: any }, status: number, code: string) {
	expect({ status: res.status, code: res.body?.code }).toEqual({ status, code });
}

const sessionTokenSet = (res: { setCookies: { name: string }[] }) =>
	res.setCookies.map((c) => c.name).includes(SESSION_TOKEN_COOKIE);

/* ------------------------------ forget: link ------------------------------ */

describe("forget password: link", () => {
	test("existing OPAQUE user: 200 { status: true }, sendResetPassword called once with user, token and exact url", async () => {
		const { email, user } = await opaqueUser(hLink, "fp-link");
		const redirectTo = "/reset-password?step=2&x=a b";

		const { res, mail } = await requestLink(hLink, email, redirectTo);

		expect(res.body).toMatchObject({ status: true });
		expect(mail.user.id).toBe(user.id);
		expect(mail.user.email).toBe(email);
		expect(typeof mail.token).toBe("string");
		expect(mail.token.length).toBeGreaterThan(0);
		expect(mail.url).toBe(
			`${ORIGIN}${BASE_PATH}/opaque/reset-password/${mail.token}?callbackURL=${encodeURIComponent(redirectTo)}`,
		);
		expect(mail.request).toBeInstanceOf(Request);
	});

	test("without redirectTo the url's callbackURL is '/' (encoded)", async () => {
		const { email } = await opaqueUser(hLink, "fp-link-noredirect");
		const { mail } = await requestLink(hLink, email);
		expect(mail.url).toBe(`${ORIGIN}${BASE_PATH}/opaque/reset-password/${mail.token}?callbackURL=%2F`);
	});

	test("a trusted absolute redirectTo is accepted", async () => {
		const { email } = await opaqueUser(hLink, "fp-link-abs");
		const redirectTo = `${ORIGIN}/reset`;
		const { mail } = await requestLink(hLink, email, redirectTo);
		expect(mail.url).toEndWith(`?callbackURL=${encodeURIComponent(redirectTo)}`);
	});

	test("each request issues a distinct token", async () => {
		const { email } = await opaqueUser(hLink, "fp-link-distinct");
		const a = await requestLink(hLink, email);
		const b = await requestLink(hLink, email);
		expect(a.mail.token).not.toBe(b.mail.token);
	});

	test("unknown email: identical 200 body and sendResetPassword is NOT called", async () => {
		const { email } = await opaqueUser(hLink, "fp-link-known");
		const known = await forget(hLink, { email, redirectTo: "/r" });
		const totalBefore = hLink.outbox.resetLinks.length;
		const ghostEmail = uniqueEmail("fp-link-ghost");

		const ghost = await forget(hLink, { email: ghostEmail, redirectTo: "/r" });

		expect(known.status).toBe(200);
		expect(ghost.status).toBe(200);
		expect(ghost.body).toMatchObject({ status: true });
		expect(ghost.body).toEqual(known.body);
		expect(hLink.outbox.resetLinks.length).toBe(totalBefore);
		expect(hLink.outbox.resetLinksFor(ghostEmail)).toHaveLength(0);
	});

	test("the email is matched case-insensitively", async () => {
		const { email, user } = await opaqueUser(hLink, "fp-link-case");
		const before = hLink.outbox.resetLinksFor(email).length;
		const res = await forget(hLink, { email: email.toUpperCase() });
		expect(res.status).toBe(200);
		const mails = hLink.outbox.resetLinksFor(email);
		expect(mails.length).toBe(before + 1);
		expect(mails[mails.length - 1]!.user.id).toBe(user.id);
	});

	test("an existing user WITHOUT an OPAQUE account also gets a link (so they can create one)", async () => {
		const email = uniqueEmail("fp-link-noopaque");
		const user = await hLink.db.createUserWithoutOpaque(email);
		const { mail } = await requestLink(hLink, email);
		expect(mail.user.id).toBe(user.id);
	});

	test.each([
		["untrusted absolute URL", "https://evil.example/steal"],
		["protocol-relative URL", "//evil.example/steal"],
	])("%s redirectTo is 403 INVALID_REDIRECT_URL (as core) and nothing is sent", async (_label, redirectTo) => {
		const { email } = await opaqueUser(hLink, "fp-link-evil");
		const before = hLink.outbox.resetLinksFor(email).length;
		const res = await forget(hLink, { email, redirectTo });
		expectCode(res, 403, "INVALID_REDIRECT_URL");
		expect(hLink.outbox.resetLinksFor(email).length).toBe(before);
	});
});

/* ---------------------------- forget: methods ----------------------------- */

describe("forget password: delivery method selection", () => {
	test("neither callback configured: 400 RESET_PASSWORD_METHOD_NOT_CONFIGURED for any method, known or unknown email", async () => {
		const { email } = await opaqueUser(hNone, "fp-none");
		for (const target of [email, uniqueEmail("fp-none-ghost")]) {
			for (const method of [undefined, "link", "otp"] as const) {
				const res = await forget(hNone, { email: target, ...(method ? { method } : {}) });
				expectCode(res, 400, "RESET_PASSWORD_METHOD_NOT_CONFIGURED");
			}
		}
	});

	test("link-only: method 'otp' is 400 RESET_PASSWORD_METHOD_NOT_CONFIGURED; nothing sent", async () => {
		const { email } = await opaqueUser(hLink, "fp-link-otp");
		const before = hLink.outbox.resetLinksFor(email).length;
		expectCode(await forget(hLink, { email, method: "otp" }), 400, "RESET_PASSWORD_METHOD_NOT_CONFIGURED");
		expectCode(
			await forget(hLink, { email: uniqueEmail("ghost"), method: "otp" }),
			400,
			"RESET_PASSWORD_METHOD_NOT_CONFIGURED",
		);
		expect(hLink.outbox.resetLinksFor(email).length).toBe(before);
	});

	test("link-only: explicit method 'link' works", async () => {
		const { email } = await opaqueUser(hLink, "fp-link-explicit");
		const before = hLink.outbox.resetLinksFor(email).length;
		const res = await forget(hLink, { email, method: "link" });
		expect(res.status).toBe(200);
		expect(hLink.outbox.resetLinksFor(email).length).toBe(before + 1);
	});

	test("otp-only: method 'link' is 400 RESET_PASSWORD_METHOD_NOT_CONFIGURED; nothing sent", async () => {
		const { email } = await opaqueUser(hOTP, "fp-otp-link");
		const before = hOTP.outbox.resetOTPsFor(email).length;
		expectCode(await forget(hOTP, { email, method: "link" }), 400, "RESET_PASSWORD_METHOD_NOT_CONFIGURED");
		expect(hOTP.outbox.resetOTPsFor(email).length).toBe(before);
	});

	test("both configured: default is 'link'", async () => {
		const { email } = await opaqueUser(hBoth, "fp-both-default");
		const links = hBoth.outbox.resetLinksFor(email).length;
		const otps = hBoth.outbox.resetOTPsFor(email).length;
		const res = await forget(hBoth, { email });
		expect(res.status).toBe(200);
		expect(hBoth.outbox.resetLinksFor(email).length).toBe(links + 1);
		expect(hBoth.outbox.resetOTPsFor(email).length).toBe(otps);
	});

	test("both configured: method 'otp' calls only the OTP callback, method 'link' only the link callback", async () => {
		const { email } = await opaqueUser(hBoth, "fp-both-select");
		const links = hBoth.outbox.resetLinksFor(email).length;
		const otps = hBoth.outbox.resetOTPsFor(email).length;

		expect((await forget(hBoth, { email, method: "otp" })).status).toBe(200);
		expect(hBoth.outbox.resetLinksFor(email).length).toBe(links);
		expect(hBoth.outbox.resetOTPsFor(email).length).toBe(otps + 1);

		expect((await forget(hBoth, { email, method: "link" })).status).toBe(200);
		expect(hBoth.outbox.resetLinksFor(email).length).toBe(links + 1);
		expect(hBoth.outbox.resetOTPsFor(email).length).toBe(otps + 1);
	});
});

/* --------------------------- link: challenge ------------------------------ */

describe("reset with link token: challenge", () => {
	test("valid token: 200 { challenge }, and it does not consume the token (twice works)", async () => {
		const { email } = await opaqueUser(hLink, "rp-ch");
		const { mail } = await requestLink(hLink, email);

		const first = await challenge(hLink, { token: mail.token });
		expect(first.status).toBe(200);
		expect(first.body).toEqual({ challenge: expect.any(String) });

		const second = await challenge(hLink, { token: mail.token });
		expect(second.status).toBe(200);
		expect(second.body).toEqual({ challenge: expect.any(String) });
	});

	test("unknown token: 400 INVALID_TOKEN", async () => {
		expectCode(await challenge(hLink, { token: randomBase64Url(18) }), 400, "INVALID_TOKEN");
	});

	test("registrationRequest of the wrong length: 400 INVALID_REGISTRATION_REQUEST", async () => {
		const { email } = await opaqueUser(hLink, "rp-ch-badreq");
		const { mail } = await requestLink(hLink, email);
		expectCode(await challenge(hLink, { token: mail.token }, randomBase64Url(16)), 400, "INVALID_REGISTRATION_REQUEST");
	});

	test("token AND email+otp together, or neither: 400 INVALID_TOKEN on both steps", async () => {
		const { email } = await opaqueUser(hBoth, "rp-both-creds");
		const { mail } = await requestLink(hBoth, email);
		const { otp } = await requestOTP(hBoth, email, "otp");
		const both = { token: mail.token, email, otp };

		expectCode(await challenge(hBoth, both), 400, "INVALID_TOKEN");
		expectCode(await challenge(hBoth, {}), 400, "INVALID_TOKEN");
		expectCode(await complete(hBoth, both, UNDESERIALISABLE_RECORD), 400, "INVALID_TOKEN");
		expectCode(await complete(hBoth, {}, UNDESERIALISABLE_RECORD), 400, "INVALID_TOKEN");
		// email without otp / otp without email is "neither" too.
		expectCode(await challenge(hBoth, { email }), 400, "INVALID_TOKEN");
		expectCode(await challenge(hBoth, { otp }), 400, "INVALID_TOKEN");

		// None of that consumed either credential.
		const viaLink = await startResetPassword(hBoth.device(), { token: mail.token }, NEW_PASSWORD);
		expect(viaLink.res.status).toBe(200);
		const viaOtp = await startResetPassword(hBoth.device(), { email, otp }, NEW_PASSWORD);
		expect(viaOtp.res.status).toBe(200);
	});
});

/* ---------------------------- link: complete ------------------------------ */

describe("reset with link token: complete", () => {
	test("success: { status: true }, record replaced, old password rejected, new accepted, no session or cookies", async () => {
		const { email } = await opaqueUser(hLink, "rp-ok");
		const recordBefore = await hLink.db.registrationRecord(email);
		const { mail } = await requestLink(hLink, email);
		const sessionsBefore = await hLink.db.sessionCount();

		const { challenge: ch, complete: done, registrationRecord } = await rawResetPassword(
			hLink.device(),
			{ token: mail.token },
			NEW_PASSWORD,
		);

		expect(ch.status).toBe(200);
		expect(done.status).toBe(200);
		expect(done.body).toEqual({ status: true });
		expect(sessionTokenSet(done)).toBe(false);
		expect(await hLink.db.sessionCount()).toBe(sessionsBefore);
		const recordAfter = await hLink.db.registrationRecord(email);
		expect(recordAfter).toBe(registrationRecord);
		expect(recordAfter).not.toBe(recordBefore);
		expect(await hLink.db.opaqueAccounts(email)).toHaveLength(1);

		expect(await canLogIn(hLink, email, OLD_PASSWORD)).toBe(false);
		expect(await canLogIn(hLink, email, NEW_PASSWORD)).toBe(true);
	});

	test("every session of the user is deleted", async () => {
		const { email, devices } = await opaqueUser(hLink, "rp-revoke", 2);
		for (const d of devices) expect((await d.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
		const { mail } = await requestLink(hLink, email);

		const { complete: done } = await rawResetPassword(hLink.device(), { token: mail.token }, NEW_PASSWORD);

		expect(done.status).toBe(200);
		expect(await hLink.db.sessionsFor(email)).toHaveLength(0);
		for (const d of devices) expect((await d.whoami({ tokenOnly: true })).session).toBeNull();
	});

	test("resetting from a device logged in as that user sets no new session either", async () => {
		const { email, devices } = await opaqueUser(hLink, "rp-self", 1);
		const self = devices[0]!;
		const { mail } = await requestLink(hLink, email);

		const { complete: done } = await rawResetPassword(self, { token: mail.token }, NEW_PASSWORD);

		expect(done.status).toBe(200);
		expect(sessionTokenSet(done)).toBe(false);
		expect(await hLink.db.sessionsFor(email)).toHaveLength(0);
		expect((await self.whoami({ tokenOnly: true })).session).toBeNull();
	});

	test("the token is single use: a second complete (and challenge) is 400 INVALID_TOKEN", async () => {
		const { email } = await opaqueUser(hLink, "rp-once");
		const { mail } = await requestLink(hLink, email);
		const first = await rawResetPassword(hLink.device(), { token: mail.token }, NEW_PASSWORD);
		expect(first.complete.status).toBe(200);
		const recordAfterFirst = await hLink.db.registrationRecord(email);

		expectCode(await complete(hLink, { token: mail.token }, first.registrationRecord), 400, "INVALID_TOKEN");
		expectCode(await challenge(hLink, { token: mail.token }), 400, "INVALID_TOKEN");
		expect(await hLink.db.registrationRecord(email)).toBe(recordAfterFirst);
	});

	test("unknown token on complete: 400 INVALID_TOKEN", async () => {
		const { email } = await opaqueUser(hLink, "rp-unknown");
		const { mail } = await requestLink(hLink, email);
		const { registrationRecord } = await startResetPassword(hLink.device(), { token: mail.token }, NEW_PASSWORD);
		expectCode(await complete(hLink, { token: randomBase64Url(18) }, registrationRecord!), 400, "INVALID_TOKEN");
	});

	test.each([
		["undeserialisable (192 bytes)", UNDESERIALISABLE_RECORD],
		["too short (100 bytes)", randomBase64Url(100)],
	])("%s registrationRecord: 400 INVALID_REGISTRATION_RECORD and the token is NOT consumed", async (_label, bad) => {
		const { email } = await opaqueUser(hLink, "rp-badrec");
		const recordBefore = await hLink.db.registrationRecord(email);
		const { mail } = await requestLink(hLink, email);

		expectCode(await complete(hLink, { token: mail.token }, bad), 400, "INVALID_REGISTRATION_RECORD");
		expect(await hLink.db.registrationRecord(email)).toBe(recordBefore);

		const retry = await rawResetPassword(hLink.device(), { token: mail.token }, NEW_PASSWORD);
		expect(retry.complete.status).toBe(200);
		expect(await canLogIn(hLink, email, NEW_PASSWORD)).toBe(true);
	});

	test("a user with NO OPAQUE account gets one (providerId 'opaque') and can then log in with OPAQUE", async () => {
		const email = uniqueEmail("rp-create");
		const user = await hLink.db.createUserWithoutOpaque(email);
		expect(await hLink.db.opaqueAccounts(email)).toHaveLength(0);
		const { mail } = await requestLink(hLink, email);

		const { complete: done, registrationRecord } = await rawResetPassword(
			hLink.device(),
			{ token: mail.token },
			NEW_PASSWORD,
		);

		expect(done.status).toBe(200);
		const accounts = await hLink.db.opaqueAccounts(email);
		expect(accounts).toHaveLength(1);
		expect(accounts[0]!.userId).toBe(user.id);
		expect((accounts[0] as { registrationRecord?: string }).registrationRecord).toBe(registrationRecord);
		const login = await hLink.device().client.signIn.opaque({ email, password: NEW_PASSWORD });
		expect(login.error).toBeNull();
		expect(login.data?.user.id).toBe(user.id);
	});

	test("a successful reset marks the email verified (link and OTP both prove the mailbox); a failed one does not", async () => {
		const viaLink = await opaqueUser(hLink, "rp-verify-link");
		const viaOtp = await opaqueUser(hOTP, "rp-verify-otp");
		expect((await hLink.db.user(viaLink.email))!.emailVerified).toBe(false);
		expect((await hOTP.db.user(viaOtp.email))!.emailVerified).toBe(false);

		const { mail } = await requestLink(hLink, viaLink.email);
		expectCode(await complete(hLink, { token: mail.token }, UNDESERIALISABLE_RECORD), 400, "INVALID_REGISTRATION_RECORD");
		expect((await hLink.db.user(viaLink.email))!.emailVerified).toBe(false);
		expect((await rawResetPassword(hLink.device(), { token: mail.token }, NEW_PASSWORD)).complete.status).toBe(200);
		expect((await hLink.db.user(viaLink.email))!.emailVerified).toBe(true);

		const { otp } = await requestOTP(hOTP, viaOtp.email);
		const wrong = otp === "000000" ? "111111" : "000000";
		expectCode(await challenge(hOTP, { email: viaOtp.email, otp: wrong }), 400, "INVALID_TOKEN");
		expect((await hOTP.db.user(viaOtp.email))!.emailVerified).toBe(false);
		expect((await rawResetPassword(hOTP.device(), { email: viaOtp.email, otp }, NEW_PASSWORD)).complete.status).toBe(200);
		expect((await hOTP.db.user(viaOtp.email))!.emailVerified).toBe(true);
	});

	test("an OPAQUE reset token is useless at core's POST /reset-password (no credential password can be set with it)", async () => {
		const { email } = await opaqueUser(hLink, "rp-core-iso");
		const { mail } = await requestLink(hLink, email);

		const core = await hLink.device().post("/reset-password", { token: mail.token, newPassword: "plaintext-password-1" });

		expect(core.status).toBe(400);
		expect((await hLink.db.accounts(email)).map((a) => a.providerId)).toEqual(["opaque"]);
		const coreLogin = await hLink.device().post("/sign-in/email", { email, password: "plaintext-password-1" });
		expect(coreLogin.status).toBe(401);
		// ...and core did not burn it either.
		const ours = await rawResetPassword(hLink.device(), { token: mail.token }, NEW_PASSWORD);
		expect(ours.complete.status).toBe(200);
	});
});

/* ------------------------------ link: expiry ------------------------------ */

describe("reset with link token: expiry", () => {
	test("resetPasswordTokenExpiresIn: 1 → after 2s both challenge and complete are 400 INVALID_TOKEN", async () => {
		const { email } = await opaqueUser(hLinkShort, "rp-exp");
		const recordBefore = await hLinkShort.db.registrationRecord(email);
		const { mail } = await requestLink(hLinkShort, email);
		const started = await startResetPassword(hLinkShort.device(), { token: mail.token }, NEW_PASSWORD);
		expect(started.res.status).toBe(200);

		setSystemTime(new Date(Date.now() + 2_000));

		expectCode(await challenge(hLinkShort, { token: mail.token }), 400, "INVALID_TOKEN");
		expectCode(await complete(hLinkShort, { token: mail.token }, started.registrationRecord!), 400, "INVALID_TOKEN");
		expect(await hLinkShort.db.registrationRecord(email)).toBe(recordBefore);
	});

	test("default lifetime is 3600s", async () => {
		const { email } = await opaqueUser(hLink, "rp-exp-default");
		const { mail } = await requestLink(hLink, email);
		const t0 = Date.now();

		setSystemTime(new Date(t0 + 3_500_000));
		expect((await challenge(hLink, { token: mail.token })).status).toBe(200);

		setSystemTime(new Date(t0 + 3_601_000));
		expectCode(await challenge(hLink, { token: mail.token }), 400, "INVALID_TOKEN");
	});
});

/* ------------------------ link: the emailed URL itself ------------------------ */

describe("reset link: GET of the emailed url (mirrors core GET /reset-password/:token)", () => {
	test("a valid token redirects to callbackURL with ?token=", async () => {
		const { email } = await opaqueUser(hLink, "rp-get");
		const { mail } = await requestLink(hLink, email, "/reset");

		const res = await hLink.device().request(mail.url.slice(`${ORIGIN}${BASE_PATH}`.length), { method: "GET" });

		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toBe(`${ORIGIN}/reset?token=${mail.token}`);
		// Following the link does not consume the token.
		expect((await challenge(hLink, { token: mail.token })).status).toBe(200);
	});

	test("an unknown token redirects to callbackURL with ?error=INVALID_TOKEN", async () => {
		const res = await hLink
			.device()
			.request(`/opaque/reset-password/${randomBase64Url(18)}?callbackURL=%2Freset`, { method: "GET" });
		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toBe(`${ORIGIN}/reset?error=INVALID_TOKEN`);
	});

	test("an expired token redirects to callbackURL with ?error=INVALID_TOKEN", async () => {
		const { email } = await opaqueUser(hLinkShort, "rp-get-expired");
		const { mail } = await requestLink(hLinkShort, email, "/reset");
		setSystemTime(new Date(Date.now() + 2_000));

		const res = await hLinkShort.device().request(mail.url.slice(`${ORIGIN}${BASE_PATH}`.length), { method: "GET" });

		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toBe(`${ORIGIN}/reset?error=INVALID_TOKEN`);
	});

	test("an untrusted callbackURL is 403 and does not redirect", async () => {
		const { email } = await opaqueUser(hLink, "rp-get-evil");
		const { mail } = await requestLink(hLink, email);

		const res = await hLink.device().request(
			`/opaque/reset-password/${mail.token}?callbackURL=${encodeURIComponent("https://evil.example/steal")}`,
			{ method: "GET" },
		);

		expect(res.status).toBe(403);
		expect(res.headers.get("location")).toBeNull();
	});
});

/* ------------------------------ forget: OTP ------------------------------- */

describe("forget password: OTP", () => {
	test("existing OPAQUE user: 200 { status: true }, sendResetPasswordOTP called once with the user and a 6-digit code", async () => {
		const { email, user } = await opaqueUser(hOTP, "fp-otp");
		const { res, mail } = await requestOTP(hOTP, email);
		expect(res.body).toMatchObject({ status: true });
		expect(mail.user.id).toBe(user.id);
		expect(mail.otp).toMatch(/^\d{6}$/);
		expect(mail.request).toBeInstanceOf(Request);
	});

	test("resetPasswordOTP.length sets the number of digits", async () => {
		const { email } = await opaqueUser(hOTPCustom, "fp-otp-len");
		const { otp } = await requestOTP(hOTPCustom, email);
		expect(otp).toMatch(/^\d{8}$/);
	});

	test("unknown email: identical 200 body and the OTP callback is NOT called", async () => {
		const { email } = await opaqueUser(hOTP, "fp-otp-known");
		const known = await forget(hOTP, { email });
		const totalBefore = hOTP.outbox.resetOTPs.length;
		const ghost = await forget(hOTP, { email: uniqueEmail("fp-otp-ghost") });
		expect(known.status).toBe(200);
		expect(ghost.status).toBe(200);
		expect(ghost.body).toEqual(known.body);
		expect(hOTP.outbox.resetOTPs.length).toBe(totalBefore);
	});

	test("the OTP is not stored in plaintext in the verification table", async () => {
		// 8-digit codes (hOTPCustom): a chance occurrence of the code inside
		// random ids / hashes is negligible, so any hit means plaintext.
		const { email } = await opaqueUser(hOTPCustom, "fp-otp-hashed");
		const { otp } = await requestOTP(hOTPCustom, email);
		const rows = hOTPCustom.db.verificationRows();
		expect(rows.length).toBeGreaterThan(0);
		expect(JSON.stringify(rows)).not.toContain(otp);
	});

	test("a second request replaces the first code (one live code per email)", async () => {
		const { email } = await opaqueUser(hOTP, "fp-otp-replace");
		const first = await requestOTP(hOTP, email);
		let second = await requestOTP(hOTP, email);
		while (second.otp === first.otp) second = await requestOTP(hOTP, email); // 1e-6 collision guard

		expectCode(await challenge(hOTP, { email, otp: first.otp }), 400, "INVALID_TOKEN");
		const ok = await rawResetPassword(hOTP.device(), { email, otp: second.otp }, NEW_PASSWORD);
		expect(ok.complete.status).toBe(200);
	});
});

/* ------------------------------- OTP: reset ------------------------------- */

describe("reset with OTP", () => {
	test("correct code: challenge 200 (twice, not consumed), complete 200 replaces the record and revokes every session", async () => {
		const { email, devices } = await opaqueUser(hOTP, "rp-otp-ok", 2);
		const recordBefore = await hOTP.db.registrationRecord(email);
		const { otp } = await requestOTP(hOTP, email);

		expect((await challenge(hOTP, { email, otp })).status).toBe(200);
		const { challenge: ch, complete: done, registrationRecord } = await rawResetPassword(
			hOTP.device(),
			{ email, otp },
			NEW_PASSWORD,
		);

		expect(ch.status).toBe(200);
		expect(ch.body).toEqual({ challenge: expect.any(String) });
		expect(done.status).toBe(200);
		expect(done.body).toEqual({ status: true });
		expect(sessionTokenSet(done)).toBe(false);
		expect(await hOTP.db.sessionsFor(email)).toHaveLength(0);
		for (const d of devices) expect((await d.whoami({ tokenOnly: true })).session).toBeNull();
		expect(await hOTP.db.registrationRecord(email)).toBe(registrationRecord);
		expect(registrationRecord).not.toBe(recordBefore!);

		expect(await canLogIn(hOTP, email, OLD_PASSWORD)).toBe(false);
		expect(await canLogIn(hOTP, email, NEW_PASSWORD)).toBe(true);
	});

	test("the code is consumed on success: reuse is 400 INVALID_TOKEN", async () => {
		const { email } = await opaqueUser(hOTP, "rp-otp-once");
		const { otp } = await requestOTP(hOTP, email);
		const first = await rawResetPassword(hOTP.device(), { email, otp }, NEW_PASSWORD);
		expect(first.complete.status).toBe(200);

		expectCode(await complete(hOTP, { email, otp }, first.registrationRecord), 400, "INVALID_TOKEN");
		expectCode(await challenge(hOTP, { email, otp }), 400, "INVALID_TOKEN");
	});

	test("the email in the reset request is matched case-insensitively", async () => {
		const { email } = await opaqueUser(hOTP, "rp-otp-case");
		const { otp } = await requestOTP(hOTP, email);
		const done = await rawResetPassword(hOTP.device(), { email: email.toUpperCase(), otp }, NEW_PASSWORD);
		expect(done.complete.status).toBe(200);
		expect(await canLogIn(hOTP, email, NEW_PASSWORD)).toBe(true);
	});

	test("wrong code: 400 INVALID_TOKEN on challenge and complete; record unchanged", async () => {
		const { email } = await opaqueUser(hOTP, "rp-otp-wrong");
		const recordBefore = await hOTP.db.registrationRecord(email);
		const { otp } = await requestOTP(hOTP, email);
		const wrong = otp === "000000" ? "111111" : "000000";

		expectCode(await challenge(hOTP, { email, otp: wrong }), 400, "INVALID_TOKEN");
		const { registrationRecord } = await startResetPassword(hOTP.device(), { email, otp }, NEW_PASSWORD);
		expectCode(await complete(hOTP, { email, otp: wrong }, registrationRecord!), 400, "INVALID_TOKEN");
		expect(await hOTP.db.registrationRecord(email)).toBe(recordBefore);
	});

	test("after allowedAttempts (default 3) wrong completes, the CORRECT code is 400 INVALID_TOKEN (the code is dead); a new request issues a working code", async () => {
		const { email } = await opaqueUser(hOTP, "rp-otp-lock");
		const recordBefore = await hOTP.db.registrationRecord(email);
		const { otp } = await requestOTP(hOTP, email);
		const { registrationRecord } = await startResetPassword(hOTP.device(), { email, otp }, NEW_PASSWORD);
		const wrong = otp === "000000" ? "111111" : "000000";

		for (let i = 0; i < 3; i++) {
			expectCode(await complete(hOTP, { email, otp: wrong }, registrationRecord!), 400, "INVALID_TOKEN");
		}
		expectCode(await complete(hOTP, { email, otp }, registrationRecord!), 400, "INVALID_TOKEN");
		expect(await hOTP.db.registrationRecord(email)).toBe(recordBefore);
		// Still dead on any later try.
		expectCode(await challenge(hOTP, { email, otp }), 400, "INVALID_TOKEN");

		const fresh = await requestOTP(hOTP, email);
		const ok = await rawResetPassword(hOTP.device(), { email, otp: fresh.otp }, NEW_PASSWORD);
		expect(ok.complete.status).toBe(200);
		expect(await canLogIn(hOTP, email, NEW_PASSWORD)).toBe(true);
	});

	test("wrong codes submitted to the CHALLENGE step count as attempts too (no free guessing oracle)", async () => {
		const { email } = await opaqueUser(hOTP, "rp-otp-lock-ch");
		const { otp } = await requestOTP(hOTP, email);
		const wrong = otp === "000000" ? "111111" : "000000";

		for (let i = 0; i < 3; i++) expectCode(await challenge(hOTP, { email, otp: wrong }), 400, "INVALID_TOKEN");
		expectCode(await challenge(hOTP, { email, otp }), 400, "INVALID_TOKEN");
	});

	test("resetPasswordOTP.allowedAttempts is honoured (1 → one wrong try locks the code)", async () => {
		const { email } = await opaqueUser(hOTPCustom, "rp-otp-lock1");
		const { otp } = await requestOTP(hOTPCustom, email);
		const wrong = otp === "00000000" ? "11111111" : "00000000";
		expectCode(await challenge(hOTPCustom, { email, otp: wrong }), 400, "INVALID_TOKEN");
		expectCode(await challenge(hOTPCustom, { email, otp }), 400, "INVALID_TOKEN");
	});

	test("lockout does not enumerate: forget + 4 wrong guesses give IDENTICAL responses (status and body) for a known and an unknown email", async () => {
		const { email } = await opaqueUser(hOTP, "rp-otp-enum-known");
		const ghost = uniqueEmail("rp-otp-enum-ghost");

		const knownForgot = await forget(hOTP, { email });
		const realOtp = hOTP.outbox.resetOTPsFor(email).at(-1)!.otp;
		const guesses = ["000000", "111111", "222222", "333333", "444444"].filter((g) => g !== realOtp).slice(0, 4);

		async function transcript(target: string, forgot: { status: number; body: unknown }) {
			const out = [{ status: forgot.status, body: forgot.body }];
			for (const otp of guesses) {
				const res = await challenge(hOTP, { email: target, otp });
				out.push({ status: res.status, body: res.body });
			}
			return out;
		}

		const known = await transcript(email, knownForgot);
		const unknown = await transcript(ghost, await forget(hOTP, { email: ghost }));

		expect(unknown).toEqual(known);
	});

	test("expired code (default 300s): challenge and complete are 400 INVALID_TOKEN", async () => {
		const { email } = await opaqueUser(hOTP, "rp-otp-exp");
		const recordBefore = await hOTP.db.registrationRecord(email);
		const { otp } = await requestOTP(hOTP, email);
		const started = await startResetPassword(hOTP.device(), { email, otp }, NEW_PASSWORD);
		expect(started.res.status).toBe(200);

		setSystemTime(new Date(Date.now() + 301_000));

		expectCode(await challenge(hOTP, { email, otp }), 400, "INVALID_TOKEN");
		expectCode(await complete(hOTP, { email, otp }, started.registrationRecord!), 400, "INVALID_TOKEN");
		expect(await hOTP.db.registrationRecord(email)).toBe(recordBefore);
	});

	test("resetPasswordOTP.expiresIn is honoured (60s)", async () => {
		const { email } = await opaqueUser(hOTPCustom, "rp-otp-exp60");
		const { otp } = await requestOTP(hOTPCustom, email);
		const t0 = Date.now();
		setSystemTime(new Date(t0 + 50_000));
		expect((await challenge(hOTPCustom, { email, otp })).status).toBe(200);
		setSystemTime(new Date(t0 + 61_000));
		expectCode(await challenge(hOTPCustom, { email, otp }), 400, "INVALID_TOKEN");
	});

	test("a code issued for email A cannot reset email B", async () => {
		const a = await opaqueUser(hOTP, "rp-otp-a");
		const b = await opaqueUser(hOTP, "rp-otp-b");
		const recordB = await hOTP.db.registrationRecord(b.email);
		const otpA = (await requestOTP(hOTP, a.email)).otp;
		let otpB = (await requestOTP(hOTP, b.email)).otp;
		while (otpB === otpA) otpB = (await requestOTP(hOTP, b.email)).otp;
		const { registrationRecord } = await startResetPassword(hOTP.device(), { email: a.email, otp: otpA }, "attacker");

		expectCode(await challenge(hOTP, { email: b.email, otp: otpA }), 400, "INVALID_TOKEN");
		expectCode(await complete(hOTP, { email: b.email, otp: otpA }, registrationRecord!), 400, "INVALID_TOKEN");
		expect(await hOTP.db.registrationRecord(b.email)).toBe(recordB);
		expect(await canLogIn(hOTP, b.email, OLD_PASSWORD)).toBe(true);
	});

	test("a malformed registrationRecord neither consumes the code nor counts as an attempt", async () => {
		const { email } = await opaqueUser(hOTP, "rp-otp-badrec");
		const { otp } = await requestOTP(hOTP, email);

		// More malformed tries than allowedAttempts (3), all with the correct code.
		for (let i = 0; i < 4; i++) {
			expectCode(await complete(hOTP, { email, otp }, UNDESERIALISABLE_RECORD), 400, "INVALID_REGISTRATION_RECORD");
		}

		const ok = await rawResetPassword(hOTP.device(), { email, otp }, NEW_PASSWORD);
		expect(ok.complete.status).toBe(200);
		expect(await canLogIn(hOTP, email, NEW_PASSWORD)).toBe(true);
	});

	test("an OTP cannot be used as a link token and vice versa", async () => {
		const { email } = await opaqueUser(hBoth, "rp-otp-cross");
		const { otp } = await requestOTP(hBoth, email, "otp");
		const { mail } = await requestLink(hBoth, email);
		expectCode(await challenge(hBoth, { token: otp }), 400, "INVALID_TOKEN");
		expectCode(await challenge(hBoth, { email, otp: mail.token }), 400, "INVALID_TOKEN");
	});
});

/* ------------------------------ client flows ------------------------------ */

describe("reset with OTP: a correct code at the challenge step is only read, never consumed and restored", () => {
	/** Every create / delete of an OTP verification row, via databaseHooks. */
	const otpRowEvents: Array<{ op: "create" | "delete"; value: string }> = [];
	const isOTPRow = (row: { identifier?: string } | null | undefined) =>
		typeof row?.identifier === "string" && row.identifier.startsWith("opaque-reset-otp:");
	const hHooks = createTestHarness({
		resetOTP: true,
		authOptions: {
			databaseHooks: {
				verification: {
					create: {
						before: async (row) => {
							if (isOTPRow(row)) otpRowEvents.push({ op: "create", value: String(row.value) });
						},
					},
					delete: {
						before: async (row) => {
							if (isOTPRow(row)) otpRowEvents.push({ op: "delete", value: String(row.value) });
						},
					},
				},
			},
		},
	});

	test("correct code: no delete / consume and no re-create of the OTP row; a wrong code does count an attempt (consume + restore)", async () => {
		const hh = await hHooks;
		const { email } = await opaqueUser(hh, "rp-otp-read");
		const { otp } = await requestOTP(hh, email);

		otpRowEvents.length = 0;
		expect((await challenge(hh, { email, otp })).status).toBe(200);
		expect((await challenge(hh, { email, otp })).status).toBe(200);
		expect(otpRowEvents).toEqual([]);

		const wrong = otp === "000000" ? "111111" : "000000";
		expectCode(await challenge(hh, { email, otp: wrong }), 400, "INVALID_TOKEN");
		expect(otpRowEvents.map((e) => e.op)).toEqual(["delete", "create"]);
		expect(otpRowEvents[1]!.value).not.toBe(otpRowEvents[0]!.value); // one more attempt recorded

		// The code still works after the wrong guess.
		expect((await rawResetPassword(hh.device(), { email, otp }, NEW_PASSWORD)).complete.status).toBe(200);
	});

	test("a correct challenge and a correct complete fired concurrently: the complete succeeds", async () => {
		const hh = await hHooks;
		for (let round = 0; round < 3; round++) {
			const { email } = await opaqueUser(hh, "rp-otp-concurrent");
			const { otp } = await requestOTP(hh, email);
			const started = await startResetPassword(hh.device(), { email, otp }, NEW_PASSWORD);
			expect(started.res.status).toBe(200);

			const [ch, done] = await Promise.all([
				challenge(hh, { email, otp }),
				complete(hh, { email, otp }, started.registrationRecord!),
			]);

			expect({ round, complete: done.status }).toEqual({ round, complete: 200 });
			expect([200, 400]).toContain(ch.status);
			expect(await canLogIn(hh, email, NEW_PASSWORD)).toBe(true);
		}
	});
});

describe("reset password: client", () => {
	test("link: forgetPassword → resetPassword({ token, newPassword }) → signIn with the new password", async () => {
		const { email } = await opaqueUser(hLink, "rp-client-link", 1);
		const client = hLink.device().client;

		const forgot = await client.opaque.forgetPassword({ email, redirectTo: "/reset" });
		expect(forgot.error).toBeNull();
		expect(forgot.data).toMatchObject({ status: true });
		const mail = hLink.outbox.resetLinksFor(email).at(-1)!;
		expect(mail.url).toEndWith("?callbackURL=%2Freset");

		const reset = await client.opaque.resetPassword({ token: mail.token, newPassword: NEW_PASSWORD });
		expect(reset.error).toBeNull();
		expect(reset.data).toEqual({ status: true });

		expect(await hLink.db.sessionsFor(email)).toHaveLength(0);
		const login = await hLink.device().client.signIn.opaque({ email, password: NEW_PASSWORD });
		expect(login.error).toBeNull();
		expect(login.data?.success).toBe(true);
		expect(await canLogIn(hLink, email, OLD_PASSWORD)).toBe(false);
	});

	test("otp: forgetPassword({ method: 'otp' }) → resetPassword({ email, otp, newPassword }) → signIn with the new password", async () => {
		const { email } = await opaqueUser(hBoth, "rp-client-otp");
		const client = hBoth.device().client;
		const linksBefore = hBoth.outbox.resetLinksFor(email).length;

		const forgot = await client.opaque.forgetPassword({ email, method: "otp" });
		expect(forgot.error).toBeNull();
		expect(forgot.data).toMatchObject({ status: true });
		expect(hBoth.outbox.resetLinksFor(email).length).toBe(linksBefore);
		const { otp } = hBoth.outbox.resetOTPsFor(email).at(-1)!;

		const reset = await client.opaque.resetPassword({ email, otp, newPassword: NEW_PASSWORD });
		expect(reset.error).toBeNull();
		expect(reset.data).toEqual({ status: true });

		const login = await hBoth.device().client.signIn.opaque({ email, password: NEW_PASSWORD });
		expect(login.error).toBeNull();
		expect(login.data?.success).toBe(true);
	});

	test("resetPassword with an invalid token returns { data: null, error: { status: 400, code: INVALID_TOKEN } }", async () => {
		const res = await hLink.device().client.opaque.resetPassword({ token: randomBase64Url(18), newPassword: NEW_PASSWORD });
		expect(res.data).toBeNull();
		expect(res.error).toMatchObject({ status: 400, code: "INVALID_TOKEN" });
	});

	test("forgetPassword with an unconfigured method surfaces 400 RESET_PASSWORD_METHOD_NOT_CONFIGURED", async () => {
		const res = await hLink.device().client.opaque.forgetPassword({ email: uniqueEmail("x"), method: "otp" });
		expect(res.data).toBeNull();
		expect(res.error).toMatchObject({ status: 400, code: "RESET_PASSWORD_METHOD_NOT_CONFIGURED" });
	});
});
