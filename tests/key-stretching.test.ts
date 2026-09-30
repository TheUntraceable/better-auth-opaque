/**
 * `opaqueClient({ keyStretching })`: the client's Argon2id configuration is
 * forwarded to every OPAQUE client operation that stretches the password
 * (`finishRegistration`, `finishLogin`). The rest of the suite runs on the
 * cheap FAST_KEY_STRETCHING; the first test here is the one round trip on the
 * library default.
 */
import { client as opaqueLib, ready } from "@serenity-kit/opaque";
import { describe, expect, test } from "bun:test";
import {
	CLIENT_FORWARDS_KEY_STRETCHING,
	createTestHarness,
	FAST_KEY_STRETCHING,
	type TestHarness,
	uniqueEmail,
} from "./helpers/harness";

await ready;

const h = await createTestHarness({ resetLink: true, emailAndPassword: true, plugin: { setPassword: { enabled: true } } });

const PASSWORD = "stretch me";
const NEW_PASSWORD = "stretch me again";

/** Raw login that stretches with exactly FAST_KEY_STRETCHING (independent of the harness probe). */
async function fastLoginWorks(hh: TestHarness, email: string, password: string) {
	const device = hh.device();
	const { clientLoginState, startLoginRequest } = opaqueLib.startLogin({ password });
	const challenge = await device.post("/sign-in/opaque/challenge", { email, loginRequest: startLoginRequest });
	expect(challenge.status).toBe(200);
	const finished = opaqueLib.finishLogin({
		clientLoginState,
		loginResponse: challenge.body.challenge,
		password,
		keyStretching: FAST_KEY_STRETCHING,
	});
	if (!finished) return false;
	const complete = await device.post("/sign-in/opaque/complete", {
		loginResult: finished.finishLoginRequest,
		encryptedServerState: challenge.body.state,
	});
	return complete.status === 200;
}

describe("library-default key stretching", () => {
	test("register + login round trip with opaqueClient() and no keyStretching option (the suite's only default-cost flow)", async () => {
		const email = uniqueEmail("ks-default");
		const device = h.device({ keyStretching: "library-default" });

		const reg = await device.client.signUp.opaque({ email, name: "Default", password: PASSWORD });
		expect(reg.error).toBeNull();
		const login = await device.client.signIn.opaque({ email, password: PASSWORD });
		expect(login.error).toBeNull();
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
	});
});

describe("opaqueClient({ keyStretching }) is forwarded", () => {
	test("the harness detects it (so the suite runs on fast stretching)", () => {
		expect(CLIENT_FORWARDS_KEY_STRETCHING).toBe(true);
	});

	test("a record made with fast stretching does not log in on a default client, and vice versa", async () => {
		const fastEmail = uniqueEmail("ks-fast");
		const defaultEmail = uniqueEmail("ks-dflt");
		const fast = h.device({ keyStretching: FAST_KEY_STRETCHING });
		const dflt = h.device({ keyStretching: "library-default" });
		expect((await fast.client.signUp.opaque({ email: fastEmail, name: "F", password: PASSWORD })).error).toBeNull();
		expect((await dflt.client.signUp.opaque({ email: defaultEmail, name: "D", password: PASSWORD })).error).toBeNull();

		const crossA = await h.device({ keyStretching: "library-default" }).client.signIn.opaque({ email: fastEmail, password: PASSWORD });
		const crossB = await h.device({ keyStretching: FAST_KEY_STRETCHING }).client.signIn.opaque({ email: defaultEmail, password: PASSWORD });
		expect(crossA.error).toMatchObject({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });
		expect(crossB.error).toMatchObject({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });

		const sameA = await h.device({ keyStretching: FAST_KEY_STRETCHING }).client.signIn.opaque({ email: fastEmail, password: PASSWORD });
		expect(sameA.error).toBeNull();
	});

	test("signUp.opaque: the stored record logs in with FAST_KEY_STRETCHING", async () => {
		const email = uniqueEmail("ks-signup");
		expect((await h.device().client.signUp.opaque({ email, name: "S", password: PASSWORD })).error).toBeNull();
		expect(await fastLoginWorks(h, email, PASSWORD)).toBe(true);
	});

	test("opaque.changePassword: the new record logs in with FAST_KEY_STRETCHING", async () => {
		const email = uniqueEmail("ks-change");
		await h.register(email, PASSWORD);
		const device = await h.loggedInDevice(email, PASSWORD);
		const res = await device.client.opaque.changePassword({ currentPassword: PASSWORD, newPassword: NEW_PASSWORD });
		expect(res.error).toBeNull();
		expect(await fastLoginWorks(h, email, NEW_PASSWORD)).toBe(true);
	});

	test("opaque.resetPassword: the new record logs in with FAST_KEY_STRETCHING", async () => {
		const email = uniqueEmail("ks-reset");
		await h.register(email, PASSWORD);
		await h.device().client.opaque.forgetPassword({ email });
		const token = h.outbox.resetLinksFor(email).at(-1)!.token;
		expect((await h.device().client.opaque.resetPassword({ token, newPassword: NEW_PASSWORD })).error).toBeNull();
		expect(await fastLoginWorks(h, email, NEW_PASSWORD)).toBe(true);
	});

	test("opaque.setPassword: the new record logs in with FAST_KEY_STRETCHING", async () => {
		const email = uniqueEmail("ks-set");
		const device = await h.coreSignUp(email);
		expect((await device.client.opaque.setPassword({ newPassword: NEW_PASSWORD })).error).toBeNull();
		expect(await fastLoginWorks(h, email, NEW_PASSWORD)).toBe(true);
	});
});
