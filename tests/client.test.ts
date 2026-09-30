/**
 * The typed client (`opaqueClient()`), as seen through `createAuthClient`.
 *
 * Password-management actions live under `authClient.opaque.*` (the plugin
 * no longer shadows core's top-level `changePassword`); `signUp.opaque` and
 * `signIn.opaque` stay. Every action returns `{ data, error }` and passes the
 * server's `{ status, code, message }` through, and accepts Better Auth's
 * optional second `fetchOptions` argument.
 */
import { ready } from "@serenity-kit/opaque";
import { describe, expect, mock, test } from "bun:test";
import type { OpaqueClientResult, StatusData } from "../src/client";
import { OPAQUE_ERROR_CODES } from "../src/utils";
import {
	createTestHarness,
	type Device,
	type Equal,
	type Expect,
	type Extends,
	type IsAny,
	SESSION_TOKEN_COOKIE,
	uniqueEmail,
} from "./helpers/harness";

await ready;

const h = await createTestHarness({
	resetLink: true,
	emailAndPassword: true,
	plugin: { setPassword: { enabled: true } },
});
/** Sessions are created on registration (for the session-signal test). */
const hAutoSession = await createTestHarness({ plugin: { insecureCreateSessionOnRegister: true } });

const PASSWORD = "client password";
const NEW_PASSWORD = "client new password";

/* ------------------------------- type tests ------------------------------- */

type Client = Device["client"];
type ChangePasswordResult = Awaited<ReturnType<Client["opaque"]["changePassword"]>>;
type ChangePasswordData = NonNullable<ChangePasswordResult["data"]>;
// `data` of opaque.changePassword is typed (not any) as { success: boolean; message: string }.
export type _ChangePasswordDataNotAny = Expect<Extends<IsAny<ChangePasswordData>, false>>;
export type _ChangePasswordDataShape = Expect<Extends<ChangePasswordData, { success: boolean; message: string }>>;
// The client's $ERROR_CODES type includes every OPAQUE code.
export type _ErrorCodesInferred = Expect<Extends<keyof typeof OPAQUE_ERROR_CODES, keyof Client["$ERROR_CODES"]>>;
// Actions have exactly the action's type (not intersected with the inferred endpoint).
export type _ForgetPasswordReturn = Expect<
	Equal<ReturnType<Client["opaque"]["forgetPassword"]>, Promise<OpaqueClientResult<StatusData>>>
>;
// The OPAQUE endpoints are only reachable through the actions: the client type
// exposes no raw path-proxy calls for their individual steps.
export function _noRawEndpointCalls(client: Client) {
	// @ts-expect-error not part of the client type
	client.signIn.opaque.challenge;
	// @ts-expect-error not part of the client type
	client.opaque.resetPassword.challenge;
	// @ts-expect-error not part of the client type
	client.opaque.forgetPassword.challenge;
}

/* --------------------------------- helpers -------------------------------- */

async function registered(label: string) {
	const email = uniqueEmail(label);
	await h.register(email, PASSWORD);
	return { email, user: (await h.db.user(email))! };
}

const HEADER = "x-passthrough-probe";

/** Assert every request the action sent carried the custom header. */
function expectHeaderOnEveryRequest(device: Device, fromIndex: number) {
	const sent = device.requests.slice(fromIndex);
	expect(sent.length).toBeGreaterThan(0);
	for (const r of sent) expect({ path: r.path, header: r.headers.get(HEADER) }).toEqual({ path: r.path, header: "1" });
}

/* ------------------------------- error codes ------------------------------ */

describe("error codes", () => {
	test("OPAQUE_ERROR_CODES includes the codes used by the new endpoints", () => {
		for (const code of [
			"INVALID_TOKEN",
			"RESET_PASSWORD_METHOD_NOT_CONFIGURED",
			"OPAQUE_ACCOUNT_ALREADY_EXISTS",
			"EMAIL_NOT_VERIFIED",
			"SET_PASSWORD_CHALLENGE_REQUIRED",
		]) {
			const entry = (OPAQUE_ERROR_CODES as Record<string, { code: string; message: string } | undefined>)[code];
			expect({ key: code, code: entry?.code, hasMessage: typeof entry?.message === "string" }).toEqual({
				key: code,
				code,
				hasMessage: true,
			});
		}
	});

	test("TOO_MANY_ATTEMPTS is gone (a locked code answers INVALID_TOKEN, like an unknown one)", () => {
		expect(Object.keys(OPAQUE_ERROR_CODES)).not.toContain("TOO_MANY_ATTEMPTS");
	});

	test("authClient.$ERROR_CODES also exposes Better Auth's core codes at runtime", () => {
		const codes = h.device().client.$ERROR_CODES as unknown as Record<string, { code?: unknown; message?: unknown } | undefined>;
		for (const key of ["INVALID_ORIGIN", "USER_NOT_FOUND"]) {
			expect({ key, code: codes[key]?.code, message: typeof codes[key]?.message }).toEqual({
				key,
				code: key,
				message: "string",
			});
		}
	});

	test("authClient.$ERROR_CODES exposes every OPAQUE error code at runtime", () => {
		const codes = h.device().client.$ERROR_CODES as unknown as Record<string, unknown>;
		for (const [key, entry] of Object.entries(OPAQUE_ERROR_CODES)) {
			expect({ key, value: codes[key] }).toEqual({ key, value: expect.objectContaining({ code: entry.code }) });
		}
	});
});

/* --------------------------------- signUp --------------------------------- */

describe("signUp.opaque", () => {
	test("success: { data: { success, message }, error: null }", async () => {
		const res = await h.device().client.signUp.opaque({ email: uniqueEmail("c-su"), name: "C", password: PASSWORD });
		expect(res).toEqual({
			data: { success: true, message: "User registered successfully" },
			error: null,
		});
	});

	test("failure at the challenge step (invalid email): { data: null, error: { status: 400, code, message } }", async () => {
		const res = await h.device().client.signUp.opaque({ email: "not-an-email", name: "C", password: PASSWORD });
		expect(res).toHaveProperty("data", null);
		expect(res.error).toMatchObject({ status: 400, code: expect.any(String), message: expect.any(String) });
	});

	test("failure at the complete step (name too long): { data: null, error: { status: 400, code, message } }", async () => {
		const res = await h.device().client.signUp.opaque({ email: uniqueEmail("c-su-long"), name: "x".repeat(101), password: PASSWORD });
		expect(res).toHaveProperty("data", null);
		expect(res.error).toMatchObject({ status: 400, code: expect.any(String), message: expect.any(String) });
	});
});

/* --------------------------------- signIn --------------------------------- */

describe("signIn.opaque", () => {
	test("default: persistent cookie and no dontRememberMe in the request", async () => {
		const { email, user } = await registered("c-si");
		const device = h.device();
		const res = await device.client.signIn.opaque({ email, password: PASSWORD });

		expect(res.error).toBeNull();
		expect(res.data).toEqual({ token: expect.any(String), success: true, user: { id: user.id } });
		expect(device.requestsTo("/sign-in/opaque/complete").at(-1)!.body.dontRememberMe).not.toBe(true);
		const cookie = device.lastSetCookies.find((c) => c.name === SESSION_TOKEN_COOKIE)!;
		expect(Number(cookie.attributes["max-age"])).toBeGreaterThan(0);
	});

	test("rememberMe: false sends dontRememberMe: true and yields a cookie without Max-Age", async () => {
		const { email } = await registered("c-si-norem");
		const device = h.device();
		const res = await device.client.signIn.opaque({ email, password: PASSWORD, rememberMe: false });

		expect(res.error).toBeNull();
		expect(device.requestsTo("/sign-in/opaque/complete").at(-1)!.body.dontRememberMe).toBe(true);
		const cookie = device.lastSetCookies.find((c) => c.name === SESSION_TOKEN_COOKIE);
		expect(cookie).toBeDefined();
		expect(cookie!.attributes["max-age"]).toBeUndefined();
		expect(cookie!.attributes.expires).toBeUndefined();
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
	});

	test("rememberMe: true behaves like the default", async () => {
		const { email } = await registered("c-si-rem");
		const device = h.device();
		const res = await device.client.signIn.opaque({ email, password: PASSWORD, rememberMe: true });
		expect(res.error).toBeNull();
		expect(device.requestsTo("/sign-in/opaque/complete").at(-1)!.body.dontRememberMe).not.toBe(true);
		const cookie = device.lastSetCookies.find((c) => c.name === SESSION_TOKEN_COOKIE)!;
		expect(Number(cookie.attributes["max-age"])).toBeGreaterThan(0);
	});

	test("wrong password: { data: null, error: { status: 401, code: INVALID_EMAIL_OR_PASSWORD, message } }", async () => {
		const { email } = await registered("c-si-wrong");
		const device = h.device();
		const res = await device.client.signIn.opaque({ email, password: "wrong password" });
		expect(res.data).toBeNull();
		expect(res.error).toMatchObject({
			status: 401,
			code: "INVALID_EMAIL_OR_PASSWORD",
			message: OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD.message,
		});
		expect(device.jar.has(SESSION_TOKEN_COOKIE)).toBe(false);
	});

	test("unknown email: an error identical to a wrong password", async () => {
		const { email } = await registered("c-si-known");
		const wrong = await h.device().client.signIn.opaque({ email, password: "wrong password" });
		const ghost = await h.device().client.signIn.opaque({ email: uniqueEmail("c-si-ghost"), password: PASSWORD });
		expect(wrong.error).toMatchObject({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });
		expect(ghost.data).toBeNull();
		expect(ghost.error).toEqual(wrong.error!);
	});

	test("invalid email: { data: null, error.status 400 }", async () => {
		const res = await h.device().client.signIn.opaque({ email: "not-an-email", password: PASSWORD });
		expect(res.data).toBeNull();
		expect(res.error).toMatchObject({ status: 400 });
	});

	test("success notifies the client's session signal once (useSession refetches)", async () => {
		const { email } = await registered("c-si-signal");
		const device = h.device();
		let signals = 0;
		const unlisten = device.client.$store.atoms.$sessionSignal!.listen(() => {
			signals += 1;
		});
		const res = await device.client.signIn.opaque({ email, password: PASSWORD });
		unlisten();
		expect(res.error).toBeNull();
		expect(signals).toBe(1);
	});

	test("a failure detected locally (wrong password) fires onError exactly once, and onSuccess never", async () => {
		const { email } = await registered("c-si-onerror");
		const onError = mock(() => {});
		const onSuccess = mock(() => {});
		const res = await h.device().client.signIn.opaque({ email, password: "wrong password" }, { onError, onSuccess });
		expect(res.error).toMatchObject({ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" });
		expect(onError).toHaveBeenCalledTimes(1);
		expect(onSuccess).toHaveBeenCalledTimes(0);
	});
});

describe("signUp.opaque with insecureCreateSessionOnRegister", () => {
	test("notifies the client's session signal, so useSession reflects the new session without an extra call", async () => {
		const device = hAutoSession.device();
		let signals = 0;
		const unlisten = device.client.$store.atoms.$sessionSignal!.listen(() => {
			signals += 1;
		});
		const email = uniqueEmail("c-su-signal");
		const res = await device.client.signUp.opaque({ email, name: "Signal", password: PASSWORD });
		unlisten();
		expect(res.error).toBeNull();
		expect(device.jar.has(SESSION_TOKEN_COOKIE)).toBe(true);
		expect(signals).toBe(1);
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
	});
});

/* -------------------------- opaque.changePassword ------------------------- */

describe("opaque.changePassword", () => {
	test("the plugin no longer shadows core's top-level changePassword", async () => {
		const { email } = await registered("c-cp-core");
		const device = await h.loggedInDevice(email, PASSWORD);
		const from = device.requests.length;
		await device.client.changePassword({ currentPassword: PASSWORD, newPassword: NEW_PASSWORD });
		expect(device.requests.slice(from).map((r) => r.path)).toEqual(["/change-password"]);
	});

	test("success: { data: { success: true, message }, error: null }; the caller's session is rotated and works", async () => {
		const { email } = await registered("c-cp");
		const device = await h.loggedInDevice(email, PASSWORD);
		const before = device.sessionToken();

		const res = await device.client.opaque.changePassword({ currentPassword: PASSWORD, newPassword: NEW_PASSWORD });

		expect(res.error).toBeNull();
		expect(res.data).toMatchObject({ success: true, message: "Password changed successfully" });
		res.data satisfies { success: boolean; message: string } | null;
		expect(device.sessionToken()).not.toBe(before!);
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
		const relog = await h.device().client.signIn.opaque({ email, password: NEW_PASSWORD });
		expect(relog.error).toBeNull();
	});

	test("wrong current password: { data: null, error: { status: 401, code: INVALID_CURRENT_PASSWORD, message } }", async () => {
		const { email } = await registered("c-cp-wrong");
		const device = await h.loggedInDevice(email, PASSWORD);
		const res = await device.client.opaque.changePassword({ currentPassword: "not it", newPassword: NEW_PASSWORD });
		expect(res.data).toBeNull();
		expect(res.error).toMatchObject({
			status: 401,
			code: "INVALID_CURRENT_PASSWORD",
			message: OPAQUE_ERROR_CODES.INVALID_CURRENT_PASSWORD.message,
		});
	});

	test("unauthenticated: error.status 401", async () => {
		const res = await h.device().client.opaque.changePassword({ currentPassword: PASSWORD, newPassword: NEW_PASSWORD });
		expect(res.data).toBeNull();
		expect(res.error).toMatchObject({ status: 401 });
	});

	test("revokeOtherSessions: false keeps other devices; the default revokes them", async () => {
		const { email } = await registered("c-cp-revoke");
		const changer = await h.loggedInDevice(email, PASSWORD);
		const other = await h.loggedInDevice(email, PASSWORD);

		const keep = await changer.client.opaque.changePassword({
			currentPassword: PASSWORD,
			newPassword: NEW_PASSWORD,
			revokeOtherSessions: false,
		});
		expect(keep.error).toBeNull();
		expect(changer.requestsTo("/opaque/change-password/complete").at(-1)!.body.revokeOtherSessions).toBe(false);
		expect((await other.whoami({ tokenOnly: true })).session?.user.email).toBe(email);

		const revoke = await changer.client.opaque.changePassword({ currentPassword: NEW_PASSWORD, newPassword: PASSWORD });
		expect(revoke.error).toBeNull();
		expect((await other.whoami({ tokenOnly: true })).session).toBeNull();
		expect((await changer.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
	});
});

/* ---------------------- forget / reset / set (shapes) --------------------- */

describe("opaque.forgetPassword / resetPassword / setPassword", () => {
	test("forgetPassword returns { data: { status: true }, error: null } for known and unknown emails alike", async () => {
		const { email } = await registered("c-fp");
		const known = await h.device().client.opaque.forgetPassword({ email });
		const ghost = await h.device().client.opaque.forgetPassword({ email: uniqueEmail("c-fp-ghost") });
		expect(known.error).toBeNull();
		expect(known.data).toMatchObject({ status: true });
		expect(ghost).toEqual(known);
	});

	test("resetPassword({ token, newPassword }) returns { data: { status: true }, error: null }", async () => {
		const { email } = await registered("c-rp");
		await h.device().client.opaque.forgetPassword({ email });
		const link = h.outbox.resetLinksFor(email).at(-1);
		expect(link).toBeDefined();
		const res = await h.device().client.opaque.resetPassword({ token: link!.token, newPassword: NEW_PASSWORD });
		expect(res).toEqual({ data: { status: true }, error: null });
	});

	test("setPassword({ newPassword }) returns { data: { status: true }, error: null }", async () => {
		const device = await h.coreSignUp(uniqueEmail("c-sp"));
		const res = await device.client.opaque.setPassword({ newPassword: NEW_PASSWORD });
		expect(res).toEqual({ data: { status: true }, error: null });
	});
});

/* -------------------------- fetchOptions passthrough ---------------------- */

describe("fetchOptions passthrough (second argument)", () => {
	const fetchOptions = () => {
		const onSuccess = mock(() => {});
		return { onSuccess, options: { onSuccess, headers: { [HEADER]: "1" } } };
	};

	test("signUp.opaque", async () => {
		const device = h.device();
		const { onSuccess, options } = fetchOptions();
		const from = device.requests.length;
		const res = await device.client.signUp.opaque({ email: uniqueEmail("c-fo-su"), name: "F", password: PASSWORD }, options);
		expect(res.error).toBeNull();
		expect(onSuccess).toHaveBeenCalledTimes(1);
		expectHeaderOnEveryRequest(device, from);
	});

	test("signIn.opaque", async () => {
		const { email } = await registered("c-fo-si");
		const device = h.device();
		const { onSuccess, options } = fetchOptions();
		const from = device.requests.length;
		const res = await device.client.signIn.opaque({ email, password: PASSWORD }, options);
		expect(res.error).toBeNull();
		expect(onSuccess).toHaveBeenCalledTimes(1);
		expectHeaderOnEveryRequest(device, from);
	});

	test("opaque.changePassword", async () => {
		const { email } = await registered("c-fo-cp");
		const device = await h.loggedInDevice(email, PASSWORD);
		const { onSuccess, options } = fetchOptions();
		const from = device.requests.length;
		const res = await device.client.opaque.changePassword({ currentPassword: PASSWORD, newPassword: NEW_PASSWORD }, options);
		expect(res.error).toBeNull();
		expect(onSuccess).toHaveBeenCalledTimes(1);
		expectHeaderOnEveryRequest(device, from);
	});

	test("opaque.forgetPassword", async () => {
		const { email } = await registered("c-fo-fp");
		const device = h.device();
		const { onSuccess, options } = fetchOptions();
		const from = device.requests.length;
		const res = await device.client.opaque.forgetPassword({ email }, options);
		expect(res.error).toBeNull();
		expect(onSuccess).toHaveBeenCalledTimes(1);
		expectHeaderOnEveryRequest(device, from);
	});

	test("opaque.resetPassword", async () => {
		const { email } = await registered("c-fo-rp");
		await h.device().post("/opaque/forget-password", { email });
		const link = h.outbox.resetLinksFor(email).at(-1);
		expect(link).toBeDefined();
		const device = h.device();
		const { onSuccess, options } = fetchOptions();
		const from = device.requests.length;
		const res = await device.client.opaque.resetPassword({ token: link!.token, newPassword: NEW_PASSWORD }, options);
		expect(res.error).toBeNull();
		expect(onSuccess).toHaveBeenCalledTimes(1);
		expectHeaderOnEveryRequest(device, from);
	});

	test("opaque.setPassword", async () => {
		const device = await h.coreSignUp(uniqueEmail("c-fo-sp"));
		const { onSuccess, options } = fetchOptions();
		const from = device.requests.length;
		const res = await device.client.opaque.setPassword({ newPassword: NEW_PASSWORD }, options);
		expect(res.error).toBeNull();
		expect(onSuccess).toHaveBeenCalledTimes(1);
		expectHeaderOnEveryRequest(device, from);
	});
});
