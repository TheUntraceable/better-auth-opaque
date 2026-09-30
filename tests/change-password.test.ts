import { client as opaqueLib, ready } from "@serenity-kit/opaque";
import { describe, expect, test } from "bun:test";
import {
	createTestHarness,
	type Device,
	randomBase64Url,
	startChangePassword,
	uniqueEmail,
} from "./helpers/harness";

const h = await createTestHarness();
await ready;

const OLD_PASSWORD = "old password 1";
const NEW_PASSWORD = "new password 2";

async function userWithDevices(count: number) {
	const email = uniqueEmail("chpw");
	await h.register(email, OLD_PASSWORD);
	const devices: Device[] = [];
	for (let i = 0; i < count; i++) devices.push(await h.loggedInDevice(email, OLD_PASSWORD));
	return { email, devices };
}

async function canLogIn(email: string, password: string) {
	const res = await h.device().client.signIn.opaque({ email, password });
	return res.error === null && res.data?.success === true;
}

function isClientError(status: number) {
	return status >= 400 && status < 500;
}

describe("change password: authentication", () => {
	test("unauthenticated requests to both endpoints are 401", async () => {
		const anon = h.device();
		const login = opaqueLib.startLogin({ password: OLD_PASSWORD });
		const reg = opaqueLib.startRegistration({ password: NEW_PASSWORD });

		const challenge = await anon.post("/opaque/changePassword/challenge", {
			loginRequest: login.startLoginRequest,
			registrationRequest: reg.registrationRequest,
		});
		expect(challenge.status).toBe(401);

		const complete = await anon.post("/opaque/changePassword/complete", {
			loginResult: randomBase64Url(64),
			registrationRecord: randomBase64Url(192),
			encryptedServerState: "x",
		});
		expect(complete.status).toBe(401);
	});

	test("unauthenticated client call returns an error and no data", async () => {
		const res = await h.device().client.changePassword({ currentPassword: OLD_PASSWORD, newPassword: NEW_PASSWORD });
		expect(res.data).toBeNull();
		expect(res.error).not.toBeNull();
	});
});

describe("change password: wrong current password", () => {
	test("via the client: error, record unchanged, session intact", async () => {
		const { email, devices } = await userWithDevices(1);
		const device = devices[0]!;
		const recordBefore = await h.db.registrationRecord(email);

		const res = await device.client.changePassword({ currentPassword: "not the password", newPassword: NEW_PASSWORD });

		expect(res.data).toBeNull();
		expect(res.error).not.toBeNull();
		expect(await h.db.registrationRecord(email)).toBe(recordBefore);
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
		expect(await canLogIn(email, OLD_PASSWORD)).toBe(true);
		expect(await canLogIn(email, NEW_PASSWORD)).toBe(false);
	});

	test("at the server (unauthenticated KE3): 4xx not 500, record unchanged, sessions intact", async () => {
		const { email, devices } = await userWithDevices(2);
		const [device, other] = devices as [Device, Device];
		const recordBefore = await h.db.registrationRecord(email);
		const sessionsBefore = (await h.db.sessionsFor(email)).map((s) => s.token).sort();

		const started = await startChangePassword(device, "not the password", NEW_PASSWORD);
		expect(started.loginResult).toBeUndefined(); // client can't prove a wrong password
		const res = await device.post("/opaque/changePassword/complete", {
			loginResult: randomBase64Url(64),
			registrationRecord: started.registrationRecord,
			encryptedServerState: started.encryptedServerState,
		});

		expect(isClientError(res.status)).toBe(true);
		expect(await h.db.registrationRecord(email)).toBe(recordBefore);
		expect((await h.db.sessionsFor(email)).map((s) => s.token).sort()).toEqual(sessionsBefore);
		expect((await other.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
		expect(await canLogIn(email, OLD_PASSWORD)).toBe(true);
	});

	test("malformed loginResult ('AAAA') is 4xx not 500 and the record is unchanged", async () => {
		const { email, devices } = await userWithDevices(1);
		const device = devices[0]!;
		const recordBefore = await h.db.registrationRecord(email);

		const started = await startChangePassword(device, OLD_PASSWORD, NEW_PASSWORD);
		const res = await device.post("/opaque/changePassword/complete", {
			loginResult: "AAAA",
			registrationRecord: started.registrationRecord,
			encryptedServerState: started.encryptedServerState,
		});

		expect(isClientError(res.status)).toBe(true);
		expect(await h.db.registrationRecord(email)).toBe(recordBefore);
	});
});

describe("change password: success", () => {
	test("happy path: success body, record replaced, old password rejected, new password accepted", async () => {
		const { email, devices } = await userWithDevices(1);
		const recordBefore = await h.db.registrationRecord(email);

		const res = await devices[0]!.client.changePassword({ currentPassword: OLD_PASSWORD, newPassword: NEW_PASSWORD });

		expect(res.error).toBeNull();
		// `as unknown`: the plugin's `changePassword` action collides with Better
		// Auth core's `changePassword` in the client's inferred types.
		expect(res.data as unknown).toEqual({ success: true, message: "Password changed successfully" });
		const recordAfter = await h.db.registrationRecord(email);
		expect(recordAfter).not.toBeNull();
		expect(recordAfter).not.toBe(recordBefore);

		expect(await canLogIn(email, OLD_PASSWORD)).toBe(false);
		expect(await canLogIn(email, NEW_PASSWORD)).toBe(true);
	});

	test("sessions on other devices are revoked in the database", async () => {
		const { email, devices } = await userWithDevices(3);
		const [changer, phone, laptop] = devices as [Device, Device, Device];
		const otherTokens = [phone.sessionToken()!, laptop.sessionToken()!];
		for (const d of [phone, laptop]) {
			expect((await d.whoami({ tokenOnly: true })).session?.user.email).toBe(email);
		}

		const res = await changer.client.changePassword({ currentPassword: OLD_PASSWORD, newPassword: NEW_PASSWORD });
		expect(res.error).toBeNull();

		const remaining = (await h.db.sessionsFor(email)).map((s) => s.token);
		for (const token of otherTokens) expect(remaining).not.toContain(token);
		for (const d of [phone, laptop]) {
			expect((await d.whoami({ tokenOnly: true })).session).toBeNull();
		}
	});

	test("the device that changed the password keeps a working session", async () => {
		const { email, devices } = await userWithDevices(2);
		const [changer] = devices as [Device, Device];

		const res = await changer.client.changePassword({ currentPassword: OLD_PASSWORD, newPassword: NEW_PASSWORD });
		expect(res.error).toBeNull();

		// Whatever token the changer now holds (kept or rotated) must be live in the DB.
		const token = changer.sessionToken();
		expect(token).toBeDefined();
		expect((await h.db.sessionsFor(email)).map((s) => s.token)).toEqual([token!]);
		const who = await changer.whoami({ tokenOnly: true });
		expect(who.session?.user.email).toBe(email);
		expect(who.session?.session.token).toBe(token!);
	});
});

describe("change password: state integrity", () => {
	test("another user's change-password state cannot be used to change their password", async () => {
		const victim = await userWithDevices(1);
		const attacker = await userWithDevices(1);
		const victimRecord = await h.db.registrationRecord(victim.email);
		const attackerRecord = await h.db.registrationRecord(attacker.email);

		// Victim's (fully valid) challenge material, submitted from the attacker's session.
		const stolen = await startChangePassword(victim.devices[0]!, OLD_PASSWORD, "attacker chosen");
		expect(stolen.loginResult).toBeDefined();
		const res = await attacker.devices[0]!.post("/opaque/changePassword/complete", {
			loginResult: stolen.loginResult,
			registrationRecord: stolen.registrationRecord,
			encryptedServerState: stolen.encryptedServerState,
		});

		expect(isClientError(res.status)).toBe(true);
		expect(await h.db.registrationRecord(victim.email)).toBe(victimRecord);
		expect(await h.db.registrationRecord(attacker.email)).toBe(attackerRecord);
	});

	test("replaying a successful change-password completion is rejected", async () => {
		const { email, devices } = await userWithDevices(1);
		const device = devices[0]!;

		const started = await startChangePassword(device, OLD_PASSWORD, NEW_PASSWORD);
		const payload = {
			loginResult: started.loginResult,
			registrationRecord: started.registrationRecord,
			encryptedServerState: started.encryptedServerState,
		};
		const first = await device.post("/opaque/changePassword/complete", payload);
		expect(first.status).toBe(200);
		const recordAfterFirst = await h.db.registrationRecord(email);

		// Precondition: the device is still authenticated, so a rejection below
		// comes from replay protection, not from a missing session.
		expect((await device.whoami({ tokenOnly: true })).session?.user.email).toBe(email);

		const replay = await device.post("/opaque/changePassword/complete", payload);
		expect(isClientError(replay.status)).toBe(true);
		expect(await h.db.registrationRecord(email)).toBe(recordAfterFirst);
	});
});
