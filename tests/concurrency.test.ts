import { describe, expect, test } from "bun:test";
import {
	createTestHarness,
	type Device,
	SESSION_TOKEN_COOKIE,
	startLogin,
	uniqueEmail,
	validLoginPayload,
} from "./helpers/harness";

const h = await createTestHarness();

const PW_A = "alice password";
const PW_B = "bob password";

async function twoUsers() {
	const a = uniqueEmail("alice");
	const b = uniqueEmail("bob");
	await Promise.all([h.register(a, PW_A, "Alice"), h.register(b, PW_B, "Bob")]);
	return { a, b };
}

async function sessionCounts(a: string, b: string): Promise<[number, number]> {
	return [(await h.db.sessionsFor(a)).length, (await h.db.sessionsFor(b)).length];
}

describe("concurrency / cross-user isolation", () => {
	test("parallel registration and login of two users yields sessions bound to the right user", async () => {
		const a = uniqueEmail("alice");
		const b = uniqueEmail("bob");

		const [regA, regB] = await Promise.all([
			h.device().client.signUp.opaque({ email: a, password: PW_A, name: "Alice" }),
			h.device().client.signUp.opaque({ email: b, password: PW_B, name: "Bob" }),
		]);
		expect(regA.error).toBeNull();
		expect(regB.error).toBeNull();
		expect(await h.db.registrationRecord(a)).not.toBe(await h.db.registrationRecord(b));

		const devA = h.device();
		const devB = h.device();
		const [loginA, loginB] = await Promise.all([
			devA.client.signIn.opaque({ email: a, password: PW_A }),
			devB.client.signIn.opaque({ email: b, password: PW_B }),
		]);
		expect(loginA.error).toBeNull();
		expect(loginB.error).toBeNull();
		expect(loginA.data!.user.id).toBe((await h.db.user(a))!.id);
		expect(loginB.data!.user.id).toBe((await h.db.user(b))!.id);

		expect((await devA.whoami({ tokenOnly: true })).session?.user.email).toBe(a);
		expect((await devB.whoami({ tokenOnly: true })).session?.user.email).toBe(b);
		expect((await devA.whoami()).session?.user.email).toBe(a);
		expect((await devB.whoami()).session?.user.email).toBe(b);
	});

	test("a user's password does not work for another user", async () => {
		const { a, b } = await twoUsers();
		const res = await h.device().client.signIn.opaque({ email: b, password: PW_A });
		expect(res.data).toBeNull();
		expect(res.error).not.toBeNull();
		expect(await sessionCounts(a, b)).toEqual([0, 0]);
	});

	test("interleaved logins: A's state cannot be completed with B's proof (and vice versa); legitimate completions still work", async () => {
		const { a, b } = await twoUsers();
		const dev = h.device();

		// Interleave challenges. a2/b2 are only ever used legitimately, so they
		// stay valid even if the server burns a challenge on a failed attempt.
		const a1 = await startLogin(dev, a, PW_A);
		const b1 = await startLogin(dev, b, PW_B);
		const a2 = await startLogin(dev, a, PW_A);
		const b2 = await startLogin(dev, b, PW_B);
		const a3 = await startLogin(dev, a, PW_A);
		const [ke3A1, ke3B1, ke3A2, ke3B2] = [a1.finish(), b1.finish(), a2.finish(), b2.finish()];
		for (const k of [ke3A1, ke3B1, ke3A2, ke3B2]) expect(k).toBeDefined();

		const crossings: Array<[string, string, string]> = [
			// [email in body, loginResult, encryptedServerState]
			[b, ke3B1!, a1.state], // B's proof on A's state, claiming B
			[a, ke3B1!, a1.state], // B's proof on A's state, claiming A
			[a, ke3A1!, b1.state], // A's proof on B's state, claiming A
			[b, ke3A1!, b1.state], // A's proof on B's state, claiming B
			[a, ke3A1!, a3.state], // A's proof on A's *other* state
		];
		const statuses: number[] = [];
		for (const [email, loginResult, encryptedServerState] of crossings) {
			const d = h.device();
			const res = await d.post("/sign-in/opaque/complete", { email, loginResult, encryptedServerState });
			statuses.push(res.status);
			expect(res.ok).toBe(false);
			expect(res.setCookies.map((c) => c.name)).not.toContain(SESSION_TOKEN_COOKIE);
			expect((await d.whoami()).session).toBeNull();
		}
		expect(await sessionCounts(a, b)).toEqual([0, 0]);

		// The untouched challenges still complete, each as the right user.
		const devA = h.device();
		const devB = h.device();
		const okB = await devB.post("/sign-in/opaque/complete", { email: b, loginResult: ke3B2, encryptedServerState: b2.state });
		const okA = await devA.post("/sign-in/opaque/complete", { email: a, loginResult: ke3A2, encryptedServerState: a2.state });
		expect(okA.status).toBe(200);
		expect(okB.status).toBe(200);
		expect((await devA.whoami({ tokenOnly: true })).session?.user.email).toBe(a);
		expect((await devB.whoami({ tokenOnly: true })).session?.user.email).toBe(b);
		expect(await sessionCounts(a, b)).toEqual([1, 1]);

		// Checked last so the isolation guarantees above are verified regardless:
		// a proof that doesn't match the state is a failed login, i.e. 401.
		expect(statuses).toEqual(crossings.map(() => 401));
	});

	test("a valid login for A submitted with B's email never yields a session for B", async () => {
		const { a, b } = await twoUsers();
		const payload = await validLoginPayload(h.device(), a, PW_A);
		const [aBefore, bBefore] = await sessionCounts(a, b);
		const totalBefore = await h.db.sessionCount();

		const d = h.device();
		const res = await d.post("/sign-in/opaque/complete", { ...payload, email: b });

		const [aAfter, bAfter] = await sessionCounts(a, b);
		expect(bAfter).toBe(bBefore);
		// Any session that was created belongs to A.
		expect((await h.db.sessionCount()) - totalBefore).toBe(aAfter - aBefore);
		const who = await d.whoami({ tokenOnly: true });
		expect(who.session?.user.email ?? null).not.toBe(b);
		if (res.ok) expect(res.body.user.id).toBe((await h.db.user(a))!.id);
	});

	test("many users logging in concurrently each get their own session", async () => {
		const users = Array.from({ length: 4 }, (_, i) => ({ email: uniqueEmail(`crowd${i}`), password: `crowd password ${i}` }));
		await Promise.all(users.map((u) => h.register(u.email, u.password)));

		const devices: Device[] = users.map(() => h.device());
		const results = await Promise.all(
			users.map((u, i) => devices[i]!.client.signIn.opaque({ email: u.email, password: u.password })),
		);
		for (const r of results) expect(r.error).toBeNull();

		for (let i = 0; i < users.length; i++) {
			const who = await devices[i]!.whoami({ tokenOnly: true });
			expect(who.session?.user.email).toBe(users[i]!.email);
			expect(who.session?.session.token).toBe(results[i]!.data!.token);
		}
	});
});
