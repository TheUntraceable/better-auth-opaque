import { describe, expect, test } from "vitest";
import { decryptState, encryptState } from "../src/server/state";

const secret = "supersecretkey";

describe("encrypted handshake state", () => {
	test("has the same length whatever it carries", async () => {
		const small = await encryptState(
			{
				purpose: "set-password",
				stateId: "a",
				issuedAt: Date.now(),
				userId: "u",
				newCredentialId: "n",
			},
			secret,
		);
		const large = await encryptState(
			{
				purpose: "change-password",
				stateId: "b".repeat(32),
				issuedAt: Date.now(),
				userId: "u".repeat(36),
				credentialId: "c".repeat(43),
				newCredentialId: "n".repeat(43),
				serverLoginState: "s".repeat(256),
			},
			secret,
		);
		expect(small).toHaveLength(large.length);
	});

	test("round-trips and strips padding", async () => {
		const state = {
			purpose: "sign-in",
			stateId: "x",
			issuedAt: 1,
			userId: "u1",
			credentialId: "c1",
			serverLoginState: "s1",
		} as const;
		const encrypted = await encryptState(state, secret);
		const decoded = await decryptState(encrypted, secret, "sign-in", Infinity);
		expect(decoded).toEqual(state);
	});

	test("rejects the wrong purpose, an expired state, and tampering", async () => {
		const encrypted = await encryptState(
			{
				purpose: "sign-in",
				stateId: "x",
				issuedAt: Date.now() - 10_000,
				userId: null,
				credentialId: "c",
				serverLoginState: "s",
			},
			secret,
		);
		await expect(
			decryptState(encrypted, secret, "change-password", Infinity),
		).rejects.toMatchObject({ body: { code: "INVALID_LOGIN_STATE" } });
		await expect(
			decryptState(encrypted, secret, "sign-in", 5_000),
		).rejects.toMatchObject({ body: { code: "INVALID_LOGIN_STATE" } });
		await expect(
			decryptState(`${encrypted.slice(0, -2)}zz`, secret, "sign-in", Infinity),
		).rejects.toMatchObject({ body: { code: "INVALID_LOGIN_STATE" } });
		await expect(
			decryptState(encrypted, "other-secret", "sign-in", Infinity),
		).rejects.toMatchObject({ body: { code: "INVALID_LOGIN_STATE" } });
	});
});
