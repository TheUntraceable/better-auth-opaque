import { describe, expect, test } from "bun:test";
import { decryptServerLoginState, encryptServerLoginState } from "../src/utils";

describe("ensure encrypted payload sent to client is safe", () => {
	test("encrypted payload is always the same length", async () => {
		const secret = "supersecretkey";

		const user1 = {
			id: "user1",
			email: "user1@example.com",
			name: "User One",
		};

		const user2 = {
			id: "user2",
			email: "user2@example.com",
			name: "User Two",
			extraField: "This is an extra field to change the size",
		};
		const serverLoginState = "someServerLoginStateData";

		const encrypted1 = await encryptServerLoginState(
			serverLoginState,
			secret,
			user1,
		);
		const encrypted2 = await encryptServerLoginState(
			serverLoginState,
			secret,
			user2,
		);

		expect(encrypted1.length).toBe(encrypted2.length);
	});

	test("payload length does not depend on the user id length or on the user existing", async () => {
		const secret = "supersecretkey";
		const state = "someServerLoginStateData";
		const lengths = new Set(
			await Promise.all(
				[
					{ id: "a", email: "a@b.c", name: "A" },
					{ id: "x".repeat(36), email: `${"y".repeat(60)}@example.com`, name: "z".repeat(100) },
					null,
				].map(async (user) => (await encryptServerLoginState(state, secret, user)).length),
			),
		);
		expect(lengths.size).toBe(1);
	});

	test("round-trips the server login state and rejects tampering or the wrong key", async () => {
		const secret = "supersecretkey";
		const user = { id: "user1", email: "user1@example.com", name: "User One" };
		const encrypted = await encryptServerLoginState("state-123", secret, user);

		const decrypted = await decryptServerLoginState(encrypted, secret);
		expect(decrypted.serverLoginState).toBe("state-123");

		const i = Math.floor(encrypted.length / 2);
		const tampered = encrypted.slice(0, i) + (encrypted[i] === "a" ? "b" : "a") + encrypted.slice(i + 1);
		await expect(decryptServerLoginState(tampered, secret)).rejects.toThrow();
		await expect(decryptServerLoginState(encrypted, "another-secret")).rejects.toThrow();
	});
});
