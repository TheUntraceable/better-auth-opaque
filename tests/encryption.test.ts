import { describe, expect, test } from "bun:test";
import { encryptServerLoginState } from "../src/utils";

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
});
