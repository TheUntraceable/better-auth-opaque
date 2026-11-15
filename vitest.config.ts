import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["tests/**/*.test.ts"],
		// Every handshake runs Argon2 on the client.
		testTimeout: 60_000,
		hookTimeout: 60_000,
	},
});
