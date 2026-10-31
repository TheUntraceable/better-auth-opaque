import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["tests/**/*.test.ts"],
		// Every handshake runs Argon2 on the client, and the statistical timing
		// tests loop hundreds of times.
		testTimeout: 60_000,
		hookTimeout: 60_000,
	},
});
