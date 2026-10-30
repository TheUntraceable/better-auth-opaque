import type { BetterFetch } from "@better-fetch/fetch";
import type { BetterAuthClientPlugin } from "better-auth/client";
import { createAuthClient } from "better-auth/client";
import { describe, expect, it } from "vitest";
import { opaqueClient, type OpaqueFetch } from "../src/client";

// Compile-time checks. If any of these stop type-checking, the published
// client plugin will break consumers' `createAuthClient` inference.

// better-auth's own $fetch must be accepted by the plugin's structural type.
const _betterFetchIsOpaqueFetch: OpaqueFetch = null as unknown as BetterFetch;

// The plugin must still be a valid better-auth client plugin.
const _plugin: BetterAuthClientPlugin = opaqueClient();


const authClient = createAuthClient({
	baseURL: "http://localhost:3000",
	plugins: [opaqueClient()],
});

// Error codes are inferred onto the auth client's types.
type ErrorCodeCheck = typeof authClient.$ERROR_CODES.SERVER_KEY_MISMATCH.code;
const _errorCode: ErrorCodeCheck = "SERVER_KEY_MISMATCH";

describe("opaqueClient typing", () => {
	it("exposes the opaque actions on the auth client", () => {
		expect(typeof authClient.signUp.opaque).toBe("function");
		expect(typeof authClient.signIn.opaque).toBe("function");
		expect(typeof authClient.opaque.changePassword).toBe("function");
		expect(typeof authClient.opaque.setPassword).toBe("function");
		expect(typeof authClient.opaque.requestPasswordReset).toBe("function");
		expect(typeof authClient.opaque.resetPassword).toBe("function");
	});
});
