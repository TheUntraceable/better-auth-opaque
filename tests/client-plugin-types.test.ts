import type { BetterFetch } from "@better-fetch/fetch";
import type {
	BetterAuthClientPlugin,
	BetterFetchOption,
	ErrorContext,
	SuccessContext,
} from "better-auth/client";
import { createAuthClient } from "better-auth/client";
import { describe, expect, it } from "vitest";
import { opaqueClient, type OpaqueFetch, type OpaqueResult } from "../src/client";
import type { Post, Reply } from "../src/client/request";

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

// Actions accept whatever better-fetch accepts as per-request options.
type ActionFetchOptions = NonNullable<
	Parameters<typeof authClient.signIn.opaque>[1]
>;
const _fromBetterFetchOption: ActionFetchOptions = {} as BetterFetchOption;
const token = undefined as string | undefined;
const _optionalHeader: ActionFetchOptions = {
	headers: { authorization: token },
};
const _betterFetchHooks: ActionFetchOptions = {
	onSuccess: (_context: SuccessContext) => {},
	onError: (_context: ErrorContext) => {},
};
const _clientFetchOption: ActionFetchOptions = { disableSignal: true };

// The same options are accepted inside the first argument, as core does.
type InlineFetchOptions = NonNullable<
	Parameters<typeof authClient.signIn.opaque>[0]["fetchOptions"]
>;
const _inlineFromBetterFetchOption: InlineFetchOptions = {} as BetterFetchOption;

type Expect<T extends true> = T;
type StringKeys<T, K extends PropertyKey> = [K] extends [keyof T]
	? T[K & keyof T] extends string
		? true
		: false
	: false;
type Data<F extends (...args: never[]) => Promise<{ data: unknown }>> =
	NonNullable<Awaited<ReturnType<F>>["data"]>;

type SignInData = Data<typeof authClient.signIn.opaque>;
type ChangePasswordData = Data<typeof authClient.opaque.changePassword>;
type _SignInKeys = Expect<
	StringKeys<SignInData, "exportKey" | "sessionKey" | "serverPublicKey">
>;
type _ChangePasswordKeys = Expect<
	StringKeys<
		ChangePasswordData,
		"exportKey" | "previousExportKey" | "serverPublicKey"
	>
>;

// `throw: true` throws instead of returning an error, so the result keeps
// its { data, error } type wherever the option is passed. Never called.
const _throwKeepsResultType = async () => {
	const second: OpaqueResult<SignInData> = await authClient.signIn.opaque(
		{ email: "", password: "" },
		{ throw: true },
	);
	const inline: OpaqueResult<SignInData> = await authClient.signIn.opaque({
		email: "",
		password: "",
		fetchOptions: { throw: true },
	});
	const change: OpaqueResult<ChangePasswordData> =
		await authClient.opaque.changePassword(
			{ currentPassword: "", newPassword: "" },
			{ throw: true },
		);
	const withFields = await authClient.signUp.opaque({
		email: "",
		name: "",
		password: "",
		nickname: "additional fields still pass through",
		fetchOptions: { throw: true },
	});
	return [second, inline, change, withFields];
};

// Paths, bodies and replies are tied to the server's endpoints. Never called.
const _postIsTyped = (post: Post) => {
	// @ts-expect-error not an endpoint
	void post("/opaque/nope", {});
	// @ts-expect-error a registration body sent to a login step
	void post("/opaque/sign-in/challenge", { registrationRequest: "" });
	const reply: Reply<"/opaque/sign-in/challenge"> = { challenge: "", state: "" };
	// @ts-expect-error a sign-in challenge is not a change-password challenge
	const _mismatch: Reply<"/opaque/change-password/challenge"> = reply;
};

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
