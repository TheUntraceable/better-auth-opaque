import { createAuthClient, type BetterAuthClientPlugin } from "better-auth/client";
import { opaqueClient, type OpaqueFetch } from "../src";

type Assert<T extends true> = T;
type IsAny<T> = 0 extends 1 & T ? true : false;
// A broken plugin can degrade the client to `any`, which is assignable to
// everything, so `any` has to be rejected explicitly.
type IsAssignable<From, To> = IsAny<From> extends true
	? false
	: [From] extends [To]
		? true
		: false;
type IsExactly<A, B> =
	(<G>() => G extends A ? 1 : 2) extends <G>() => G extends B ? 1 : 2 ? true : false;

type PassedFetch = Parameters<NonNullable<BetterAuthClientPlugin["getActions"]>>[0];
type OpaqueActions = ReturnType<ReturnType<typeof opaqueClient>["getActions"]>;

type _FetchFitsOpaqueFetch = Assert<IsAssignable<PassedFetch, OpaqueFetch>>;
// Without the annotation, `$fetch` is contextually typed as better-auth's own
// `BetterFetch`, so every assignability check here passes in-repo while the
// emitted `.d.ts` still fails for consumers. Pin the declared type exactly.
type _GetActionsTakesOpaqueFetch = Assert<
	IsExactly<Parameters<ReturnType<typeof opaqueClient>["getActions"]>[0], OpaqueFetch>
>;
type _PluginFitsClientPlugin = Assert<
	IsAssignable<ReturnType<typeof opaqueClient>, BetterAuthClientPlugin>
>;

const authClient = createAuthClient({ plugins: [opaqueClient()] });
type Client = typeof authClient;

type _SignUp = Assert<IsAssignable<Client["signUp"]["opaque"], OpaqueActions["signUp"]["opaque"]>>;
type _SignIn = Assert<IsAssignable<Client["signIn"]["opaque"], OpaqueActions["signIn"]["opaque"]>>;
// better-auth's own `changePassword` shares this name; asserting against the
// plugin's signature is what proves the plugin's action was merged in.
type _ChangePassword = Assert<
	IsAssignable<Client["changePassword"], OpaqueActions["changePassword"]>
>;
