import { BASE_ERROR_CODES } from "@better-auth/core/error";
import { client, ready } from "@serenity-kit/opaque";
import type {
	BetterAuthClientOptions,
	BetterAuthClientPlugin,
	BetterFetch,
	BetterFetchOption,
	ClientStore,
	ErrorContext,
	RequestContext,
	SuccessContext,
} from "better-auth/client";
import { OPAQUE_ERROR_CODES } from "./error-codes.js";
import type { opaque } from "./server.js";

export { OPAQUE_ERROR_CODES, type OpaqueErrorCode } from "./error-codes.js";

/* -------------------------------------------------------------------------- */
/*                                Public types                                */
/* -------------------------------------------------------------------------- */

/**
 * Argon2id configuration of the OPAQUE client library (`@serenity-kit/opaque`),
 * which does not export the type under a name of its own.
 */
export type KeyStretchingFunctionConfig = NonNullable<client.FinishRegistrationParams["keyStretching"]>;

/** Options of `opaqueClient()`. */
export interface OpaqueClientOptions {
	/**
	 * Key stretching (Argon2id) applied to the password whenever the client
	 * finishes a registration or a login. Must be the same for every client of
	 * a deployment: a record registered with one configuration only logs in
	 * with that same configuration. Default: the library default
	 * (`"memory-constrained"`).
	 */
	keyStretching?: KeyStretchingFunctionConfig | undefined;
}

/**
 * The error of a failed action: the server's error body (`code`, `message`)
 * plus the HTTP `status` / `statusText` of whichever request failed. When the
 * client detects the failure itself (the password did not verify locally), it
 * returns exactly what the server would have returned for that failure.
 */
export interface OpaqueClientError {
	code?: string | undefined;
	message?: string | undefined;
	status: number;
	statusText: string;
}

/** Every action resolves to `{ data, error }`; exactly one of them is non-null. */
export type OpaqueClientResult<T> =
	| { data: T; error: null }
	| { data: null; error: OpaqueClientError };

/**
 * Better Auth fetch options accepted by every action (second argument, or
 * `fetchOptions` inside the first one, like core actions).
 *
 * - Transport options (`headers`, `query`, `credentials`, `signal`, `timeout`,
 *   `retry`, `customFetchImpl`, `onRequest`, `onResponse`, ...) apply to EVERY
 *   request an action sends.
 * - `onSuccess` fires once, for the action's final successful response.
 * - `onError` fires once, for whichever step failed (including a failure the
 *   client detected locally, with a synthesised response).
 * - `body`, `method`, `params`, `output` and `throw` are not accepted: each
 *   action owns its requests and always resolves to `{ data, error }`.
 */
export type OpaqueFetchOptions = Omit<BetterFetchOption, "body" | "method" | "params" | "output" | "throw"> & {
	/** Do not notify the session signal after a successful action. */
	disableSignal?: boolean | undefined;
};

type WithFetchOptions<T> = T & { fetchOptions?: OpaqueFetchOptions | undefined };

export type SignUpOpaqueInput = WithFetchOptions<
	{
		email: string;
		name: string;
		password: string;
		image?: string | undefined;
		/** Where the email verification link sends the user once verified. */
		callbackURL?: string | undefined;
	} & {
		/**
		 * Additional user fields (`user.additionalFields` with `input: true` on
		 * the server), sent with the complete step as core's `signUp.email` does.
		 */
		[field: string]: unknown;
	}
>;

export type SignInOpaqueInput = WithFetchOptions<{
	email: string;
	password: string;
	/**
	 * `false` creates a session cookie that ends with the browser session
	 * (sends `dontRememberMe: true`). Default `true`.
	 */
	rememberMe?: boolean | undefined;
	/**
	 * Where the email verification link sends the user, when signing in
	 * re-sends one (unverified email with verification required).
	 */
	callbackURL?: string | undefined;
}>;

export type ChangePasswordOpaqueInput = WithFetchOptions<{
	currentPassword: string;
	newPassword: string;
	/** Revoke every other session of the user. Default `true` (server default). */
	revokeOtherSessions?: boolean | undefined;
}>;

export type ForgetPasswordOpaqueInput = WithFetchOptions<{
	email: string;
	/** Delivery method; defaults to the one the server has configured. */
	method?: "link" | "otp" | undefined;
	/** Where the emailed link sends the user (becomes the link's `callbackURL`). */
	redirectTo?: string | undefined;
}>;

export type ResetPasswordOpaqueInput = WithFetchOptions<
	| { token: string; newPassword: string; email?: never; otp?: never }
	| { email: string; otp: string; newPassword: string; token?: never }
>;

export type SetPasswordOpaqueInput = WithFetchOptions<{ newPassword: string }>;

export interface SignUpOpaqueData {
	success: boolean;
	message: string;
}
export interface SignInOpaqueData {
	token: string;
	success: boolean;
	user: { id: string };
}
export interface ChangePasswordOpaqueData {
	success: boolean;
	message: string;
}
export interface StatusData {
	status: boolean;
}

/* -------------------------------------------------------------------------- */
/*                              Request plumbing                              */
/* -------------------------------------------------------------------------- */

type Hooks = {
	onSuccess?: ((context: SuccessContext<any>) => Promise<void> | void) | undefined;
	onError?: ((context: ErrorContext) => Promise<void> | void) | undefined;
};

/** Better Auth sends the APIError status name as the HTTP status text. */
const STATUS_TEXT: Record<number, string> = {
	400: "BAD_REQUEST",
	401: "UNAUTHORIZED",
};

/**
 * One action = one or more requests. Transport options go on every request;
 * the caller's `onSuccess` only on the final one; the caller's `onError` on
 * every request (a failed step ends the action, so it fires at most once).
 */
class ActionFlow {
	private readonly transport: Record<string, unknown>;
	private readonly hooks: Hooks;
	private readonly disableSignal: boolean;
	private lastRequest: RequestContext | undefined;

	constructor(
		private readonly $fetch: BetterFetch,
		private readonly $store: ClientStore,
		...optionSources: Array<OpaqueFetchOptions | undefined>
	) {
		const merged = Object.assign({}, ...optionSources.filter(Boolean)) as Record<string, unknown>;
		const {
			onSuccess,
			onError,
			disableSignal,
			// Owned by the action (see OpaqueFetchOptions).
			body: _body,
			method: _method,
			params: _params,
			output: _output,
			throw: _throw,
			...transport
		} = merged;
		this.transport = transport;
		this.hooks = { onSuccess, onError } as Hooks;
		this.disableSignal = disableSignal === true;
	}

	/** A non-final step: its success does not fire the caller's `onSuccess`. */
	step<T>(path: string, body: Record<string, unknown>) {
		return this.send<T>(path, body, async (context) => {
			this.lastRequest = context.request;
		});
	}

	/** The final step: its success is the action's success. */
	finish<T>(path: string, body: Record<string, unknown>) {
		return this.send<T>(path, body, this.hooks.onSuccess);
	}

	private async send<T>(
		path: string,
		body: Record<string, unknown>,
		onSuccess: Hooks["onSuccess"],
	): Promise<OpaqueClientResult<T>> {
		const res = (await this.$fetch<T>(path, {
			...this.transport,
			method: "POST",
			body,
			onSuccess,
			onError: this.hooks.onError,
		})) as { data: T | null; error: OpaqueClientError | null };
		if (res.error) return { data: null, error: res.error };
		return { data: res.data as T, error: null };
	}

	/**
	 * A failure detected locally (the password did not verify): report it
	 * exactly as the server would, and fire the caller's `onError` once.
	 */
	async fail(status: number, entry: { code: string; message: string }): Promise<OpaqueClientResult<never>> {
		const statusText = STATUS_TEXT[status] ?? "";
		const error: OpaqueClientError = { message: entry.message, code: entry.code, status, statusText };
		if (this.hooks.onError) {
			const response = new Response(JSON.stringify({ message: entry.message, code: entry.code }), {
				status,
				statusText,
				headers: { "content-type": "application/json" },
			});
			await this.hooks.onError({
				response,
				request: this.lastRequest as RequestContext,
				error: error as ErrorContext["error"],
			});
		}
		return { data: null, error };
	}

	/** Let session-bound hooks (`useSession`) refetch, like core does for its own endpoints. */
	notifySession() {
		if (this.disableSignal) return;
		try {
			this.$store.notify("$sessionSignal");
		} catch {
			// No session atom (should not happen): nothing to refresh.
		}
	}
}

/** Finish an OPAQUE login; `undefined` when the password does not verify. */
function finishLoginSafely(params: Parameters<typeof client.finishLogin>[0]) {
	try {
		return client.finishLogin(params);
	} catch {
		// A response the client cannot use is, to the caller, a failed login.
		return undefined;
	}
}

/**
 * `authClient.$ERROR_CODES`, populated at runtime.
 *
 * Better Auth's client proxy returns functions (and atoms) from the actions
 * unchanged but replaces any plain object with a path proxy, so a plain object
 * here would read back as proxies (`$ERROR_CODES.X.code` would not be a
 * string). A function carrying the codes as own enumerable properties is the
 * one shape that reaches callers intact. Better Auth's core codes and the
 * codes of every client plugin that declares `$ERROR_CODES` are included, since
 * only one plugin can own the key (OPAQUE's own codes win on a clash).
 */
function runtimeErrorCodes(options: BetterAuthClientOptions | undefined) {
	const codes: Record<string, { code: string; message: string }> = { ...BASE_ERROR_CODES };
	for (const plugin of options?.plugins ?? []) {
		if (plugin.$ERROR_CODES) Object.assign(codes, plugin.$ERROR_CODES);
	}
	Object.assign(codes, OPAQUE_ERROR_CODES);
	return Object.assign(function $ERROR_CODES() {
		return codes;
	}, codes);
}

/* -------------------------------------------------------------------------- */
/*                                   Plugin                                   */
/* -------------------------------------------------------------------------- */

export const opaqueClient = (options?: OpaqueClientOptions) => {
	// Forwarded to every library call that stretches the password; omitted
	// entirely when unset so the library applies its own default.
	const stretch: { keyStretching?: KeyStretchingFunctionConfig } =
		options?.keyStretching === undefined ? {} : { keyStretching: options.keyStretching };
	return {
		id: "opaque",
		$InferServerPlugin: {} as ReturnType<typeof opaque>,
		$ERROR_CODES: OPAQUE_ERROR_CODES,
		getActions($fetch: BetterFetch, $store: ClientStore, clientOptions: BetterAuthClientOptions | undefined) {
			const flow = (inline: OpaqueFetchOptions | undefined, fetchOptions: OpaqueFetchOptions | undefined) =>
				new ActionFlow($fetch, $store, fetchOptions, inline);

			const actions = {
				signUp: {
					/**
					 * Register with OPAQUE. Creates a session only when the server enables
					 * `insecureCreateSessionOnRegister`.
					 */
					opaque: async (
						data: SignUpOpaqueInput,
						fetchOptions?: OpaqueFetchOptions,
					): Promise<OpaqueClientResult<SignUpOpaqueData>> => {
						const { email, name, password, fetchOptions: inline, ...fields } = data;
						const f = flow(inline, fetchOptions);
						await ready;
						const { clientRegistrationState, registrationRequest } = client.startRegistration({ password });
						const challenge = await f.step<{ challenge: string }>("/sign-up/opaque/challenge", {
							email,
							registrationRequest,
						});
						if (challenge.error) return challenge;
						const { registrationRecord } = client.finishRegistration({
							clientRegistrationState,
							password,
							registrationResponse: challenge.data.challenge,
							...stretch,
						});
						// `image`, `callbackURL` and additional user fields travel as given.
						const extra = Object.fromEntries(Object.entries(fields).filter(([, value]) => value !== undefined));
						const res = await f.finish<SignUpOpaqueData>("/sign-up/opaque/complete", {
							...extra,
							email,
							name,
							registrationRecord,
						});
						// The server may have created a session (insecureCreateSessionOnRegister).
						if (!res.error) f.notifySession();
						return res;
					},
				},
				signIn: {
					/** Log in with OPAQUE and create a session. */
					opaque: async (
						data: SignInOpaqueInput,
						fetchOptions?: OpaqueFetchOptions,
					): Promise<OpaqueClientResult<SignInOpaqueData>> => {
						const { email, password, rememberMe, callbackURL, fetchOptions: inline } = data;
						const f = flow(inline, fetchOptions);
						await ready;
						const { clientLoginState, startLoginRequest } = client.startLogin({ password });
						const challenge = await f.step<{ challenge: string; state: string }>("/sign-in/opaque/challenge", {
							email,
							loginRequest: startLoginRequest,
						});
						if (challenge.error) return challenge;
						const { challenge: loginResponse, state: encryptedServerState } = challenge.data;
						const loginAttempt = finishLoginSafely({ password, clientLoginState, loginResponse, ...stretch });
						if (!loginAttempt) {
							return await f.fail(401, OPAQUE_ERROR_CODES.INVALID_EMAIL_OR_PASSWORD);
						}
						const res = await f.finish<SignInOpaqueData>("/sign-in/opaque/complete", {
							loginResult: loginAttempt.finishLoginRequest,
							encryptedServerState,
							...(rememberMe === false ? { dontRememberMe: true } : {}),
							...(callbackURL === undefined ? {} : { callbackURL }),
						});
						if (!res.error) f.notifySession();
						return res;
					},
				},
				opaque: {
					/**
					 * Change the password of the logged-in user. Proves the current
					 * password and registers the new one in a single exchange; the
					 * caller's session cookie is refreshed.
					 */
					changePassword: async (
						data: ChangePasswordOpaqueInput,
						fetchOptions?: OpaqueFetchOptions,
					): Promise<OpaqueClientResult<ChangePasswordOpaqueData>> => {
						const { currentPassword, newPassword, revokeOtherSessions, fetchOptions: inline } = data;
						const f = flow(inline, fetchOptions);
						await ready;
						// Login flow with the current password, registration flow with the new one.
						const { clientLoginState, startLoginRequest } = client.startLogin({ password: currentPassword });
						const { clientRegistrationState, registrationRequest } = client.startRegistration({
							password: newPassword,
						});
						const challenge = await f.step<{
							loginChallenge: string;
							registrationChallenge: string;
							state: string;
						}>("/opaque/change-password/challenge", {
							loginRequest: startLoginRequest,
							registrationRequest,
						});
						if (challenge.error) return challenge;
						const { loginChallenge, registrationChallenge, state: encryptedServerState } = challenge.data;
						const loginAttempt = finishLoginSafely({
							password: currentPassword,
							clientLoginState,
							loginResponse: loginChallenge,
							...stretch,
						});
						if (!loginAttempt) {
							return await f.fail(401, OPAQUE_ERROR_CODES.INVALID_CURRENT_PASSWORD);
						}
						const { registrationRecord } = client.finishRegistration({
							clientRegistrationState,
							password: newPassword,
							registrationResponse: registrationChallenge,
							...stretch,
						});
						const res = await f.finish<ChangePasswordOpaqueData>("/opaque/change-password/complete", {
							loginResult: loginAttempt.finishLoginRequest,
							registrationRecord,
							encryptedServerState,
							...(revokeOtherSessions === undefined ? {} : { revokeOtherSessions }),
						});
						if (!res.error) f.notifySession();
						return res;
					},

					/**
					 * Ask for a password reset link or one-time code by email. Resolves
					 * identically whether or not the email belongs to a user.
					 */
					forgetPassword: async (
						data: ForgetPasswordOpaqueInput,
						fetchOptions?: OpaqueFetchOptions,
					): Promise<OpaqueClientResult<StatusData>> => {
						const { email, method, redirectTo, fetchOptions: inline } = data;
						return await flow(inline, fetchOptions).finish<StatusData>("/opaque/forget-password", {
							email,
							...(method === undefined ? {} : { method }),
							...(redirectTo === undefined ? {} : { redirectTo }),
						});
					},

					/**
					 * Set a new password with a reset link token (`{ token }`) or an
					 * emailed one-time code (`{ email, otp }`).
					 */
					resetPassword: async (
						data: ResetPasswordOpaqueInput,
						fetchOptions?: OpaqueFetchOptions,
					): Promise<OpaqueClientResult<StatusData>> => {
						const { newPassword, fetchOptions: inline } = data;
						const credential =
							typeof data.token === "string"
								? { token: data.token }
								: { email: data.email as string, otp: data.otp as string };
						const f = flow(inline, fetchOptions);
						await ready;
						const { clientRegistrationState, registrationRequest } = client.startRegistration({
							password: newPassword,
						});
						const challenge = await f.step<{ challenge: string }>("/opaque/reset-password/challenge", {
							...credential,
							registrationRequest,
						});
						if (challenge.error) return challenge;
						const { registrationRecord } = client.finishRegistration({
							clientRegistrationState,
							password: newPassword,
							registrationResponse: challenge.data.challenge,
							...stretch,
						});
						const res = await f.finish<StatusData>("/opaque/reset-password/complete", {
							...credential,
							registrationRecord,
						});
						// A reset revokes the user's sessions.
						if (!res.error) f.notifySession();
						return res;
					},

					/**
					 * Add an OPAQUE password to the logged-in user's account (a user
					 * who signed up another way and has no OPAQUE account yet).
					 */
					setPassword: async (
						data: SetPasswordOpaqueInput,
						fetchOptions?: OpaqueFetchOptions,
					): Promise<OpaqueClientResult<StatusData>> => {
						const { newPassword, fetchOptions: inline } = data;
						const f = flow(inline, fetchOptions);
						await ready;
						const { clientRegistrationState, registrationRequest } = client.startRegistration({
							password: newPassword,
						});
						const challenge = await f.step<{ challenge: string }>("/opaque/set-password/challenge", {
							registrationRequest,
						});
						if (challenge.error) return challenge;
						const { registrationRecord } = client.finishRegistration({
							clientRegistrationState,
							password: newPassword,
							registrationResponse: challenge.data.challenge,
							...stretch,
						});
						return await f.finish<StatusData>("/opaque/set-password/complete", { registrationRecord });
					},
				},
			};

			// Runtime-only: `authClient.$ERROR_CODES` is already typed by Better
			// Auth from `$InferServerPlugin`.
			return Object.assign(actions, { $ERROR_CODES: runtimeErrorCodes(clientOptions) }) as typeof actions;
		},
	} satisfies BetterAuthClientPlugin;
};
