import { client, ready } from "@serenity-kit/opaque";
import type { BetterAuthClientPlugin } from "better-auth/client";
import { OPAQUE_ERROR_CODES, type OpaqueErrorCode } from "./error-codes";
import type { opaque } from "./server";

export { OPAQUE_ERROR_CODES, type OpaqueErrorCode } from "./error-codes";

/* -------------------------------------------------------------------------- */
/*                                    Types                                   */
/* -------------------------------------------------------------------------- */

type Endpoints = ReturnType<typeof opaque>["endpoints"];
type Reply<K extends keyof Endpoints> = Awaited<ReturnType<Endpoints[K]>>;

type SignUpChallenge = Reply<"opaqueSignUpChallenge">;
type SignUpComplete = Reply<"opaqueSignUpComplete">;
type SignInChallenge = Reply<"opaqueSignInChallenge">;
type SignInComplete = Reply<"opaqueSignInComplete">;
type ChangePasswordChallenge = Reply<"opaqueChangePasswordChallenge">;
type ChangePasswordComplete = Reply<"opaqueChangePasswordComplete">;
type SetPasswordChallenge = Reply<"opaqueSetPasswordChallenge">;
type SetPasswordComplete = Reply<"opaqueSetPasswordComplete">;
type ResetRequest = Reply<"opaqueRequestPasswordReset">;
type ResetChallenge = Reply<"opaqueResetPasswordChallenge">;
type ResetComplete = Reply<"opaqueResetPasswordComplete">;

export interface OpaqueClientError {
	code?: string | undefined;
	message?: string | undefined;
	status: number;
	statusText: string;
}

export type OpaqueResult<T> =
	| { data: T; error: null }
	| { data: null; error: OpaqueClientError };

/**
 * Per-call options forwarded to better-auth's `$fetch`: `headers`, `query`,
 * `signal`, the `onRequest` / `onResponse` / `onSuccess` / `onError` hooks,
 * and anything else `@better-fetch/fetch` accepts. The plugin sets `method`
 * and `body` itself. Typed structurally for the same reason as
 * {@link OpaqueFetch}; the hook contexts list the fields you are likely to
 * touch and leave the rest open.
 */
export interface OpaqueFetchOptions {
	headers?: Headers | Record<string, string> | [string, string][] | undefined;
	query?: Record<string, unknown> | undefined;
	signal?: AbortSignal | undefined;
	credentials?: "omit" | "same-origin" | "include" | undefined;
	onRequest?:
		| ((context: { headers: Headers; [key: string]: unknown }) => unknown)
		| undefined;
	onResponse?:
		| ((context: { response: Response; [key: string]: unknown }) => unknown)
		| undefined;
	onSuccess?:
		| ((context: {
				data: unknown;
				response: Response;
				[key: string]: unknown;
		  }) => unknown)
		| undefined;
	onError?:
		| ((context: {
				error: OpaqueClientError;
				response: Response;
				[key: string]: unknown;
		  }) => unknown)
		| undefined;
	[key: string]: unknown;
}

/**
 * Minimal structural view of better-auth's `$fetch`.
 *
 * Deliberately self-contained: typing this with `BetterFetch` from
 * `@better-fetch/fetch` would pin the emitted `.d.ts` to the exact copy of
 * that package the plugin was built against, and any app whose
 * `better-auth` resolves a different copy fails with "Types of property
 * 'getActions' are incompatible" and loses all `authClient.*.opaque`
 * inference. `tests/client-plugin-types.test.ts` asserts `BetterFetch` stays
 * assignable to this.
 */
export type OpaqueFetch = <T = unknown>(
	url: string,
	options?: {
		method?: string;
		body?: unknown;
		[key: string]: unknown;
	},
) => Promise<{
	data: T | null;
	error: OpaqueClientError | null;
}>;

export interface OpaqueClientStore {
	notify: (signal: "$sessionSignal") => void;
}

export interface OpaqueClientOptions {
	/**
	 * The server's OPAQUE public key, from
	 * `server.getPublicKey(OPAQUE_SERVER_KEY)`. When set, every handshake
	 * checks the key the server proved possession of against this value and
	 * refuses to continue on a mismatch, which detects a swapped server key
	 * or an active man-in-the-middle.
	 */
	serverPublicKey?: string | undefined;
}

/* -------------------------------------------------------------------------- */
/*                                   Plugin                                   */
/* -------------------------------------------------------------------------- */

const fail = (
	code: OpaqueErrorCode,
	status: number,
	statusText: string,
): { data: null; error: OpaqueClientError } => ({
	data: null,
	error: { ...OPAQUE_ERROR_CODES[code], status, statusText },
});

export const opaqueClient = (options: OpaqueClientOptions = {}) => {
	// True when a key is pinned and the server just proved a different one.
	const serverKeyMismatch = (serverStaticPublicKey: string) =>
		options.serverPublicKey !== undefined &&
		options.serverPublicKey !== serverStaticPublicKey;

	return {
		id: "opaque",
		$InferServerPlugin: {} as ReturnType<typeof opaque>,
		$ERROR_CODES: OPAQUE_ERROR_CODES,
		getActions($fetch: OpaqueFetch, $store: OpaqueClientStore) {
			const post = <T>(
				url: string,
				body: Record<string, unknown>,
				fetchOptions?: OpaqueFetchOptions,
			) => $fetch<T>(url, { ...fetchOptions, method: "POST", body });

			/**
			 * Registration round trip shared by sign-up, change-password,
			 * set-password and reset-password. Returns the record to send plus
			 * the export key the app may keep.
			 */
			const register = async (
				password: string,
				getChallenge: (registrationRequest: string) => Promise<{
					data: { challenge: string; state: string } | null;
					error: OpaqueClientError | null;
				}>,
			): Promise<
				OpaqueResult<{
					registrationRecord: string;
					state: string;
					exportKey: string;
					serverPublicKey: string;
				}>
			> => {
				await ready;
				const { clientRegistrationState, registrationRequest } =
					client.startRegistration({ password });
				const challenge = await getChallenge(registrationRequest);
				if (challenge.error || !challenge.data) {
					return {
						data: null,
						error: challenge.error ?? fail("CHALLENGE_FAILED", 500, "ERROR").error,
					};
				}
				const { registrationRecord, exportKey, serverStaticPublicKey } =
					client.finishRegistration({
						clientRegistrationState,
						password,
						registrationResponse: challenge.data.challenge,
					});
				if (serverKeyMismatch(serverStaticPublicKey)) {
					return fail("SERVER_KEY_MISMATCH", 400, "BAD_REQUEST");
				}
				return {
					data: {
						registrationRecord,
						state: challenge.data.state,
						exportKey,
						serverPublicKey: serverStaticPublicKey,
					},
					error: null,
				};
			};

			return {
				signUp: {
					/**
					 * Register with OPAQUE. The password never leaves the device.
					 * Returns the `exportKey`: a stable 64-byte secret derived from
					 * the password that the server never learns, suitable for
					 * client-side encryption. It changes whenever the password does.
					 */
					opaque: async (
						{
							email,
							name,
							password,
							image,
							callbackURL,
							...additionalFields
						}: {
							email: string;
							name: string;
							password: string;
							image?: string;
							callbackURL?: string;
							[key: string]: unknown;
						},
						fetchOptions?: OpaqueFetchOptions,
					): Promise<
						OpaqueResult<
							SignUpComplete & { exportKey: string; serverPublicKey: string }
						>
					> => {
						const registration = await register(password, (registrationRequest) =>
							post<SignUpChallenge>(
								"/opaque/sign-up/challenge",
								{ email, registrationRequest },
								fetchOptions,
							),
						);
						if (registration.error) return registration;
						const result = await post<SignUpComplete>(
							"/opaque/sign-up/complete",
							{
								email,
								name,
								image,
								callbackURL,
								...additionalFields,
								registrationRecord: registration.data.registrationRecord,
								state: registration.data.state,
							},
							fetchOptions,
						);
						if (result.error || !result.data) {
							return {
								data: null,
								error: result.error ?? fail("CHALLENGE_FAILED", 500, "ERROR").error,
							};
						}
						if (result.data.token) $store.notify("$sessionSignal");
						return {
							data: {
								...result.data,
								exportKey: registration.data.exportKey,
								serverPublicKey: registration.data.serverPublicKey,
							},
							error: null,
						};
					},
				},
				signIn: {
					/**
					 * Log in with OPAQUE. On success returns the session token and
					 * user like `signIn.email`, plus:
					 * - `exportKey`: the same key `signUp.opaque` returned, for
					 *   unlocking client-side encrypted data.
					 * - `sessionKey`: the 64-byte key both sides derived from this
					 *   handshake. The server does not store it.
					 */
					opaque: async (
						{
							email,
							password,
							rememberMe,
							callbackURL,
						}: {
							email: string;
							password: string;
							rememberMe?: boolean;
							callbackURL?: string;
						},
						fetchOptions?: OpaqueFetchOptions,
					): Promise<
						OpaqueResult<
							SignInComplete & {
								exportKey: string;
								sessionKey: string;
								serverPublicKey: string;
							}
						>
					> => {
						await ready;
						const { clientLoginState, startLoginRequest } = client.startLogin({
							password,
						});
						const challenge = await post<SignInChallenge>(
							"/opaque/sign-in/challenge",
							{ email, loginRequest: startLoginRequest },
							fetchOptions,
						);
						if (challenge.error || !challenge.data) {
							return {
								data: null,
								error: challenge.error ?? fail("CHALLENGE_FAILED", 500, "ERROR").error,
							};
						}
						const login = client.finishLogin({
							clientLoginState,
							loginResponse: challenge.data.challenge,
							password,
						});
						if (!login) {
							// Wrong password (or no such account): the server never sees a
							// proof, so this is decided entirely on the client.
							return fail("INVALID_EMAIL_OR_PASSWORD", 401, "UNAUTHORIZED");
						}
						if (serverKeyMismatch(login.serverStaticPublicKey)) {
							return fail("SERVER_KEY_MISMATCH", 400, "BAD_REQUEST");
						}
						const result = await post<SignInComplete>(
							"/opaque/sign-in/complete",
							{
								loginResult: login.finishLoginRequest,
								state: challenge.data.state,
								rememberMe,
								callbackURL,
							},
							fetchOptions,
						);
						if (result.error || !result.data) {
							return {
								data: null,
								error: result.error ?? fail("INVALID_EMAIL_OR_PASSWORD", 401, "UNAUTHORIZED").error,
							};
						}
						$store.notify("$sessionSignal");
						return {
							data: {
								...result.data,
								exportKey: login.exportKey,
								sessionKey: login.sessionKey,
								serverPublicKey: login.serverStaticPublicKey,
							},
							error: null,
						};
					},
				},
				opaque: {
					/**
					 * Change the password of the signed-in user. Proves the current
					 * password with an OPAQUE login, registers the new one, and by
					 * default revokes every other session.
					 *
					 * Returns both `previousExportKey` and `exportKey` so data
					 * encrypted under the old key can be re-wrapped before the app
					 * forgets it. Nothing encrypted under the old key is recoverable
					 * once it is gone.
					 */
					changePassword: async (
						{
							currentPassword,
							newPassword,
							revokeOtherSessions,
						}: {
							currentPassword: string;
							newPassword: string;
							revokeOtherSessions?: boolean;
						},
						fetchOptions?: OpaqueFetchOptions,
					): Promise<
						OpaqueResult<
							ChangePasswordComplete & {
								exportKey: string;
								previousExportKey: string;
								serverPublicKey: string;
							}
						>
					> => {
						await ready;
						const { clientLoginState, startLoginRequest } = client.startLogin({
							password: currentPassword,
						});
						const { clientRegistrationState, registrationRequest } =
							client.startRegistration({ password: newPassword });
						const challenge = await post<ChangePasswordChallenge>(
							"/opaque/change-password/challenge",
							{ loginRequest: startLoginRequest, registrationRequest },
							fetchOptions,
						);
						if (challenge.error || !challenge.data) {
							return {
								data: null,
								error: challenge.error ?? fail("CHALLENGE_FAILED", 500, "ERROR").error,
							};
						}
						const login = client.finishLogin({
							clientLoginState,
							loginResponse: challenge.data.loginChallenge,
							password: currentPassword,
						});
						if (!login) {
							return fail("INVALID_PASSWORD", 401, "UNAUTHORIZED");
						}
						const registration = client.finishRegistration({
							clientRegistrationState,
							password: newPassword,
							registrationResponse: challenge.data.registrationChallenge,
						});
						if (
							serverKeyMismatch(login.serverStaticPublicKey) ||
							serverKeyMismatch(registration.serverStaticPublicKey)
						) {
							return fail("SERVER_KEY_MISMATCH", 400, "BAD_REQUEST");
						}
						const result = await post<ChangePasswordComplete>(
							"/opaque/change-password/complete",
							{
								loginResult: login.finishLoginRequest,
								registrationRecord: registration.registrationRecord,
								state: challenge.data.state,
								revokeOtherSessions,
							},
							fetchOptions,
						);
						if (result.error || !result.data) {
							return {
								data: null,
								error: result.error ?? fail("INVALID_PASSWORD", 401, "UNAUTHORIZED").error,
							};
						}
						$store.notify("$sessionSignal");
						return {
							data: {
								...result.data,
								exportKey: registration.exportKey,
								previousExportKey: login.exportKey,
								serverPublicKey: registration.serverStaticPublicKey,
							},
							error: null,
						};
					},

					/**
					 * Set an OPAQUE password on a signed-in account that has none,
					 * for example one created through a social provider.
					 */
					setPassword: async (
						{ password }: { password: string },
						fetchOptions?: OpaqueFetchOptions,
					): Promise<
						OpaqueResult<
							SetPasswordComplete & { exportKey: string; serverPublicKey: string }
						>
					> => {
						const registration = await register(password, (registrationRequest) =>
							post<SetPasswordChallenge>(
								"/opaque/set-password/challenge",
								{ registrationRequest },
								fetchOptions,
							),
						);
						if (registration.error) return registration;
						const result = await post<SetPasswordComplete>(
							"/opaque/set-password/complete",
							{
								registrationRecord: registration.data.registrationRecord,
								state: registration.data.state,
							},
							fetchOptions,
						);
						if (result.error || !result.data) {
							return {
								data: null,
								error: result.error ?? fail("CHALLENGE_FAILED", 500, "ERROR").error,
							};
						}
						return {
							data: {
								...result.data,
								exportKey: registration.data.exportKey,
								serverPublicKey: registration.data.serverPublicKey,
							},
							error: null,
						};
					},

					/**
					 * Email a password reset link. Always succeeds from the caller's
					 * point of view so it cannot be used to probe for accounts.
					 */
					requestPasswordReset: async (
						{ email, redirectTo }: { email: string; redirectTo?: string },
						fetchOptions?: OpaqueFetchOptions,
					): Promise<OpaqueResult<ResetRequest>> => {
						const result = await post<ResetRequest>(
							"/opaque/reset-password/request",
							{ email, redirectTo },
							fetchOptions,
						);
						if (result.error || !result.data) {
							return {
								data: null,
								error: result.error ?? fail("CHALLENGE_FAILED", 500, "ERROR").error,
							};
						}
						return { data: result.data, error: null };
					},

					/**
					 * Finish a password reset with the token from the emailed link.
					 * Every existing session is revoked. The returned `exportKey` is
					 * new; anything encrypted under the previous one is unrecoverable
					 * unless the app kept a separate recovery path.
					 */
					resetPassword: async (
						{ token, newPassword }: { token: string; newPassword: string },
						fetchOptions?: OpaqueFetchOptions,
					): Promise<
						OpaqueResult<
							ResetComplete & { exportKey: string; serverPublicKey: string }
						>
					> => {
						const registration = await register(newPassword, (registrationRequest) =>
							post<ResetChallenge>(
								"/opaque/reset-password/challenge",
								{ token, registrationRequest },
								fetchOptions,
							),
						);
						if (registration.error) return registration;
						const result = await post<ResetComplete>(
							"/opaque/reset-password/complete",
							{
								token,
								registrationRecord: registration.data.registrationRecord,
								state: registration.data.state,
							},
							fetchOptions,
						);
						if (result.error || !result.data) {
							return {
								data: null,
								error: result.error ?? fail("INVALID_TOKEN", 400, "BAD_REQUEST").error,
							};
						}
						// Every session was revoked server-side; drop the cached one.
						$store.notify("$sessionSignal");
						return {
							data: {
								...result.data,
								exportKey: registration.data.exportKey,
								serverPublicKey: registration.data.serverPublicKey,
							},
							error: null,
						};
					},
				},
			};
		},
	} satisfies BetterAuthClientPlugin;
};
