import { client, ready } from "@serenity-kit/opaque";
import { fail, type Reply, type Requester } from "./request";
import type { OpaqueFetchOptions, OpaqueResult } from "./types";

type SignInData = Reply<"/opaque/sign-in/complete"> & {
	exportKey: string;
	sessionKey: string;
	serverPublicKey: string;
};

export const signInActions = ({ run, serverKeyMismatch }: Requester) => ({
	/**
	 * Log in with OPAQUE. On success returns the session token and
	 * user like `signIn.email`, plus:
	 * - `exportKey`: the same key `signUp.opaque` returned, for
	 *   unlocking client-side encrypted data.
	 * - `sessionKey`: the 64-byte key both sides derived from this
	 *   handshake. The server does not store it.
	 */
	opaque: (
		{
			fetchOptions: inline,
			email,
			password,
			rememberMe,
			callbackURL,
		}: {
			email: string;
			password: string;
			rememberMe?: boolean;
			callbackURL?: string;
			fetchOptions?: OpaqueFetchOptions;
		},
		fetchOptions?: OpaqueFetchOptions,
	): Promise<OpaqueResult<SignInData>> =>
		run(
			{ ...fetchOptions, ...inline },
			async (post) => {
				await ready;
				const { clientLoginState, startLoginRequest } = client.startLogin({
					password,
				});
				const challenge = await post("/opaque/sign-in/challenge", {
					email,
					loginRequest: startLoginRequest,
				});
				if (challenge.error) return challenge;
				const login = client.finishLogin({
					clientLoginState,
					loginResponse: challenge.data.challenge,
					password,
				});
				if (!login) {
					// Wrong password (or no such account): the server never sees a
					// proof, so this is decided entirely on the client.
					return fail("INVALID_EMAIL_OR_PASSWORD", 401, "Unauthorized");
				}
				if (serverKeyMismatch(login.serverStaticPublicKey)) {
					return fail("SERVER_KEY_MISMATCH", 400, "Bad Request");
				}
				const result = await post("/opaque/sign-in/complete", {
					loginResult: login.finishLoginRequest,
					state: challenge.data.state,
					rememberMe,
					callbackURL,
				});
				if (result.error) return result;
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
			() => true,
		),
});
