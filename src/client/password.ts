import { client, ready } from "@serenity-kit/opaque";
import { fail, type Reply, type Requester } from "./request";
import type { OpaqueFetchOptions, OpaqueResult } from "./types";

type ChangePasswordData = Reply<"/opaque/change-password/complete"> & {
	exportKey: string;
	previousExportKey: string;
	serverPublicKey: string;
};

type SetPasswordData = Reply<"/opaque/set-password/complete"> & {
	exportKey: string;
	serverPublicKey: string;
};

export const passwordActions = ({
	run,
	register,
	serverKeyMismatch,
}: Requester) => ({
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
	changePassword: (
		{
			fetchOptions: inline,
			currentPassword,
			newPassword,
			revokeOtherSessions,
		}: {
			currentPassword: string;
			newPassword: string;
			revokeOtherSessions?: boolean;
			fetchOptions?: OpaqueFetchOptions;
		},
		fetchOptions?: OpaqueFetchOptions,
	): Promise<OpaqueResult<ChangePasswordData>> =>
		run(
			{ ...fetchOptions, ...inline },
			async (post) => {
				await ready;
				const { clientLoginState, startLoginRequest } = client.startLogin({
					password: currentPassword,
				});
				const { clientRegistrationState, registrationRequest } =
					client.startRegistration({ password: newPassword });
				const challenge = await post("/opaque/change-password/challenge", {
					loginRequest: startLoginRequest,
					registrationRequest,
				});
				if (challenge.error) return challenge;
				const login = client.finishLogin({
					clientLoginState,
					loginResponse: challenge.data.loginChallenge,
					password: currentPassword,
				});
				if (!login) {
					return fail("INVALID_PASSWORD", 401, "Unauthorized");
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
					return fail("SERVER_KEY_MISMATCH", 400, "Bad Request");
				}
				const result = await post("/opaque/change-password/complete", {
					loginResult: login.finishLoginRequest,
					registrationRecord: registration.registrationRecord,
					state: challenge.data.state,
					revokeOtherSessions,
				});
				if (result.error) return result;
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
			() => true,
		),

	/**
	 * Set an OPAQUE password on a signed-in account that has none,
	 * for example one created through a social provider.
	 */
	setPassword: (
		{
			fetchOptions: inline,
			password,
		}: { password: string; fetchOptions?: OpaqueFetchOptions },
		fetchOptions?: OpaqueFetchOptions,
	): Promise<OpaqueResult<SetPasswordData>> =>
		run({ ...fetchOptions, ...inline }, async (post) => {
			const registration = await register(password, (registrationRequest) =>
				post("/opaque/set-password/challenge", { registrationRequest }),
			);
			if (registration.error) return registration;
			const result = await post("/opaque/set-password/complete", {
				registrationRecord: registration.data.registrationRecord,
				state: registration.data.state,
			});
			if (result.error) return result;
			return {
				data: {
					...result.data,
					exportKey: registration.data.exportKey,
					serverPublicKey: registration.data.serverPublicKey,
				},
				error: null,
			};
		}),
});
