import type { Reply, Requester } from "./request";
import type { OpaqueFetchOptions, OpaqueResult } from "./types";

type ResetPasswordData = Reply<"/opaque/reset-password/complete"> & {
	exportKey: string;
	serverPublicKey: string;
};

export const resetPasswordActions = ({ run, register }: Requester) => ({
	/**
	 * Email a password reset link. Always succeeds from the caller's
	 * point of view so it cannot be used to probe for accounts.
	 */
	requestPasswordReset: (
		{
			fetchOptions: inline,
			email,
			redirectTo,
		}: {
			email: string;
			redirectTo?: string;
			fetchOptions?: OpaqueFetchOptions;
		},
		fetchOptions?: OpaqueFetchOptions,
	): Promise<OpaqueResult<Reply<"/opaque/reset-password/request">>> =>
		run({ ...fetchOptions, ...inline }, (post) =>
			post("/opaque/reset-password/request", { email, redirectTo }),
		),

	/**
	 * Finish a password reset with the token from the emailed link.
	 * Every existing session is revoked. The returned `exportKey` is
	 * new; anything encrypted under the previous one is unrecoverable
	 * unless the app kept a separate recovery path.
	 */
	resetPassword: (
		{
			fetchOptions: inline,
			token,
			newPassword,
		}: {
			token: string;
			newPassword: string;
			fetchOptions?: OpaqueFetchOptions;
		},
		fetchOptions?: OpaqueFetchOptions,
	): Promise<OpaqueResult<ResetPasswordData>> =>
		run(
			{ ...fetchOptions, ...inline },
			async (post) => {
				const registration = await register(newPassword, (registrationRequest) =>
					post("/opaque/reset-password/challenge", {
						token,
						registrationRequest,
					}),
				);
				if (registration.error) return registration;
				const result = await post("/opaque/reset-password/complete", {
					token,
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
			},
			// Every session was revoked server-side; drop the cached one.
			() => true,
		),
});
