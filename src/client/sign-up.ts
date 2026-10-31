import type { Reply, Requester } from "./request";
import type { OpaqueFetchOptions, OpaqueResult } from "./types";

type SignUpData = Reply<"/opaque/sign-up/complete"> & {
	exportKey: string;
	serverPublicKey: string;
};

export const signUpActions = ({ run, register }: Requester) => ({
	/**
	 * Register with OPAQUE. The password never leaves the device.
	 * Returns the `exportKey`: a stable 64-byte secret derived from
	 * the password that the server never learns, suitable for
	 * client-side encryption. It changes whenever the password does.
	 */
	opaque: (
		{
			fetchOptions: inline,
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
			fetchOptions?: OpaqueFetchOptions;
			[key: string]: unknown;
		},
		fetchOptions?: OpaqueFetchOptions,
	): Promise<OpaqueResult<SignUpData>> =>
		run(
			{ ...fetchOptions, ...inline },
			async (post) => {
				const registration = await register(password, (registrationRequest) =>
					post("/opaque/sign-up/challenge", { email, registrationRequest }),
				);
				if (registration.error) return registration;
				const result = await post("/opaque/sign-up/complete", {
					email,
					name,
					image,
					callbackURL,
					...additionalFields,
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
			(data) => data.token !== null,
		),
});
