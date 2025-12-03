import type { BetterAuthClientPlugin } from "@better-auth/core";
import { client, ready } from "@serenity-kit/opaque";
import type { opaque } from "./server";

type RegisterChallengeResponse = Awaited<ReturnType<ReturnType<typeof opaque>["endpoints"]["getRegisterChallenge"]>>
type LoginChallengeResponse = Awaited<ReturnType<ReturnType<typeof opaque>["endpoints"]["getLoginChallenge"]>>
type RegisterComplete = Awaited<ReturnType<ReturnType<typeof opaque>["endpoints"]["completeRegistration"]>>
type LoginComplete = Awaited<ReturnType<ReturnType<typeof opaque>["endpoints"]["completeLogin"]>>
type ChangePasswordChallengeResponse = Awaited<ReturnType<ReturnType<typeof opaque>["endpoints"]["getChangePasswordChallenge"]>>
type VerifyCurrentPasswordResponse = Awaited<ReturnType<ReturnType<typeof opaque>["endpoints"]["verifyCurrentPassword"]>>
type CompleteChangePasswordResponse = Awaited<ReturnType<ReturnType<typeof opaque>["endpoints"]["completeChangePassword"]>>

export const opaqueClient = () => {
	return {
		id: "opaque",
		getActions($fetch) {
			return {
				signUp: {
					opaque: async ({ email, name, password }: {
						email: string;
						name: string;
						password: string;
					}) => {
						await ready;
						const { clientRegistrationState, registrationRequest } = client.startRegistration({
							password
						})
						const challengeResponse = await $fetch<RegisterChallengeResponse>("/sign-up/opaque/challenge", {
							method: "POST",
							body: {
								email,
								registrationRequest
							},
						});
						if (challengeResponse.error || !challengeResponse.data || !challengeResponse.data.challenge) {
							return {
								error: challengeResponse.error || {
									message: "Failed to get registration challenge"
								}
							}
						}
						const { challenge: registrationResponse } = challengeResponse.data;
						const { registrationRecord } = client.finishRegistration({
							clientRegistrationState,
							password,
							registrationResponse,
						})
						return await $fetch<RegisterComplete>("/sign-up/opaque/complete", {
							method: "POST",
							body: {
								email,
								name,
								registrationRecord,
							},
						});
					}
				},
				signIn: {
					opaque: async ({ email, password }: {
						email: string;
						password: string;
					}) => {
						await ready;
						const { clientLoginState, startLoginRequest } = client.startLogin({
							password,
						})
						const challengeResponse = await $fetch<LoginChallengeResponse>("/sign-in/opaque/challenge", {
							method: "POST",
							body: {
								email,
								loginRequest: startLoginRequest,
							},
						});

						if (!challengeResponse.data || !challengeResponse.data.challenge) {
							return { data: null, error: { message: "Failed to get registration challenge" } };
						}

						const { challenge: loginResponse, state: encryptedServerState } = challengeResponse.data;

						const loginAttempt = client.finishLogin({
							password,
							clientLoginState,
							loginResponse,
						})
						if (!loginAttempt) {
							return { data: null, error: { message: "Login failed" } };
						}

						const { finishLoginRequest: loginResult } = loginAttempt;

						return await $fetch<LoginComplete>("/sign-in/opaque/complete", {
							method: "POST",
							body: {
								email,
								loginResult,
								encryptedServerState
							},
						});
					}
				},
				changePassword: async ({ currentPassword, newPassword }: {
					currentPassword: string;
					newPassword: string;
				}) => {
					await ready;

					// Step 1: Start login with current password to verify it
					const { clientLoginState, startLoginRequest } = client.startLogin({
						password: currentPassword,
					});

					const challengeResponse = await $fetch<ChangePasswordChallengeResponse>("/change-password/opaque/challenge", {
						method: "POST",
						body: {
							loginRequest: startLoginRequest,
						},
					});

					if (!challengeResponse.data || !challengeResponse.data.challenge) {
						return { data: null, error: challengeResponse.error || { message: "Failed to get password change challenge" } };
					}

					const { challenge: loginResponse, state: encryptedServerState } = challengeResponse.data;

					// Complete login with current password
					const loginAttempt = client.finishLogin({
						password: currentPassword,
						clientLoginState,
						loginResponse,
					});

					if (!loginAttempt) {
						return { data: null, error: { message: "Current password verification failed" } };
					}

					const { finishLoginRequest: loginResult } = loginAttempt;

					// Step 2: Start registration with new password
					const { clientRegistrationState, registrationRequest } = client.startRegistration({
						password: newPassword,
					});

					// Verify current password and get registration challenge for new password
					const verifyResponse = await $fetch<VerifyCurrentPasswordResponse>("/change-password/opaque/verify", {
						method: "POST",
						body: {
							loginResult,
							encryptedServerState,
							registrationRequest,
						},
					});

					if (!verifyResponse.data || !verifyResponse.data.verified || !verifyResponse.data.challenge) {
						return { data: null, error: verifyResponse.error || { message: "Current password verification failed" } };
					}

					const { challenge: registrationResponse } = verifyResponse.data;

					// Step 3: Complete registration with new password
					const { registrationRecord } = client.finishRegistration({
						clientRegistrationState,
						password: newPassword,
						registrationResponse,
					});

					// Complete password change
					return await $fetch<CompleteChangePasswordResponse>("/change-password/opaque/complete", {
						method: "POST",
						body: {
							registrationRecord,
						},
					});
				}
			}
		},
		// $InferServerPlugin: {} as ReturnType<typeof opaque>,
	} satisfies BetterAuthClientPlugin;
};
