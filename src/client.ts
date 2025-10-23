import type { BetterAuthClientPlugin } from "@better-auth/core";
import { client, ready } from "@serenity-kit/opaque";
import type { opaque } from "./server";

type RegisterChallengeResponse = Awaited<ReturnType<ReturnType<typeof opaque>["endpoints"]["getRegisterChallenge"]>>
type LoginChallengeResponse = Awaited<ReturnType<ReturnType<typeof opaque>["endpoints"]["getLoginChallenge"]>>
type RegisterComplete = Awaited<ReturnType<ReturnType<typeof opaque>["endpoints"]["completeRegistration"]>>
type LoginComplete = Awaited<ReturnType<ReturnType<typeof opaque>["endpoints"]["completeLogin"]>>

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
				}
			}
		},
		// $InferServerPlugin: {} as ReturnType<typeof opaque>,
	} satisfies BetterAuthClientPlugin;
};
