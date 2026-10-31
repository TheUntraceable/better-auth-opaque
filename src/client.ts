import type { BetterAuthClientPlugin } from "better-auth/client";
import { passwordActions } from "./client/password";
import { type ClientConfig, createRequester } from "./client/request";
import { resetPasswordActions } from "./client/reset-password";
import { signInActions } from "./client/sign-in";
import { signUpActions } from "./client/sign-up";
import type {
	OpaqueClientOptions,
	OpaqueClientStore,
	OpaqueFetch,
} from "./client/types";
import { OPAQUE_ERROR_CODES } from "./error-codes";
import type { opaque } from "./server";

export { OpaqueFetchError } from "./client/request";
export type {
	OpaqueClientError,
	OpaqueClientOptions,
	OpaqueClientStore,
	OpaqueFetch,
	OpaqueFetchOptions,
	OpaqueResult,
} from "./client/types";
export { OPAQUE_ERROR_CODES, type OpaqueErrorCode } from "./error-codes";

export const opaqueClient = (options: OpaqueClientOptions = {}) => {
	return {
		id: "opaque",
		$InferServerPlugin: {} as ReturnType<typeof opaque>,
		$ERROR_CODES: OPAQUE_ERROR_CODES,
		getActions(
			$fetch: OpaqueFetch,
			$store: OpaqueClientStore,
			clientOptions: ClientConfig | undefined,
		) {
			const requester = createRequester(
				$fetch,
				$store,
				clientOptions,
				options.serverPublicKey,
			);
			return {
				signUp: signUpActions(requester),
				signIn: signInActions(requester),
				opaque: {
					...passwordActions(requester),
					...resetPasswordActions(requester),
				},
			};
		},
	} satisfies BetterAuthClientPlugin;
};
