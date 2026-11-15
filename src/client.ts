import type { BetterAuthClientPlugin } from "better-auth/client";
import { passwordActions } from "./client/password.js";
import { type ClientConfig, createRequester } from "./client/request.js";
import { resetPasswordActions } from "./client/reset-password.js";
import { signInActions } from "./client/sign-in.js";
import { signUpActions } from "./client/sign-up.js";
import type {
	OpaqueClientOptions,
	OpaqueClientStore,
	OpaqueFetch,
} from "./client/types.js";
import { OPAQUE_ERROR_CODES } from "./error-codes.js";
import type { opaque } from "./server.js";

export { OpaqueFetchError } from "./client/request.js";
export type {
	OpaqueClientError,
	OpaqueClientOptions,
	OpaqueClientStore,
	OpaqueFetch,
	OpaqueFetchOptions,
	OpaqueResult,
} from "./client/types.js";
export { OPAQUE_ERROR_CODES, type OpaqueErrorCode } from "./error-codes.js";

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
				options,
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
