/**
 * Combined entry (server plugin + client plugin), kept for backwards
 * compatibility. Browser code should import from `better-auth-opaque/client`
 * and server code from `better-auth-opaque/server`, so neither bundle pulls in
 * the other side.
 */
export {
	type ChangePasswordOpaqueData,
	type ChangePasswordOpaqueInput,
	type ForgetPasswordOpaqueInput,
	type OpaqueClientError,
	type OpaqueClientResult,
	type OpaqueFetchOptions,
	opaqueClient,
	type ResetPasswordOpaqueInput,
	type SetPasswordOpaqueInput,
	type SignInOpaqueData,
	type SignInOpaqueInput,
	type SignUpOpaqueData,
	type SignUpOpaqueInput,
	type StatusData,
} from "./client.js";
export { opaque } from "./server.js";
export { OPAQUE_ERROR_CODES, type OpaqueErrorCode } from "./error-codes.js";
export type { OpaqueOptions } from "./utils.js";
