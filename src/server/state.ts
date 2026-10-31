import { APIError } from "better-auth";
import {
	type SecretConfig,
	symmetricDecrypt,
	symmetricEncrypt,
} from "better-auth/crypto";
import { OPAQUE_ERROR_CODES } from "../error-codes";
import type { LoginIdentity } from "./account";

export const PURPOSE = {
	signUp: "sign-up",
	signIn: "sign-in",
	changePassword: "change-password",
	setPassword: "set-password",
	resetPassword: "reset-password",
} as const;

export type Purpose = (typeof PURPOSE)[keyof typeof PURPOSE];

export type StatePayload =
	| { purpose: typeof PURPOSE.signUp; email: string; credentialId: string }
	| (LoginIdentity & {
			purpose: typeof PURPOSE.signIn;
			serverLoginState: string;
			userId: string | null;
	  })
	| (LoginIdentity & {
			purpose: typeof PURPOSE.changePassword;
			serverLoginState: string;
			userId: string;
			newCredentialId: string;
	  })
	| {
			purpose: typeof PURPOSE.setPassword;
			userId: string;
			newCredentialId: string;
	  }
	| {
			purpose: typeof PURPOSE.resetPassword;
			userId: string;
			newCredentialId: string;
			token: string;
	  };

/**
 * Everything the server needs to finish a handshake lives in this blob,
 * handed to the client between the challenge and complete steps. It is
 * AEAD-encrypted under the auth secret, bound to a purpose so a sign-in
 * state cannot be replayed into change-password, and (via `stateId`)
 * consumed exactly once. Only the server can mint it, so once the purpose
 * matches, the fields are the ones that purpose was issued with.
 */
type OpaqueState = StatePayload & { stateId: string; issuedAt: number };

type StateFor<P extends Purpose> = Extract<OpaqueState, { purpose: P }>;

// Fixed-length ciphertext so the state's size never reveals which branch
// produced it. Large enough for every purpose above with headroom.
const STATE_PADDED_LENGTH = 1024;
const encoder = new TextEncoder();

function padToLength(input: string, length: number): string {
	const byteLength = encoder.encode(input).length;
	if (byteLength > length) {
		throw new Error(
			`Opaque state is ${byteLength} bytes, over the ${length} byte limit`,
		);
	}
	return input + " ".repeat(length - byteLength);
}

export async function encryptState(
	state: OpaqueState,
	secret: string | SecretConfig,
): Promise<string> {
	return symmetricEncrypt({
		key: secret,
		data: padToLength(JSON.stringify(state), STATE_PADDED_LENGTH),
	});
}

export async function decryptState<P extends Purpose>(
	encrypted: string,
	secret: string | SecretConfig,
	expectedPurpose: P,
	maxAgeMs: number,
): Promise<StateFor<P>> {
	let state: Partial<OpaqueState> | null;
	try {
		state = JSON.parse(
			(await symmetricDecrypt({ key: secret, data: encrypted })).trimEnd(),
		);
	} catch {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE);
	}
	// Domain separation and expiry share one generic error so the response
	// does not say which check failed.
	if (
		!state ||
		typeof state !== "object" ||
		state.purpose !== expectedPurpose ||
		typeof state.stateId !== "string" ||
		typeof state.issuedAt !== "number" ||
		state.issuedAt + maxAgeMs < Date.now()
	) {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE);
	}
	return state as StateFor<P>;
}

export const stateIdentifier = (stateId: string) => `opaque-state:${stateId}`;
