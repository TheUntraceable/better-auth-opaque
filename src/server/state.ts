import { APIError, type GenericEndpointContext } from "better-auth";
import {
	generateRandomString,
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
export type OpaqueState = StatePayload & { stateId: string; issuedAt: number };

export type StateFor<P extends Purpose> = Extract<OpaqueState, { purpose: P }>;

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
	secret: string,
): Promise<string> {
	return symmetricEncrypt({
		key: secret,
		data: padToLength(JSON.stringify(state), STATE_PADDED_LENGTH),
	});
}

export async function decryptState<P extends Purpose>(
	encrypted: string,
	secret: string,
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

const stateIdentifier = (stateId: string) => `opaque-state:${stateId}`;

export const createStateStore = (challengeTtlMs: number) => ({
	// The encrypted blob alone is replayable; the marker row is what makes it single-use.
	issueState: async (ctx: GenericEndpointContext, data: StatePayload) => {
		const stateId = generateRandomString(32);
		// Core purges expired rows only in findVerificationValue, not in
		// consumeVerificationValue, and abandoned challenges never reach complete;
		// looking up the fresh id runs that purge with its hooks and disableCleanup.
		await ctx.context.internalAdapter.findVerificationValue(
			stateIdentifier(stateId),
		);
		await ctx.context.internalAdapter.createVerificationValue({
			identifier: stateIdentifier(stateId),
			value: data.purpose,
			expiresAt: new Date(Date.now() + challengeTtlMs),
		});
		return encryptState(
			{ ...data, stateId, issuedAt: Date.now() },
			ctx.context.secret,
		);
	},

	// consumeVerificationValue is atomic, so racing requests cannot both pass,
	// and it returns null for an expired row, hence no expiry check here.
	consumeState: async <P extends Purpose>(
		ctx: GenericEndpointContext,
		encrypted: string,
		purpose: P,
	) => {
		const decoded = await decryptState(
			encrypted,
			ctx.context.secret,
			purpose,
			challengeTtlMs,
		);
		const marker = await ctx.context.internalAdapter.consumeVerificationValue(
			stateIdentifier(decoded.stateId),
		);
		if (!marker || marker.value !== purpose) {
			throw APIError.from(
				"BAD_REQUEST",
				OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE,
			);
		}
		return decoded;
	},
});
