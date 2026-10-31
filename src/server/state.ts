import { APIError } from "better-auth";
import {
	generateRandomString,
	symmetricDecrypt,
	symmetricEncrypt,
} from "better-auth/crypto";
import { OPAQUE_ERROR_CODES } from "../error-codes";

export const PURPOSE = {
	signUp: "sign-up",
	signIn: "sign-in",
	changePassword: "change-password",
	setPassword: "set-password",
	resetPassword: "reset-password",
} as const;

/**
 * Everything the server needs to finish a handshake lives in this blob,
 * handed to the client between the challenge and complete steps. It is
 * AEAD-encrypted under the auth secret, bound to a purpose so a sign-in
 * state cannot be replayed into change-password, and (via `stateId`)
 * consumed exactly once.
 */
export interface OpaqueState {
	purpose: string;
	stateId: string;
	issuedAt: number;
	serverLoginState?: string;
	userId?: string | null;
	email?: string;
	credentialId?: string;
	newCredentialId?: string;
	token?: string;
}

// Fixed-length ciphertext so the state's size never reveals which branch
// produced it. Large enough for every purpose above with headroom.
const STATE_PADDED_LENGTH = 1024;
export const encoder = new TextEncoder();

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

export async function decryptState(
	encrypted: string,
	secret: string,
	expectedPurpose: string,
	maxAgeMs: number,
): Promise<OpaqueState> {
	let state: OpaqueState;
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
	return state;
}

const stateIdentifier = (stateId: string) => `opaque-state:${stateId}`;

type Ctx = {
	context: {
		secret: string;
		internalAdapter: {
			createVerificationValue: (data: {
				identifier: string;
				value: string;
				expiresAt: Date;
			}) => Promise<unknown>;
			consumeVerificationValue: (
				identifier: string,
			) => Promise<{ value: string; expiresAt: Date } | null | undefined>;
		};
	};
};

export const createStateStore = (challengeTtlMs: number) => ({
	// Issue a one-time, purpose-bound state. The stateId is recorded so the
	// complete step can consume it exactly once.
	issueState: async (
		ctx: Ctx,
		data: Omit<OpaqueState, "stateId" | "issuedAt">,
	) => {
		const stateId = generateRandomString(32);
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

	// Decrypt a state and burn its one-time marker. The marker is consumed
	// atomically (better-auth's consumeVerificationValue), so two requests
	// racing with the same state cannot both pass; it also returns null for
	// an expired row, so there is no separate expiry check to get wrong.
	consumeState: async (ctx: Ctx, encrypted: string, purpose: string) => {
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
