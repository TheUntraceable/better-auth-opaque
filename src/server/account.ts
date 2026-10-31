import { client, ready, server } from "@serenity-kit/opaque";
import { APIError } from "better-auth";
import { OPAQUE_ERROR_CODES } from "../error-codes";
import { encoder } from "./state";

function toBase64Url(bytes: ArrayBuffer): string {
	let binary = "";
	for (const byte of new Uint8Array(bytes)) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * The OPAQUE credential identifier is server-chosen and stable; it must not
 * be the email, which better-auth lower-cases and lets users change. For
 * accounts that do not exist we still need an identifier that is the same
 * every time the same email is tried (otherwise a client reusing a blinded
 * request could tell the OPRF evaluations apart), so derive one from the
 * secret.
 */
export async function fakeCredentialId(
	secret: string,
	email: string,
): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sig = await crypto.subtle.sign(
		"HMAC",
		key,
		encoder.encode(`better-auth-opaque:fake-credential:${email}`),
	);
	return toBase64Url(sig);
}

let dummyLoginRequest: string | undefined;

/**
 * Checks that a client-supplied registration record deserialises and can
 * start a login under the given credential identifier. Without this a
 * malformed record would be persisted and every later login would crash.
 */
export async function assertValidRegistrationRecord(
	serverSetup: string,
	credentialId: string,
	registrationRecord: string,
): Promise<void> {
	await ready;
	dummyLoginRequest ??= client.startLogin({
		password: "record-validation",
	}).startLoginRequest;
	try {
		server.startLogin({
			serverSetup,
			userIdentifier: credentialId,
			registrationRecord,
			startLoginRequest: dummyLoginRequest,
		});
	} catch {
		throw APIError.from(
			"BAD_REQUEST",
			OPAQUE_ERROR_CODES.INVALID_REGISTRATION_RECORD,
		);
	}
}

export interface OpaqueAccount {
	id: string;
	userId: string;
	providerId: string;
	registrationRecord?: string | null;
	credentialId?: string | null;
	[key: string]: unknown;
}

export async function findOpaqueAccount(
	ctx: {
		context: {
			internalAdapter: { findAccounts: (userId: string) => Promise<unknown[]> };
		};
	},
	userId: string,
): Promise<OpaqueAccount | undefined> {
	const accounts = (await ctx.context.internalAdapter.findAccounts(
		userId,
	)) as OpaqueAccount[];
	return accounts.find((account) => account.providerId === "opaque");
}

/**
 * Records written by 2.x were bound to the (lower-cased) email rather than
 * a credential id. Fall back to that so those users keep working.
 */
export function credentialIdFor(
	account: OpaqueAccount | undefined,
	email: string,
): string {
	return account?.credentialId || email;
}
