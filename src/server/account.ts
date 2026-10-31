import { client, ready, server } from "@serenity-kit/opaque";
import { APIError, type GenericEndpointContext } from "better-auth";
import { OPAQUE_ERROR_CODES } from "../error-codes";

export interface OpaqueAccount {
	id: string;
	userId: string;
	providerId: string;
	registrationRecord?: string | null;
	credentialId?: string | null;
	[key: string]: unknown;
}

export async function findOpaqueAccount(
	ctx: GenericEndpointContext,
	userId: string,
): Promise<OpaqueAccount | undefined> {
	const accounts = (await ctx.context.internalAdapter.findAccounts(
		userId,
	)) as OpaqueAccount[];
	return accounts.find((account) => account.providerId === "opaque");
}

const encoder = new TextEncoder();

function toBase64Url(bytes: ArrayBuffer): string {
	let binary = "";
	for (const byte of new Uint8Array(bytes)) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const digest = async (value: string) =>
	toBase64Url(await crypto.subtle.digest("SHA-256", encoder.encode(value)));

/** The identifier a login challenge was computed under, carried in its state. */
export interface LoginIdentity {
	credentialId: string;
	legacyRecordDigest?: string | undefined;
}

/**
 * Records written by 2.x have no credentialId: they were bound to the email
 * exactly as the client sent it, untrimmed and in its original case, so only
 * that same string can open them. Changing, setting or resetting the
 * password writes a credentialId, which ends the fallback for that account.
 */
export async function loginIdentity(
	account: OpaqueAccount,
	registrationRecord: string,
	email: string,
): Promise<LoginIdentity> {
	if (account.credentialId) return { credentialId: account.credentialId };
	return {
		credentialId: email,
		legacyRecordDigest: await digest(registrationRecord),
	};
}

/**
 * Whether the account still holds the record a challenge was computed
 * against. Every write gives a new credentialId, except that nothing does
 * for a 2.x record replaced in place, hence the digest.
 */
export async function matchesLoginIdentity(
	account: OpaqueAccount | undefined,
	identity: LoginIdentity,
): Promise<boolean> {
	if (!account?.registrationRecord) return false;
	if (account.credentialId) {
		return (
			!identity.legacyRecordDigest &&
			account.credentialId === identity.credentialId
		);
	}
	return (
		identity.legacyRecordDigest === (await digest(account.registrationRecord))
	);
}

/**
 * The OPAQUE credential identifier is server-chosen and stable; it must not
 * be the email, which better-auth lower-cases and lets users change. For
 * emails with no record we still need an identifier that is the same every
 * time the same email is tried (otherwise a client reusing a blinded request
 * could tell the OPRF evaluations apart). Keyed on the server setup, which
 * already determines every real evaluation: keyed on the auth secret,
 * rotating that secret would change the answers for unknown emails only.
 */
export async function fakeCredentialId(
	serverSetup: string,
	email: string,
): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		encoder.encode(serverSetup),
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

// The plugin's account fields are not in core's account type, hence the casts.
export async function saveOpaqueRecord(
	ctx: GenericEndpointContext,
	existing: OpaqueAccount | undefined,
	data: { userId: string; registrationRecord: string; credentialId: string },
): Promise<void> {
	const { internalAdapter } = ctx.context;
	const fields = {
		registrationRecord: data.registrationRecord,
		credentialId: data.credentialId,
	};
	if (existing) {
		await internalAdapter.updateAccount(
			existing.id,
			fields as Parameters<typeof internalAdapter.updateAccount>[1],
		);
		return;
	}
	await internalAdapter.createAccount({
		providerId: "opaque",
		accountId: data.userId,
		userId: data.userId,
		...fields,
	} as Parameters<typeof internalAdapter.createAccount>[0]);
}
