import { client, server } from "@serenity-kit/opaque";
import {
	type Account,
	APIError,
	type GenericEndpointContext,
} from "better-auth";
import { makeSignature } from "better-auth/crypto";
import { OPAQUE_ERROR_CODES } from "../error-codes";

type OpaqueAccount = Account & {
	registrationRecord?: string | null;
	credentialId?: string | null;
};

export async function findOpaqueAccount(
	ctx: GenericEndpointContext,
	userId: string,
): Promise<OpaqueAccount | undefined> {
	const accounts = (await ctx.context.internalAdapter.findAccounts(
		userId,
	)) as OpaqueAccount[];
	return accounts.find((account) => account.providerId === "opaque");
}

// Only compared against a value the server itself put in an encrypted
// state, so the key needs no secrecy.
const recordDigest = (registrationRecord: string) =>
	makeSignature(registrationRecord, "better-auth-opaque:legacy-record");

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
		legacyRecordDigest: await recordDigest(registrationRecord),
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
		identity.legacyRecordDigest ===
		(await recordDigest(account.registrationRecord))
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
export function fakeCredentialId(
	serverSetup: string,
	email: string,
): Promise<string> {
	return makeSignature(
		`better-auth-opaque:fake-credential:${email}`,
		serverSetup,
	);
}

/**
 * Checks that a client-supplied registration record deserialises and can
 * start a login under the given credential identifier. Without this a
 * malformed record would be persisted and every later login would crash.
 */
export function assertValidRegistrationRecord(
	serverSetup: string,
	credentialId: string,
	registrationRecord: string,
): void {
	const { startLoginRequest } = client.startLogin({
		password: "record-validation",
	});
	try {
		server.startLogin({
			serverSetup,
			userIdentifier: credentialId,
			registrationRecord,
			startLoginRequest,
		});
	} catch {
		throw APIError.from(
			"BAD_REQUEST",
			OPAQUE_ERROR_CODES.INVALID_REGISTRATION_RECORD,
		);
	}
}

export async function upsertOpaqueAccount(
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
		// updateAccount is typed to core's columns only.
		await internalAdapter.updateAccount(existing.id, fields as Partial<Account>);
		return;
	}
	await internalAdapter.createAccount({
		providerId: "opaque",
		accountId: data.userId,
		userId: data.userId,
		...fields,
	});
}
