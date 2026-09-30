/**
 * Helpers shared by the endpoint modules: OPAQUE library calls with their
 * error mapping, the challenge state round trip, OPAQUE account access, and
 * credential invalidation. Endpoints receive an `OpaqueDeps` object.
 */
import { server } from "@serenity-kit/opaque";
import {
	type Account,
	APIError,
	type GenericEndpointContext,
	getCurrentAdapter,
	type User,
} from "better-auth";
import { createEmailVerificationToken } from "better-auth/api";
import { constantTimeEqual } from "better-auth/crypto";
import {
	cloneRequest,
	decryptServerLoginState,
	deriveKey,
	encryptServerLoginState,
	generateNonce,
	hasBase64LengthInRange,
	isDeserializableRegistrationRecord,
	isExpired,
	KEY_LABELS,
	type KeyLabel,
	keyedHash,
	LOGIN_STATE_TTL_MS,
	type LoginStatePurpose,
	NONCE_IDENTIFIER_PREFIX,
	nonceIdentifier,
	normalizeEmail,
	OPAQUE_ERROR_CODES,
	parseOpaqueError,
	REGISTRATION_RECORD_MAX_LENGTH,
	REGISTRATION_RECORD_MIN_LENGTH,
	RESET_TOKEN_IDENTIFIER_PREFIX,
	resetInFlightIdentifier,
	resetOTPIdentifier,
	type ServerLoginStatePayload,
	undecodableInput,
	validateBase64LengthRange,
} from "../utils.js";
import type { ResolvedOpaqueOptions } from "./options.js";

/** What every endpoint factory receives. */
export interface OpaqueDeps {
	options: ResolvedOpaqueOptions;
	/** The OPAQUE server setup (available once `init` has run). */
	getServerSetup: () => string;
}

/** An account row with the plugin's `registrationRecord` column. */
export type OpaqueAccount = Account & { registrationRecord?: string | null };

export type ErrorEntry = { code: string; message: string };

type Logger = GenericEndpointContext["context"]["logger"];

export const OPAQUE_PROVIDER_ID = "opaque";

/**
 * `metadata` of every OPAQUE endpoint. Each is one step of a multi-request
 * flow that only the client plugin's actions can drive, so it is hidden from
 * the inferred client (and `auth.api`) types. No runtime effect.
 */
export const HIDDEN_FROM_CLIENT = { isAction: false } as const;

/* ------------------------------------------------------------------------- */
/*                                   Keys                                    */
/* ------------------------------------------------------------------------- */

/** A per-purpose key derived from the auth secret. */
export function keyFor(ctx: GenericEndpointContext, label: KeyLabel): Promise<string> {
	return deriveKey(ctx.context.secret, label);
}

/** Stands in for "no record" in digests (users without an OPAQUE account, unknown users). */
const NO_RECORD = "\u0000no-registration-record";

/**
 * Keyed digest of a stored registration record (or of its absence) and of
 * the OPAQUE identifier a challenge used with it.
 */
export async function recordDigest(
	ctx: GenericEndpointContext,
	registrationRecord: string | null | undefined,
	identifier: string,
): Promise<string> {
	return keyedHash(
		await keyFor(ctx, KEY_LABELS.recordDigest),
		"record",
		`${identifier}\u0000${registrationRecord ?? NO_RECORD}`,
	);
}

/**
 * The OPAQUE `userIdentifier` of a user's record. The handshake depends on
 * it, so it must not follow later email changes: it is stored as the
 * account's `accountId` (the normalised email the record was registered
 * under). Accounts written by earlier versions hold a generated id there
 * (never an "@"); their records were registered under the user's email.
 */
export function opaqueIdentifier(account: OpaqueAccount | undefined, email: string): string {
	const stored = account?.accountId;
	// Legacy heuristic: an `accountId` containing "@" is taken to be the
	// identifier the record was registered under (every version that stores
	// the identifier stores a normalised email, which always has an "@");
	// anything else (earlier versions' generated ids, or no account at all)
	// falls back to the user's CURRENT email. Limits: the fallback is only
	// right for a legacy record whose user has not changed their email since
	// it was registered (after a change, the password stops verifying until
	// it is reset, which rewrites `accountId`); and a legacy `accountId` that
	// happens to contain "@" (e.g. hand-migrated rows) would be trusted as the
	// identifier. Rows are never rewritten here: a successful reset, change or
	// set-password stores the identifier explicitly.
	return typeof stored === "string" && stored.includes("@") ? stored : normalizeEmail(email);
}

/**
 * Binds a reset credential to the user's current email and password record:
 * any change of either (a password reset / change / set, an email change)
 * invalidates every credential issued before it, on any storage.
 */
export async function resetBinding(
	ctx: GenericEndpointContext,
	user: { id: string; email: string },
	registrationRecord: string | null | undefined,
): Promise<string> {
	return keyedHash(
		await keyFor(ctx, KEY_LABELS.recordDigest),
		"reset-binding",
		[user.id, normalizeEmail(user.email), registrationRecord ?? NO_RECORD].join("\u0000"),
	);
}

/* ------------------------------------------------------------------------- */
/*                         OPAQUE library error mapping                      */
/* ------------------------------------------------------------------------- */

/** The 400 for input that the OPAQUE library could not decode or deserialise. */
const UNDECODABLE_INPUT_ERRORS: Record<string, ErrorEntry> = {
	registrationRequest: OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
	registrationRecord: OPAQUE_ERROR_CODES.INVALID_REGISTRATION_RECORD,
	startLoginRequest: OPAQUE_ERROR_CODES.INVALID_LOGIN_REQUEST,
	finishLoginRequest: OPAQUE_ERROR_CODES.INVALID_LOGIN_RESULT,
	serverLoginState: OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE,
};

/**
 * Maps an exception thrown by `@serenity-kit/opaque` to an `APIError`.
 * Undecodable client input is a 400 (no log: attacker-controlled), a failed
 * credential check is a 401 with `credentialError`. Only an error nothing a
 * client sends explains (e.g. a corrupt server setup) is logged, at error
 * level, and answered with `fallbackStatus` + `credentialError`.
 */
export function toOpaqueAPIError(
	error: unknown,
	logger: Logger,
	credentialError: ErrorEntry,
	fallbackStatus: "UNAUTHORIZED" | "BAD_REQUEST" = "UNAUTHORIZED",
): APIError {
	if (error instanceof APIError) return error;
	const input = undecodableInput(error);
	const inputError = input ? UNDECODABLE_INPUT_ERRORS[input] : undefined;
	if (inputError) return APIError.from("BAD_REQUEST", inputError);
	if (parseOpaqueError(error)?.stage === "finish server login") {
		return APIError.from("UNAUTHORIZED", credentialError);
	}
	logger.error("[better-auth-opaque] Unexpected OPAQUE error", error);
	return APIError.from(fallbackStatus, credentialError);
}

/** `server.createRegistrationResponse`; malformed input is 400 INVALID_REGISTRATION_REQUEST. */
export function registrationResponseOr400(
	deps: OpaqueDeps,
	logger: Logger,
	userIdentifier: string,
	registrationRequest: string,
): string {
	try {
		return server.createRegistrationResponse({
			serverSetup: deps.getServerSetup(),
			userIdentifier,
			registrationRequest,
		}).registrationResponse;
	} catch (error) {
		throw toOpaqueAPIError(
			error,
			logger,
			OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
			"BAD_REQUEST",
		);
	}
}

/**
 * `server.startLogin`. `registrationRecord: null` (unknown user, user without
 * an OPAQUE account) uses the library's built-in fake record, which costs no
 * key stretching and produces a response indistinguishable from a real one.
 * A stored record that cannot be used (corrupt / legacy row) falls back to
 * the same fake path: never a 500, never distinguishable from a wrong password.
 */
export function startLoginSafely(
	deps: OpaqueDeps,
	logger: Logger,
	params: { userIdentifier: string; startLoginRequest: string; registrationRecord: string | null },
	credentialError: ErrorEntry,
) {
	const reportCorrupt = () =>
		logger.error(
			"[better-auth-opaque] A stored registration record is unusable; treating it as invalid credentials",
		);
	let { registrationRecord } = params;
	if (
		registrationRecord !== null &&
		!hasBase64LengthInRange(
			registrationRecord,
			REGISTRATION_RECORD_MIN_LENGTH,
			REGISTRATION_RECORD_MAX_LENGTH,
		)
	) {
		reportCorrupt();
		registrationRecord = null;
	}
	const start = (record: string | null) =>
		server.startLogin({
			serverSetup: deps.getServerSetup(),
			userIdentifier: params.userIdentifier,
			startLoginRequest: params.startLoginRequest,
			registrationRecord: record,
		});
	try {
		return start(registrationRecord);
	} catch (error) {
		if (registrationRecord !== null && undecodableInput(error) === "registrationRecord") {
			reportCorrupt();
			try {
				return start(null);
			} catch (retryError) {
				throw toOpaqueAPIError(retryError, logger, credentialError);
			}
		}
		throw toOpaqueAPIError(error, logger, credentialError);
	}
}

/** `server.finishLogin`; a proof that does not verify is 401 `credentialError`. */
export function finishLoginOr401(
	logger: Logger,
	serverLoginState: string,
	finishLoginRequest: string,
	credentialError: ErrorEntry,
): void {
	try {
		server.finishLogin({ serverLoginState, finishLoginRequest });
	} catch (error) {
		throw toOpaqueAPIError(error, logger, credentialError);
	}
}

/** 400 INVALID_REGISTRATION_RECORD unless the record has a valid length and deserialises. */
export function assertStorableRegistrationRecord(deps: OpaqueDeps, registrationRecord: string) {
	validateBase64LengthRange(
		registrationRecord,
		REGISTRATION_RECORD_MIN_LENGTH,
		REGISTRATION_RECORD_MAX_LENGTH,
		OPAQUE_ERROR_CODES.INVALID_REGISTRATION_RECORD,
	);
	if (!isDeserializableRegistrationRecord(registrationRecord, deps.getServerSetup())) {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_REGISTRATION_RECORD);
	}
}

/* ------------------------------------------------------------------------- */
/*                         Challenge state (login-like)                      */
/* ------------------------------------------------------------------------- */

/**
 * Creates the single-use nonce row (`value` = user id) and the encrypted
 * state of a challenge, bound to `recordDigest`.
 */
export async function issueChallengeState(
	ctx: GenericEndpointContext,
	purpose: LoginStatePurpose,
	userId: string,
	serverLoginState: string,
	digest: string,
): Promise<string> {
	const nonce = generateNonce();
	await ctx.context.internalAdapter.createVerificationValue({
		identifier: nonceIdentifier(purpose, nonce),
		value: userId,
		expiresAt: new Date(Date.now() + LOGIN_STATE_TTL_MS),
	});
	return await encryptServerLoginState(
		serverLoginState,
		await keyFor(ctx, KEY_LABELS.state),
		{ id: userId },
		{ nonce, purpose, recordDigest: digest },
	);
}

/**
 * Decrypts a challenge state issued for `purpose` and consumes its nonce
 * (single use, BEFORE any credential check). A state of another flow is 400
 * INVALID_LOGIN_STATE; a state of another user (`expectedUserId`, checked
 * before consuming so nobody can burn someone else's challenge) or a used /
 * unknown nonce is 401 `credentialError`.
 */
export async function consumeChallengeState(
	ctx: GenericEndpointContext,
	encryptedState: string,
	purpose: LoginStatePurpose,
	credentialError: ErrorEntry,
	expectedUserId?: string,
): Promise<ServerLoginStatePayload> {
	const state = await decryptServerLoginState(
		encryptedState,
		await keyFor(ctx, KEY_LABELS.state),
	);
	if (state.purpose !== purpose) {
		throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_LOGIN_STATE);
	}
	if (expectedUserId !== undefined && state.userId !== expectedUserId) {
		throw APIError.from("UNAUTHORIZED", credentialError);
	}
	const nonceRow = await ctx.context.internalAdapter.consumeVerificationValue(
		nonceIdentifier(purpose, state.nonce),
	);
	if (!nonceRow || nonceRow.value !== state.userId) {
		throw APIError.from("UNAUTHORIZED", credentialError);
	}
	return state;
}

/**
 * The user's current OPAQUE account, provided its record (and identifier)
 * is still the one the challenge was issued against (constant-time digest
 * comparison); otherwise 401 `credentialError`. A challenge issued before a
 * password reset / change can therefore never be completed.
 */
export async function assertRecordUnchanged(
	ctx: GenericEndpointContext,
	state: ServerLoginStatePayload,
	user: { id: string; email: string },
	credentialError: ErrorEntry,
): Promise<OpaqueAccount | undefined> {
	const account = await findOpaqueAccount(ctx, user.id);
	const current = await recordDigest(
		ctx,
		account?.registrationRecord,
		opaqueIdentifier(account, user.email),
	);
	if (!constantTimeEqual(current, state.recordDigest)) {
		throw APIError.from("UNAUTHORIZED", credentialError);
	}
	return account;
}

/* ------------------------------------------------------------------------- */
/*                              OPAQUE accounts                              */
/* ------------------------------------------------------------------------- */

/** Every `opaque` account of a user. */
export async function findOpaqueAccounts(
	ctx: GenericEndpointContext,
	userId: string,
): Promise<OpaqueAccount[]> {
	const accounts: OpaqueAccount[] = await ctx.context.internalAdapter.findAccounts(userId);
	return accounts.filter((account) => account.providerId === OPAQUE_PROVIDER_ID);
}

/** The canonical account: the oldest (by `createdAt`, then `id`). */
function canonicalAccount(accounts: OpaqueAccount[]): OpaqueAccount | undefined {
	let best: OpaqueAccount | undefined;
	let bestTime = Number.POSITIVE_INFINITY;
	for (const account of accounts) {
		const time = new Date(account.createdAt).getTime();
		const t = Number.isFinite(time) ? time : Number.POSITIVE_INFINITY;
		if (!best || t < bestTime || (t === bestTime && String(account.id) < String(best.id))) {
			best = account;
			bestTime = t;
		}
	}
	return best;
}

/** The user's (canonical) OPAQUE account, if any. */
export async function findOpaqueAccount(
	ctx: GenericEndpointContext,
	userId: string,
): Promise<OpaqueAccount | undefined> {
	return canonicalAccount(await findOpaqueAccounts(ctx, userId));
}

/** A registration record and the OPAQUE identifier it was registered under. */
export interface OpaqueCredential {
	registrationRecord: string;
	identifier: string;
}

export async function createOpaqueAccount(
	ctx: GenericEndpointContext,
	userId: string,
	credential: OpaqueCredential,
): Promise<OpaqueAccount> {
	const now = new Date();
	return await ctx.context.internalAdapter.createAccount({
		accountId: credential.identifier,
		providerId: OPAQUE_PROVIDER_ID,
		userId,
		registrationRecord: credential.registrationRecord,
		createdAt: now,
		updatedAt: now,
	});
}

/** Replaces the record (and its identifier) of an OPAQUE account. */
export async function updateOpaqueRecord(
	ctx: GenericEndpointContext,
	accountId: string,
	credential: OpaqueCredential,
): Promise<void> {
	const update: Partial<OpaqueAccount> = {
		accountId: credential.identifier,
		registrationRecord: credential.registrationRecord,
		updatedAt: new Date(),
	};
	await ctx.context.internalAdapter.updateAccount(accountId, update);
}

/**
 * Compare-and-swap of an OPAQUE account's record: replaces it (and its
 * identifier) only if the stored record is still `expectedRecord`, the one
 * the caller checked its credential against. Returns whether a row was
 * written. One conditional `updateMany` (`id = ? AND registrationRecord = ?`),
 * atomic on every database; inside `runWithTransaction` it joins the
 * transaction. Being a raw adapter write, it runs no `databaseHooks`.
 */
export async function swapOpaqueRecord(
	ctx: GenericEndpointContext,
	accountId: string,
	expectedRecord: string | null | undefined,
	credential: OpaqueCredential,
): Promise<boolean> {
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const updated = await adapter.updateMany({
		model: "account",
		where: [
			{ field: "id", value: accountId },
			{ field: "registrationRecord", value: expectedRecord ?? null },
		],
		update: {
			accountId: credential.identifier,
			registrationRecord: credential.registrationRecord,
			updatedAt: new Date(),
		},
	});
	return updated > 0;
}

/**
 * Converges concurrent password resets (of a user who had no OPAQUE
 * account) on exactly one OPAQUE account. The adapter cannot enforce "one
 * opaque account per user", so every such writer, AFTER its own account is
 * committed, lists the user's OPAQUE accounts; the canonical one (oldest by
 * `createdAt`, then `id`) is kept. A writer whose account is not canonical
 * moves its record into the canonical account (a compare-and-swap: if the
 * canonical account changed or disappeared meanwhile, it lists again); every
 * non-canonical account is deleted. Whichever writer lists last sees every
 * account and leaves exactly one; its record is one of the writers' records.
 * A concurrent set-password yields to resets (`yieldToOtherOpaqueWriters`).
 *
 * Must run outside a transaction, so that it sees the other writers' rows.
 */
export async function convergeOpaqueAccounts(
	ctx: GenericEndpointContext,
	userId: string,
	ourAccountId: string,
	credential: OpaqueCredential,
): Promise<void> {
	for (let attempt = 0; attempt < 5; attempt++) {
		const accounts = await findOpaqueAccounts(ctx, userId);
		const canonical = canonicalAccount(accounts);
		if (!canonical) return;
		if (
			canonical.id !== ourAccountId &&
			accounts.some((a) => a.id === ourAccountId) &&
			!(await swapOpaqueRecord(ctx, canonical.id, canonical.registrationRecord, credential))
		) {
			continue;
		}
		for (const account of accounts) {
			if (account.id !== canonical.id) {
				await ctx.context.internalAdapter.deleteAccount(account.id);
			}
		}
		return;
	}
}

/**
 * For set-password, which yields to every concurrent password writer (a
 * reset has priority). Runs after its own account is committed; returns
 * whether it yielded (then the request is a 400).
 *
 * - A reset of the user is in flight (its marker, written before the reset
 *   checks its credential's binding, exists): our account is deleted if it
 *   still holds our record (compare-and-delete; if the reset already wrote
 *   into it, it is left alone). Either the reset saw no account when it
 *   checked, and it writes its own, or it saw ours and fails.
 * - Another OPAQUE account exists: ours is deleted or, when it is the
 *   canonical one (which concurrent resets copy their record into, so it
 *   must survive), it takes over the other writer's record and the others
 *   are deleted.
 *
 * A reset whose binding check ran before our account was committed wrote
 * its marker before that commit, so it is seen here: either its marker or
 * (once it has finished) its record. Must run outside a transaction.
 */
export async function yieldToOtherOpaqueWriters(
	ctx: GenericEndpointContext,
	userId: string,
	ourAccountId: string,
	ourRecord: string,
): Promise<boolean> {
	const inFlight = await ctx.context.internalAdapter.findVerificationValue(
		resetInFlightIdentifier(userId),
	);
	if (inFlight && !isExpired(inFlight)) {
		const adapter = await getCurrentAdapter(ctx.context.adapter);
		await adapter.deleteMany({
			model: "account",
			where: [
				{ field: "id", value: ourAccountId },
				{ field: "registrationRecord", value: ourRecord },
			],
		});
		return true;
	}
	const accounts = await findOpaqueAccounts(ctx, userId);
	const others = accounts.filter((account) => account.id !== ourAccountId);
	const theirs = canonicalAccount(others);
	if (!theirs) return false;
	if (canonicalAccount(accounts)?.id !== ourAccountId) {
		await ctx.context.internalAdapter.deleteAccount(ourAccountId);
		return true;
	}
	if (typeof theirs.registrationRecord === "string") {
		await updateOpaqueRecord(ctx, ourAccountId, {
			registrationRecord: theirs.registrationRecord,
			identifier: theirs.accountId,
		});
	}
	for (const account of others) {
		await ctx.context.internalAdapter.deleteAccount(account.id);
	}
	return true;
}

/* ------------------------------------------------------------------------- */
/*                         Credential invalidation                           */
/* ------------------------------------------------------------------------- */

/** Whether verification rows are stored in the database (not only in secondary storage). */
function verificationRowsInDatabase(ctx: GenericEndpointContext): boolean {
	const options = ctx.context.options;
	return !options.secondaryStorage || options.verification?.storeInDatabase === true;
}

/**
 * After the user's password record changed: deletes every outstanding
 * credential issued against the old record — sign-in and change-password
 * challenge nonces, reset links, and the reset code of the current email.
 *
 * Nonce and link rows store the user id as `value`, so they are deleted
 * with one `deleteMany` per prefix: `identifier LIKE '<prefix>%' AND value = ?`
 * (portable `starts_with` + `eq`; the prefixes contain no LIKE wildcard).
 * The OTP row is found by its identifier (a keyed hash of the email).
 *
 * This is hygiene, not the security boundary: every such credential is also
 * bound to the record it was issued against (`recordDigest` /
 * `resetBinding`), which is what makes it unusable on every storage,
 * including secondary-storage-only verification and hashed identifiers
 * (`verification.storeIdentifier`), where rows cannot be enumerated.
 */
export async function purgeOutstandingCredentials(
	ctx: GenericEndpointContext,
	user: { id: string; email: string },
): Promise<void> {
	await ctx.context.internalAdapter.deleteVerificationByIdentifier(
		await resetOTPIdentifier(await keyFor(ctx, KEY_LABELS.resetOTP), user.email),
	);
	if (!verificationRowsInDatabase(ctx)) return;
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	for (const prefix of [
		NONCE_IDENTIFIER_PREFIX.login,
		NONCE_IDENTIFIER_PREFIX["change-password"],
		RESET_TOKEN_IDENTIFIER_PREFIX,
	]) {
		await adapter.deleteMany({
			model: "verification",
			where: [
				{ field: "identifier", operator: "starts_with", value: prefix },
				{ field: "value", value: user.id },
			],
		});
	}
}

/**
 * Deletes every expired verification row (as core's `findVerificationValue`
 * does, and honouring `verification.disableCleanup`), e.g. challenge nonces
 * that were never completed. Called only on authenticated or rate-limited,
 * rarely used paths (change-password and set-password challenges,
 * forget-password), never on the unauthenticated sign-in challenge, whose
 * cost must not depend on the table. No-op when verification rows live only
 * in secondary storage (they expire there by TTL).
 */
export async function deleteExpiredVerificationRows(ctx: GenericEndpointContext): Promise<void> {
	if (!verificationRowsInDatabase(ctx) || ctx.context.options.verification?.disableCleanup) return;
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	await adapter.deleteMany({
		model: "verification",
		where: [{ field: "expiresAt", operator: "lt", value: new Date() }],
	});
}

/* ------------------------------------------------------------------------- */
/*                             Email verification                            */
/* ------------------------------------------------------------------------- */

/** Plugin option if set, else core's `emailAndPassword.requireEmailVerification`. */
export function requiresEmailVerification(deps: OpaqueDeps, ctx: GenericEndpointContext): boolean {
	return (
		deps.options.raw.requireEmailVerification ??
		ctx.context.options.emailAndPassword?.requireEmailVerification ??
		false
	);
}

/**
 * Sends core's verification email exactly as core's `/sign-up/email` and
 * `/sign-in/email` do (same token helper, same URL). No-op when
 * `emailVerification.sendVerificationEmail` is not configured.
 */
export async function sendVerificationEmail(
	ctx: GenericEndpointContext,
	user: User,
	callbackURL: string | undefined,
): Promise<void> {
	const send = ctx.context.options.emailVerification?.sendVerificationEmail;
	if (!send) return;
	const token = await createEmailVerificationToken(
		ctx.context.secret,
		user.email,
		undefined,
		ctx.context.options.emailVerification?.expiresIn,
	);
	const url = `${ctx.context.baseURL}/verify-email?token=${token}&callbackURL=${encodeURIComponent(callbackURL || "/")}`;
	await runEmailCallback(ctx, () => send({ user, url, token }, cloneRequest(ctx.request)));
}

/**
 * Runs an app-supplied email callback through `runInBackgroundOrAwait`
 * (awaited, or handed to `advanced.backgroundTasks`), which logs a failure
 * at error level instead of failing the request. The call itself is
 * deferred into the promise, so a callback that throws synchronously is
 * handled the same way: the response never depends on whether it threw.
 */
export async function runEmailCallback(
	ctx: GenericEndpointContext,
	callback: () => unknown,
): Promise<void> {
	await ctx.context.runInBackgroundOrAwait(Promise.resolve().then(callback));
}

/* ------------------------------------------------------------------------- */
/*                                   Misc                                    */
/* ------------------------------------------------------------------------- */

/**
 * An id that belongs to no user, for the unknown-user path of flows that
 * must touch the database exactly as for a known user.
 */
export function phantomUserId(ctx: GenericEndpointContext): string {
	const generated = ctx.context.generateId({ model: "user" });
	if (generated) return generated;
	// Database-generated ids: a value of the column's type that no row has.
	return ctx.context.options.advanced?.database?.generateId === "serial"
		? "0"
		: crypto.randomUUID();
}
