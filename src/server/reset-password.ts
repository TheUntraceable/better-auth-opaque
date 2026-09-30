/**
 * Forgot / reset password, by emailed link (token) or one-time code (OTP):
 * `/opaque/forget-password`, `GET /opaque/reset-password/:token`,
 * `/opaque/reset-password/{challenge,complete}`.
 *
 * Every credential is bound (`resetBinding`) to the user's email and password
 * record when it was issued: an email change or any password write kills it.
 */
import { runWithTransaction } from "@better-auth/core/context";
import { APIError, type GenericEndpointContext, type User } from "better-auth";
import { createAuthEndpoint, originCheck } from "better-auth/api";
import { constantTimeEqual, generateRandomString } from "better-auth/crypto";
import * as z from "zod";
import {
	cloneRequest,
	createResetToken,
	decodeResetOTPRecord,
	encodeResetOTPRecord,
	hashResetOTP,
	isExpired,
	KEY_LABELS,
	normalizeEmail,
	OPAQUE_ERROR_CODES,
	REGISTRATION_REQUEST_LENGTH,
	resetOTPIdentifier,
	resetTokenBinding,
	resetTokenIdentifier,
	validateBase64Length,
} from "../utils.js";
import {
	assertStorableRegistrationRecord,
	convergeOpaqueAccounts,
	findOpaqueAccount,
	HIDDEN_FROM_CLIENT,
	keyFor,
	type OpaqueDeps,
	phantomUserId,
	purgeOutstandingCredentials,
	registrationResponseOr400,
	resetBinding,
	writeOpaqueRecord,
} from "./shared.js";

type ResetCredential =
	| { kind: "token"; token: string }
	| { kind: "otp"; email: string; otp: string };

const invalidToken = () => APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_TOKEN);

/** Exactly one of `{ token }` or `{ email, otp }`; anything else is INVALID_TOKEN. */
function parseResetCredential(body: {
	token?: string;
	email?: string;
	otp?: string;
}): ResetCredential {
	const { token, email, otp } = body;
	if (token && email === undefined && otp === undefined) {
		return { kind: "token", token };
	}
	if (token === undefined && email && otp) {
		return { kind: "otp", email: normalizeEmail(email), otp };
	}
	throw invalidToken();
}

/** Whether `binding` is what the user's current email and record would get now. */
async function bindingIsCurrent(
	ctx: GenericEndpointContext,
	user: User,
	binding: string,
): Promise<boolean> {
	const account = await findOpaqueAccount(ctx, user.id);
	const expected = await resetBinding(ctx, user, account?.registrationRecord);
	return constantTimeEqual(expected, binding);
}

/**
 * Checks a reset credential and returns the user it was issued for. Every
 * failure is 400 INVALID_TOKEN.
 *
 * Link token: looked up by its keyed hash; consumed (atomically) only when
 * `consume` is set; its binding must be current.
 *
 * OTP: the stored row is taken with an atomic consume, which serialises
 * concurrent guesses (a racer finds nothing and is rejected). A wrong code
 * puts the row back with one more attempt counted, unless that was the last
 * allowed attempt: then the row stays deleted. A correct code puts it back
 * unchanged unless `consume` is set. A locked code is indistinguishable from
 * an unknown one.
 */
async function verifyResetCredential(
	ctx: GenericEndpointContext,
	deps: OpaqueDeps,
	credential: ResetCredential,
	consume: boolean,
): Promise<User> {
	const adapter = ctx.context.internalAdapter;
	if (credential.kind === "token") {
		const binding = resetTokenBinding(credential.token);
		if (!binding) throw invalidToken();
		const identifier = await resetTokenIdentifier(
			await keyFor(ctx, KEY_LABELS.resetToken),
			credential.token,
		);
		const row = consume
			? await adapter.consumeVerificationValue(identifier)
			: await adapter.findVerificationValue(identifier);
		if (!row || isExpired(row)) throw invalidToken();
		const user = await adapter.findUserById(row.value);
		if (!user || !(await bindingIsCurrent(ctx, user, binding))) throw invalidToken();
		return user;
	}

	const otpKey = await keyFor(ctx, KEY_LABELS.resetOTP);
	const identifier = await resetOTPIdentifier(otpKey, credential.email);
	// Hash first so a missing row costs the same as a present one.
	const submittedHash = await hashResetOTP(otpKey, credential.email, credential.otp);
	const row = await adapter.consumeVerificationValue(identifier);
	if (!row) throw invalidToken();
	const record = decodeResetOTPRecord(row.value);
	const { allowedAttempts } = deps.options.resetOTP;
	if (!record || record.attempts >= allowedAttempts) throw invalidToken();
	const restore = (attempts: number) =>
		adapter.createVerificationValue({
			identifier,
			value: encodeResetOTPRecord({ ...record, attempts }),
			expiresAt: new Date(row.expiresAt),
		});
	if (!constantTimeEqual(record.otpHash, submittedHash)) {
		const attempts = record.attempts + 1;
		// The guess that uses up the budget leaves the code deleted.
		if (attempts < allowedAttempts) await restore(attempts);
		throw invalidToken();
	}
	const user = await adapter.findUserById(record.userId);
	if (
		!user ||
		normalizeEmail(user.email) !== credential.email ||
		!(await bindingIsCurrent(ctx, user, record.binding))
	) {
		// Superseded: stays deleted.
		throw invalidToken();
	}
	if (!consume) await restore(record.attempts);
	return user;
}

export function resetPasswordEndpoints(deps: OpaqueDeps) {
	const { raw } = deps.options;

	/** 400 RESET_PASSWORD_METHOD_NOT_CONFIGURED unless the delivery callback exists. */
	const resolveResetMethod = (requested: "link" | "otp" | undefined) => {
		const method = requested ?? (raw.sendResetPassword ? "link" : "otp");
		const configured =
			method === "link" ? !!raw.sendResetPassword : !!raw.sendResetPasswordOTP;
		if (!configured) {
			throw APIError.from(
				"BAD_REQUEST",
				OPAQUE_ERROR_CODES.RESET_PASSWORD_METHOD_NOT_CONFIGURED,
			);
		}
		return method;
	};

	return {
		/**
		 * Sends a reset link (`sendResetPassword`) or code
		 * (`sendResetPasswordOTP`) to an existing user. Always 200 with the
		 * same body for unknown emails (nothing is sent).
		 */
		opaqueForgetPassword: createAuthEndpoint(
			"/opaque/forget-password",
			{
				method: "POST",
				body: z.object({
					email: z.string().email(),
					/** Default: "link" if `sendResetPassword` is configured, else "otp". */
					method: z.enum(["link", "otp"]).optional(),
					/** Link only: where the emailed link finally lands (with `?token=`). Default "/". */
					redirectTo: z.string().optional(),
				}),
				// As core's /request-password-reset (the router-level origin
				// check also rejects an untrusted `redirectTo`).
				use: [originCheck((ctx) => ctx.body.redirectTo)],
				metadata: HIDDEN_FROM_CLIENT,
			},
			async (ctx) => {
				const method = resolveResetMethod(ctx.body.method);
				const email = normalizeEmail(ctx.body.email);
				const adapter = ctx.context.internalAdapter;
				const found = await adapter.findUserByEmail(email);
				// Same account lookup for unknown emails.
				const account = await findOpaqueAccount(ctx, found?.user.id ?? phantomUserId(ctx));
				const response = {
					status: true,
					message:
						method === "link"
							? "If this email exists in our system, check your email for the reset link"
							: "If this email exists in our system, check your email for the reset code",
				};
				const binding = await resetBinding(
					ctx,
					found?.user ?? { id: "", email },
					account?.registrationRecord,
				);

				if (method === "link") {
					const token = createResetToken(binding);
					const identifier = await resetTokenIdentifier(
						await keyFor(ctx, KEY_LABELS.resetToken),
						token,
					);
					if (!found) {
						// Same token work plus a verification-table round trip, as core.
						await adapter.findVerificationValue(identifier);
						return ctx.json(response);
					}
					await adapter.createVerificationValue({
						identifier,
						// The user id, so the row can be purged after a password change.
						value: found.user.id,
						expiresAt: new Date(Date.now() + deps.options.resetTokenExpiresIn * 1000),
					});
					const callbackURL = encodeURIComponent(ctx.body.redirectTo || "/");
					const url = `${ctx.context.baseURL}/opaque/reset-password/${token}?callbackURL=${callbackURL}`;
					await ctx.context.runInBackgroundOrAwait(
						raw.sendResetPassword?.({ user: found.user, url, token }, cloneRequest(ctx.request)),
					);
					return ctx.json(response);
				}

				const otp = generateRandomString(deps.options.resetOTP.length, "0-9");
				const otpKey = await keyFor(ctx, KEY_LABELS.resetOTP);
				const identifier = await resetOTPIdentifier(otpKey, email);
				const otpHash = await hashResetOTP(otpKey, email, otp);
				if (!found) {
					await adapter.findVerificationValue(identifier);
					return ctx.json(response);
				}
				// One live code per email; a new code starts a new attempt budget.
				await adapter.deleteVerificationByIdentifier(identifier);
				await adapter.createVerificationValue({
					identifier,
					value: encodeResetOTPRecord({
						userId: found.user.id,
						otpHash,
						attempts: 0,
						binding,
					}),
					expiresAt: new Date(Date.now() + deps.options.resetOTP.expiresIn * 1000),
				});
				await ctx.context.runInBackgroundOrAwait(
					raw.sendResetPasswordOTP?.({ user: found.user, otp }, cloneRequest(ctx.request)),
				);
				return ctx.json(response);
			},
		),

		/**
		 * The emailed link. Mirrors core's GET /reset-password/:token:
		 * redirects to `callbackURL?token=...`, or `?error=INVALID_TOKEN`.
		 * Does not consume the token.
		 */
		opaqueResetPasswordCallback: createAuthEndpoint(
			"/opaque/reset-password/:token",
			{
				method: "GET",
				query: z.object({ callbackURL: z.string() }),
				use: [originCheck((ctx) => ctx.query.callbackURL)],
				metadata: HIDDEN_FROM_CLIENT,
			},
			async (ctx) => {
				const { token } = ctx.params;
				const { callbackURL } = ctx.query;
				const redirectURL = (query: Record<string, string>) => {
					const url = new URL(callbackURL, ctx.context.baseURL);
					for (const [key, value] of Object.entries(query)) {
						url.searchParams.set(key, value);
					}
					return url.href;
				};
				try {
					if (!token) throw invalidToken();
					await verifyResetCredential(ctx, deps, { kind: "token", token }, false);
				} catch (error) {
					if (!(error instanceof APIError)) throw error;
					throw ctx.redirect(redirectURL({ error: "INVALID_TOKEN" }));
				}
				throw ctx.redirect(redirectURL({ token }));
			},
		),

		/** Step 1 of a reset: `{ token } | { email, otp }` + `registrationRequest` → `{ challenge }`. Does not consume the credential. */
		opaqueResetPasswordChallenge: createAuthEndpoint(
			"/opaque/reset-password/challenge",
			{
				method: "POST",
				body: z.object({
					token: z.string().optional(),
					email: z.string().optional(),
					otp: z.string().optional(),
					registrationRequest: z.string().base64url(),
				}),
				metadata: HIDDEN_FROM_CLIENT,
			},
			async (ctx) => {
				const credential = parseResetCredential(ctx.body);
				const { registrationRequest } = ctx.body;
				validateBase64Length(
					registrationRequest,
					REGISTRATION_REQUEST_LENGTH,
					OPAQUE_ERROR_CODES.INVALID_REGISTRATION_REQUEST,
				);
				const user = await verifyResetCredential(ctx, deps, credential, false);
				const challenge = registrationResponseOr400(
					deps,
					ctx.context.logger,
					normalizeEmail(user.email),
					registrationRequest,
				);
				return { challenge };
			},
		),

		/**
		 * Step 2 of a reset: `{ token } | { email, otp }` + `registrationRecord`
		 * → `{ status: true }`. Consumes the credential, replaces (or creates)
		 * the OPAQUE account, marks the email verified, deletes every session
		 * and every outstanding challenge / reset credential of the user, and
		 * sets no cookies.
		 */
		opaqueResetPasswordComplete: createAuthEndpoint(
			"/opaque/reset-password/complete",
			{
				method: "POST",
				body: z.object({
					token: z.string().optional(),
					email: z.string().optional(),
					otp: z.string().optional(),
					registrationRecord: z.string().base64url(),
				}),
				metadata: HIDDEN_FROM_CLIENT,
			},
			async (ctx) => {
				const credential = parseResetCredential(ctx.body);
				const { registrationRecord } = ctx.body;
				// Before touching the credential: a malformed record neither
				// consumes it nor counts as an OTP attempt.
				assertStorableRegistrationRecord(deps, registrationRecord);

				// Consumed outside the transaction: the atomic consume is the
				// gate between concurrent completes.
				const user = await verifyResetCredential(ctx, deps, credential, true);
				const adapter = ctx.context.internalAdapter;

				// Re-registered under the current email (the challenge step's
				// identifier; the credential's binding guarantees it is unchanged).
				const newCredential = { registrationRecord, identifier: normalizeEmail(user.email) };

				const accountId = await runWithTransaction(ctx.context.adapter, async () => {
					const id = await writeOpaqueRecord(ctx, user.id, newCredential);
					// Following the emailed link/code proved control of the mailbox.
					if (!user.emailVerified) {
						await adapter.updateUser(user.id, { emailVerified: true });
					}
					await adapter.deleteUserSessions(user.id);
					await purgeOutstandingCredentials(ctx, user);
					return id;
				});
				// After commit: never leave two OPAQUE accounts (e.g. two resets,
				// or a reset and a set-password, completing concurrently).
				await convergeOpaqueAccounts(ctx, user.id, accountId, newCredential);

				return ctx.json({ status: true });
			},
		),
	};
}
