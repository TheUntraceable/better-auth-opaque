/**
 * Self-contained test harness for the OPAQUE Better Auth plugin.
 *
 * - Every call to `createTestHarness()` builds a brand new `betterAuth()`
 *   instance (with its own in-memory database and its own OPAQUE server
 *   setup), so test files never share state.
 * - Requests never touch the network: they are dispatched straight into
 *   `auth.handler(new Request(...))`, both for the typed client (via
 *   `fetchOptions.customFetchImpl`) and for raw requests.
 * - Each `Device` owns a cookie jar that captures every `Set-Cookie`
 *   (session token, cookie-cache `session_data`, `dont_remember`, ...) and
 *   replays them, and sends a trusted `Origin` header. Origin/CSRF checks are
 *   explicitly re-enabled (Better Auth disables them when NODE_ENV=test), so
 *   the tests exercise the same code paths as production.
 */
import { client as opaqueLib, ready, server as opaqueServer } from "@serenity-kit/opaque";
import { setDefaultTimeout } from "bun:test";
import { type BetterAuthOptions, betterAuth, type User } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthClient } from "better-auth/client";
import { opaqueClient } from "../../src/client";
import { type OpaqueOptions, opaque } from "../../src/server";

// With the library-default key stretching every OPAQUE client operation runs
// Argon2id (~0.3s); flows that register and log in several devices easily
// exceed bun's 5s default.
setDefaultTimeout(30_000);

export const ORIGIN = "http://localhost:3000";
export const BASE_PATH = "/api/auth";
export const COOKIE_PREFIX = "better-auth";
export const SESSION_TOKEN_COOKIE = `${COOKIE_PREFIX}.session_token`;
export const SESSION_DATA_COOKIE = `${COOKIE_PREFIX}.session_data`;
export const DONT_REMEMBER_COOKIE = `${COOKIE_PREFIX}.dont_remember`;

/* -------------------------------------------------------------------------- */
/*                                 Cookie jar                                 */
/* -------------------------------------------------------------------------- */

export interface ParsedSetCookie {
	name: string;
	value: string;
	/** Attribute names are lower-cased; flag attributes map to `true`. */
	attributes: Record<string, string | true>;
	raw: string;
}

export function parseSetCookie(raw: string): ParsedSetCookie {
	const [pair = "", ...attrs] = raw.split(";");
	const eq = pair.indexOf("=");
	const name = (eq === -1 ? pair : pair.slice(0, eq)).trim();
	const value = eq === -1 ? "" : pair.slice(eq + 1).trim();
	const attributes: Record<string, string | true> = {};
	for (const attr of attrs) {
		const i = attr.indexOf("=");
		const key = (i === -1 ? attr : attr.slice(0, i)).trim().toLowerCase();
		if (!key) continue;
		attributes[key] = i === -1 ? true : attr.slice(i + 1).trim();
	}
	return { name, value, attributes, raw };
}

function isExpiring(cookie: ParsedSetCookie): boolean {
	const maxAge = cookie.attributes["max-age"];
	if (typeof maxAge === "string" && Number(maxAge) <= 0) return true;
	const expires = cookie.attributes.expires;
	if (typeof expires === "string" && new Date(expires).getTime() <= Date.now())
		return true;
	return cookie.value === "";
}

export class CookieJar {
	private readonly store = new Map<string, ParsedSetCookie>();

	/** Apply `Set-Cookie` headers from a response (deletions included). */
	apply(setCookies: ParsedSetCookie[]): void {
		for (const c of setCookies) {
			if (isExpiring(c)) this.store.delete(c.name);
			else this.store.set(c.name, c);
		}
	}

	get(name: string): string | undefined {
		return this.store.get(name)?.value;
	}

	has(name: string): boolean {
		return this.store.has(name);
	}

	names(): string[] {
		return [...this.store.keys()].sort();
	}

	clear(): void {
		this.store.clear();
	}

	/** Snapshot of the stored cookies (for copying into another jar). */
	entries(): ParsedSetCookie[] {
		return [...this.store.values()];
	}

	/** Serialise to a `Cookie` request header, optionally restricted to `only`. */
	header(only?: string[]): string {
		return [...this.store.values()]
			.filter((c) => !only || only.includes(c.name))
			.map((c) => `${c.name}=${c.value}`)
			.join("; ");
	}
}

/* -------------------------------------------------------------------------- */
/*                                  Devices                                   */
/* -------------------------------------------------------------------------- */

export type CookieMode = "all" | "token-only" | "none";

export interface RequestOptions {
	method?: "GET" | "POST";
	body?: unknown;
	/** Which cookies from the jar to send. Default: "all". */
	cookies?: CookieMode;
	/** Origin header to send. Default: trusted ORIGIN; `null` sends none. */
	origin?: string | null;
	headers?: Record<string, string>;
	/** Whether Set-Cookie on the response updates the jar. Default: true. */
	updateJar?: boolean;
}

export interface RawResponse<T = any> {
	status: number;
	ok: boolean;
	/** Parsed JSON body (or null for an empty body / non-JSON). */
	body: T;
	text: string;
	setCookies: ParsedSetCookie[];
	headers: Headers;
}

type Handler = (request: Request) => Promise<Response>;

/* -------------------------------------------------------------------------- */
/*                               Key stretching                               */
/* -------------------------------------------------------------------------- */

export type KeyStretching = NonNullable<Parameters<typeof opaqueLib.finishLogin>[0]["keyStretching"]>;

/**
 * A deliberately weak Argon2id configuration for the test suite only: the
 * library default costs ~0.3s per client operation, which dominates the suite.
 * Every typed client (via `opaqueClient({ keyStretching })`) and every raw
 * helper below use the same configuration, so records and logins agree.
 */
export const FAST_KEY_STRETCHING: KeyStretching = {
	"argon2id-custom": { iterations: 1, memory: 256, parallelism: 1 },
};

type OpaqueClientOptions = NonNullable<Parameters<typeof opaqueClient>[0]>;

/**
 * Whether `opaqueClient({ keyStretching })` really forwards the option to the
 * OPAQUE client library. Probed once, entirely in-process (a fake server
 * answers the typed client's sign-up): the record the client produced must be
 * usable by a login that stretches with FAST_KEY_STRETCHING.
 *
 * The raw helpers only switch to FAST_KEY_STRETCHING when it is, so the
 * rest of the suite never mixes configurations (a client that ignored the
 * option would otherwise make every raw login fail). The option itself is
 * tested directly in key-stretching.test.ts, without this probe.
 */
async function probeClientKeyStretching(): Promise<boolean> {
	await ready;
	const setup = opaqueServer.createSetup();
	const email = "key-stretching-probe@example.test";
	const password = "key stretching probe";
	let registrationRecord: string | undefined;
	const probeClient = createAuthClient({
		baseURL: `${ORIGIN}${BASE_PATH}`,
		plugins: [opaqueClient({ keyStretching: FAST_KEY_STRETCHING } as OpaqueClientOptions)],
		fetchOptions: {
			customFetchImpl: async (input, init) => {
				const request = input instanceof Request ? new Request(input, init) : new Request(input.toString(), init);
				const body = (await request.json()) as { registrationRequest: string; registrationRecord: string };
				if (request.url.endsWith("/sign-up/opaque/challenge")) {
					const { registrationResponse } = opaqueServer.createRegistrationResponse({
						serverSetup: setup,
						userIdentifier: email,
						registrationRequest: body.registrationRequest,
					});
					return Response.json({ challenge: registrationResponse });
				}
				registrationRecord = body.registrationRecord;
				return Response.json({ success: true, message: "User registered successfully" });
			},
		},
	});
	await probeClient.signUp.opaque({ email, name: "probe", password });
	if (!registrationRecord) return false;
	const { clientLoginState, startLoginRequest } = opaqueLib.startLogin({ password });
	const { loginResponse } = opaqueServer.startLogin({
		serverSetup: setup,
		userIdentifier: email,
		registrationRecord,
		startLoginRequest,
	});
	try {
		return !!opaqueLib.finishLogin({ clientLoginState, loginResponse, password, keyStretching: FAST_KEY_STRETCHING });
	} catch {
		return false;
	}
}

export const CLIENT_FORWARDS_KEY_STRETCHING = await probeClientKeyStretching();

/** What the raw helpers pass to `finishRegistration` / `finishLogin` (undefined = library default). */
export const RAW_KEY_STRETCHING: KeyStretching | undefined = CLIENT_FORWARDS_KEY_STRETCHING
	? FAST_KEY_STRETCHING
	: undefined;

function makeClient(
	fetchImpl: (input: string | URL | Request, init?: RequestInit) => Promise<Response>,
	keyStretching: KeyStretching | "library-default" = FAST_KEY_STRETCHING,
) {
	return createAuthClient({
		baseURL: `${ORIGIN}${BASE_PATH}`,
		plugins: [
			keyStretching === "library-default"
				? opaqueClient()
				: opaqueClient({ keyStretching } as OpaqueClientOptions),
		],
		fetchOptions: { customFetchImpl: fetchImpl },
	});
}

export interface DeviceOptions {
	/**
	 * Key stretching of this device's typed client. Default FAST_KEY_STRETCHING;
	 * "library-default" builds `opaqueClient()` without the option.
	 */
	keyStretching?: KeyStretching | "library-default";
	/** Sent as `x-forwarded-for` on every request (rate limiting is per IP). */
	ip?: string;
}

/** A request as it reached the auth handler (after origin/cookies were applied). */
export interface LoggedRequest {
	method: string;
	/** Path relative to BASE_PATH, without the query string (e.g. "/sign-in/opaque/complete"). */
	path: string;
	url: string;
	headers: Headers;
	/** Parsed JSON body, or null. */
	body: any;
}

export class Device {
	readonly jar = new CookieJar();
	/** Set-Cookie headers from the most recent response on this device. */
	lastSetCookies: ParsedSetCookie[] = [];
	/** Every request this device sent into the handler, in order. */
	readonly requests: LoggedRequest[] = [];
	/** Typed Better Auth client (with the opaque client plugin) bound to this device. */
	readonly client: ReturnType<typeof makeClient>;

	constructor(
		private readonly handler: Handler,
		private readonly options: DeviceOptions = {},
	) {
		this.client = makeClient(
			(input, init) =>
				this.dispatch(
					input instanceof Request ? new Request(input, init) : new Request(input.toString(), init),
					{},
				),
			options.keyStretching,
		);
	}

	/** Send a Request into the auth handler, applying origin + cookies. */
	private async dispatch(
		request: Request,
		opts: Pick<RequestOptions, "cookies" | "origin" | "updateJar">,
	): Promise<Response> {
		const headers = new Headers(request.headers);
		const origin = opts.origin === undefined ? ORIGIN : opts.origin;
		if (origin === null) headers.delete("origin");
		else headers.set("origin", origin);

		const mode = opts.cookies ?? "all";
		const cookie =
			mode === "none"
				? ""
				: this.jar.header(mode === "token-only" ? [SESSION_TOKEN_COOKIE] : undefined);
		if (cookie) headers.set("cookie", cookie);
		else headers.delete("cookie");
		if (this.options.ip) headers.set("x-forwarded-for", this.options.ip);

		const body =
			request.method === "GET" || request.method === "HEAD"
				? undefined
				: await request.text();
		let parsedBody: any = null;
		try {
			parsedBody = body ? JSON.parse(body) : null;
		} catch {
			parsedBody = null;
		}
		const url = new URL(request.url);
		this.requests.push({
			method: request.method,
			path: url.pathname.startsWith(BASE_PATH) ? url.pathname.slice(BASE_PATH.length) : url.pathname,
			url: request.url,
			headers,
			body: parsedBody,
		});
		const response = await this.handler(
			new Request(request.url, { method: request.method, headers, body }),
		);
		const setCookies = response.headers.getSetCookie().map(parseSetCookie);
		this.lastSetCookies = setCookies;
		if (opts.updateJar !== false) this.jar.apply(setCookies);
		return response;
	}

	/** Raw request against `${ORIGIN}${BASE_PATH}${path}`. */
	async request<T = any>(path: string, opts: RequestOptions = {}): Promise<RawResponse<T>> {
		const method = opts.method ?? (opts.body === undefined ? "GET" : "POST");
		const headers = new Headers(opts.headers);
		let body: string | undefined;
		if (opts.body !== undefined) {
			headers.set("content-type", "application/json");
			body = JSON.stringify(opts.body);
		}
		const response = await this.dispatch(
			new Request(`${ORIGIN}${BASE_PATH}${path}`, { method, headers, body }),
			opts,
		);
		const text = await response.text();
		let parsed: any = null;
		try {
			parsed = text ? JSON.parse(text) : null;
		} catch {
			parsed = null;
		}
		return {
			status: response.status,
			ok: response.ok,
			body: parsed as T,
			text,
			setCookies: this.lastSetCookies,
			headers: response.headers,
		};
	}

	post<T = any>(path: string, body: unknown, opts: Omit<RequestOptions, "body" | "method"> = {}) {
		return this.request<T>(path, { ...opts, method: "POST", body });
	}

	/**
	 * Ask the server who this device is. `tokenOnly` sends only the session
	 * token cookie, bypassing the `session_data` cookie cache, so the answer
	 * reflects the database. Never mutates the jar.
	 */
	async whoami(opts: { tokenOnly?: boolean } = {}): Promise<{
		status: number;
		session: { user: { id: string; email: string; name: string }; session: { token: string; userId: string } } | null;
	}> {
		const res = await this.request("/get-session", {
			method: "GET",
			cookies: opts.tokenOnly ? "token-only" : "all",
			updateJar: false,
		});
		return { status: res.status, session: res.body };
	}

	/**
	 * A new device holding a copy of this device's current cookies (e.g. to
	 * keep replaying a session token after this device has been given a new one).
	 */
	fork(): Device {
		const copy = new Device(this.handler, this.options);
		copy.jar.apply(this.jar.entries());
		return copy;
	}

	/** Requests sent to `path` (relative to BASE_PATH), in order. */
	requestsTo(path: string): LoggedRequest[] {
		return this.requests.filter((r) => r.path === path);
	}

	/** The raw session token (without the cookie signature). */
	sessionToken(): string | undefined {
		const signed = this.jar.get(SESSION_TOKEN_COOKIE);
		if (!signed) return undefined;
		return decodeURIComponent(signed).split(".")[0];
	}
}

/* -------------------------------------------------------------------------- */
/*                              OPAQUE raw helpers                             */
/* -------------------------------------------------------------------------- */

export function randomBase64Url(bytes: number): string {
	return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

let emailCounter = 0;
/** Unique email per call so tests in the same file never collide. */
export function uniqueEmail(label = "user"): string {
	emailCounter += 1;
	return `${label}-${emailCounter}-${randomBase64Url(4).replace(/[-_]/g, "x").toLowerCase()}@example.test`;
}

export interface LoginPayload {
	email: string;
	loginResult: string;
	encryptedServerState: string;
	dontRememberMe?: boolean;
}

/**
 * Real OPAQUE registration over raw HTTP. Returns both responses and the
 * registration record the client produced.
 */
export async function rawRegister(
	device: Device,
	email: string,
	password: string,
	name = "Test User",
	/** Extra fields for the complete step (e.g. `user.additionalFields`, `callbackURL`). */
	extra: Record<string, unknown> = {},
) {
	await ready;
	const { clientRegistrationState, registrationRequest } = opaqueLib.startRegistration({ password });
	const challenge = await device.post("/sign-up/opaque/challenge", { email, registrationRequest });
	if (challenge.status !== 200) {
		throw new Error(`register challenge failed: ${challenge.status} ${challenge.text}`);
	}
	const { registrationRecord } = opaqueLib.finishRegistration({
		clientRegistrationState,
		password,
		registrationResponse: challenge.body.challenge,
		keyStretching: RAW_KEY_STRETCHING,
	});
	const complete = await device.post("/sign-up/opaque/complete", { ...extra, email, name, registrationRecord });
	return { challenge, complete, registrationRecord };
}

/** Step 1 of login over raw HTTP; keeps the client state for step 2. */
export async function startLogin(device: Device, email: string, password: string) {
	await ready;
	const { clientLoginState, startLoginRequest } = opaqueLib.startLogin({ password });
	const res = await device.post<{ challenge: string; state: string }>("/sign-in/opaque/challenge", {
		email,
		loginRequest: startLoginRequest,
	});
	if (res.status !== 200) {
		throw new Error(`login challenge failed: ${res.status} ${res.text}`);
	}
	return {
		res,
		challenge: res.body.challenge,
		state: res.body.state,
		/** KE3 computed with the password given to startLogin; undefined if wrong. */
		finish: () =>
			opaqueLib.finishLogin({
				clientLoginState,
				loginResponse: res.body.challenge,
				password,
				keyStretching: RAW_KEY_STRETCHING,
			})?.finishLoginRequest,
	};
}

/** A complete, valid `/sign-in/opaque/complete` payload for a correct password. */
export async function validLoginPayload(device: Device, email: string, password: string): Promise<LoginPayload> {
	const started = await startLogin(device, email, password);
	const loginResult = started.finish();
	if (!loginResult) throw new Error(`client could not finish login for ${email} (wrong password?)`);
	return { email, loginResult, encryptedServerState: started.state };
}

/**
 * A server-side "wrong password" attempt: a genuine challenge/state from the
 * server paired with a well-formed (64 byte) but unauthenticated KE3 message,
 * which is all an attacker without the password can produce.
 */
export async function forgedLoginPayload(device: Device, email: string): Promise<LoginPayload> {
	const started = await startLogin(device, email, `not-the-password-${randomBase64Url(8)}`);
	return { email, loginResult: randomBase64Url(64), encryptedServerState: started.state };
}

/**
 * Raw change-password challenge for a logged-in device. Returns everything
 * needed to call `/opaque/change-password/complete`; `loginResult` is
 * undefined when `currentPassword` is wrong (the client cannot produce KE3).
 */
export async function startChangePassword(device: Device, currentPassword: string, newPassword: string) {
	await ready;
	const login = opaqueLib.startLogin({ password: currentPassword });
	const registration = opaqueLib.startRegistration({ password: newPassword });
	const res = await device.post<{ loginChallenge: string; registrationChallenge: string; state: string }>(
		"/opaque/change-password/challenge",
		{ loginRequest: login.startLoginRequest, registrationRequest: registration.registrationRequest },
	);
	if (res.status !== 200) {
		throw new Error(`change-password challenge failed: ${res.status} ${res.text}`);
	}
	const loginResult = opaqueLib.finishLogin({
		clientLoginState: login.clientLoginState,
		loginResponse: res.body.loginChallenge,
		password: currentPassword,
		keyStretching: RAW_KEY_STRETCHING,
	})?.finishLoginRequest;
	const { registrationRecord } = opaqueLib.finishRegistration({
		clientRegistrationState: registration.clientRegistrationState,
		registrationResponse: res.body.registrationChallenge,
		password: newPassword,
		keyStretching: RAW_KEY_STRETCHING,
	});
	return { res, loginResult, registrationRecord, encryptedServerState: res.body.state };
}

/**
 * A registration record of the valid length (192 bytes) whose client public
 * key is not a valid group element, so it can never be deserialised by the
 * OPAQUE server (unlike random bytes, which occasionally decode).
 */
export const UNDESERIALISABLE_RECORD = Buffer.alloc(192, 0xff).toString("base64url");

/** How a password reset is authorised: a link token, or an emailed OTP. */
export type ResetCredential = { token: string } | { email: string; otp: string };

/**
 * Step 1 of a raw password reset. Never throws on an HTTP error: returns the
 * response and, if it was a 200, the registration record for `newPassword`.
 */
export async function startResetPassword(device: Device, credential: ResetCredential, newPassword: string) {
	await ready;
	const { clientRegistrationState, registrationRequest } = opaqueLib.startRegistration({ password: newPassword });
	const res = await device.post<{ challenge: string }>("/opaque/reset-password/challenge", {
		...credential,
		registrationRequest,
	});
	const registrationRecord =
		res.status === 200 && typeof res.body?.challenge === "string"
			? opaqueLib.finishRegistration({
					clientRegistrationState,
					password: newPassword,
					registrationResponse: res.body.challenge,
					keyStretching: RAW_KEY_STRETCHING,
				}).registrationRecord
			: undefined;
	return { res, registrationRecord };
}

/** A full raw password reset; throws if the challenge step is not a 200. */
export async function rawResetPassword(device: Device, credential: ResetCredential, newPassword: string) {
	const started = await startResetPassword(device, credential, newPassword);
	if (!started.registrationRecord) {
		throw new Error(`reset challenge failed: ${started.res.status} ${started.res.text}`);
	}
	const complete = await device.post("/opaque/reset-password/complete", {
		...credential,
		registrationRecord: started.registrationRecord,
	});
	return { challenge: started.res, complete, registrationRecord: started.registrationRecord };
}

/** Step 1 of a raw set-password (logged-in user without an OPAQUE account). Never throws on HTTP errors. */
export async function startSetPassword(device: Device, newPassword: string) {
	await ready;
	const { clientRegistrationState, registrationRequest } = opaqueLib.startRegistration({ password: newPassword });
	const res = await device.post<{ challenge: string }>("/opaque/set-password/challenge", { registrationRequest });
	const registrationRecord =
		res.status === 200 && typeof res.body?.challenge === "string"
			? opaqueLib.finishRegistration({
					clientRegistrationState,
					password: newPassword,
					registrationResponse: res.body.challenge,
					keyStretching: RAW_KEY_STRETCHING,
				}).registrationRecord
			: undefined;
	return { res, registrationRecord };
}

/* -------------------------------------------------------------------------- */
/*                                 Type helpers                               */
/* -------------------------------------------------------------------------- */

export type Expect<T extends true> = T;
export type Equal<X, Y> = (<T>() => T extends X ? 1 : 2) extends <T>() => T extends Y ? 1 : 2 ? true : false;
export type IsAny<T> = 0 extends 1 & T ? true : false;
export type Extends<A, B> = [A] extends [B] ? true : false;

export function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/* -------------------------------------------------------------------------- */
/*                                   Outbox                                   */
/* -------------------------------------------------------------------------- */

export interface ResetLinkMail {
	user: User;
	url: string;
	token: string;
	request?: Request;
}
export interface ResetOTPMail {
	user: User;
	otp: string;
	request?: Request;
}
export interface VerificationMail {
	user: User;
	url: string;
	token: string;
	request?: Request;
}

/* -------------------------------------------------------------------------- */
/*                                  Spies                                     */
/* -------------------------------------------------------------------------- */

/** One log line as it reached Better Auth's `logger.log`. */
export interface LogEntry {
	level: "debug" | "info" | "success" | "warn" | "error";
	message: string;
	args: unknown[];
}

/** One call on the database adapter Better Auth uses (`ctx.adapter`). */
export interface AdapterCall {
	method: string;
	model: string | undefined;
}

const ADAPTER_METHODS = new Set([
	"create",
	"findOne",
	"findMany",
	"count",
	"update",
	"updateMany",
	"delete",
	"deleteMany",
	"consumeOne",
	"incrementOne",
]);

/** Records every public adapter method call ({ method, model }) into `calls`. */
function spyOnAdapter<A extends object>(adapter: A, calls: AdapterCall[]): A {
	return new Proxy(adapter, {
		get(target, key, receiver) {
			const value = Reflect.get(target, key, receiver);
			if (typeof key !== "string" || typeof value !== "function" || !ADAPTER_METHODS.has(key)) return value;
			return (...args: any[]) => {
				calls.push({ method: key, model: args[0]?.model });
				return value.apply(target, args);
			};
		},
	});
}

/* -------------------------------------------------------------------------- */
/*                               Harness options                              */
/* -------------------------------------------------------------------------- */

export interface HarnessOptions {
	/** Plugin options (the harness always supplies `OPAQUE_SERVER_KEY`). */
	plugin?: Omit<OpaqueOptions, "OPAQUE_SERVER_KEY">;
	/** Install a capturing `sendResetPassword` (link). */
	resetLink?: boolean;
	/** Install a capturing `sendResetPasswordOTP`. */
	resetOTP?: boolean;
	/**
	 * Enable Better Auth core `emailVerification` with a capturing
	 * `sendVerificationEmail` and these flags.
	 */
	verification?: {
		sendOnSignUp?: boolean;
		sendOnSignIn?: boolean;
		autoSignInAfterVerification?: boolean;
	};
	/** Enable core email + password (`/sign-up/email`, `/sign-in/email`). */
	emailAndPassword?: boolean;
	/**
	 * Extra `betterAuth` options, applied over the harness defaults. `advanced`,
	 * `session`, `rateLimit` and `logger` are merged one level deep; `plugins`
	 * are appended after the OPAQUE plugin; everything else replaces.
	 */
	authOptions?: Partial<BetterAuthOptions>;
}

/* -------------------------------------------------------------------------- */
/*                                  Harness                                   */
/* -------------------------------------------------------------------------- */

export async function createTestHarness(options: HarnessOptions = {}) {
	await ready;
	const serverSetup = opaqueServer.createSetup();
	// Everything the auth instance "emailed", in order.
	const outbox = {
		resetLinks: [] as ResetLinkMail[],
		resetOTPs: [] as ResetOTPMail[],
		verificationEmails: [] as VerificationMail[],
		resetLinksFor(email: string) {
			return outbox.resetLinks.filter((m) => m.user.email.toLowerCase() === email.toLowerCase());
		},
		resetOTPsFor(email: string) {
			return outbox.resetOTPs.filter((m) => m.user.email.toLowerCase() === email.toLowerCase());
		},
		verificationEmailsFor(email: string) {
			return outbox.verificationEmails.filter((m) => m.user.email.toLowerCase() === email.toLowerCase());
		},
	};
	const pluginOptions: OpaqueOptions = {
		...options.plugin,
		OPAQUE_SERVER_KEY: serverSetup,
	};
	if (options.resetLink) {
		pluginOptions.sendResetPassword = async ({ user, url, token }, request) => {
			outbox.resetLinks.push({ user, url, token, request });
		};
	}
	if (options.resetOTP) {
		pluginOptions.sendResetPasswordOTP = async ({ user, otp }, request) => {
			outbox.resetOTPs.push({ user, otp, request });
		};
	}
	const emailVerification: BetterAuthOptions["emailVerification"] = options.verification
		? {
				...options.verification,
				sendVerificationEmail: async ({ user, url, token }, request) => {
					outbox.verificationEmails.push({ user, url, token, request });
				},
			}
		: undefined;

	// Every log line of this instance (info and above unless overridden), in
	// order. Captured instead of printed.
	const logs: LogEntry[] = [];
	// Every public adapter call of this instance, in order.
	const adapterCalls: AdapterCall[] = [];

	// An explicit (per-harness) in-memory database. Without `database`, Better
	// Auth 1.7 runs in *stateless* mode (JWE cookie cache valid for the whole
	// session lifetime), which is not what a production deployment with a DB
	// does and would make server-side revocation unobservable.
	const memoryDB: Record<string, any[]> = {};
	const baseAdapter = memoryAdapter(memoryDB);
	const extra = options.authOptions ?? {};
	const auth = betterAuth({
		database: ((dbOptions: BetterAuthOptions) =>
			spyOnAdapter(baseAdapter(dbOptions), adapterCalls)) as unknown as BetterAuthOptions["database"],
		baseURL: ORIGIN,
		basePath: BASE_PATH,
		secret: `test-secret-${randomBase64Url(32)}`,
		trustedOrigins: [ORIGIN],
		...(options.emailAndPassword ? { emailAndPassword: { enabled: true } } : {}),
		...(emailVerification ? { emailVerification } : {}),
		...extra,
		// Better Auth turns origin/CSRF checks off when NODE_ENV=test; turn them
		// back on so the suite exercises production behaviour.
		advanced: { disableOriginCheck: false, disableCSRFCheck: false, ...extra.advanced },
		rateLimit: { enabled: false, ...extra.rateLimit },
		session: { cookieCache: { enabled: true, maxAge: 300 }, ...extra.session },
		logger: {
			level: "info",
			log: (level, message, ...args) => {
				logs.push({ level, message, args });
			},
			...extra.logger,
		},
		plugins: [opaque(pluginOptions), ...(extra.plugins ?? [])],
	});
	const ctx = await auth.$context;
	// Create every table in the resolved schema (core + plugins), mirroring
	// what Better Auth does for its implicit memory DB.
	for (const table of Object.keys(ctx.tables)) memoryDB[table] ??= [];
	const handler: Handler = (req) => auth.handler(req);

	const db = {
		async user(email: string) {
			return (await ctx.internalAdapter.findUserByEmail(email))?.user ?? null;
		},
		async accounts(email: string) {
			const user = await db.user(email);
			if (!user) return [];
			return ctx.internalAdapter.findAccounts(user.id);
		},
		async opaqueAccounts(email: string) {
			return (await db.accounts(email)).filter((a) => a.providerId === "opaque");
		},
		async opaqueAccount(email: string) {
			const user = await db.user(email);
			if (!user) return null;
			const accounts = await ctx.internalAdapter.findAccounts(user.id);
			return (
				(accounts.find((a) => a.providerId === "opaque") as
					| (typeof accounts)[number] & { registrationRecord?: string }
					| undefined) ?? null
			);
		},
		async registrationRecord(email: string) {
			return (await db.opaqueAccount(email))?.registrationRecord ?? null;
		},
		async sessionsFor(email: string) {
			const user = await db.user(email);
			if (!user) return [];
			return ctx.internalAdapter.listSessions(user.id);
		},
		async sessionCount() {
			return ctx.adapter.count({ model: "session" });
		},
		async userCount() {
			return ctx.adapter.count({ model: "user" });
		},
		/** Every row of the verification table (raw, as stored). */
		verificationRows(): Array<{ id: string; identifier: string; value: string; expiresAt: Date }> {
			return [...(memoryDB.verification ?? [])];
		},
		/** A user with NO accounts at all (as if created by another provider). */
		async createUserWithoutOpaque(email: string, name = "No Opaque") {
			return ctx.internalAdapter.createUser({ email, name, emailVerified: false }, { method: "admin" });
		},
		async setEmailVerified(email: string, emailVerified: boolean) {
			const user = await db.user(email);
			if (!user) throw new Error(`no user ${email}`);
			await ctx.internalAdapter.updateUser(user.id, { emailVerified });
		},
		/**
		 * Runs `fn` and counts how often each table of the in-memory database
		 * is read by the adapter underneath Better Auth (one read per query
		 * the adapter runs against that table, including the separate queries
		 * Better Auth issues to emulate joins). Tables are instrumented only
		 * for the duration of `fn`.
		 */
		async countTableReads(fn: () => Promise<unknown>): Promise<Record<string, number>> {
			const counts: Record<string, number> = {};
			const tables = Object.keys(memoryDB);
			for (const table of tables) {
				let rows = memoryDB[table];
				counts[table] = 0;
				Object.defineProperty(memoryDB, table, {
					configurable: true,
					enumerable: true,
					get() {
						counts[table]! += 1;
						return rows;
					},
					set(value) {
						rows = value;
					},
				});
			}
			try {
				await fn();
			} finally {
				for (const table of tables) {
					const descriptor = Object.getOwnPropertyDescriptor(memoryDB, table);
					const rows = descriptor?.get ? descriptor.get.call(memoryDB) : memoryDB[table];
					Object.defineProperty(memoryDB, table, {
						configurable: true,
						enumerable: true,
						writable: true,
						value: rows,
					});
				}
			}
			return counts;
		},
	};

	return {
		auth,
		ctx,
		db,
		outbox,
		serverSetup,
		/** Captured log lines of this instance (see LogEntry). */
		logs,
		/** Captured public adapter calls of this instance (see AdapterCall). */
		adapterCalls,
		/** Adapter calls made while `fn` runs. */
		async recordAdapterCalls(fn: () => Promise<unknown>): Promise<AdapterCall[]> {
			const from = adapterCalls.length;
			await fn();
			return adapterCalls.slice(from);
		},
		device: (deviceOptions: DeviceOptions = {}) => new Device(handler, deviceOptions),
		/** Register via the typed client on a throwaway device; asserts success. */
		async register(email: string, password: string, name = "Test User") {
			const d = new Device(handler);
			const res = await d.client.signUp.opaque({ email, password, name });
			if (res.error || !res.data) {
				throw new Error(`registration of ${email} failed: ${JSON.stringify(res.error)}`);
			}
			return res;
		},
		/** A new device logged in as `email`; throws if login fails. */
		async loggedInDevice(email: string, password: string, deviceOptions: DeviceOptions = {}) {
			const d = new Device(handler, deviceOptions);
			const res = await d.client.signIn.opaque({ email, password });
			if (res.error || !res.data) {
				throw new Error(`login of ${email} failed: ${JSON.stringify(res.error)}`);
			}
			return d;
		},
		/**
		 * Sign up through core `/sign-up/email` (requires `emailAndPassword`):
		 * a user with a "credential" account and NO OPAQUE account, logged in
		 * on the returned device.
		 */
		async coreSignUp(email: string, password = "core-password-123", name = "Core User") {
			const d = new Device(handler);
			const res = await d.post("/sign-up/email", { email, password, name });
			if (res.status !== 200 || !d.sessionToken()) {
				throw new Error(`core sign-up of ${email} failed: ${res.status} ${res.text}`);
			}
			return d;
		},
	};
}

export type TestHarness = Awaited<ReturnType<typeof createTestHarness>>;
