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
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthClient } from "better-auth/client";
import { opaqueClient } from "../../src/client";
import { opaque } from "../../src/server";

// Each OPAQUE client operation runs a key-stretching KSF (~0.3s); flows that
// register and log in several devices easily exceed bun's 5s default.
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

function makeClient(fetchImpl: (input: string | URL | Request, init?: RequestInit) => Promise<Response>) {
	return createAuthClient({
		baseURL: `${ORIGIN}${BASE_PATH}`,
		plugins: [opaqueClient()],
		fetchOptions: { customFetchImpl: fetchImpl },
	});
}

export class Device {
	readonly jar = new CookieJar();
	/** Set-Cookie headers from the most recent response on this device. */
	lastSetCookies: ParsedSetCookie[] = [];
	/** Typed Better Auth client (with the opaque client plugin) bound to this device. */
	readonly client: ReturnType<typeof makeClient>;

	constructor(private readonly handler: Handler) {
		this.client = makeClient((input, init) =>
			this.dispatch(
				input instanceof Request ? new Request(input, init) : new Request(input.toString(), init),
				{},
			),
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

		const body =
			request.method === "GET" || request.method === "HEAD"
				? undefined
				: await request.text();
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
export async function rawRegister(device: Device, email: string, password: string, name = "Test User") {
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
	});
	const complete = await device.post("/sign-up/opaque/complete", { email, name, registrationRecord });
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
 * needed to call `/opaque/changePassword/complete`; `loginResult` is
 * undefined when `currentPassword` is wrong (the client cannot produce KE3).
 */
export async function startChangePassword(device: Device, currentPassword: string, newPassword: string) {
	await ready;
	const login = opaqueLib.startLogin({ password: currentPassword });
	const registration = opaqueLib.startRegistration({ password: newPassword });
	const res = await device.post<{ loginChallenge: string; registrationChallenge: string; state: string }>(
		"/opaque/changePassword/challenge",
		{ loginRequest: login.startLoginRequest, registrationRequest: registration.registrationRequest },
	);
	if (res.status !== 200) {
		throw new Error(`change-password challenge failed: ${res.status} ${res.text}`);
	}
	const loginResult = opaqueLib.finishLogin({
		clientLoginState: login.clientLoginState,
		loginResponse: res.body.loginChallenge,
		password: currentPassword,
	})?.finishLoginRequest;
	const { registrationRecord } = opaqueLib.finishRegistration({
		clientRegistrationState: registration.clientRegistrationState,
		registrationResponse: res.body.registrationChallenge,
		password: newPassword,
	});
	return { res, loginResult, registrationRecord, encryptedServerState: res.body.state };
}

/* -------------------------------------------------------------------------- */
/*                                  Harness                                   */
/* -------------------------------------------------------------------------- */

export async function createTestHarness() {
	await ready;
	const serverSetup = opaqueServer.createSetup();
	// An explicit (per-harness) in-memory database. Without `database`, Better
	// Auth 1.7 runs in *stateless* mode (JWE cookie cache valid for the whole
	// session lifetime), which is not what a production deployment with a DB
	// does and would make server-side revocation unobservable.
	const memoryDB: Record<string, any[]> = {};
	const auth = betterAuth({
		database: memoryAdapter(memoryDB),
		baseURL: ORIGIN,
		basePath: BASE_PATH,
		secret: `test-secret-${randomBase64Url(32)}`,
		trustedOrigins: [ORIGIN],
		// Better Auth turns origin/CSRF checks off when NODE_ENV=test; turn them
		// back on so the suite exercises production behaviour.
		advanced: { disableOriginCheck: false, disableCSRFCheck: false },
		rateLimit: { enabled: false },
		session: { cookieCache: { enabled: true, maxAge: 300 } },
		plugins: [opaque({ OPAQUE_SERVER_KEY: serverSetup })],
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
	};

	return {
		auth,
		ctx,
		db,
		serverSetup,
		device: () => new Device(handler),
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
		async loggedInDevice(email: string, password: string) {
			const d = new Device(handler);
			const res = await d.client.signIn.opaque({ email, password });
			if (res.error || !res.data) {
				throw new Error(`login of ${email} failed: ${JSON.stringify(res.error)}`);
			}
			return d;
		},
	};
}

export type TestHarness = Awaited<ReturnType<typeof createTestHarness>>;
