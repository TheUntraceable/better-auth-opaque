import type { ClientFetchOption } from "better-auth";

export interface OpaqueClientError {
	code?: string | undefined;
	message?: string | undefined;
	status: number;
	statusText: string;
}

export type OpaqueResult<T> =
	| { data: T; error: null }
	| { data: null; error: OpaqueClientError };

// Safe to name better-fetch here, unlike in OpaqueFetch: better-auth is a
// peer dependency, so this resolves to the app's copy, and getActions'
// assignability depends only on its parameters.
export type OpaqueFetchOptions = Omit<ClientFetchOption, "method" | "body">;

/**
 * Minimal structural view of better-auth's `$fetch`.
 *
 * Deliberately self-contained: typing this with `BetterFetch` from
 * `@better-fetch/fetch` would pin the emitted `.d.ts` to the exact copy of
 * that package the plugin was built against, and any app whose
 * `better-auth` resolves a different copy fails with "Types of property
 * 'getActions' are incompatible" and loses all `authClient.*.opaque`
 * inference. `tests/client-plugin-types.test.ts` asserts `BetterFetch` stays
 * assignable to this.
 */
export type OpaqueFetch = <T = unknown>(
	url: string,
	options?: {
		method?: string;
		body?: unknown;
		[key: string]: unknown;
	},
) => Promise<{
	data: T | null;
	error: OpaqueClientError | null;
}>;

export interface OpaqueClientStore {
	notify: (signal: "$sessionSignal") => void;
}

export interface OpaqueClientOptions {
	/**
	 * The server's OPAQUE public key, from
	 * `server.getPublicKey(serverSetup)`. When set, every handshake
	 * checks the key the server proved possession of against this value and
	 * refuses to continue on a mismatch, which detects a swapped server key
	 * or an active man-in-the-middle.
	 */
	serverPublicKey?: string | undefined;
}
