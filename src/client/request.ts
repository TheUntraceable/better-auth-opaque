import { client, ready } from "@serenity-kit/opaque";
import { OPAQUE_ERROR_CODES, type OpaqueErrorCode } from "../error-codes";
import type { opaque } from "../server";
import type {
	OpaqueClientError,
	OpaqueClientStore,
	OpaqueFetch,
	OpaqueFetchOptions,
	OpaqueResult,
} from "./types";

type Endpoints = ReturnType<typeof opaque>["endpoints"];
type Path = Endpoints[keyof Endpoints]["path"];
type Endpoint<P extends Path> = Endpoints[{
	[K in keyof Endpoints]: Endpoints[K]["path"] extends P ? K : never;
}[keyof Endpoints]];

export type Reply<P extends Path> = Awaited<ReturnType<Endpoint<P>>>;
type Body<P extends Path> = NonNullable<Parameters<Endpoint<P>>[0]>["body"];

export type Post = <P extends Path>(
	path: P,
	body: Body<P>,
) => Promise<OpaqueResult<Reply<P>>>;

type RequestContext = Parameters<NonNullable<OpaqueFetchOptions["onRequest"]>>[0];
type ResponseContext = Parameters<
	NonNullable<OpaqueFetchOptions["onResponse"]>
>[0];
type ErrorContext = Parameters<NonNullable<OpaqueFetchOptions["onError"]>>[0];

// Only what the actions read, typed structurally for the same reason as
// OpaqueFetch.
export interface ClientConfig {
	fetchOptions?: { throw?: boolean | undefined } | undefined;
}

/**
 * Thrown by an action called with `throw: true`. Same shape as better-fetch's
 * `BetterFetchError`, which cannot be imported without depending on
 * `@better-fetch/fetch` directly.
 */
export class OpaqueFetchError extends Error {
	readonly status: number;
	readonly statusText: string;
	readonly error: OpaqueClientError;

	constructor(error: OpaqueClientError) {
		super(error.statusText || String(error.status), { cause: error });
		this.name = "OpaqueFetchError";
		this.status = error.status;
		this.statusText = error.statusText;
		this.error = error;
	}
}

export const fail = (
	code: OpaqueErrorCode,
	status: number,
	statusText: string,
): { data: null; error: OpaqueClientError } => ({
	data: null,
	error: { ...OPAQUE_ERROR_CODES[code], status, statusText },
});

// The caller's onRequest runs once per action, yet a header it adds is meant
// for the whole action, so it is replayed on every later request.
const replayFirstRequestHeaders = (
	onRequest: OpaqueFetchOptions["onRequest"],
): ((request: RequestContext) => Promise<RequestContext>) | undefined => {
	if (!onRequest) return undefined;
	let carried: [string, string][] | undefined;
	return async (request) => {
		if (carried) {
			for (const [name, value] of carried) request.headers.set(name, value);
			return request;
		}
		const before = new Headers(request.headers);
		const next = (await onRequest(request)) ?? request;
		carried = [...next.headers].filter(
			([name, value]) => before.get(name) !== value,
		);
		return next;
	};
};

export const createRequester = (
	$fetch: OpaqueFetch,
	$store: OpaqueClientStore,
	config: ClientConfig | undefined,
	serverPublicKey: string | undefined,
) => {
	const serverKeyMismatch = (serverStaticPublicKey: string) =>
		serverPublicKey !== undefined && serverPublicKey !== serverStaticPublicKey;

	/**
	 * Runs one action's requests as a single call: transport options go on
	 * every request, while `throw` and the `onRequest` / `onResponse` /
	 * `onSuccess` / `onError` hooks apply once to the final outcome, which may
	 * be decided on the client after the last response arrived.
	 */
	const run = async <T>(
		fetchOptions: OpaqueFetchOptions,
		flow: (post: Post) => Promise<OpaqueResult<T>>,
		signalsSession: (data: T) => boolean = () => false,
	): Promise<OpaqueResult<T>> => {
		const {
			onRequest,
			onResponse,
			onSuccess,
			onError,
			throw: shouldThrow = config?.fetchOptions?.throw ?? false,
			...transport
		} = fetchOptions;
		const requestHook = replayFirstRequestHeaders(onRequest);
		const latest: {
			exchange?: ResponseContext;
			serverError?: OpaqueClientError | null;
		} = {};

		const post: Post = async <P extends Path>(path: P, body: Body<P>) => {
			const result = await $fetch<Reply<P>>(path, {
				...transport,
				method: "POST",
				body,
				throw: false,
				onRequest: requestHook,
				onResponse: ({ request, response }: ResponseContext) => {
					// better-fetch reads the body after this hook; the caller's
					// onResponse, run later, expects it unread. The cast only
					// bridges @types/node typing clone() with undici's Response.
					latest.exchange = {
						request,
						response: onResponse ? (response.clone() as Response) : response,
					};
				},
			});
			latest.serverError = result.error;
			if (result.error) return { data: null, error: result.error };
			if (result.data === null || result.data === undefined) {
				return fail("REQUEST_FAILED", 500, "Internal Server Error");
			}
			return { data: result.data, error: null };
		};

		const outcome = await flow(post);
		let settled = latest.exchange;
		// A failure decided on the client has no response of its own. The hooks
		// get one carrying the error so `response.status` agrees with
		// `error.status`.
		if (settled && outcome.error && outcome.error !== latest.serverError) {
			const { code, message, status, statusText } = outcome.error;
			settled = {
				request: settled.request,
				response: new Response(JSON.stringify({ code, message }), {
					status,
					statusText,
					headers: { "content-type": "application/json" },
				}),
			};
		}
		if (settled) {
			await onResponse?.(settled);
			if (outcome.error) {
				// better-fetch passes a plain `{ ...body, status, statusText }`
				// here too, despite typing it as BetterFetchError.
				const error = outcome.error as ErrorContext["error"];
				await onError?.({ ...settled, error });
			} else {
				await onSuccess?.({ ...settled, data: outcome.data });
			}
		}
		if (outcome.error) {
			if (shouldThrow) throw new OpaqueFetchError(outcome.error);
		} else if (signalsSession(outcome.data) && !fetchOptions.disableSignal) {
			$store.notify("$sessionSignal");
		}
		return outcome;
	};

	/**
	 * Registration round trip shared by sign-up, set-password and
	 * reset-password. Change-password runs its own because it carries the
	 * registration in the same request as its login. Returns the record to
	 * send plus the export key the app may keep.
	 */
	const register = async (
		password: string,
		getChallenge: (
			registrationRequest: string,
		) => Promise<OpaqueResult<{ challenge: string; state: string }>>,
	): Promise<
		OpaqueResult<{
			registrationRecord: string;
			state: string;
			exportKey: string;
			serverPublicKey: string;
		}>
	> => {
		await ready;
		const { clientRegistrationState, registrationRequest } =
			client.startRegistration({ password });
		const challenge = await getChallenge(registrationRequest);
		if (challenge.error) return challenge;
		const { registrationRecord, exportKey, serverStaticPublicKey } =
			client.finishRegistration({
				clientRegistrationState,
				password,
				registrationResponse: challenge.data.challenge,
			});
		if (serverKeyMismatch(serverStaticPublicKey)) {
			return fail("SERVER_KEY_MISMATCH", 400, "Bad Request");
		}
		return {
			data: {
				registrationRecord,
				state: challenge.data.state,
				exportKey,
				serverPublicKey: serverStaticPublicKey,
			},
			error: null,
		};
	};

	return { run, register, serverKeyMismatch };
};

export type Requester = ReturnType<typeof createRequester>;
