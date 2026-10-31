import { server } from "@serenity-kit/opaque";
import type { BetterAuthOptions } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { getHttpTestInstance } from "better-auth/test";
import { opaqueClient, type OpaqueClientOptions } from "../src/client";
import { opaque, type OpaqueOptions } from "../src/server";

// Fixed key so registration records stay valid across the server instances a
// test file may create. Test-only; never reuse outside this suite.
export const TEST_OPAQUE_SERVER_KEY =
	"bgTA0wwx_5WvwoyDHURXOsnN3u1y2uJLr1vXYGc1_F5yNgubuj6Pf4JVIM83aIWHHJ7GIPUxDW74-j8CEuv0Os4rE4lQ7GnBQk3nVLDl5s1J4BsNrPXqx_i-T44FaZYLQPDzr2huMv49zUIRxA15XVU9dFuzZZgf-XiaaNDnIA0";

export const TEST_OPAQUE_PUBLIC_KEY = () =>
	server.getPublicKey(TEST_OPAQUE_SERVER_KEY);

export const password = "supersecurepassword";

export const uniqueEmail = (prefix: string) =>
	`${prefix}-${crypto.randomUUID()}@untraceable.dev`;

/**
 * Spins up a real better-auth instance (fresh in-memory SQLite, real HTTP
 * listener on an OS-assigned port) with the OPAQUE plugin installed, plus
 * auth clients that already carry the OPAQUE client plugin.
 *
 * Call `server.close()` in `afterAll`.
 */
export async function createOpaqueTestInstance(
	pluginOptions: Omit<OpaqueOptions, "OPAQUE_SERVER_KEY"> = {},
	authOptions: Partial<BetterAuthOptions> = {},
	clientOptions: OpaqueClientOptions = {},
) {
	const instance = await getHttpTestInstance(
		{
			emailAndPassword: { enabled: true },
			logger: { level: "error" },
			...authOptions,
			plugins: [
				opaque({ OPAQUE_SERVER_KEY: TEST_OPAQUE_SERVER_KEY, ...pluginOptions }),
				...(authOptions.plugins ?? []),
			],
		},
		{ disableTestUser: true },
	);

	// getHttpTestInstance does not carry client-plugin types through to its
	// returned client, so build our own over the same HTTP listener.
	const client = createAuthClient({
		baseURL: instance.baseURL,
		plugins: [opaqueClient(clientOptions)],
	});

	// The shared client has no cookie jar, and the authenticated endpoints sit
	// behind a session middleware. better-auth rejects cookie-bearing requests
	// without an Origin header (CSRF check), so the jar also sets Origin.
	const createSessionClient = () => {
		let cookie = "";
		return createAuthClient({
			baseURL: instance.baseURL,
			plugins: [opaqueClient(clientOptions)],
			fetchOptions: {
				onRequest(context) {
					if (cookie) {
						context.headers.set("cookie", cookie);
						context.headers.set("origin", instance.baseURL);
					}
				},
				onResponse(context) {
					const setCookies = context.response.headers.getSetCookie();
					if (setCookies.length > 0) {
						cookie = setCookies.map((c) => c.split(";")[0]).join("; ");
					}
				},
			},
		});
	};

	return { ...instance, client, createSessionClient };
}

export type OpaqueTestInstance = Awaited<
	ReturnType<typeof createOpaqueTestInstance>
>;

/** Error code from a raw `$fetch` result, whose error type does not carry one. */
export const errorCode = (result: { error: unknown }) =>
	(result.error as { code?: string } | null)?.code;
