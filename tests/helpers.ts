import { client as opaqueCrypto, server } from "@serenity-kit/opaque";
import type { BetterAuthOptions } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { getHttpTestInstance } from "better-auth/test";
import { opaqueClient, type OpaqueClientOptions } from "../src/client";
import { opaque, type OpaqueOptions } from "../src/server";
import { TEST_OPAQUE_SERVER_KEY } from "./test-key";

export { TEST_OPAQUE_SERVER_KEY } from "./test-key";

export const TEST_OPAQUE_PUBLIC_KEY = () =>
	server.getPublicKey(TEST_OPAQUE_SERVER_KEY);

export const password = "supersecurepassword";

export const uniqueEmail = (prefix: string) =>
	`${prefix}-${crypto.randomUUID()}@untraceable.dev`;

// On the in-memory test database nothing yields between reading and deleting
// a verification row, so a non-atomic consume would never visibly race.
// Stalling each delete lets every concurrent request read the row first.
export const slowVerificationDeletes: Partial<BetterAuthOptions> = {
	databaseHooks: {
		verification: {
			delete: {
				before: () => new Promise<void>((resolve) => setTimeout(resolve, 50)),
			},
		},
	},
};

/**
 * Spins up a real better-auth instance (fresh in-memory SQLite, real HTTP
 * listener on an OS-assigned port) with the OPAQUE plugin installed, plus
 * auth clients that already carry the OPAQUE client plugin.
 *
 * Call `server.close()` in `afterAll`.
 */
export async function createOpaqueTestInstance(
	pluginOptions: OpaqueOptions = {},
	authOptions: Partial<BetterAuthOptions> = {},
	clientOptions: OpaqueClientOptions = {},
) {
	const instance = await getHttpTestInstance(
		{
			emailAndPassword: { enabled: true },
			logger: { level: "error" },
			...authOptions,
			plugins: [
				opaque({ serverSetup: TEST_OPAQUE_SERVER_KEY, ...pluginOptions }),
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
	const createSessionClient = (options: OpaqueClientOptions = clientOptions) => {
		let cookie = "";
		return createAuthClient({
			baseURL: instance.baseURL,
			plugins: [opaqueClient(options)],
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

/**
 * Rewrites a user's OPAQUE account the way 2.x stored it: no credentialId,
 * and a record bound to the email string exactly as given here.
 */
export async function writeV2Record(
	t: OpaqueTestInstance,
	email: string,
	password: string,
) {
	const { clientRegistrationState, registrationRequest } =
		opaqueCrypto.startRegistration({ password });
	const { registrationRecord, exportKey } = opaqueCrypto.finishRegistration({
		clientRegistrationState,
		password,
		registrationResponse: server.createRegistrationResponse({
			serverSetup: TEST_OPAQUE_SERVER_KEY,
			userIdentifier: email,
			registrationRequest,
		}).registrationResponse,
	});
	const { internalAdapter } = await t.auth.$context;
	const found = await internalAdapter.findUserByEmail(email);
	const accounts = await internalAdapter.findAccounts(found!.user.id);
	const account = accounts.find((a) => a.providerId === "opaque");
	await internalAdapter.updateAccount(account!.id, {
		registrationRecord,
		credentialId: null,
	} as never);
	return { exportKey, accountId: account!.id };
}
