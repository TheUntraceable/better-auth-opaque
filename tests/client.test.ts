import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { ready } from "@serenity-kit/opaque";
import { createAuthClient } from "better-auth/client";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { OpaqueFetchError, opaqueClient } from "../src/client";
import {
	createOpaqueTestInstance,
	type OpaqueTestInstance,
	password,
	uniqueEmail,
} from "./helpers";

/** Records what actually went over the wire for each request of an action. */
const recorder = () => {
	const requests: { path: string; headers: Headers; body: string }[] = [];
	const customFetchImpl = (input: string | URL | Request, init?: RequestInit) => {
		requests.push({
			path: new URL(String(input)).pathname.replace("/api/auth", ""),
			headers: new Headers(init?.headers),
			body: String(init?.body),
		});
		return fetch(input, init);
	};
	return { requests, customFetchImpl };
};

const hookSpy = () => {
	const calls = {
		request: 0,
		response: [] as number[],
		success: [] as unknown[],
		error: [] as { status: number; url: string; error: unknown }[],
	};
	return {
		calls,
		hooks: {
			onRequest: () => void calls.request++,
			onResponse: ({ response }: { response: Response }) =>
				void calls.response.push(response.status),
			onSuccess: ({ data }: { data: unknown }) => void calls.success.push(data),
			onError: ({
				response,
				request,
				error,
			}: {
				response: Response;
				request: { url: URL | string };
				error: unknown;
			}) =>
				void calls.error.push({
					status: response.status,
					url: String(request.url),
					error,
				}),
		},
	};
};

describe("opaque client: fetch semantics", () => {
	let t: OpaqueTestInstance;
	let email: string;

	beforeAll(async () => {
		await ready;
		t = await createOpaqueTestInstance();
		email = uniqueEmail("client");
		await t.client.signUp.opaque({ email, name: "Client", password });
	});
	afterAll(() => t.server.close());

	test("transport options go on every request; hooks fire once on success", async () => {
		const { requests, customFetchImpl } = recorder();
		const { calls, hooks } = hookSpy();
		const signIn = await t.client.signIn.opaque(
			{ email, password },
			{ ...hooks, customFetchImpl, headers: { "x-transport": "1" } },
		);
		expect(signIn.error).toBeNull();
		expect(requests.map((r) => r.path)).toEqual([
			"/opaque/sign-in/challenge",
			"/opaque/sign-in/complete",
		]);
		expect(requests.map((r) => r.headers.get("x-transport"))).toEqual(["1", "1"]);
		expect(calls).toEqual({
			request: 1,
			response: [200],
			success: [signIn.data],
			error: [],
		});
	});

	test("a header set by onRequest reaches every request of the action", async () => {
		const { requests, customFetchImpl } = recorder();
		let fired = 0;
		const signIn = await t.client.signIn.opaque(
			{ email, password },
			{
				customFetchImpl,
				onRequest: (context) => {
					fired++;
					context.headers.set("x-flow", "carried");
				},
			},
		);
		expect(signIn.error).toBeNull();
		expect(fired).toBe(1);
		expect(requests.map((r) => r.headers.get("x-flow"))).toEqual([
			"carried",
			"carried",
		]);
	});

	test("a wrong password fires onError once and never onSuccess", async () => {
		const { calls, hooks } = hookSpy();
		const result = await t.client.signIn.opaque(
			{ email, password: "not-the-password" },
			hooks,
		);
		expect(result.error?.code).toBe("INVALID_EMAIL_OR_PASSWORD");
		expect(calls.request).toBe(1);
		expect(calls.success).toEqual([]);
		expect(calls.response).toEqual([401]);
		expect(calls.error).toHaveLength(1);
		expect(calls.error[0]).toMatchObject({ status: 401, error: result.error });
	});

	test("a pinned-key mismatch fires onError once and stops the flow", async () => {
		const pinned = t.createSessionClient({ serverPublicKey: "nope" });
		const { requests, customFetchImpl } = recorder();
		const { calls, hooks } = hookSpy();
		const result = await pinned.signUp.opaque(
			{ email: uniqueEmail("pinned"), name: "Pinned", password },
			{ ...hooks, customFetchImpl },
		);
		expect(result.error).toMatchObject({
			code: "SERVER_KEY_MISMATCH",
			status: 400,
			statusText: "Bad Request",
		});
		expect(requests.map((r) => r.path)).toEqual(["/opaque/sign-up/challenge"]);
		expect(calls.success).toEqual([]);
		expect(calls.error).toHaveLength(1);
		expect(calls.error[0]).toMatchObject({ status: 400, error: result.error });
	});

	test("a server failure fires onError once with the failing request", async () => {
		const { calls, hooks } = hookSpy();
		const result = await t.client.opaque.changePassword(
			{ currentPassword: password, newPassword: "never-applied" },
			hooks,
		);
		expect(result.error?.status).toBe(401);
		expect(calls.success).toEqual([]);
		expect(calls.error).toHaveLength(1);
		expect(calls.error[0]?.url).toMatch(/\/opaque\/change-password\/challenge$/);
		expect(calls.error[0]?.status).toBe(401);
	});

	test("a step that answers without data fails with REQUEST_FAILED", async () => {
		const { calls, hooks } = hookSpy();
		const result = await t.client.opaque.requestPasswordReset(
			{ email },
			{ ...hooks, customFetchImpl: async () => new Response(null, { status: 200 }) },
		);
		expect(result.data).toBeNull();
		expect(result.error).toMatchObject({
			code: "REQUEST_FAILED",
			status: 500,
			statusText: "Internal Server Error",
		});
		expect(calls.success).toEqual([]);
		expect(calls.response).toEqual([500]);
		expect(calls.error).toHaveLength(1);
		expect(calls.error[0]).toMatchObject({ status: 500, error: result.error });
	});

	test("throw: true returns { data, error } on success and throws once on failure", async () => {
		const ok = await t.client.signIn.opaque({ email, password }, { throw: true });
		expect(ok.error).toBeNull();
		expect(ok.data?.token).toBeTruthy();
		expect(ok.data?.exportKey).toHaveLength(86);

		const { calls, hooks } = hookSpy();
		const wrong = t.client.signIn.opaque(
			{ email, password: "not-the-password" },
			{ ...hooks, throw: true },
		);
		await expect(wrong).rejects.toBeInstanceOf(OpaqueFetchError);
		await expect(wrong).rejects.toMatchObject({
			status: 401,
			statusText: "Unauthorized",
			error: { code: "INVALID_EMAIL_OR_PASSWORD", status: 401 },
		});
		expect(calls.error).toHaveLength(1);

		await expect(
			t.client.opaque.changePassword(
				{ currentPassword: password, newPassword: "never-applied" },
				{ throw: true },
			),
		).rejects.toMatchObject({ status: 401 });
	});

	test("honours a global throw: true, and a per-call throw: false overrides it", async () => {
		const throwing = createAuthClient({
			baseURL: t.baseURL,
			plugins: [opaqueClient()],
			fetchOptions: { throw: true },
		});
		const ok = await throwing.signIn.opaque({ email, password });
		expect(ok.error).toBeNull();
		expect(ok.data?.sessionKey).toHaveLength(86);

		await expect(
			throwing.signIn.opaque({ email, password: "not-the-password" }),
		).rejects.toMatchObject({ error: { code: "INVALID_EMAIL_OR_PASSWORD" } });

		const quiet = await throwing.signIn.opaque(
			{ email, password: "not-the-password" },
			{ throw: false },
		);
		expect(quiet.error?.code).toBe("INVALID_EMAIL_OR_PASSWORD");
	});

	test("fetchOptions in the first argument are honoured and never sent", async () => {
		const { requests, customFetchImpl } = recorder();
		const { calls, hooks } = hookSpy();
		const fresh = uniqueEmail("inline");
		const signUp = await t.client.signUp.opaque({
			email: fresh,
			name: "Inline",
			password,
			fetchOptions: { ...hooks, customFetchImpl, headers: { "x-inline": "1" } },
		});
		expect(signUp.error).toBeNull();
		expect(requests.map((r) => r.headers.get("x-inline"))).toEqual(["1", "1"]);
		expect(requests.some((r) => r.body.includes("fetchOptions"))).toBe(false);
		expect(calls.success).toEqual([signUp.data]);
		expect((await t.client.signIn.opaque({ email: fresh, password })).error).toBeNull();

		const winner = recorder();
		await t.client.signIn.opaque(
			{
				email: fresh,
				password,
				fetchOptions: { customFetchImpl: winner.customFetchImpl, headers: { "x-from": "inline" } },
			},
			{ headers: { "x-from": "second" } },
		);
		expect(winner.requests.map((r) => r.headers.get("x-from"))).toEqual([
			"inline",
			"inline",
		]);

		await expect(
			t.client.signIn.opaque({
				email: fresh,
				password: "not-the-password",
				fetchOptions: { throw: true },
			}),
		).rejects.toBeInstanceOf(OpaqueFetchError);
	});
});

describe("opaque client: bundle boundary", () => {
	test("client modules never import server code at runtime", () => {
		const dir = fileURLToPath(new URL("../src", import.meta.url));
		const files = [
			join(dir, "client.ts"),
			...readdirSync(join(dir, "client")).map((f) => join(dir, "client", f)),
		];
		const runtimeServerImport =
			/^(?:import|export)\s+(?!type\b)[^;]*?from\s+["'](?:\.{1,2}\/)+server\b/m;
		for (const file of files) {
			expect(readFileSync(file, "utf8"), file).not.toMatch(runtimeServerImport);
		}
	});
});
