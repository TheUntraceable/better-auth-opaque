/**
 * Entry-point hygiene: the browser client must not drag server code
 * (better-auth server, better-auth/api, better-auth/crypto, zod, ...) into a
 * browser bundle, and the client and server must agree on error codes.
 */
import { describe, expect, test } from "bun:test";
import * as clientEntry from "../src/client";
import * as serverEntry from "../src/server";

const SERVER_ONLY_MARKERS = [
	"createAuthEndpoint",
	"better-auth/api",
	"better-auth/crypto",
	"symmetricEncrypt",
	"symmetricDecrypt",
	"setSessionCookie",
	"sessionMiddleware",
];

async function bundleForBrowser(entrypoint: string) {
	const specifiers: string[] = [];
	const result = await Bun.build({
		entrypoints: [entrypoint],
		target: "browser",
		format: "esm",
		minify: false,
		plugins: [
			{
				name: "record-imports",
				setup(build) {
					build.onResolve({ filter: /.*/ }, (args) => {
						specifiers.push(args.path);
						return undefined;
					});
				},
			},
		],
	});
	expect(result.success).toBe(true);
	const code = (await Promise.all(result.outputs.map((o) => o.text()))).join("\n");
	return { code, specifiers };
}

describe("browser bundle of src/client.ts", () => {
	test("contains no server-only code", async () => {
		const { code, specifiers } = await bundleForBrowser(
			new URL("../src/client.ts", import.meta.url).pathname,
		);
		for (const marker of SERVER_ONLY_MARKERS) {
			expect({ marker, found: code.includes(marker) }).toEqual({ marker, found: false });
		}
		// Only the OPAQUE crypto library (and our own error-code module) may be
		// resolved at runtime; better-auth is imported for types only.
		expect(specifiers.filter((s) => s.startsWith("better-auth") || s === "zod")).toEqual([]);
		expect(specifiers.filter((s) => s === "./utils" || s === "./server")).toEqual([]);
	});
});

describe("error codes", () => {
	test("client and server export the same OPAQUE_ERROR_CODES", () => {
		expect(clientEntry.OPAQUE_ERROR_CODES).toBeDefined();
		expect(clientEntry.OPAQUE_ERROR_CODES).toEqual(serverEntry.OPAQUE_ERROR_CODES);
		expect(clientEntry.opaqueClient().$ERROR_CODES).toEqual(serverEntry.OPAQUE_ERROR_CODES);
	});
});
