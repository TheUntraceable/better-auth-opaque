/**
 * Entry-point hygiene: the browser client must not drag server code
 * (better-auth server, better-auth/api, better-auth/crypto, zod, ...) into a
 * browser bundle, and the client and server must agree on error codes.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
		expect(specifiers.filter((s) => /^\.\/(utils|server)(\.[jt]s)?$/.test(s))).toEqual([]);
	});
});

describe("error codes", () => {
	test("client and server export the same OPAQUE_ERROR_CODES", () => {
		expect(clientEntry.OPAQUE_ERROR_CODES).toBeDefined();
		expect(clientEntry.OPAQUE_ERROR_CODES).toEqual(serverEntry.OPAQUE_ERROR_CODES);
		expect(clientEntry.opaqueClient().$ERROR_CODES).toEqual(serverEntry.OPAQUE_ERROR_CODES);
	});
});

/**
 * The published dist/ must be importable by plain Node ESM (no bundler), which
 * requires fully specified relative imports. Builds with the project's tsc into
 * a temp dir that mimics an installed package (type: module + node_modules).
 */
describe("compiled output under Node ESM", () => {
	const repoRoot = new URL("..", import.meta.url).pathname;
	let pkgDir = "";

	beforeAll(async () => {
		pkgDir = await mkdtemp(join(tmpdir(), "better-auth-opaque-dist-"));
		await writeFile(join(pkgDir, "package.json"), JSON.stringify({ type: "module" }));
		await symlink(join(repoRoot, "node_modules"), join(pkgDir, "node_modules"), "dir");
		const tsc = Bun.spawnSync(
			[join(repoRoot, "node_modules/.bin/tsc"), "-p", join(repoRoot, "tsconfig.json"), "--outDir", join(pkgDir, "dist")],
			{ cwd: repoRoot, stdout: "pipe", stderr: "pipe" },
		);
		expect({ exitCode: tsc.exitCode, output: tsc.stdout.toString() + tsc.stderr.toString() }).toEqual({
			exitCode: 0,
			output: "",
		});
	});

	afterAll(async () => {
		if (pkgDir) await rm(pkgDir, { recursive: true, force: true });
	});

	function nodeImport(file: string) {
		const url = new URL(`file://${join(pkgDir, "dist", file)}`).href;
		const proc = Bun.spawnSync(
			[
				"node",
				"--input-type=module",
				"-e",
				`import(${JSON.stringify(url)}).then((m) => console.log(JSON.stringify(Object.keys(m).sort())))`,
			],
			{ cwd: pkgDir, stdout: "pipe", stderr: "pipe" },
		);
		const stdout = proc.stdout.toString().trim();
		return {
			exitCode: proc.exitCode,
			exports: proc.exitCode === 0 ? JSON.parse(stdout.split("\n").at(-1) ?? "null") : proc.stderr.toString(),
		};
	}

	test("client.js", () => {
		expect(nodeImport("client.js")).toEqual({ exitCode: 0, exports: ["OPAQUE_ERROR_CODES", "opaqueClient"] });
	});

	test("server.js", () => {
		expect(nodeImport("server.js")).toEqual({ exitCode: 0, exports: ["OPAQUE_ERROR_CODES", "opaque"] });
	});

	test("index.js", () => {
		expect(nodeImport("index.js")).toEqual({
			exitCode: 0,
			exports: ["OPAQUE_ERROR_CODES", "opaque", "opaqueClient"],
		});
	});
});
