// Run by `bun run test:dist` under plain Node. tsc emits relative imports as
// written and Node's ESM loader adds no extension and resolves no directory,
// so an import in src/ without `.js` only fails here, never under bun or vitest.
for (const entry of ["index", "client", "server"]) {
	await import(new URL(`../dist/${entry}.js`, import.meta.url).href);
}
