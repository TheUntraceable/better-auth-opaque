// Fixed key so registration records stay valid across the server instances a
// test file may create. Test-only; never reuse outside this suite.
// Kept apart from helpers.ts, whose better-auth/test import only loads under
// vitest, so the manual server in tests/server.ts can share it.
export const TEST_OPAQUE_SERVER_KEY =
	"bgTA0wwx_5WvwoyDHURXOsnN3u1y2uJLr1vXYGc1_F5yNgubuj6Pf4JVIM83aIWHHJ7GIPUxDW74-j8CEuv0Os4rE4lQ7GnBQk3nVLDl5s1J4BsNrPXqx_i-T44FaZYLQPDzr2huMv49zUIRxA15XVU9dFuzZZgf-XiaaNDnIA0";
