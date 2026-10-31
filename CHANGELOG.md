# Changelog

## 3.0.0

Changes are relative to 2.1.0, the last published release.

### Breaking

- `authClient.changePassword` moved to `authClient.opaque.changePassword`.
- Endpoints moved under `/opaque/*` with kebab-case paths (`/opaque/sign-up/challenge`, `/opaque/change-password/complete`, ...).
- Sign-in responds with `{ redirect: false, token, user }` and change-password with `{ token, user }` like core; sign-up responds with `{ status, token }`. Client actions always return `{ data, error }`.
- `dontRememberMe` replaced by `rememberMe`.
- New `account.credentialId` column; run migrations. OPAQUE records are now bound to a stable server-generated id instead of the email. 2.x records keep working through a fallback until the password is changed or reset. They were bound to the email exactly as sent, so they still need that casing at sign-in, and a 2.x user who registered in mixed case must reset rather than change their password.
- Handshake state expires after 2 minutes (was 15) and is single-use, consumed atomically (`consumeVerificationValue`) so concurrent requests with the same state cannot both succeed.
- `requireEmailVerification` (own option or `emailAndPassword.requireEmailVerification`) now blocks unverified sign-ins.
- Behaviour change: without a server setup the plugin throws at startup unless `NODE_ENV` is `development` or `test`, where it generates a per-process key and no longer prints it. 2.x generated and printed one in every environment.
- Behaviour change: change-password requires a fresh session (core's `freshSessionMiddleware`, 403 `SESSION_NOT_FRESH`); 2.1.0 accepted any session. With `revokeOtherSessions` (the default) it issues the current device a new session, where 2.1.0 revoked every session including the current one.

### Changed

- `OPAQUE_SERVER_KEY` renamed to `serverSetup`. The old name still works as a deprecated alias, so this is not breaking.
- Behaviour change: rate limits on every `/opaque/*` endpoint, per IP and path (2.x had none): 3 per 60 s for the reset-password request, 3 per 10 s for each `*/challenge` endpoint, 5 per 10 s for the rest. The new `rateLimit: { window, max }` option replaces them with one rule.
- Behaviour change: `insecureCreateSessionOnRegister` is ignored while email verification is required, like core's `autoSignIn`, and a failed session insert returns 500 `FAILED_TO_CREATE_SESSION` instead of a session-less success.
- `typescript` is no longer a peer dependency.

### Added

- `exportKey` returned from sign-up, sign-in, change-password (with `previousExportKey`), set-password and reset-password. It is stable until the password is changed, set or reset, even to the same value.
- `sessionKey` returned from sign-in. The server never stores its copy; the new `onSessionKey({ user, session, sessionKey }, ctx)` option receives it after each successful sign-in.
- `serverPublicKey` returned from every action except `requestPasswordReset`; `opaqueClient({ serverPublicKey })` pins the server key.
- `opaque.setPassword` for accounts without an OPAQUE password. Requires a fresh session.
- `opaque.requestPasswordReset` / `opaque.resetPassword` with `sendResetPassword`, `resetPasswordTokenExpiresIn`, and a redirect endpoint. Reset tokens are single-use and consumed atomically.
- `onExistingUserSignUp` hook.
- Verification emails on sign-up when `emailVerification.sendOnSignUp` is true, or is unset and verification is required, and on a blocked sign-in when `emailVerification.sendOnSignIn` is true. `callbackURL` on sign-up and sign-in only feeds that email's link: sign-in never responds with a redirect, because Better Auth's client would navigate before the app can store the export key.
- Errors thrown by `onExistingUserSignUp`, `onSessionKey`, `sendResetPassword` and `sendVerificationEmail` (sync or async) are logged and never change the response.
- `rememberMe` support; `useSession` refresh after sign-in, password change, reset, and a sign-up that issued a session.
- `fetchOptions` on every action, inside the first argument as with core actions or as a second argument (typed: headers, query, signal, better-fetch hooks). Hooks passed to an action fire once per action with the final outcome, so a wrong password fires `onError`, never `onSuccess`; a header set in `onRequest` goes on every request of the action; a response returned from `onResponse` is ignored; failures decided on the client give the hooks a stand-in `Response` with the error status. Hooks set globally in `createAuthClient({ fetchOptions })` still fire per request, because Better Auth installs them as a fetch plugin.
- `throw: true`, per call or global: failures throw `OpaqueFetchError` (exported from `better-auth-opaque/client` and the root), which has the shape of `BetterFetchError` but is not an instance of it. Success still returns `{ data, error: null }`, unlike core actions, which return the bare data.
- Failures decided on the client carry a `code`, `status` and standard `statusText` (`Unauthorized`), like server errors. A server reply without data fails with `REQUEST_FAILED` (500).
- Additional user fields and `image` accepted at sign-up.
- Disallowed, missing or invalid additional fields are rejected before the email lookup, so those rejections do not reveal whether the email is registered.
- `timingSafeResponseMs`, an opt-in minimum response time for the sign-in challenge, sign-up completion and reset request.
- `OPAQUE_ERROR_CODES` with typed error codes on both plugins. `CHALLENGE_FAILED` is exported but not produced.
- `better-auth-opaque/client` and `better-auth-opaque/server` entry points; `sideEffects: false`. Browser code should use `/client`: the root export also includes the server plugin.

### Fixed

- Email casing: records are bound to a credential id, so the casing typed at sign-in and `changeEmail` no longer lock anyone out (2.x records excepted until their password is changed or reset).
- Invalid proofs return 401, and well-formed requests that are not valid OPAQUE messages return 400 `INVALID_REQUEST`, instead of crashing with a 500.
- Malformed registration records are rejected before being stored.
- `registrationRecord` is no longer returned by `/list-accounts` and no longer carries a unique index.
- A challenge minted before a password change can no longer complete afterwards.
- Change-password reads the session from the store (`sensitiveSessionMiddleware`) rather than the cookie cache.
- Debug logs no longer include emails or whether an account exists.
- Base64url field lengths are validated exactly against the sizes `@serenity-kit/opaque` produces.

### Internal

- Test suite runs on `better-auth/test`'s HTTP test instance under vitest (no external server). Statistical timing tests are opt-in via `OPAQUE_TIMING_TESTS=1`.
- `bun run typecheck` type-checks the tests (vitest alone never did, so the compile-time plugin-typing assertions were not enforced); `bun run check` runs typecheck, build and tests and backs `prepublishOnly`.
- GitHub Actions: CI on pushes to master and on pull requests; the release workflow publishes to npm with provenance from a GitHub release whose tag matches package.json `version`, behind the `release` environment.
- npm metadata (description, keywords, repository, license) on the package.

## 2.1.0

Published 2026-10-30.

### Added

- `authClient.changePassword({ currentPassword, newPassword })`, backed by `/opaque/changePassword/challenge` and `/opaque/changePassword/complete` (#1). The current password is proven with an OPAQUE login before the new record is stored, and every session of the user is then revoked. An account without an OPAQUE password gets a challenge computed against a dummy record.

### Changed

- `better-auth` `^1.7.0` and `zod` `^4` are peer dependencies; `better-auth` was a bundled `^1.3.28` dependency. Internal adapter calls follow the 1.7 signatures. The `typescript` peer range widened to `>=5`.

### Fixed

- `Types of property 'getActions' are incompatible`, with all `authClient.*.opaque` inference lost. 2.0.3's declarations inferred `getActions`' `$fetch` parameter as `BetterFetch` from `@better-fetch/fetch`; it is now a self-contained structural type.

### Internal

- Tests for the plugin and the login-state encryption, and a manual Express test server.

## 2.0.3 and earlier

See git history.
