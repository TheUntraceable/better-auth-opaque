# Changelog

## 3.0.0

Changes are relative to 2.0.3, the last published release.

### Breaking

- `better-auth` 1.7+ is a peer dependency (was a bundled dependency on 1.3). Fixes the `getActions is incompatible` / `Property 'opaque' does not exist` type errors caused by two `better-auth` copies.
- `authClient.changePassword` moved to `authClient.opaque.changePassword`.
- Endpoints moved under `/opaque/*` with kebab-case paths (`/opaque/sign-up/challenge`, `/opaque/change-password/complete`, ...).
- Sign-in and change-password respond with `{ token, user }` like core; sign-up responds with `{ status, token }`. Client actions always return `{ data, error }`.
- `dontRememberMe` replaced by `rememberMe`.
- New `account.credentialId` column; run migrations. OPAQUE records are now bound to a stable server-generated id instead of the email. 2.x records keep working through a fallback, except mixed-case 2.x registrations, which need a password reset.
- Handshake state expires after 2 minutes (was 15) and is single-use.
- `timingSafeResponseMs` is off by default (2.x padded every endpoint to 250 ms) and only applies to the three existence-dependent endpoints when set.
- `OPAQUE_SERVER_KEY` is required when `NODE_ENV=production`; the generated dev key is no longer printed.
- `requireEmailVerification` (own option or `emailAndPassword.requireEmailVerification`) now blocks unverified sign-ins.

### Added

- `exportKey` returned from sign-up, sign-in, change-password (with `previousExportKey`), set-password and reset-password.
- `sessionKey` and `serverPublicKey` returned from sign-in; `opaqueClient({ serverPublicKey })` pins the server key.
- `opaque.setPassword` for accounts without an OPAQUE password.
- `opaque.requestPasswordReset` / `opaque.resetPassword` with `sendResetPassword`, `resetPasswordTokenExpiresIn`, and a redirect endpoint.
- `onExistingUserSignUp` hook.
- Verification emails on sign-up when `emailVerification.sendOnSignUp` or `requireEmailVerification` is set.
- `rememberMe` support, `useSession` refresh after sign-in and password change, `fetchOptions` second argument on every action.
- Additional user fields and `image` accepted at sign-up.
- Plugin-level rate limit (5 req / 10 s / IP / path) on every `/opaque/*` endpoint.
- `OPAQUE_ERROR_CODES` with typed error codes on both plugins.
- `better-auth-opaque/client` and `better-auth-opaque/server` entry points; `sideEffects: false`.

### Fixed

- Email casing: sign-in and change-password no longer fail for users who registered with a mixed-case email, and `changeEmail` no longer locks users out.
- Invalid proofs return 401 with a code instead of crashing with a 500.
- Malformed registration records are rejected before being stored.
- `registrationRecord` is no longer returned by `/list-accounts` and no longer carries a unique index.
- A challenge minted before a password change can no longer complete afterwards.
- Change-password uses the authoritative (`sensitiveSessionMiddleware`) session.
- Debug logs no longer include emails or whether an account exists.
- Base64url field lengths are validated exactly against the sizes `@serenity-kit/opaque` produces.

### Internal

- Test suite runs on `better-auth/test`'s HTTP test instance under vitest (no external server). Statistical timing tests are opt-in via `OPAQUE_TIMING_TESTS=1`.

## 2.0.3

Last 2.x release. See git history.
