# Better Auth OPAQUE

[![npm version](https://img.shields.io/npm/v/better-auth-opaque.svg)](https://www.npmjs.com/package/better-auth-opaque)
[![CI](https://github.com/TheUntraceable/better-auth-opaque/actions/workflows/ci.yml/badge.svg)](https://github.com/TheUntraceable/better-auth-opaque/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A [Better Auth](https://better-auth.com) plugin that implements password authentication with the **OPAQUE** protocol ([RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html)).

With OPAQUE the password never leaves the device. The server stores a per-user record it cannot open, a full database breach gives an attacker nothing to crack offline, and every login hands the client an **export key** the server never learns, which you can use to encrypt the user's data end to end.

## Features

* **The password never leaves the device.** The server never sees, stores or hashes the password.
* **Export key.** Every sign-up, sign-in, password change, set and reset gives the client a 64-byte secret derived from the password, stable until the password is changed, set or reset, even to the same value. Use it to unlock client-side encrypted data.
* **Session key.** Each sign-in also yields a fresh key that both sides derive. The server never stores its copy; the `onSessionKey` option is the only way to use it there.
* **Complete password lifecycle.** Sign up, sign in, change password, set a password on a social-login account, and email-based password reset, all OPAQUE-native.
* **Server key pinning.** The client can pin the server's OPAQUE public key and refuse a swapped key or a man-in-the-middle.
* **Enumeration resistant by design.** Unknown emails get a real challenge computed under a deterministic fake record, the same query count, and the same response shape (see [Security](#security)).
* **Plays by Better Auth's rules.** Email verification, `rememberMe`, session refresh signals, rate limits, error codes, additional user fields, `auth.api.*` access and the test utilities all work.

## How it works

OPAQUE is an asymmetric password-authenticated key exchange. Both registration and login are two-round handshakes:

1. **Registration.** The client blinds the password and sends a registration request. The server evaluates it with its key and returns a challenge. The client finishes the handshake locally, producing a `registrationRecord` (an envelope only the password can open) and the `exportKey`. The server stores the record under a random, stable credential id.
2. **Login.** The client sends a login request. The server answers with a challenge built from the stored record. Only a client holding the right password can turn that challenge into a valid proof. The server checks the proof, both sides derive the same `sessionKey`, the client recovers the `exportKey`, and Better Auth issues a session.

## Installation

```bash
bun add better-auth-opaque
# or
npm install better-auth-opaque
```

Peer dependencies: `better-auth` 1.7 or newer and `zod` 4. `@serenity-kit/opaque` (the WebAssembly OPAQUE implementation) is installed automatically. The server plugin needs a global Web Crypto API (`globalThis.crypto`).

The plugin adds two columns to the `account` table, `registrationRecord` and `credentialId`. Run your Better Auth migration (`npx @better-auth/cli migrate` or `generate`) after installing.

## Setup

### 1. Generate the server key

```bash
npx @serenity-kit/opaque@0.9 create-server-setup
```

```env
# .env
OPAQUE_SERVER_KEY="..."
```

Every registration record is bound to this key. Rotating it invalidates every password; losing it locks every user out. Back it up like a database master key. Without it the plugin throws at startup unless `NODE_ENV` is `development` or `test`; there it generates a temporary key and warns that accounts will not survive a restart.

### 2. Server

```typescript
// src/lib/auth.ts
import { betterAuth } from "better-auth";
import { opaque } from "better-auth-opaque";

export const auth = betterAuth({
    secret: process.env.BETTER_AUTH_SECRET, // also encrypts the in-flight handshake state
    plugins: [
        opaque({
            serverSetup: process.env.OPAQUE_SERVER_KEY,

            // Needed for opaque.requestPasswordReset
            sendResetPassword: async ({ user, url, token }) => {
                await sendEmail(user.email, `Reset your password: ${url}`);
            },

            // Optional: tell the real owner someone tried to register their email
            onExistingUserSignUp: async ({ user }) => {
                await sendEmail(user.email, "Someone tried to sign up with your address.");
            },
        }),
    ],
});
```

All options, endpoints and error codes are listed in [docs/reference.md](docs/reference.md).

`sendResetPassword`, `onExistingUserSignUp`, `onSessionKey` and Better Auth's `sendVerificationEmail` run through Better Auth's background-task runner: detached when `advanced.backgroundTasks` is configured, awaited otherwise. An error thrown by any of them is logged and never returned to the client, because a 500 that only happens when the account exists would be an enumeration oracle. Watch your logs for mailer failures.

### 3. Client

```typescript
// src/lib/auth-client.ts
import { createAuthClient } from "better-auth/client";
import { opaqueClient } from "better-auth-opaque/client";

export const authClient = createAuthClient({
    plugins: [
        opaqueClient({
            // Optional: pin the server's OPAQUE public key.
            // Get it once with: server.getPublicKey(process.env.OPAQUE_SERVER_KEY)
            serverPublicKey: process.env.NEXT_PUBLIC_OPAQUE_SERVER_PUBLIC_KEY,
        }),
    ],
});
```

Browser code should import from `better-auth-opaque/client`, which contains only client code. The root export also includes the server plugin, so with a bundler that does not tree-shake it pulls server-only modules into the browser bundle. `better-auth-opaque/server` exposes only the server plugin.

## Usage

Every action returns `{ data, error }` like the rest of the Better Auth client and refreshes `useSession` when the session changes. Each accepts `fetchOptions` (anything `$fetch` accepts except `method` and `body`) inside its first argument, as core actions do, or as a second argument; where both set the same option, the first argument's wins.

Every action except `requestPasswordReset` makes two requests but behaves as one call:

* Transport options such as `headers` go on every request, and so does a header set in `onRequest`.
* `onRequest` fires once. `onResponse`, `onSuccess` and `onError` fire once with the final outcome, so a wrong password fires `onError`, never `onSuccess`. For failures decided on the client (wrong password, pinned-key mismatch, `REQUEST_FAILED`) they receive a stand-in `Response` carrying the error status. A response returned from `onResponse` is ignored.
* Hooks set globally in `createAuthClient({ fetchOptions })` still fire per request, because Better Auth installs them as a fetch plugin: a wrong-password sign-in reaches them as a successful challenge.
* With `throw: true` (per call, in the first argument's `fetchOptions`, or global) a failure throws `OpaqueFetchError`, exported from `better-auth-opaque/client` and the root. It has the same shape as better-fetch's `BetterFetchError` (`status`, `statusText`, `error`) but is not an instance of it. Success still returns `{ data, error: null }`, whereas core actions return the bare data under `throw: true`.

Every action except `requestPasswordReset` also returns `serverPublicKey`.

### Sign up

```typescript
const { data, error } = await authClient.signUp.opaque({
    email,
    password,
    name: "Ada",
    // image, callbackURL and any user.additionalFields are accepted too
});
// data.status      -> true (also when the email already exists; see Security)
// data.token       -> null unless insecureCreateSessionOnRegister is on and email verification is not required
// data.exportKey   -> keep this on the device if you use client-side encryption
```

The user is registered but **not** signed in. Call `signIn.opaque` next.

### Sign in

```typescript
const { data, error } = await authClient.signIn.opaque({
    email,
    password,
    rememberMe: false, // optional, session-only cookie like signIn.email
});
if (error?.code === "INVALID_EMAIL_OR_PASSWORD") { /* wrong password or no account */ }
if (error?.code === "EMAIL_NOT_VERIFIED") { /* requireEmailVerification is on */ }
// data.token, data.user   -> as signIn.email, but data.redirect is always false and there is no data.url
// data.exportKey          -> same value signUp.opaque returned, until the password changes
// data.sessionKey         -> fresh per sign-in; the server never stores its copy (see onSessionKey)
```

A wrong password is detected on the client: the handshake fails locally and no proof is ever sent, so the server only ever sees challenge requests.

`callbackURL` is accepted but only used for the link in a verification email (`emailVerification.sendOnSignIn`). Unlike `signIn.email`, the response is never a redirect: Better Auth's client would navigate away inside the request, before the action hands you the export key. Store the key, then redirect yourself.

### Change password

```typescript
const { data, error } = await authClient.opaque.changePassword({
    currentPassword,
    newPassword,
    revokeOtherSessions: true, // default
});
// data.token             -> a fresh session for this device
// data.previousExportKey -> the key for the OLD password
// data.exportKey         -> the key for the NEW password
```

Requires a fresh session (within Better Auth's `session.freshAge`, default one day), else it fails with 403 `SESSION_NOT_FRESH`. The current password is proven with a full OPAQUE login before anything changes.

If the complete request fails after the server stored the new record (a dropped connection, say), the action returns only the error. Signing in with the new password recovers the new export key, but the previous one cannot be re-derived, so keep the previous key until data wrapped under it is confirmed re-wrapped under the new key.

### Set a password on an account that has none

```typescript
// Signed in through Google/GitHub/magic link and wants a password too
const { data, error } = await authClient.opaque.setPassword({ password });
// error.code === "OPAQUE_ACCOUNT_EXISTS" if one is already set
```

Also requires a fresh session.

### Reset a forgotten password

```typescript
// 1. From the login page
await authClient.opaque.requestPasswordReset({
    email,
    redirectTo: "/reset-password", // the emailed link redirects here with ?token=...
});

// 2. On /reset-password?token=...
const { data, error } = await authClient.opaque.resetPassword({
    token,
    newPassword,
});
// Every existing session is revoked. data.exportKey is a NEW key.
```

### Using the export key

The export key is the reason to use OPAQUE over bcrypt. A typical pattern:

```typescript
// On sign-up: make a random data key, wrap it with a key derived from exportKey
const kek = await hkdf(exportKey, "my-app/vault-kek");
const dataKey = crypto.getRandomValues(new Uint8Array(32));
const wrapped = await aesGcmEncrypt(kek, dataKey);
await api.storeWrappedKey(wrapped); // the server can store this, it is useless without the password

// On sign-in: unwrap it
const dataKey = await aesGcmDecrypt(await hkdf(exportKey, "my-app/vault-kek"), wrapped);

// On password change: re-wrap before you forget the old key
const { previousExportKey, exportKey } = result.data;
const dataKey = await aesGcmDecrypt(await hkdf(previousExportKey, ...), wrapped);
await api.storeWrappedKey(await aesGcmEncrypt(await hkdf(exportKey, ...), dataKey));
```

Two rules follow from this:

* **Never send the export key to the server.** The plugin does not, and your code should not either.
* **A password reset produces a new export key and the old one is gone.** Anything wrapped only under the old key is unrecoverable. If you build client-side encryption, give users a recovery key or re-wrap the data key from a signed-in session before they lose access.

## Security

**What OPAQUE gives you.** Passwords are never transmitted or stored. A database breach yields registration records that cannot be brute-forced offline without also stealing the server setup (`serverSetup`), and even then each guess costs a full Argon2 evaluation. The server cannot be tricked into revealing anything about the password by a malicious client.

**What it does not give you.** Online guessing is still possible. Each guess costs the attacker one challenge request plus client-side Argon2, and the plugin rate limits every endpoint, but there is no per-account lockout. A wrong password is decided on the client, so the server never observes failed attempts; add a CAPTCHA or per-email throttle in front of the sign-in challenge if that matters for you.

**Account enumeration.** The sign-in challenge for an unknown email is computed under a fake record with a deterministic credential id, performs the same database queries as the real path, and returns a response of identical shape and size. Sign-up and reset-password requests respond identically for known and unknown emails. The exception is an additional user field with a database `unique` constraint: the insert fails only for new emails, so sign-up completion tells them apart; keep such fields out of sign-up or set them after sign-in. This only holds if the rest of your configuration does too: Better Auth's own `/sign-up/email` reveals existing emails by default, so either keep `emailAndPassword` disabled or configure it to respond generically. Debug logs never include the email or whether it exists.

**Timing.** On the sign-in challenge, the matched-work design keeps the real and fake-record branches within tens of microseconds of each other, well under network jitter, which is the same approach Better Auth core takes for `/sign-in/email`. Sign-up completion and reset request have no fake branch: for a new email or a known account they do extra database writes, sub-millisecond on a local database and more on a networked one. To hide that, set `timingSafeResponseMs` to pad the sign-in challenge, sign-up completion and reset request to a floor of roughly 2 to 3 times your p99 handler time. It is a backstop, not constant time: a request that overruns the floor leaks its real duration.

**Handshake state.** The state blob handed to the client between the two steps is encrypted with the Better Auth secret, padded to a fixed size, bound to its purpose (sign-in state cannot complete a password change), expires after `challengeExpiresIn` seconds, and can be completed exactly once. Consumption is atomic (Better Auth's `consumeVerificationValue`), so concurrent requests carrying the same state, or the same reset token, cannot both succeed. A challenge minted before a password change cannot complete after it.

**Email changes.** Records are bound to a server-generated credential id, not the email, so `changeEmail` and case differences in the typed email do not lock anyone out. Accounts still on a 2.x record are the exception until their password is changed or reset; see [Upgrading](#upgrading-from-2x).

**Two-factor.** The Better Auth `twoFactor` plugin hooks only the core sign-in routes, so an OPAQUE sign-in currently completes without the second factor. If you need both, enforce the second factor in your own `databaseHooks.session.create.before` or in front of the session.

**Core password routes.** With `emailAndPassword` enabled, Better Auth's `/reset-password` and `/set-password` create a server-side hashed credential next to the OPAQUE record. The plugin warns about this at startup. Use `opaque.requestPasswordReset` and `opaque.setPassword` instead.

**Key handling.** The server key is validated at startup and is never logged. The client can pin the corresponding public key with `opaqueClient({ serverPublicKey })`; the server proves possession of it in every handshake.

## Upgrading from 2.x

3.0.0 is a breaking release. Most apps only need to rerun migrations and rename `changePassword`, plus upgrade `better-auth` if they are coming from 2.0.x.

* **`better-auth` 1.7 or newer is required** as a peer dependency, as in 2.1.0 (2.0.x bundled 1.3). The `Types of property 'getActions' are incompatible` / `Property 'opaque' does not exist` errors from 2.0.3 are gone: its published types gave `getActions` a `$fetch` typed as `BetterFetch` from `@better-fetch/fetch`, typed structurally since 2.1.0.
* **New `account.credentialId` column.** Run your migration. Records written by 2.x keep working through a fallback until the password is changed or reset, which moves the account to a credential id. 2.x bound each record to the email exactly as it was typed at sign-up, so those users must sign in with that same casing; any other casing fails with `INVALID_EMAIL_OR_PASSWORD`. Change-password on a 2.x account uses the stored, lower-cased email, so a 2.x user who registered in mixed case must reset their password rather than change it.
* **`authClient.changePassword` is now `authClient.opaque.changePassword`.** The old name refers to Better Auth's built-in action.
* **Change password requires a fresh session** (2.1.0 accepted any session), and by default it now issues this device a new session instead of signing it out with every other one.
* **Endpoints moved** from `/sign-up/opaque/*`, `/sign-in/opaque/*` and `/opaque/changePassword/*` to `/opaque/sign-up/*`, `/opaque/sign-in/*` and `/opaque/change-password/*`. Only custom clients are affected.
* **Response shapes** now match core: sign-in returns `{ redirect: false, token, user }`, change-password `{ token, user }`, sign-up `{ status, token }`. The client adds `exportKey`, `sessionKey`, `previousExportKey` and `serverPublicKey` where they apply.
* **`dontRememberMe` is now `rememberMe`**, same semantics as `signIn.email`.
* **Challenges expire after 2 minutes and are single-use** (2.x: 15 minutes, replayable).
* **Email verification is honoured.** If `requireEmailVerification` is set, unverified users can no longer sign in with OPAQUE.
* **`OPAQUE_SERVER_KEY` is now `serverSetup`.** The old name still works as a deprecated alias. One of them is required unless `NODE_ENV` is `development` or `test`; 2.x generated and printed a throwaway key in any environment.
* **Rate limits** now apply to every `/opaque/*` endpoint; see [Endpoints](docs/reference.md#endpoints).

## Development

```bash
bun install
bun run typecheck    # tsc over src/ and tests/ (the type-level tests only bite here)
bun run build        # tsc -> dist/
bun run test         # vitest on better-auth's HTTP test instance, run under bun
bun run check        # all three; run by the release workflow and prepublishOnly
bun run test:timing  # opt-in statistical timing tests (slow)
bun run test:server  # manual Express server on :8080
```

Tests use `better-auth/test`, which needs `node:sqlite` with `StatementSync.columns()`. That ships in Bun and in Node 22.16+/23.11+; `bun run test:node` runs the suite on plain Node.

Releases: publishing a GitHub release runs the `release` workflow in the `release` environment. It checks the tag against the `package.json` version, then publishes to npm with provenance and `--ignore-scripts`. `NPM_TOKEN` must be a granular access token with read and write access to this package and 2FA bypass enabled, since the workflow cannot enter a one-time password.

## License

MIT
