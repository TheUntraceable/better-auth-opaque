# Better Auth OPAQUE

[![npm version](https://img.shields.io/npm/v/better-auth-opaque.svg)](https://www.npmjs.com/package/better-auth-opaque)
[![CI](https://github.com/TheUntraceable/better-auth-opaque/actions/workflows/ci.yml/badge.svg)](https://github.com/TheUntraceable/better-auth-opaque/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A [Better Auth](https://better-auth.com) plugin that implements password authentication with the **OPAQUE** protocol ([RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html)).

With OPAQUE the password never leaves the device. The server stores a per-user record it cannot open, a full database breach gives an attacker nothing to crack offline, and every login hands the client an **export key** the server never learns, which you can use to encrypt the user's data end to end.

## Features

* **Zero-knowledge passwords.** The server never sees, stores or hashes the password.
* **Export key.** Every sign-up, sign-in, password change and reset gives the client a stable 64-byte secret derived from the password. Use it to unlock client-side encrypted data.
* **Session key.** Each login handshake also yields a fresh shared key on both sides.
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

Peer dependencies: `better-auth` 1.7 or newer and `zod` 4. `@serenity-kit/opaque` (the WebAssembly OPAQUE implementation) is installed automatically. The server plugin runs anywhere Better Auth does with a global Web Crypto API: Node 20+, Bun, and the edge runtimes.

The plugin adds two columns to the `account` table, `registrationRecord` and `credentialId`. Run your Better Auth migration (`npx @better-auth/cli migrate` or `generate`) after installing.

## Setup

### 1. Generate the server key

```bash
npx @serenity-kit/opaque@latest create-server-setup
```

```env
# .env
OPAQUE_SERVER_KEY="..."
```

Every registration record is bound to this key. Rotating it invalidates every password; losing it locks every user out. Back it up like a database master key. The plugin refuses to start without it when `NODE_ENV=production`; in development it generates a temporary key and warns that accounts will not survive a restart.

### 2. Server

```typescript
// src/lib/auth.ts
import { betterAuth } from "better-auth";
import { opaque } from "better-auth-opaque";

export const auth = betterAuth({
    secret: process.env.BETTER_AUTH_SECRET, // also encrypts the in-flight handshake state
    plugins: [
        opaque({
            OPAQUE_SERVER_KEY: process.env.OPAQUE_SERVER_KEY,

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

All options:

| Option | Default | Purpose |
| :-- | :-- | :-- |
| `OPAQUE_SERVER_KEY` | required in production | The server setup from `create-server-setup`. |
| `sendResetPassword` | none | Delivers the reset email. `url` goes through the plugin's redirect endpoint and lands on `redirectTo?token=...`. |
| `resetPasswordTokenExpiresIn` | `3600` | Reset token lifetime in seconds. |
| `onExistingUserSignUp` | none | Called when a sign-up targets an existing email. The HTTP response is identical either way. |
| `requireEmailVerification` | `emailAndPassword.requireEmailVerification` | Block sign-in until the email is verified. Verification emails are sent on sign-up when `emailVerification.sendOnSignUp` or this is set. |
| `challengeExpiresIn` | `120` | Seconds a challenge stays valid between the two steps. Each one can be completed exactly once. |
| `timingSafeResponseMs` | off | Minimum response time for the three endpoints whose work depends on whether an account exists. See [Security](#security). |
| `insecureCreateSessionOnRegister` | `false` | Issue a session straight from sign-up. Makes sign-up an account-existence oracle. |

`sendResetPassword`, `onExistingUserSignUp` and Better Auth's `sendVerificationEmail` run through Better Auth's background-task runner: detached when `advanced.backgroundTasks` is configured, awaited otherwise. An error thrown by any of them is logged and never returned to the client, because a 500 that only happens when the account exists would be an enumeration oracle. Watch your logs for mailer failures.

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

`better-auth-opaque/client` contains only client code. The root import also works, and `better-auth-opaque/server` exposes only the server plugin.

## Usage

Every action returns `{ data, error }` like the rest of the Better Auth client, accepts an optional second `fetchOptions` argument (`headers`, `query`, `signal`, `onSuccess`, `onError`, ... applied to every request of the flow), and refreshes `useSession` when the session changes.

### Sign up

```typescript
const { data, error } = await authClient.signUp.opaque({
    email,
    password,
    name: "Ada",
    // image, callbackURL and any user.additionalFields are accepted too
});
// data.status      -> true (also when the email already exists; see Security)
// data.token       -> null unless insecureCreateSessionOnRegister is on
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
// data.token, data.user   -> same shape as signIn.email
// data.exportKey          -> same value signUp.opaque returned
// data.sessionKey         -> fresh per login, shared with the server, not stored by it
```

A wrong password is detected on the client: the handshake fails locally and no proof is ever sent, so the server only ever sees challenge requests.

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

Requires a fresh session (Better Auth's sensitive-session rule). The current password is proven with a full OPAQUE login before anything changes.

### Set a password on an account that has none

```typescript
// Signed in through Google/GitHub/magic link and wants a password too
const { data, error } = await authClient.opaque.setPassword({ password });
// error.code === "OPAQUE_ACCOUNT_EXISTS" if one is already set
```

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

The export key is the reason to use OPAQUE over bcrypt. It is a 64-byte secret, stable for a given password, that only the client ever holds. A typical pattern:

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

### Error codes

Every failure carries a `code`. The plugin's codes are available as `OPAQUE_ERROR_CODES` from the package and are inferred onto `authClient.$ERROR_CODES` for typing.

| Code | Meaning |
| :-- | :-- |
| `INVALID_EMAIL_OR_PASSWORD` | Wrong password, or no account with that email. |
| `INVALID_PASSWORD` | Wrong current password during a change. |
| `EMAIL_NOT_VERIFIED` | Sign-in blocked until the email is verified. |
| `INVALID_LOGIN_STATE` | The challenge expired, was already used, or belongs to another flow. Start over. |
| `INVALID_TOKEN` | Reset token unknown, expired or already used. |
| `NO_OPAQUE_ACCOUNT` | The signed-in user has no OPAQUE password. Use `setPassword`. |
| `OPAQUE_ACCOUNT_EXISTS` | `setPassword` on an account that already has one. Use `changePassword`. |
| `SERVER_KEY_MISMATCH` | The server's key does not match the pinned `serverPublicKey`. |
| `INVALID_REGISTRATION_RECORD` | The client sent a record the server could not use. |
| `RESET_PASSWORD_NOT_CONFIGURED` | `sendResetPassword` is missing from the plugin options. |

## Endpoints

All endpoints live under `/api/auth/opaque/` and are rate limited to 5 requests per 10 seconds per IP and path. The two-step flows are driven by the client plugin; call them directly only if you are writing your own client.

| Flow | Method | Path | Auth |
| :-- | :-- | :-- | :-- |
| Sign up | `POST` | `/opaque/sign-up/challenge` | none |
| Sign up | `POST` | `/opaque/sign-up/complete` | none |
| Sign in | `POST` | `/opaque/sign-in/challenge` | none |
| Sign in | `POST` | `/opaque/sign-in/complete` | none |
| Change password | `POST` | `/opaque/change-password/challenge` | fresh session |
| Change password | `POST` | `/opaque/change-password/complete` | fresh session |
| Set password | `POST` | `/opaque/set-password/challenge` | fresh session |
| Set password | `POST` | `/opaque/set-password/complete` | fresh session |
| Reset password | `POST` | `/opaque/reset-password/request` | none |
| Reset password | `GET` | `/opaque/reset-password/:token` | none (redirects to `callbackURL?token=`) |
| Reset password | `POST` | `/opaque/reset-password/challenge` | reset token |
| Reset password | `POST` | `/opaque/reset-password/complete` | reset token |

The `state` value each challenge returns is an encrypted, purpose-bound, single-use blob. The complete step must present it within `challengeExpiresIn` seconds. Each challenge also writes one row to Better Auth's `verification` table, which the complete step consumes; rows for abandoned challenges are purged with Better Auth's normal expired-verification cleanup.

## Security

**What OPAQUE gives you.** Passwords are never transmitted or stored. A database breach yields registration records that cannot be brute-forced offline without also stealing `OPAQUE_SERVER_KEY`, and even then each guess costs a full Argon2 evaluation. The server cannot be tricked into revealing anything about the password by a malicious client.

**What it does not give you.** Online guessing is still possible. Each guess costs the attacker one challenge request plus client-side Argon2, and the plugin rate limits every endpoint, but there is no per-account lockout. A wrong password is decided on the client, so the server never observes failed attempts; add a CAPTCHA or per-email throttle in front of the sign-in challenge if that matters for you.

**Account enumeration.** The sign-in challenge for an unknown email is computed under a fake record with a deterministic credential id, performs the same database queries as the real path, and returns a response of identical shape and size. Sign-up and reset-password requests respond identically for known and unknown emails. This only holds if the rest of your configuration does too: Better Auth's own `/sign-up/email` reveals existing emails by default, so either keep `emailAndPassword` disabled or configure it to respond generically. Debug logs never include the email or whether it exists.

**Timing.** The matched-work design keeps the real and fake branches within tens of microseconds of each other, well under network jitter, which is the same approach Better Auth core takes for `/sign-in/email`. If your write path is much slower than your read path you can additionally set `timingSafeResponseMs` to pad the sign-in challenge, sign-up completion and reset request to a floor. Set it to roughly 2 to 3 times your p99 handler time. It is a backstop, not constant time: a request that overruns the floor leaks its real duration.

**Handshake state.** The state blob handed to the client between the two steps is encrypted with the Better Auth secret, padded to a fixed size, bound to its purpose (sign-in state cannot complete a password change), expires after `challengeExpiresIn` seconds, and can be completed exactly once. Consumption is atomic (Better Auth's `consumeVerificationValue`), so concurrent requests carrying the same state, or the same reset token, cannot both succeed. A challenge minted before a password change cannot complete after it.

**Email changes.** Records are bound to a server-generated credential id, not the email, so `changeEmail` and case differences in the typed email do not lock anyone out.

**Two-factor.** The Better Auth `twoFactor` plugin hooks only the core sign-in routes, so an OPAQUE sign-in currently completes without the second factor. If you need both, enforce the second factor in your own `databaseHooks.session.create.before` or in front of the session.

**Core password routes.** With `emailAndPassword` enabled, Better Auth's `/reset-password` and `/set-password` create a server-side hashed credential next to the OPAQUE record. The plugin warns about this at startup. Use `opaque.requestPasswordReset` and `opaque.setPassword` instead.

**Key handling.** The server key is validated at startup and is never logged. The client can pin the corresponding public key with `opaqueClient({ serverPublicKey })`; the server proves possession of it in every handshake.

## Upgrading from 2.x

3.0.0 is a breaking release. Most apps only need to upgrade `better-auth`, rerun migrations and rename `changePassword`.

* **`better-auth` 1.7 or newer is required.** The plugin now declares it as a peer dependency instead of bundling its own copy, which also fixes the `Types of property 'getActions' are incompatible` / `Property 'opaque' does not exist` errors apps hit when their `better-auth` and the plugin's copy diverged. If those persist, run `npm ls better-auth @better-fetch/fetch` and dedupe.
* **New `account.credentialId` column.** Run your migration. Records written by 2.x keep working through a fallback, except that 2.x bound records to the exact email casing typed at sign-up: users who registered with mixed-case emails under 2.x must reset their password.
* **`authClient.changePassword` is now `authClient.opaque.changePassword`.** The old name refers to Better Auth's built-in action.
* **Endpoints moved** from `/sign-up/opaque/*`, `/sign-in/opaque/*` and `/opaque/changePassword/*` to `/opaque/sign-up/*`, `/opaque/sign-in/*` and `/opaque/change-password/*`. Only custom clients are affected.
* **Response shapes** now match core: sign-in and change-password return `{ token, user }`, sign-up returns `{ status, token }`. The client adds `exportKey`, `sessionKey`, `previousExportKey` and `serverPublicKey` where they apply.
* **`dontRememberMe` is now `rememberMe`**, same semantics as `signIn.email`.
* **The timing floor is off by default.** 2.x padded every endpoint to 250 ms. Set `timingSafeResponseMs` explicitly if you want it back.
* **Challenges expire after 2 minutes and are single-use** (2.x: 15 minutes, replayable).
* **Email verification is honoured.** If `requireEmailVerification` is set, unverified users can no longer sign in with OPAQUE.
* `OPAQUE_SERVER_KEY` is required when `NODE_ENV=production`.

## Development

```bash
bun install
bun run typecheck    # tsc over src/ and tests/ (the type-level tests only bite here)
bun run build        # tsc -> dist/
bun run test         # vitest on better-auth's HTTP test instance, run under bun
bun run check        # all three, which is also what CI and prepublishOnly run
bun run test:timing  # opt-in statistical timing tests (slow)
bun run test:server  # manual Express server on :8080
```

Tests use `better-auth/test`, which needs `node:sqlite` with `StatementSync.columns()`. That ships in Bun and in Node 22.16+/23.11+; `bun run test:node` runs the suite on plain Node if yours is new enough.

Releases: publishing a GitHub release runs the `release` workflow, which re-runs `bun run check` and publishes to npm with provenance. It needs an npm automation token in the `NPM_TOKEN` repository secret.

## License

MIT
