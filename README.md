# Better Auth OPAQUE

[![npm version](https://img.shields.io/npm/v/better-auth-opaque.svg)](https://www.npmjs.com/package/better-auth-opaque)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Better Auth plugin that implements **zero-knowledge password authentication** using the **OPAQUE** protocol.

With this plugin the server **never** sees, stores or handles a user's raw password, so even a full database breach does not expose passwords.

> **Upgrading from 2.x?** Version 3.0 has breaking changes, and some users may need to reset their password. Read [Migrating to 3.0](#9-migrating-to-30-breaking-changes) before you deploy.

## Key Features

* **Zero-Knowledge:** The password never leaves the client. The server stores only an OPAQUE registration record, which it cannot decrypt.
* **Post-Breach Security:** An attacker who steals your whole database still cannot crack passwords offline.
* **Complete password lifecycle:** Sign up, sign in (with "remember me"), change password (with session rotation), forgot/reset password by emailed **link** or one-time **code**, and "set a password" for users who signed up another way (for example with a social provider).
* **Email verification:** Works with Better Auth's core `emailVerification` (send on sign-up or sign-in, and block unverified logins).
* **User enumeration protection:** Unknown emails get the same responses as real ones. Login uses a dummy registration record, so failed logins for unknown users look the same as wrong passwords.
* **Hardened protocol state:** Challenges are encrypted, single-use, expire after 15 minutes, and are bound to one user and one purpose. Malformed client input returns a 4xx error, never a 500.
* **Typed client:** Every action returns `{ data, error }`, and errors carry a stable `code`.

## How It Works

OPAQUE is an asymmetric password-authenticated key exchange (aPAKE). There is no password hash to check. Instead, the client and server run an interactive cryptographic handshake, which is why every flow below takes two requests (a *challenge* and a *complete*).

1. **Registration**
    * The client derives a `registrationRequest` from the password and sends it with the email.
    * The server replies with a challenge, computed with its secret `OPAQUE_SERVER_KEY` and the (lower-cased) email.
    * The client uses the password and the challenge to build a `registrationRecord`, which holds the user's credentials in a form only the password can unlock.
    * The server stores this record on an `account` row with `providerId: "opaque"`. It **cannot** decrypt it.

2. **Login**
    * The client sends a `loginRequest`. The server loads the stored record (or a dummy one if the user doesn't exist) and replies with a challenge and an encrypted, single-use `state`.
    * Only a client that knows the password can finish the handshake. It sends back a `loginResult`, the server verifies it, and a Better Auth session is created.

3. **Change, reset and set password** reuse the same building blocks. Change password runs a login with the current password and a registration with the new one in a single exchange. Reset and set password run a registration, authorised by an emailed link or code (reset) or by a fresh session (set password).

## 1. Installation

```bash
# Using Bun
bun add better-auth-opaque @serenity-kit/opaque

# Using NPM
npm install better-auth-opaque @serenity-kit/opaque

# Using Yarn
yarn add better-auth-opaque @serenity-kit/opaque
```

Peer dependencies: **`better-auth` ^1.7** and **`zod` ^4**. `@serenity-kit/opaque` is the OPAQUE implementation that runs on both the server and the client.

The package has three entry points:

| Import                        | Contents                                                                                            |
| :---------------------------- | :-------------------------------------------------------------------------------------------------- |
| `better-auth-opaque/server`   | `opaque` (server plugin), `OPAQUE_ERROR_CODES`, `OpaqueOptions` type                                |
| `better-auth-opaque/client`   | `opaqueClient` (client plugin), `OPAQUE_ERROR_CODES`, client types. Contains no server code.        |
| `better-auth-opaque`          | Everything above. Kept for backwards compatibility.                                                 |

In browser code, import from `better-auth-opaque/client` so the bundle doesn't include server code.

## 2. Setup & Configuration

### 2.1 Generate the OPAQUE server key

The plugin needs a secret, **stable** OPAQUE server setup. Generate one (a 171-character base64url string encoding 128 bytes):

```bash
npx @serenity-kit/opaque@latest create-server-setup
```

```env
# .env
OPAQUE_SERVER_KEY="your-generated-server-setup"
```

Keep this key secret and never change it. **Changing it makes every registered password stop working.**

If `OPAQUE_SERVER_KEY` is **not provided** (`undefined`):

* In development, the plugin generates a random key at startup and logs a warning. Every password registered with it stops working when the process restarts.
* When `NODE_ENV === "production"`, the plugin **throws at startup**.

A key that *is* provided but malformed (not base64url, or not 128 bytes) throws when `opaque()` is called. A key that fails OPAQUE's own validation throws during Better Auth initialisation. An empty string counts as provided and malformed, so an empty `OPAQUE_SERVER_KEY=` in your environment throws.

### 2.2 Server plugin

```typescript
// src/lib/auth.ts
import { betterAuth } from "better-auth";
import { opaque } from "better-auth-opaque/server";

export const auth = betterAuth({
    // Better Auth's secret also encrypts OPAQUE challenge state and keys the
    // reset-token / reset-code hashes.
    secret: process.env.BETTER_AUTH_SECRET,
    database: /* your adapter */,
    plugins: [
        opaque({
            OPAQUE_SERVER_KEY: process.env.OPAQUE_SERVER_KEY,
            // Optional: enable forgot/reset password (see section 4)
            sendResetPassword: async ({ user, url, token }, request) => {
                await sendEmail(user.email, "Reset your password", url);
            },
        }),
    ],
});
```

### 2.3 Client plugin

```typescript
// src/lib/auth-client.ts
import { createAuthClient } from "better-auth/client"; // or "better-auth/react", etc.
import { opaqueClient } from "better-auth-opaque/client";

export const authClient = createAuthClient({
    plugins: [opaqueClient()],
});
```

### 2.4 Database schema

The plugin adds one optional, unique field to Better Auth's `account` table: `registrationRecord` (string). Run Better Auth's CLI (`npx @better-auth/cli generate` or `migrate`) after adding the plugin. Challenge nonces, reset tokens and reset codes are stored in core's `verification` table.

### 2.5 Plugin options

All options are optional. The options type is exported as `OpaqueOptions` (from `better-auth-opaque/server` or the package root).

| Option                              | Type                                                                          | Default                                                  | Purpose |
| :---------------------------------- | :---------------------------------------------------------------------------- | :------------------------------------------------------- | :------ |
| `OPAQUE_SERVER_KEY`                 | `string`                                                                      | Random development key. Throws in production.            | OPAQUE server setup (see 2.1). |
| `insecureCreateSessionOnRegister`   | `boolean`                                                                     | `false`                                                  | Sign the user in (session and cookie) when a **new** user registers. **Skipped when email verification is required** (see `requireEmailVerification`). This weakens enumeration protection, because only a new registration gets a session cookie, so the plugin logs a warning when it is on. |
| `rateLimit`                         | `{ window?: number; max?: number }`                                           | `{ window: 10, max: 3 }`                                 | Per-IP, per-path limit (window in seconds) for every OPAQUE endpoint. `/opaque/forget-password` uses `window ?? 60` and `max ?? 3`. See [Rate limits](#rate-limits). |
| `sendResetPassword`                 | `(data: { user: User; url: string; token: string }, request?: Request) => void \| Promise<void>` | not set (reset links disabled)            | Enables password reset by emailed **link**. Called only for existing users. |
| `sendResetPasswordOTP`              | `(data: { user: User; otp: string }, request?: Request) => void \| Promise<void>` | not set (reset codes disabled)                       | Enables password reset by emailed one-time **code**. Called only for existing users. |
| `resetPasswordTokenExpiresIn`       | `number` (seconds)                                                            | `3600`                                                   | Lifetime of a reset link token. |
| `resetPasswordOTP.expiresIn`        | `number` (seconds)                                                            | `300`                                                    | Lifetime of a reset code. |
| `resetPasswordOTP.length`           | `number`                                                                      | `6`                                                      | Number of digits in a reset code. |
| `resetPasswordOTP.allowedAttempts`  | `number`                                                                      | `3`                                                      | Wrong guesses allowed, counting the challenge and complete steps together, before the code is locked. |
| `requireEmailVerification`          | `boolean`                                                                     | core's `emailAndPassword.requireEmailVerification`, else `false` | Refuse OPAQUE login with `403 EMAIL_NOT_VERIFIED` until the email is verified. When set, it **takes precedence** over core's `emailAndPassword.requireEmailVerification`, in either direction. |

## 3. Client Usage

Every action is `async` and **never throws for server or credential errors**. It resolves to:

```typescript
type OpaqueClientResult<T> =
    | { data: T; error: null }
    | { data: null; error: { status: number; statusText: string; code?: string; message?: string } };
```

`error.status` is the HTTP status of whichever step failed, and `error.code` / `error.message` come from the server (see [Error codes](#7-error-codes)). When the client itself detects a wrong password (the OPAQUE handshake can't be completed locally), it returns exactly the error the server would have returned.

Compare `error.code` against the codes exposed on the client:

```typescript
const { data, error } = await authClient.signIn.opaque({ email, password });
if (error) {
    if (error.code === authClient.$ERROR_CODES.INVALID_EMAIL_OR_PASSWORD.code) {
        showMessage("Wrong email or password");
    } else if (error.code === authClient.$ERROR_CODES.EMAIL_NOT_VERIFIED.code) {
        showMessage("Please verify your email first");
    } else {
        showMessage(error.message ?? "Something went wrong");
    }
}
```

`OPAQUE_ERROR_CODES` can also be imported directly from `better-auth-opaque/client`.

**Fetch options.** Every action takes Better Auth fetch options as an optional **second argument** (or as `fetchOptions` inside the first). Transport options (`headers`, `signal`, `credentials`, `onRequest`, `onResponse`, ...) apply to every request the action sends. `onSuccess` fires once, for the final response. `onError` fires once, for whichever step failed. `body`, `method`, `params`, `output` and `throw` are ignored. Set `disableSignal: true` to stop the action from refreshing `useSession`.

```typescript
await authClient.signIn.opaque(
    { email, password },
    {
        headers: { "x-request-id": id },
        onSuccess: () => router.push("/dashboard"),
        onError: (ctx) => console.warn(ctx.error),
    },
);
```

### `signUp.opaque`

Registers a user. **No session is created** (unless `insecureCreateSessionOnRegister` is on), so sign the user in afterwards if you want them logged in. An already-registered email gets the **same** successful result and nothing is changed, which prevents enumeration.

```typescript
const { data, error } = await authClient.signUp.opaque({
    email: "alice@example.com",
    password: "correct horse battery staple",
    name: "Alice", // 1 to 100 characters
});
// data: { success: true, message: "User registered successfully" }  (HTTP 201)
```

Emails are lower-cased before use, so `Alice@Example.com` and `alice@example.com` are the same user.

### `signIn.opaque`

Logs in and sets the session cookies. Set `rememberMe: false` to get a browser-session cookie (the default is `true`).

```typescript
const { data, error } = await authClient.signIn.opaque({
    email: "alice@example.com",
    password: "correct horse battery staple",
    rememberMe: false,
});
// data: { token: string, success: true, user: { id: string } }
// error (wrong password OR unknown email): { status: 401, code: "INVALID_EMAIL_OR_PASSWORD", ... }
// error (unverified email, if required):   { status: 403, code: "EMAIL_NOT_VERIFIED", ... }
```

### `opaque.changePassword`

Requires a signed-in user who has an OPAQUE password. Proves the current password and registers the new one in a single exchange. On success, the calling session is **rotated**: the old session token is deleted and a new one is set in fresh cookies, keeping the caller's "remember me" choice. By default every other session of the user is revoked too.

```typescript
const { data, error } = await authClient.opaque.changePassword({
    currentPassword: "old password",
    newPassword: "new password",
    revokeOtherSessions: false, // default true
});
// data: { success: true, message: "Password changed successfully" }
// error: { status: 401, code: "INVALID_CURRENT_PASSWORD", ... }
```

### `opaque.forgetPassword`

Asks for a reset link or code by email. It resolves the same way (`{ status: true, message }`) whether or not the email belongs to a user. `method` defaults to `"link"` if `sendResetPassword` is configured, otherwise `"otp"`. `redirectTo` (links only) is where the emailed link finally lands, and must be a relative path or a trusted origin.

```typescript
// Link
await authClient.opaque.forgetPassword({ email, method: "link", redirectTo: "/reset-password" });

// One-time code
await authClient.opaque.forgetPassword({ email, method: "otp" });
// error if that method isn't configured: { status: 400, code: "RESET_PASSWORD_METHOD_NOT_CONFIGURED" }
```

### `opaque.resetPassword`

Sets a new password using **either** a link token **or** the email plus the code. On success the user's OPAQUE password is replaced (or created, if the user had none), the email is marked verified, and **every session of the user is revoked**. No new session is created, so the user signs in again with the new password.

```typescript
// From a reset link
const { data, error } = await authClient.opaque.resetPassword({
    token,
    newPassword: "new password",
});

// From an emailed code
const { data, error } = await authClient.opaque.resetPassword({
    email: "alice@example.com",
    otp: "123456",
    newPassword: "new password",
});
// data: { status: true }
// error: { status: 400, code: "INVALID_TOKEN" | "TOO_MANY_ATTEMPTS", ... }
```

### `opaque.setPassword`

Adds an OPAQUE password for a signed-in user who **doesn't have one yet**, such as a user who signed up with a social provider or core email and password. It requires a **fresh** session: one created within Better Auth's `session.freshAge` (default 24 hours). Otherwise it fails with `403 SESSION_NOT_FRESH`, and the user has to sign in again. The session and cookies are left unchanged. Users who already have an OPAQUE password must use `changePassword` instead.

```typescript
const { data, error } = await authClient.opaque.setPassword({ newPassword: "new password" });
// data: { status: true }
// error: { status: 400, code: "OPAQUE_ACCOUNT_ALREADY_EXISTS" } | { status: 401 } | { status: 403, code: "SESSION_NOT_FRESH" }
```

### React example

```tsx
import { useState } from "react";
import { authClient } from "@/lib/auth-client";

export function AuthForm() {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [message, setMessage] = useState<string | null>(null);

    const register = async () => {
        const { error } = await authClient.signUp.opaque({ email, password, name: "New user" });
        if (error) return setMessage(error.message ?? "Registration failed");
        // Registration does not sign the user in; do it explicitly.
        await login();
    };

    const login = async () => {
        const { error } = await authClient.signIn.opaque({ email, password });
        setMessage(error ? (error.message ?? "Login failed") : "Signed in");
    };

    return (
        <div>
            {/* ... inputs bound to email / password ... */}
            <button onClick={register}>Register</button>
            <button onClick={login}>Login</button>
            {message && <p>{message}</p>}
        </div>
    );
}
```

## 4. Password Reset

Reset is enabled by configuring `sendResetPassword` (link), `sendResetPasswordOTP` (code), or both. If neither is configured, `forgetPassword` fails with `400 RESET_PASSWORD_METHOD_NOT_CONFIGURED`. Both callbacks are called **only for existing users**, including users who have no OPAQUE password yet, so they can create one. They are never called for unknown emails, and the response is identical either way.

Reset also works for users whose email is not verified, and a successful reset marks the email as verified, because using the emailed link or code proves control of the mailbox.

The callbacks are awaited unless you configure Better Auth's `advanced.backgroundTasks.handler`. An error thrown by a callback is logged, and the endpoint still responds normally.

### Link flow

```typescript
opaque({
    OPAQUE_SERVER_KEY: process.env.OPAQUE_SERVER_KEY,
    resetPasswordTokenExpiresIn: 60 * 60, // seconds, default 3600
    sendResetPassword: async ({ user, url, token }, request) => {
        await sendEmail(user.email, "Reset your password", `Click here: ${url}`);
    },
});
```

1. The client calls `authClient.opaque.forgetPassword({ email, redirectTo: "/reset-password" })`.
2. `sendResetPassword` receives the `user`, the raw `token` and a `url` of the form

   ```
   {baseURL}/opaque/reset-password/{token}?callbackURL={encodeURIComponent(redirectTo || "/")}
   ```

   where `baseURL` includes Better Auth's base path, for example `https://app.example.com/api/auth`.
3. The user opens the link. `GET /opaque/reset-password/:token` checks the token **without consuming it**, then redirects (302) to `callbackURL?token={token}`, or to `callbackURL?error=INVALID_TOKEN` if the token is unknown or expired. A relative `callbackURL` resolves against your `baseURL` origin.
4. Your reset page reads the query string and calls `resetPassword`:

   ```typescript
   // /reset-password page
   const params = new URLSearchParams(window.location.search);
   const token = params.get("token");
   if (!token || params.get("error")) {
       showMessage("This reset link is invalid or has expired.");
   } else {
       const { error } = await authClient.opaque.resetPassword({ token, newPassword });
       if (!error) router.push("/sign-in");
   }
   ```

You can also skip `url` and put `token` into a link of your own that points straight at your reset page.

Token rules:

* Tokens are 32 random alphanumeric characters. They are stored only as an HMAC keyed with Better Auth's `secret`, so a leaked `verification` table does not yield working links.
* A token is consumed by a successful `resetPassword`. The challenge step and the GET redirect don't consume it, so a failed attempt can be retried.
* Each request issues a new token. Earlier tokens are **not** invalidated and stay valid until they are used or expire.
* OPAQUE reset tokens are in a separate namespace from core's `/reset-password`, so core cannot accept or consume them.
* `redirectTo` / `callbackURL` must be relative or on a trusted origin. Otherwise the request fails with `403` (`INVALID_REDIRECT_URL` on `forget-password`, `INVALID_CALLBACK_URL` on the GET link).

### Code (OTP) flow

```typescript
opaque({
    OPAQUE_SERVER_KEY: process.env.OPAQUE_SERVER_KEY,
    resetPasswordOTP: { expiresIn: 300, length: 6, allowedAttempts: 3 }, // the defaults
    sendResetPasswordOTP: async ({ user, otp }, request) => {
        await sendEmail(user.email, "Your password reset code", `Your code is ${otp}`);
    },
});
```

1. The client calls `authClient.opaque.forgetPassword({ email, method: "otp" })`.
2. `sendResetPasswordOTP` receives the `user` and the `otp`, a string of `length` digits.
3. The user types the code, and the client calls `authClient.opaque.resetPassword({ email, otp, newPassword })`.

Code rules:

* **One live code per email.** Requesting a new code deletes the previous one and starts a new attempt budget.
* **Expiry:** a code is valid for `expiresIn` seconds (default 300).
* **Attempt limit:** wrong codes count against `allowedAttempts` (default 3), across the challenge and complete steps together. Once the limit is reached, the next try, even with the correct code, fails with `400 TOO_MANY_ATTEMPTS` and the code is deleted, so later tries get `INVALID_TOKEN`. The user must request a new code.
* **Hashed at rest:** only an HMAC of the code, keyed with Better Auth's `secret` and bound to the email, is stored. A code issued for one email can't reset another.
* The code is consumed by a successful `resetPassword`. A malformed request (for example a bad `registrationRecord`) neither consumes it nor counts as an attempt.

### Offering both

Configure both callbacks and let the user choose. When `method` is omitted, `"link"` is used.

```typescript
// server
opaque({ OPAQUE_SERVER_KEY, sendResetPassword, sendResetPasswordOTP });

// client
const method = userPrefersCode ? "otp" : "link";
await authClient.opaque.forgetPassword({ email, method, redirectTo: "/reset-password" });

// then either
await authClient.opaque.resetPassword({ token, newPassword });      // from the link page
await authClient.opaque.resetPassword({ email, otp, newPassword }); // from the code form
```

A request must contain **exactly one** credential, either `token` or `email` + `otp`. Anything else fails with `400 INVALID_TOKEN`.

## 5. Email Verification

The plugin uses Better Auth's core `emailVerification` configuration and sends the same verification email as core's `/sign-up/email` and `/sign-in/email`: a link to core's `GET /verify-email`.

```typescript
betterAuth({
    emailVerification: {
        sendOnSignUp: true,
        sendOnSignIn: true,
        sendVerificationEmail: async ({ user, url, token }, request) => {
            await sendEmail(user.email, "Verify your email", url);
        },
    },
    plugins: [
        opaque({
            OPAQUE_SERVER_KEY: process.env.OPAQUE_SERVER_KEY,
            requireEmailVerification: true,
        }),
    ],
});
```

* **On sign-up**, a verification email is sent if `emailVerification.sendOnSignUp` is true. If `sendOnSignUp` is unset, it falls back to whether verification is required. It is sent only when a **new** user is created, never for an already-registered email.
* **On sign-in**, when verification is required (plugin `requireEmailVerification`, or else core's `emailAndPassword.requireEmailVerification`), an unverified user with the **correct** password gets `403 EMAIL_NOT_VERIFIED` and no session. If `emailVerification.sendOnSignIn` is true, the verification email is sent again. A wrong password always gets the usual `401 INVALID_EMAIL_OR_PASSWORD` and sends nothing, so the password is checked first.
* Nothing is sent if `sendVerificationEmail` is not configured.
* The verification link lands on `/` by default. The raw `/sign-up/opaque/complete` and `/sign-in/opaque/complete` endpoints accept an optional `callbackURL` body field, but the client actions don't send one.
* A successful **password reset** marks the email as verified.
* Change password, set password and reset password work for unverified users.
* `insecureCreateSessionOnRegister` never creates a session while verification is required.

## 6. API Endpoints Reference

Paths are relative to Better Auth's base path (default `/api/auth`). All POST endpoints go through Better Auth's origin/CSRF checks, so browser requests must come from a trusted origin.

| Flow            | Method | Path                                  | Auth required                               | Purpose |
| :-------------- | :----- | :------------------------------------ | :------------------------------------------ | :------ |
| Register        | `POST` | `/sign-up/opaque/challenge`           | none                                        | Takes `{ email, registrationRequest }` and returns `{ challenge }`. |
| Register        | `POST` | `/sign-up/opaque/complete`            | none                                        | Takes `{ email, name, registrationRecord, callbackURL? }`. Creates the user and OPAQUE account (only if the email is new). Always returns **201** `{ success: true, message }`. No session by default. |
| Login           | `POST` | `/sign-in/opaque/challenge`           | none                                        | Takes `{ email, loginRequest }` and returns `{ challenge, state }`. |
| Login           | `POST` | `/sign-in/opaque/complete`            | none                                        | Takes `{ loginResult, encryptedServerState, dontRememberMe?, callbackURL? }` (`email` is accepted but ignored). Verifies the proof, creates a session, sets cookies and returns `{ token, success: true, user: { id } }`. |
| Change password | `POST` | `/opaque/changePassword/challenge`    | session (read from the database)            | Takes `{ loginRequest, registrationRequest }` and returns `{ loginChallenge, registrationChallenge, state }`. |
| Change password | `POST` | `/opaque/changePassword/complete`     | session (read from the database)            | Takes `{ loginResult, registrationRecord, encryptedServerState, revokeOtherSessions? }`. Replaces the record, rotates the caller's session and returns `{ success: true, message }`. |
| Forgot password | `POST` | `/opaque/forget-password`             | none                                        | Takes `{ email, method?, redirectTo? }`. Sends a link or code to an existing user. Always returns `{ status: true, message }`. |
| Reset link      | `GET`  | `/opaque/reset-password/:token`       | none (`?callbackURL=` required)             | The emailed link. Redirects to `callbackURL?token=…` or `callbackURL?error=INVALID_TOKEN`. Does not consume the token. |
| Reset password  | `POST` | `/opaque/reset-password/challenge`    | reset credential: `token` or `email` + `otp` | Takes the credential plus `registrationRequest` and returns `{ challenge }`. Does not consume the credential. |
| Reset password  | `POST` | `/opaque/reset-password/complete`     | reset credential: `token` or `email` + `otp` | Takes the credential plus `registrationRecord`. Consumes the credential, sets the password, marks the email verified, revokes all sessions and returns `{ status: true }`. |
| Set password    | `POST` | `/opaque/setPassword/challenge`       | **fresh** session (read from the database)  | Takes `{ registrationRequest }` and returns `{ challenge }`. Reserves the single set-password slot (valid 15 minutes). |
| Set password    | `POST` | `/opaque/setPassword/complete`        | **fresh** session (read from the database)  | Takes `{ registrationRecord }`. Creates the OPAQUE account and returns `{ status: true }`. The session is unchanged. |

"Read from the database" means the session is checked against the database or secondary storage, not trusted from the cookie cache (see [Security](#the-cookie-cache-caveat)). Missing or revoked sessions get `401`, and sessions that aren't fresh get `403 SESSION_NOT_FRESH`.

## 7. Error Codes

Errors use Better Auth's `{ code, message }` body. The codes below are exported as `OPAQUE_ERROR_CODES` and are available on `authClient.$ERROR_CODES`. Core Better Auth errors can also occur: `401 UNAUTHORIZED` (no session), `403 SESSION_NOT_FRESH`, `403 INVALID_ORIGIN` / `INVALID_REDIRECT_URL` / `INVALID_CALLBACK_URL`, `400 VALIDATION_ERROR` (a body that fails schema validation, such as an invalid email or a `name` longer than 100 characters) and `429` (rate limit).

| Code                                   | Status | When |
| :------------------------------------- | :----- | :--- |
| `INVALID_EMAIL_OR_PASSWORD`            | 401    | Login: wrong password, unknown email, user without an OPAQUE password, or a replayed or unknown challenge. Deliberately the same in every case. |
| `INVALID_CURRENT_PASSWORD`             | 401    | Change password: the current password didn't verify, or the challenge was replayed or belongs to another user. |
| `INVALID_REGISTRATION_REQUEST`         | 400    | A `registrationRequest` is not 32 bytes or can't be deserialised (sign-up, change, reset or set password challenge). |
| `INVALID_REGISTRATION_RECORD`          | 400    | A `registrationRecord` is not 170 to 200 bytes or can't be deserialised (sign-up, change, reset or set password complete). |
| `INVALID_LOGIN_REQUEST`                | 400    | A `loginRequest` is not 96 bytes or can't be deserialised (login or change password challenge). |
| `INVALID_LOGIN_RESULT`                 | 400    | A `loginResult` is not 64 bytes or can't be deserialised (login or change password complete). |
| `INVALID_LOGIN_STATE`                  | 400    | `encryptedServerState` was tampered with, can't be decrypted, or was issued for the other flow (a login state sent to change password, or the reverse). |
| `LOGIN_STATE_EXPIRED`                  | 400    | `encryptedServerState` is older than 15 minutes. |
| `OPAQUE_ACCOUNT_NOT_FOUND`             | 400    | Change password complete for a user without an OPAQUE password. The client usually reports `INVALID_CURRENT_PASSWORD` first, because such a user can't complete the handshake. Use `setPassword` for them. |
| `FAILED_TO_CREATE_SESSION`             | 500    | The database adapter did not return a session after login or a password change. |
| `INVALID_TOKEN`                        | 400    | Reset: unknown, expired or already-used link token or code, a wrong code, a code for a different email, or not exactly one credential (`token` **or** `email` + `otp`). |
| `TOO_MANY_ATTEMPTS`                    | 400    | Reset: the code was guessed wrong `allowedAttempts` times. Request a new code. |
| `RESET_PASSWORD_METHOD_NOT_CONFIGURED` | 400    | Forgot password: the requested `method` (or, with no `method`, both methods) has no callback configured. Returned for any email. |
| `OPAQUE_ACCOUNT_ALREADY_EXISTS`        | 400    | Set password: the user already has an OPAQUE password (use change password). Also returned when `complete` is called without a valid pending challenge, or loses a race with another `complete`. |
| `EMAIL_NOT_VERIFIED`                   | 403    | Login: the password is correct but the email is not verified and verification is required. |

## 8. Security Considerations

### Keys and secrets

* **`OPAQUE_SERVER_KEY`** must stay secret and stable. Treat it like a database password and never commit it. Changing it makes every registered password stop working.
* **Better Auth's `secret`** encrypts the challenge state and keys the stored hashes of reset tokens and codes. Rotating it doesn't affect passwords, but it invalidates in-flight challenges and outstanding reset links and codes.

### User enumeration

* **Login**: the challenge step always builds a dummy registration record and does the same work (one user lookup, one nonce write) whether or not the user exists or has an OPAQUE password. Challenges for unknown users have the same shape and length as real ones, and completing one fails with the same `401 INVALID_EMAIL_OR_PASSWORD` as a wrong password. Stored records that can't be deserialised are treated the same way instead of causing a 500.
* **Change password** also uses a dummy record when the session user has no OPAQUE password.
* **Sign-up** returns the same `201` body for new and existing emails and never overwrites an existing user, record or name. **Forgot password** returns the same body for known and unknown emails and sends nothing for unknown ones. The *bodies* are identical, but timing is not fully equalised: a new sign-up writes to the database, and a known email triggers your email callback. Use `advanced.backgroundTasks.handler` so email sending doesn't delay the response.
* `insecureCreateSessionOnRegister` defeats sign-up enumeration protection. Leave it off unless you accept that.

### Single-use challenge state

The login and change-password server state goes through the client in encrypted form (Better Auth's `symmetricEncrypt` with your `secret`). It contains only the user id, padded to a fixed block size so its length doesn't depend on the user. Each state:

* is bound to a nonce row in the `verification` table, which is **consumed before** the proof is checked, so a replay or a failed attempt can't be retried with the same state;
* **expires after 15 minutes**, both the nonce row and the timestamp inside the state;
* is bound to a **purpose**, so a login state can't be used to change a password and the reverse;
* for change password, must belong to the session user. This is checked before the nonce is consumed, so another user can't burn it.

### Sessions

* **Password change rotates the session.** The calling session is always deleted and replaced with a new token and new cookies, keeping its "remember me" setting. With `revokeOtherSessions` (the default) every other session of the user is deleted too.
* **Password reset revokes all sessions** of the user and doesn't create a new one. Other outstanding reset links and codes for the user are not invalidated by a successful reset, and expire on their own schedule.
* **Set password** requires a *fresh* session (created within `session.freshAge`, default 24 hours) that is read from the database. A stolen or old session can't attach a permanent password to, for example, a social-only account. Don't set `session.freshAge: 0`, because that disables the freshness check. Only one set-password `complete` can succeed per challenge, and concurrent attempts can't create two OPAQUE accounts.
* Change password and set password read the session from the database, so a revoked session is rejected there even while its cookie cache is still valid.

### The cookie cache caveat

Revoking a session (change password, reset password, or any core revocation) deletes it from the database, but **Better Auth's cookie cache is validated without the database.** With `session.cookieCache.enabled`, the signed `session_data` cookie keeps working for `getSession` / `useSession` and every endpoint that doesn't read the session from the database, **until `cookieCache.maxAge` expires** (default 300 seconds). Better Auth has no per-user way to invalidate these cookies. The plugin logs this at startup when the cookie cache is enabled.

Recommendations:

* Run with a `database` or `secondaryStorage`, so sessions can be revoked at all.
* Disable the cookie cache (`session: { cookieCache: { enabled: false } }`) or keep `cookieCache.maxAge` short.
* For sensitive server-side checks, bypass the cache: `auth.api.getSession({ headers, query: { disableCookieCache: true } })`.

**DB-less (stateless) mode can't revoke sessions at all.** Without `database` or `secondaryStorage`, sessions exist only in cookies and stay valid until they expire, whatever happens to the password. The plugin logs a warning at startup in this mode.

### Rate limits

The plugin registers per-IP, per-path rate limits:

* `/opaque/forget-password`: 3 requests per 60 seconds (`rateLimit.max`, window `rateLimit.window ?? 60`).
* Every other `/sign-in/opaque/*`, `/sign-up/opaque/*` and `/opaque/*` path: 3 requests per 10 seconds (`rateLimit.window`, `rateLimit.max`).

These limits apply only when Better Auth's rate limiter is on (`rateLimit.enabled`, which by default is on only in production). Core `rateLimit.customRules` override them. Reset codes also have their own attempt limit (`resetPasswordOTP.allowedAttempts`). Because the limiter is keyed by client IP, configure `advanced.ipAddress` if you run behind a proxy.

### Input handling

Every OPAQUE message is checked for base64url format and byte length before any cryptographic work, the encrypted state is size-bounded before it is decrypted, and registration records must deserialise before they are stored. Malformed input from a client produces a `400` or `401`, never a `500`.

## 9. Migrating to 3.0 (Breaking Changes)

1. **`authClient.changePassword` is now `authClient.opaque.changePassword`.** The plugin no longer overrides core's top-level `changePassword`, so `authClient.changePassword` now calls core's `/change-password`, which doesn't work for OPAQUE users. Update every call site:

   ```diff
   - await authClient.changePassword({ currentPassword, newPassword });
   + await authClient.opaque.changePassword({ currentPassword, newPassword });
   ```

   The new actions `opaque.forgetPassword`, `opaque.resetPassword` and `opaque.setPassword` are in the same namespace.

2. **`/sign-in/opaque/complete` no longer needs `email`.** The user comes from the encrypted challenge state. `email` is still accepted but ignored. This only matters if you call the endpoint directly.

3. **Errors are now `{ message, code }` with correct statuses.** Wrong credentials are `401` (`INVALID_EMAIL_OR_PASSWORD` / `INVALID_CURRENT_PASSWORD`) and malformed input is `400`, where 2.x often returned `500`. Client errors now include `status` and `code`, and a wrong password detected on the client returns `{ status: 401, code: "INVALID_EMAIL_OR_PASSWORD" }` instead of `{ message: "Login failed" }`. Branch on `error.code`, not on message strings.

4. **Users who registered with a mixed-case email can no longer log in, and must reset their password.** Older versions used the email *exactly as typed* as the OPAQUE user identifier. 3.0 lower-cases it everywhere, and the OPAQUE handshake depends on that identifier. So a user who signed up as `Alice@Example.com` under 2.x **will fail to log in after the upgrade, whatever casing they type**. Their password is not recoverable, and change password doesn't help because it has to verify the old password first. **The only fix is the password reset flow**, which re-registers them under the lower-cased identifier. Before upgrading:
   * configure at least one reset method (`sendResetPassword` and/or `sendResetPasswordOTP`), otherwise these users are locked out;
   * tell users that if login fails after the upgrade, they should use "Forgot password". Better Auth stores emails lower-cased, so you generally can't tell from the database which users typed capitals when they signed up.

5. **A missing `OPAQUE_SERVER_KEY` now throws in production** (`NODE_ENV === "production"`). A malformed key throws at startup in every environment.

6. **Sign-up complete now returns HTTP `201`** instead of `200`. The body is unchanged. Check `res.ok`, or `{ error }` from the client, rather than `status === 200`.

Also new in 3.0, and worth checking before you deploy:

* OPAQUE endpoints are now rate limited (see [Rate limits](#rate-limits)) whenever Better Auth's rate limiter is enabled.
* Challenge state has a new format, so logins or password changes in progress during the deploy fail once with `INVALID_LOGIN_STATE` and have to be retried.
* A successful change password now rotates the caller's session token.
* New entry points `better-auth-opaque/client` and `better-auth-opaque/server`. The root import still works.

## 10. Development

```bash
bun install          # install dependencies
bun run typecheck    # type-check src/ and tests/
bun test             # full test suite: self-contained (in-memory database, no network), about 3 minutes
bun run build        # compile to dist/
```

---

## License

This project is licensed under the MIT License.
