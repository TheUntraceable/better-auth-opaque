# Reference

## Options

| Option | Default | Purpose |
| :-- | :-- | :-- |
| `serverSetup` | required unless `NODE_ENV` is `development` or `test` | The server setup from `create-server-setup`. Without it, development and test generate a per-process key (accounts do not survive a restart); any other environment throws when the plugin initialises. |
| `OPAQUE_SERVER_KEY` | none | Deprecated name for `serverSetup`, read only when `serverSetup` is not set. |
| `sendResetPassword` | none | Delivers the reset email. `url` goes through the plugin's redirect endpoint and lands on `redirectTo?token=...`. |
| `resetPasswordTokenExpiresIn` | `3600` | Reset token lifetime in seconds. |
| `onExistingUserSignUp` | none | Called when a sign-up targets an existing email. The HTTP response is identical either way. |
| `onSessionKey` | none | `({ user, session, sessionKey }, ctx)`, called after a successful sign-in with the server's copy of the session key, the same value the client returns as `sessionKey`. The plugin never stores the key, so this is the only server-side access to it. Not called by the other flows. |
| `requireEmailVerification` | `emailAndPassword.requireEmailVerification` | Block sign-in until the email is verified. Verification emails are sent on sign-up when `emailVerification.sendOnSignUp` is true, or is unset and verification is required, and on a blocked sign-in when `emailVerification.sendOnSignIn` is true. |
| `challengeExpiresIn` | `120` | Seconds a challenge stays valid between the two steps. Each one can be completed exactly once. |
| `timingSafeResponseMs` | off | Minimum response time for the three endpoints whose work depends on whether an account exists. See [Security](../README.md#security). |
| `rateLimit` | see [Endpoints](#endpoints) | `{ window, max }` applied to every `/opaque/*` endpoint in place of the defaults. |
| `insecureCreateSessionOnRegister` | `false` | Issue a session straight from sign-up. Makes sign-up an account-existence oracle. Ignored while email verification is required, like core's `autoSignIn`. |

`onExistingUserSignUp`, `onSessionKey`, `sendResetPassword` and Better Auth's `sendVerificationEmail` never change the response: an error they throw is logged.

## Endpoints

All endpoints live under `/api/auth/opaque/` and are rate limited per IP and path: the reset-password request to 3 per 60 seconds, each `*/challenge` endpoint to 3 per 10 seconds, everything else to 5 per 10 seconds. Better Auth reads the client IP from `x-forwarded-for` (or `advanced.ipAddress.ipAddressHeaders`); when it finds no usable IP, as with a multi-hop header and no `advanced.ipAddress.trustedProxies`, every client shares one bucket per path, so any three reset requests within 60 seconds block reset requests for everyone until the window ends. The `rateLimit` option replaces all three with one rule; Better Auth's `rateLimit.customRules` override both. Like every Better Auth limit, they apply only while Better Auth's rate limiter is enabled, which by default is in production only. The two-step flows are driven by the client plugin; call them directly only if you are writing your own client.

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
| Reset password | `GET` | `/opaque/reset-password/:token` | none (redirects to `callbackURL?token=` or `callbackURL?error=INVALID_TOKEN`) |
| Reset password | `POST` | `/opaque/reset-password/challenge` | reset token |
| Reset password | `POST` | `/opaque/reset-password/complete` | reset token |

A fresh session is one created less than `session.freshAge` seconds ago (Better Auth's `freshSessionMiddleware`, default one day); an older one gets 403 `SESSION_NOT_FRESH`.

`/opaque/sign-in/complete` returns `{ redirect: false, token, user }` and never a redirect, even with a `callbackURL`, which only feeds the link in a verification email.

The `state` value each challenge returns is an encrypted, purpose-bound, single-use blob. The complete step must present it within `challengeExpiresIn` seconds. Each challenge also writes one row to Better Auth's `verification` table, which the complete step consumes; every challenge first deletes expired `verification` rows (unless `verification.disableCleanup` is set), so rows left by abandoned challenges do not accumulate.

## Error codes

Every failure from the plugin carries a `code`. The plugin's codes are available as `OPAQUE_ERROR_CODES` from the package and are inferred onto `authClient.$ERROR_CODES` for typing. Codes marked *client* are decided by the client plugin without a server response.

| Code | Status | Meaning |
| :-- | :-- | :-- |
| `INVALID_EMAIL_OR_PASSWORD` | 401 | Wrong password, or no account with that email. Usually *client*: a wrong password never reaches the server. |
| `INVALID_PASSWORD` | 401 | Wrong current password during a change. Usually *client*, like the above. |
| `INVALID_LOGIN_STATE` | 400 | The challenge expired, was already used, or belongs to another flow. Start over. A change-password challenge also fails this way once the password has changed since it was issued. |
| `INVALID_REGISTRATION_RECORD` | 400 | The client sent a record the server could not use. |
| `INVALID_REQUEST` | 400 | A registration or login request had the right size but did not decode as an OPAQUE message. Answered the same whether or not the email exists. |
| `INVALID_TOKEN` | 400 | Reset token unknown, expired or already used. |
| `EMAIL_NOT_VERIFIED` | 403 | Sign-in blocked until the email is verified. |
| `EMAIL_MISMATCH` | 400 | Sign-up complete sent a different email from its challenge. |
| `USER_MISMATCH` | 401 | Change or set password completed with a challenge issued to another user, or the user no longer exists. |
| `NO_OPAQUE_ACCOUNT` | 400 | The signed-in user has no OPAQUE password. Use `setPassword`. |
| `OPAQUE_ACCOUNT_EXISTS` | 400 | `setPassword` on an account that already has one. Use `changePassword`. |
| `RESET_PASSWORD_NOT_CONFIGURED` | 400 | `sendResetPassword` is missing from the plugin options. |
| `FAILED_TO_CREATE_USER` | 422 | The user insert failed, for example on a `unique` additional field. |
| `FAILED_TO_CREATE_SESSION` | 500 | The session insert failed after sign-in, a password change, or sign-up with `insecureCreateSessionOnRegister`. |
| `SERVER_KEY_MISMATCH` | 400 | *Client*: the server's key does not match the pinned `serverPublicKey`. |
| `REQUEST_FAILED` | 500 | *Client*: a server reply arrived without the data the step needs. |
| `CHALLENGE_FAILED` | | Still defined for compatibility; no longer produced. |

Failures from Better Auth itself carry core's codes, such as `SESSION_NOT_FRESH`. A rate-limited request gets a 429 with a message and no code.
