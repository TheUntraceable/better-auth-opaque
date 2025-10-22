# Better Auth OPAQUE

[![npm version](https://img.shields.io/npm/v/better-auth-opaque.svg)](https://www.npmjs.com/package/better-auth-opaque)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Better Auth plugin that implements **zero-knowledge password authentication** using the **OPAQUE** protocol.

This plugin allows you to build authentication systems where the server **never** sees, stores, or handles the user's raw password, providing exceptional security against a full database breach.

## Key Features

* **Zero-Knowledge:** The server remains completely ignorant of user passwords, fulfilling a core tenet of privacy-first design.
* **Post-Breach Security:** User passwords cannot be cracked offline even if an attacker steals your entire database and server secrets.
* **Built-in User Enumeration Protection:** The login and registration flow is designed to be constant-time, preventing attackers from discovering which emails are registered on your service.
* **Seamless Integration:** Designed to work flawlessly within the Better Auth ecosystem.
* **Client-Agnostic API:** Provides a clear, multi-stage API for any frontend (web, mobile, CLI) to interact with.

## How It Works

The OPAQUE protocol is an asymmetric password-authenticated key exchange (aPAKE). Unlike traditional hash-based systems, the authentication process is an interactive, cryptographic handshake.

1. **Registration:**
    * The client initiates a registration request with a value derived from the password.
    * The server responds with a cryptographic challenge.
    * The client uses the password and the server's challenge to create a `registrationRecord`. This record contains the user's credentials, encrypted in a way that only the user can unlock with their password.
    * The server stores this `registrationRecord`. The server **cannot** decrypt it.

2. **Login:**
    * The client initiates a login request.
    * The server retrieves the stored `registrationRecord` and uses it to issue a new challenge.
    * Only the client with the correct password can solve the challenge. Upon success, both the client and server derive a shared session key, proving the client's identity without ever exchanging the password itself.

## 1. Installation

```bash
# Using Bun
bun add better-auth-opaque @serenity-kit/opaque

# Using NPM
npm install better-auth-opaque @serenity-kit/opaque

# Using Yarn
yarn add better-auth-opaque @serenity-kit/opaque
```

## 2. Setup & Configuration

### Step 2.1: Set Environment Variables

You must provide a secret server key for the OPAQUE protocol. This key should be kept private and remain stable for the lifetime of your application.

Generate a secure, 171 character long key:

```bash
npx @serenity-kit/opaque@latest create-server-setup
```

Add the generated key to your `.env` file:

```env
# .env
OPAQUE_SERVER_KEY="your-secure-randomly-generated-key-here"
```

### Step 2.2: Integrate with Better Auth

Import the `opaque` plugin and add it to your Better Auth configuration.

```typescript
// src/lib/auth.ts
import { BetterAuth } from "better-auth";
import { opaque } from "better-auth-opaque";
// ... other imports (adapters, etc.)

export const auth = BetterAuth({
    adapter: YourAdapter(),
    secret: process.env.AUTH_SECRET, // Used to encrypt user data when sent to the client for login
    plugins: [
        // Add the OPAQUE plugin
        opaque({
            OPAQUE_SERVER_KEY: process.env.OPAQUE_SERVER_KEY,
        }),
    ],
});
```

## 3. Client-Side Implementation

Your frontend will need to interact with the multi-stage API endpoints. You will also need the `@serenity-kit/opaque` library on the client.

Here is a reference implementation using React/TypeScript.

```tsx
// src/components/AuthForm.tsx
import { useState } from 'react';
import { client, ready } from '@serenity-kit/opaque';
import { authClient } from "@/lib/auth-client";
// Ensure the WASM module is ready before making any calls
await ready;

export const AuthForm = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');

    const handleRegister = async () => {
        try {
            // 1. Start registration on the client
            const { clientRegistrationState, registrationRequest } = client.startRegistration({ password });

            // 2. Send the request to the server for a challenge
            const {data: challengeResponse} = await client.signUp.opaque.challenge({
                email,
                registrationRequest,
            });

            const { challenge: registrationResponse } = challengeResponse

            // 3. Finish registration on the client with the server's response
            const { registrationRecord } = client.finishRegistration({
                clientRegistrationState,
                registrationResponse,
                password,
            });
            
            // 4. Send the final record to the server to create the account and session
            const { data: completeResponse } = await client.signUp.opaque.complete({
                email,
                name: "user",
                registrationRecord,
            });
            // 5. The user is now registered BUT NOT logged in. You must log them in separately.
            // This is for security because registration can be used to enumerate users by seeing already registered emails
            // do not return a session on registration, yet registering new users does.

  
        } catch (error) {
            console.error('Registration failed:', error);
        }
    };

    const handleLogin = async () => {
        try {
            // 1. Start the login process on the client
            const { clientLoginState, loginRequest } = client.startLogin({ password });

            // 2. Send the login request to the server for a challenge
            const {data: challengeResponse} = await client.signIn.opaque.challenge({
                email,
                loginRequest,
            });
            const { challenge: loginResponse, state: encryptedServerState } = challengeResponse;

            // 3. Finalize login on the client with the server's challenge
            const { finishLoginRequest: loginResult } = client.finishLogin({
                clientLoginState,
                loginResponse,
                password,
            });

            const { data, error } = await client.signIn.opaque.complete({
                email,
                loginResult: loginResult.finishLoginRequest,
                encryptedServerState,
            });
            // 4. The user is now logged in!
        } catch (error) {
            console.error('Login failed:', error);
        }
    };

    return (
        <div>
            {/* ... form inputs for email and password ... */}
            <button onClick={handleRegister}>Register</button>
            <button onClick={handleLogin}>Login</button>
        </div>
    );
};
```

## 4. API Endpoints Reference

This plugin adds the following four endpoints to your Better Auth instance:

| Flow         | Method | Endpoint                      | Purpose                                                        |
| :----------- | :----- | :------------------------------ | :------------------------------------------------------------- |
| **Register** | `POST` | `/api/auth/sign-up/opaque/challenge` | Client sends initial request; Server responds with a challenge.    |
| **Register** | `POST` | `/api/auth/sign-up/opaque/complete`  | Client sends final record; Server creates user BUT NOT a session.        |
| **Login**    | `POST` | `/api/auth/sign-in/opaque/challenge` | Client sends initial request; Server responds with a challenge.    |
| **Login**    | `POST` | `/api/auth/sign-in/opaque/complete`  | Client sends final proof; Server validates and creates a session. |

## 5. Security Considerations

* **`OPAQUE_SERVER_KEY`:** Your server key must be kept secret and should never be committed to version control. Treat it with the same care as a database password or API secret.
* **User Enumeration:** This plugin automatically protects against user enumeration attacks. Requests for non-existent users will receive a cryptographically valid-looking (but ultimately fake) challenge, ensuring that an attacker cannot distinguish between a registered and an unregistered email address by observing server responses.

---

## License

This project is licensed under the MIT License.
