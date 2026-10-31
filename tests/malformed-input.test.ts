import { client as opaqueCrypto, ready } from "@serenity-kit/opaque";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
	createOpaqueTestInstance,
	errorCode,
	type OpaqueTestInstance,
	password,
	uniqueEmail,
} from "./helpers";

// 32 bytes of 0xff is not a canonical ristretto255 encoding, so the element
// a request starts with no longer decodes while length and alphabet still
// pass the schema.
const withInvalidPoint = (message: string) => {
	const bytes = Buffer.from(message, "base64url");
	bytes.fill(0xff, 0, 32);
	return bytes.toString("base64url");
};

const badRegistrationRequest = () =>
	withInvalidPoint(
		opaqueCrypto.startRegistration({ password }).registrationRequest,
	);
const badLoginRequest = () =>
	withInvalidPoint(opaqueCrypto.startLogin({ password }).startLoginRequest);

const expectInvalidRequest = (result: { error: unknown }) => {
	expect((result.error as { status?: number } | null)?.status).toBe(400);
	expect(errorCode(result)).toBe("INVALID_REQUEST");
};

describe("opaque: malformed input", () => {
	let t: OpaqueTestInstance;
	const resetTokens = new Map<string, string>();

	beforeAll(async () => {
		await ready;
		t = await createOpaqueTestInstance({
			sendResetPassword: async ({ user, token }) => {
				resetTokens.set(user.email, token);
			},
		});
	});
	afterAll(() => t.server.close());

	test("a sign-up request that is not a valid point is a 400", async () => {
		expectInvalidRequest(
			await t.client.$fetch("/opaque/sign-up/challenge", {
				method: "POST",
				body: {
					email: uniqueEmail("bad-point"),
					registrationRequest: badRegistrationRequest(),
				},
			}),
		);
	});

	test("a sign-in request that is not a valid point gets the same 400 for known and unknown emails", async () => {
		const known = uniqueEmail("bad-point-known");
		await t.client.signUp.opaque({ email: known, name: "Known", password });
		const loginRequest = badLoginRequest();
		const [real, ghost] = await Promise.all(
			[known, uniqueEmail("bad-point-ghost")].map((email) =>
				t.client.$fetch("/opaque/sign-in/challenge", {
					method: "POST",
					body: { email, loginRequest },
				}),
			),
		);
		expectInvalidRequest(real!);
		expect(ghost!.error).toEqual(real!.error);
	});

	test("change, set and reset challenges reject requests that are not valid points", async () => {
		const email = uniqueEmail("bad-point-session");
		await t.client.signUp.opaque({ email, name: "Session", password });
		const device = t.createSessionClient();
		await device.signIn.opaque({ email, password });
		const valid = {
			loginRequest: opaqueCrypto.startLogin({ password }).startLoginRequest,
			registrationRequest: opaqueCrypto.startRegistration({ password })
				.registrationRequest,
		};
		for (const body of [
			{ ...valid, loginRequest: badLoginRequest() },
			{ ...valid, registrationRequest: badRegistrationRequest() },
		]) {
			expectInvalidRequest(
				await device.$fetch("/opaque/change-password/challenge", {
					method: "POST",
					body,
				}),
			);
		}

		const coreEmail = uniqueEmail("bad-point-core");
		await t.auth.api.signUpEmail({
			body: { email: coreEmail, name: "Core", password: "core-password-123" },
		});
		const coreDevice = t.createSessionClient();
		await coreDevice.signIn.email({
			email: coreEmail,
			password: "core-password-123",
		});
		expectInvalidRequest(
			await coreDevice.$fetch("/opaque/set-password/challenge", {
				method: "POST",
				body: { registrationRequest: badRegistrationRequest() },
			}),
		);

		await t.client.opaque.requestPasswordReset({ email });
		expectInvalidRequest(
			await t.client.$fetch("/opaque/reset-password/challenge", {
				method: "POST",
				body: {
					token: resetTokens.get(email),
					registrationRequest: badRegistrationRequest(),
				},
			}),
		);
	});

	test("an email over 254 characters is a 400, not a 500", async () => {
		const email = `${"a".repeat(284)}@untraceable.dev`;
		expect(email).toHaveLength(300);
		const requests = [
			[
				"/opaque/sign-up/challenge",
				{
					email,
					registrationRequest: opaqueCrypto.startRegistration({ password })
						.registrationRequest,
				},
			],
			[
				"/opaque/sign-in/challenge",
				{
					email,
					loginRequest: opaqueCrypto.startLogin({ password }).startLoginRequest,
				},
			],
			["/opaque/reset-password/request", { email }],
		] as const;
		for (const [path, body] of requests) {
			const result = await t.client.$fetch(path, { method: "POST", body });
			expect(result.error?.status).toBe(400);
		}
	});
});
