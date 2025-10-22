import { client, server } from "@serenity-kit/opaque";
import { type Account, APIError, type User } from "better-auth";
import {
	generateRandomString,
	symmetricDecrypt,
	symmetricEncrypt,
} from "better-auth/crypto";

export interface OpaqueOptions {
	OPAQUE_SERVER_KEY: string;
	sendRegistrationEmail: (
		email: string,
		type: "registration" | "already-registered",
	) => Promise<void>;
}

export const REGISTRATION_REQUEST_LENGTH = 32;
export const REGISTRATION_RECORD_MIN_LENGTH = 170;
export const REGISTRATION_RECORD_MAX_LENGTH = 200;
export const LOGIN_REQUEST_LENGTH = 96;

export function base64UrlDecode(str: string): string {
	const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
	return atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
}

export function validateBase64Length(
	base64: string,
	expectedLength: number,
	fieldName: string,
): void {
	const bytes = base64UrlDecode(base64);
	if (bytes.length !== expectedLength) {
		throw new APIError("BAD_REQUEST", {
			message: `Invalid ${fieldName}`,
		});
	}
}

export async function createDummyRegistrationRecord(): Promise<string> {
	const tempServerSetup = server.createSetup(); // Use a temporary key

	const userId = generateRandomString(12);
	const password = generateRandomString(24);

	const { registrationRequest, clientRegistrationState } =
		client.startRegistration({
			password,
		});

	const { registrationResponse } = server.createRegistrationResponse({
		registrationRequest,
		serverSetup: tempServerSetup,
		userIdentifier: userId,
	});

	const { registrationRecord } = client.finishRegistration({
		clientRegistrationState,
		registrationResponse,
		password,
	});

	return registrationRecord;
}

export function validateBase64LengthRange(
	base64: string,
	min: number,
	max: number,
	fieldName: string,
): void {
	const bytes = base64UrlDecode(base64);
	if (bytes.length < min || bytes.length > max) {
		throw new APIError("BAD_REQUEST", {
			message: `Invalid ${fieldName}`,
		});
	}
}
export function padToLength(input: string, targetLength: number): string {
	const currentLength = Buffer.byteLength(input, "utf8");

	if (currentLength > targetLength) {
		// This is a critical safety check. If this error is ever thrown,
		// it means your user objects have grown and you need to increase
		// the TARGET_PAYLOAD_LENGTH constant.
		throw new Error("Payload size exceeds target padding length.");
	}

	const paddingNeeded = targetLength - currentLength;
	// We use a simple space for padding. Since the entire payload is
	// encrypted, the padding character itself is not security-sensitive.
	return input + " ".repeat(paddingNeeded);
}

export async function encryptServerLoginState(
	serverLoginState: string,
	secret: string,
	user: {
		id: string;
		email: string;
		name: string;
		[key: string]: unknown;
	} | null,
): Promise<string> {
	return await symmetricEncrypt({
		data: padToLength(
			JSON.stringify({ serverLoginState, user, issuedAt: Date.now() }),
			1024,
		),
		key: secret,
	});
}

export async function decryptServerLoginState(
	encryptedState: string,
	secret: string,
): Promise<{
	serverLoginState: string;
	user: User;
}> {
	const decrypted = await symmetricDecrypt({
		key: secret,
		data: encryptedState,
	});
	const data = JSON.parse(decrypted);
	if (data.issuedAt + 15 * 60 * 1000 < Date.now()) {
		// 15 minutes expiry
		throw new APIError("BAD_REQUEST", {
			message: "Login state has expired",
		});
	}
	return data;
}

export async function findOpaqueAccount(
	ctx: {
		context: {
			internalAdapter: { findAccounts: (userId: string) => Promise<Account[]> };
		};
	},
	userId: string,
): Promise<(Account & { registrationRecord: string }) | undefined> {
	const accounts = await ctx.context.internalAdapter.findAccounts(userId);
	return accounts.find((account: Account) => account.providerId === "opaque") as
		| (Account & { registrationRecord: string })
		| undefined;
}

export async function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
