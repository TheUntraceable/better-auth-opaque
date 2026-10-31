import { ready } from "@serenity-kit/opaque";
import type { BetterAuthPlugin } from "better-auth";
import { OPAQUE_ERROR_CODES } from "./error-codes";
import type { OpaqueOptions } from "./server/options";
import { passwordEndpoints } from "./server/password";
import { resetPasswordEndpoints } from "./server/reset-password";
import { createShared } from "./server/shared";
import { signInEndpoints } from "./server/sign-in";
import { signUpEndpoints } from "./server/sign-up";

export { OPAQUE_ERROR_CODES } from "./error-codes";
export type { OpaqueOptions } from "./server/options";

export const opaque = (options: OpaqueOptions = {}) => {
	const shared = createShared(options);

	return {
		id: "opaque",
		init: async (ctx) => {
			await ready;
			shared.init(ctx);
			if (options.insecureCreateSessionOnRegister) {
				ctx.logger.warn(
					"[better-auth-opaque] insecureCreateSessionOnRegister is enabled: the sign-up endpoint can now reveal whether an email is registered.",
				);
			}
			if (ctx.options.emailAndPassword?.enabled) {
				ctx.logger.warn(
					"[better-auth-opaque] emailAndPassword is enabled alongside OPAQUE. Core /reset-password and /set-password create a server-side password hash next to the OPAQUE record. Use opaque.requestPasswordReset / opaque.setPassword instead, or disable emailAndPassword.",
				);
			}
		},
		schema: {
			account: {
				fields: {
					registrationRecord: {
						type: "string",
						required: false,
						returned: false,
						input: false,
					},
					credentialId: {
						type: "string",
						required: false,
						returned: false,
						input: false,
					},
				},
			},
		},
		rateLimit: [
			{
				pathMatcher: (path) => path.startsWith("/opaque/"),
				window: 10,
				max: 5,
			},
		],
		endpoints: {
			...signUpEndpoints(shared),
			...signInEndpoints(shared),
			...passwordEndpoints(shared),
			...resetPasswordEndpoints(shared),
		},
		$ERROR_CODES: OPAQUE_ERROR_CODES,
	} satisfies BetterAuthPlugin;
};
