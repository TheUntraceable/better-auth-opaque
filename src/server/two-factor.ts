import type { AuthContext, BetterAuthPlugin } from "better-auth";

export type AfterHook = NonNullable<
	NonNullable<BetterAuthPlugin["hooks"]>["after"]
>[number];

export const SIGN_IN_COMPLETE_PATH = "/opaque/sign-in/complete";

const guardsCoreSignIn = (ctx: AuthContext) => (hook: AfterHook) => {
	try {
		return hook.matcher({ path: "/sign-in/email", context: ctx });
	} catch {
		return false;
	}
};

/**
 * Better Auth's twoFactor plugin stops a sign-in from an after hook that is
 * matched to core's sign-in paths and otherwise only reads the session the
 * sign-in just issued. Registering that same handler for the OPAQUE path
 * makes the second factor apply here exactly as it does to `signIn.email`:
 * trusted devices, the pending cookie and the `twoFactorRedirect` response
 * are all the plugin's own.
 *
 * `unsupported` means the plugin is installed but that hook was not found,
 * so sign-in has to refuse its users rather than skip the second factor.
 */
export function twoFactorSignInHooks(ctx: AuthContext): {
	hooks: AfterHook[];
	unsupported: boolean;
} {
	const twoFactor = ctx.options.plugins?.find(
		(plugin) => plugin.id === "two-factor",
	);
	if (!twoFactor) return { hooks: [], unsupported: false };
	const hooks = (twoFactor.hooks?.after ?? [])
		.filter(guardsCoreSignIn(ctx))
		.map(
			({ handler }): AfterHook => ({
				matcher: (context) => context.path === SIGN_IN_COMPLETE_PATH,
				handler,
			}),
		);
	return { hooks, unsupported: hooks.length === 0 };
}
