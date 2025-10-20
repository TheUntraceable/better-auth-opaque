import type { BetterAuthClientPlugin } from "@better-auth/core";
import type { opaque } from "./server";

export const opaqueClient = () => {
	return {
		id: "opaque",
		$InferServerPlugin: {} as ReturnType<typeof opaque>,
	} satisfies BetterAuthClientPlugin;
};
