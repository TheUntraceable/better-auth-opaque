import { betterAuth } from "better-auth";
import { toNodeHandler } from "better-auth/node";
import express from "express";
import morgan from "morgan";
import { opaque } from "../src/server";
import { TEST_OPAQUE_SERVER_KEY } from "./test-key";

// The fallback key is the suite's throwaway test key; never reuse it.
const auth = betterAuth({
	emailAndPassword: {
		enabled: true,
	},
	plugins: [
		opaque({
			serverSetup: process.env.OPAQUE_SERVER_KEY ?? TEST_OPAQUE_SERVER_KEY,
		}),
	],
});

const app = express();

app.use(morgan("dev"));
app.all("/api/auth/*splat", toNodeHandler(auth)); // For ExpressJS v5
app.use(express.json());

app.listen(8080, () => {
	console.log("Server is running on http://localhost:8080");
});
