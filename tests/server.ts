import { betterAuth } from "better-auth";
import { toNodeHandler } from "better-auth/node";
import express from "express";
import morgan from "morgan";
import { opaque } from "../src/server";


const auth = betterAuth({
	// database: mongodbAdapter(db),
	emailAndPassword: {
		enabled: true,
	},
	plugins: [
		opaque({
			OPAQUE_SERVER_KEY:
				"bgTA0wwx_5WvwoyDHURXOsnN3u1y2uJLr1vXYGc1_F5yNgubuj6Pf4JVIM83aIWHHJ7GIPUxDW74-j8CEuv0Os4rE4lQ7GnBQk3nVLDl5s1J4BsNrPXqx_i-T44FaZYLQPDzr2huMv49zUIRxA15XVU9dFuzZZgf-XiaaNDnIA0",
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
