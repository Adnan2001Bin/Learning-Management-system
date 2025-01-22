import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import authAouter from "./routes/auth/auth.route.js";
import userRouter from "./routes/auth/user.route.js";

const app = express();

app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    methods: ["GET", " POST", "DELETE", "PUT"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Cache-Control",
      "Expires",
      "Pragma",
    ],
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());
app.use("/api/auth" , authAouter)
app.use("/api/user" , userRouter)


export default app;
