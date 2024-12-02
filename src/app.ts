import express from "express";
import cors from "cors";
import { errorHandler } from "./errorHandler";
import authRoutes from "./routes/authRoutes";

const app = express();

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

//Routes
app.use("/auth", authRoutes);

app.use(errorHandler);

export default app;
