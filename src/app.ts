import express from "express";
import cors from "cors";
import { errorHandler } from "./errorHandler";
import userRoutes from "./routes/userRoutes";

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
app.use("/users", userRoutes);

app.use(errorHandler);

export default app;
