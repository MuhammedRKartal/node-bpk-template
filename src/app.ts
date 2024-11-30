import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import { errorHandler } from "./errorhandler";

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

app.use(errorHandler);

export default app;
