import { Request, Response, NextFunction } from "express";
import logger from "./logger";

interface CustomError extends Error {
  statusCode?: number;
  details?: any;
}

export const errorHandler = (
  err: CustomError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  logger.error("Global error handler:", {
    message: err.message,
    stack: err.stack,
    details: err.details,
  });

  const statusCode = err.statusCode || 500;
  res.status(statusCode).json({
    code: statusCode,
    message: err.message || "Internal Server Error",
    details: err.details || null,
  });
};
