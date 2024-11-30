import { Request, Response, NextFunction } from "express";
import logger from "./logger";
import HttpError from "./custom-errors/httpError";

export const errorHandler = (
  err: HttpError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  logger.error("Global error handler:", {
    message: err.message,
    details: err.details,
    method: req.method,
    url: req.url,
    userAgent: req.headers["user-agent"],
    stack: err.stack,
  });

  const statusCode = err.statusCode || 500;
  const statusMessage = err.message || "Internal Server Error";
  const statusDetails = err.details || null;

  res.status(statusCode).json({
    code: statusCode,
    message: statusMessage,
    details: statusDetails,
  });
};
