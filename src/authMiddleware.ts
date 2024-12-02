import { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import HttpError from "./custom-errors/httpError";

const JWT_SECRET = process.env.JWT_SECRET || "";

export interface CustomRequest extends Request {
  token: JwtPayload | string;
}

export const validateToken = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next(new HttpError("Authorization token missing or invalid.", 401));
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as jwt.JwtPayload;
    (req as CustomRequest).token = decoded;
    next();
  } catch (error) {
    return next(new HttpError("Token is invalid or expired.", 403));
  }
};
