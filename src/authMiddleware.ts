import { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import HttpError from "./custom-errors/httpError";

const JWT_SECRET = process.env.JWT_SECRET || "";

export interface CustomRequest extends Request {
  user: JwtPayload | string;
}

export const validateToken = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next(new HttpError("Authorization token is missing.", 401));
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as jwt.JwtPayload;
    (req as CustomRequest).user = decoded;
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return next(new HttpError("Token is expired.", 401));
    } else if (error instanceof jwt.JsonWebTokenError) {
      return next(new HttpError("Token is invalid.", 403));
    } else {
      return next(
        new HttpError("An error occurred during token validation.", 500)
      );
    }
  }
};
