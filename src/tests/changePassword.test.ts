import { changePassword } from "../controllers/authController";
import { validateToken, CustomRequest } from "../authMiddleware";
import { prismaMock } from "../prisma/singleton";
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import HttpError from "../custom-errors/httpError";
import { comparePassword, generateRandomSecret } from "../utils";

// Mock dependencies
jest.mock("../utils", () => ({
  comparePassword: jest.fn(),
  generateRandomSecret: jest.fn(),
}));
jest.mock("jsonwebtoken");

describe("Change Password and Token Validation", () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;

  beforeEach(() => {
    req = { body: {}, headers: {} };
    res = { json: jest.fn(), status: jest.fn().mockReturnThis() };
    next = jest.fn();
  });

  // Middleware Tests
  describe("validateToken Middleware", () => {
    it("should call next with an error if the authorization header is missing", () => {
      validateToken(req as Request, res as Response, next);
      expect(next).toHaveBeenCalledWith(
        new HttpError("Authorization token is missing.", 401)
      );
    });

    it("should call next with an error if the authorization header is malformed", () => {
      req.headers = { authorization: "InvalidTokenFormat" };
      validateToken(req as Request, res as Response, next);
      expect(next).toHaveBeenCalledWith(
        new HttpError("Authorization token is missing.", 401)
      );
    });

    it("should call next with an error if the token is expired", () => {
      req.headers = { authorization: "Bearer expiredToken" };
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new jwt.TokenExpiredError("Token is expired", new Date());
      });

      validateToken(req as Request, res as Response, next);
      expect(next).toHaveBeenCalledWith(
        new HttpError("Token is expired.", 401)
      );
    });

    it("should set the user in the request object for a valid token", () => {
      req.headers = { authorization: "Bearer validToken" };
      const mockDecoded = { email: "user@example.com" };
      (jwt.verify as jest.Mock).mockReturnValue(mockDecoded);

      validateToken(req as Request, res as Response, next);
      expect((req as CustomRequest).user).toEqual(mockDecoded);
      expect(next).toHaveBeenCalledWith();
    });
  });

  // Change Password Tests
  describe("changePassword Controller", () => {
    it("should throw an error if fields are missing", async () => {
      req.body = { currentPassword: "", newPassword: "", confirmPassword: "" };
      (req as CustomRequest).user = { email: "user@example.com" };

      await changePassword(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(
        new HttpError(
          "Missing field(s): currentPassword, newPassword, confirmPassword.",
          404
        )
      );
    });

    it("should throw an error if new password's length is less than 4", async () => {
      req.body = {
        currentPassword: "testPw",
        newPassword: "tst",
        confirmPassword: "tst",
      };
      (req as CustomRequest).user = { email: "user@example.com" };

      await changePassword(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(
        new HttpError("New password must be at least 4 characters long.", 400)
      );
    });

    it("should throw an error if both passwords are same", async () => {
      req.body = {
        currentPassword: "newTestPw",
        newPassword: "newTestPw",
        confirmPassword: "newTestPw",
      };
      (req as CustomRequest).user = { email: "user@example.com" };

      await changePassword(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(
        new HttpError("Current and new passwords cannot be the same.", 400)
      );
    });

    it("should throw an error if new password and confirm password aren't matching", async () => {
      req.body = {
        currentPassword: "testPw",
        newPassword: "newTestPw",
        confirmPassword: "newTestPassword",
      };
      (req as CustomRequest).user = { email: "user@example.com" };

      await changePassword(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(
        new HttpError("New password and confirmation do not match.", 400)
      );
    });

    it("should throw an error if user is not found", async () => {
      req.body = {
        currentPassword: "testPw",
        newPassword: "newTestPw",
        confirmPassword: "newTestPw",
      };
      (req as CustomRequest).user = { email: "user@example.com" };

      (prismaMock.user.findFirst as jest.Mock).mockResolvedValue(null);
      await changePassword(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(
        new HttpError("User not found with the current access token.", 404)
      );
    });

    it("should throw an error if current password is incorrect", async () => {
      req.body = {
        currentPassword: "wrongPassword",
        newPassword: "newPassword",
        confirmPassword: "newPassword",
      };
      (req as CustomRequest).user = { email: "user@example.com" };

      (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
        id: "1",
        email: "user@example.com",
        password: "hashedPassword",
      });
      (comparePassword as jest.Mock).mockResolvedValue(false);

      await changePassword(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(
        new HttpError("Current password is incorrect.", 400)
      );
    });

    it("should update the verification code if expired", async () => {
      req.body = {
        currentPassword: "currentPassword",
        newPassword: "newPassword",
        confirmPassword: "newPassword",
      };
      (req as CustomRequest).user = { email: "user@example.com" };

      const expiredTime = new Date();
      expiredTime.setMinutes(expiredTime.getMinutes() - 1);

      (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
        id: "1",
        username: "testuser",
        email: "user@example.com",
        password: "hashedPassword",
      });
      (comparePassword as jest.Mock).mockResolvedValue(true);
      (prismaMock.verificationCode.findFirst as jest.Mock).mockResolvedValue({
        id: "1",
        code: "expiredCode",
        expiration_time: expiredTime,
        used: false,
      });
      (prismaMock.verificationCode.update as jest.Mock).mockResolvedValue({
        id: "1",
        code: "newCode",
        expiration_time: new Date(),
        used: false,
      });

      await changePassword(req as Request, res as Response, next);

      expect(prismaMock.user.findFirst).toHaveBeenCalledWith({
        where: {
          email: "user@example.com",
        },
      });

      expect(comparePassword).toHaveBeenCalledWith(
        req.body.currentPassword,
        "hashedPassword"
      );
      expect(prismaMock.verificationCode.findFirst).toHaveBeenCalledWith({
        where: {
          type: "PasswordChange",
          user: {
            username: "testuser",
          },
          used: false,
        },
      });
      expect(prismaMock.verificationCode.update).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "newCode" })
      );
    });

    it("should create a new verification code if none exists", async () => {
      req.body = {
        currentPassword: "currentPassword",
        newPassword: "newPassword",
        confirmPassword: "newPassword",
      };
      (req as CustomRequest).user = { email: "user@example.com" };

      (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
        id: "1",
        email: "user@example.com",
        password: "hashedPassword",
      });
      (comparePassword as jest.Mock).mockResolvedValue(true);
      (prismaMock.verificationCode.findFirst as jest.Mock).mockResolvedValue(
        null
      );

      (generateRandomSecret as jest.Mock).mockReturnValue("newCode");
      (prismaMock.verificationCode.create as jest.Mock).mockResolvedValue({
        id: "1",
        user_id: "1",
        code: "newCode",
        expiration_time: new Date(),
        used: false,
      });

      await changePassword(req as Request, res as Response, next);

      expect(
        prismaMock.verificationCode.create as jest.Mock
      ).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "newCode" })
      );
    });
  });
});
