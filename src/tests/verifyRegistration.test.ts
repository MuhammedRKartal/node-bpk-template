import { verifyRegistration } from "../controllers/authController";
import { prismaMock } from "../prisma/singleton";
import HttpError from "../custom-errors/httpError";
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

jest.mock("jsonwebtoken", () => ({
  sign: jest.fn(),
}));

describe("verifyRegistration", () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;

  beforeEach(() => {
    req = { body: {} };
    res = { json: jest.fn(), status: jest.fn().mockReturnThis() };
    next = jest.fn();
  });

  test("should throw an error if both fields are missing", async () => {
    req.body = {};
    await verifyRegistration(req as Request, res as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("Missing field(s): email, code.", 404)
    );
  });

  test("should throw an error if one field is missing", async () => {
    req.body = { email: "test@example.com" };
    await verifyRegistration(req as Request, res as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("Missing field(s): code.", 404)
    );
  });

  test("should throw an error if user doesn't exist", async () => {
    req.body = { email: "nonexistent@example.com", code: "123456" };
    prismaMock.user.findFirst.mockResolvedValue(null);

    await verifyRegistration(req as Request, res as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("User nonexistent@example.com doesn't exists.", 404)
    );
  });

  test("should throw an error if user is already verified", async () => {
    req.body = { email: "verified@example.com", code: "123456" };
    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      email: "verified@example.com",
      verified: true,
    });

    await verifyRegistration(req as Request, res as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("User verified@example.com is already verified.", 400)
    );
  });

  test("should throw an error if verificationCode entry doesn't exist", async () => {
    req.body = { email: "test@example.com", code: "123456" };
    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      email: "test@example.com",
      verified: false,
    });
    (prismaMock.verificationCode.findFirst as jest.Mock).mockResolvedValue(
      null
    );

    await verifyRegistration(req as Request, res as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError(
        "Verification code for test@example.com doesn't exist.",
        404
      )
    );
  });

  test("should throw an error if verification code doesn't match", async () => {
    req.body = { email: "test@example.com", code: "123456" };
    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      email: "test@example.com",
      verified: false,
    });
    (prismaMock.verificationCode.findFirst as jest.Mock).mockResolvedValue({
      type: "Register",
      code: "654321",
      used: false,
    });

    await verifyRegistration(req as Request, res as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError(
        "The verification code '123456' doesn't match with test@example.com.",
        400
      )
    );
  });

  test("should throw an error if verification code is already used", async () => {
    req.body = { email: "test@example.com", code: "123456" };
    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      email: "test@example.com",
      verified: false,
    });
    (prismaMock.verificationCode.findFirst as jest.Mock).mockResolvedValue({
      type: "Register",
      code: "123456",
      used: true,
    });

    await verifyRegistration(req as Request, res as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError(
        "The verification code is already used for test@example.com.",
        400
      )
    );
  });

  test("should successfully update the verification code's used status", async () => {
    req.body = { email: "test@example.com", code: "123456" };
    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      email: "test@example.com",
      verified: false,
    });
    (prismaMock.verificationCode.findFirst as jest.Mock).mockResolvedValue({
      id: 1,
      type: "Register",
      code: "123456",
      used: false,
    });
    (prismaMock.verificationCode.update as jest.Mock).mockResolvedValue({
      id: 1,
      type: "Register",
      code: "123456",
      used: true,
    });
    (prismaMock.user.update as jest.Mock).mockResolvedValue({
      email: "test@example.com",
      verified: true,
    });

    await verifyRegistration(req as Request, res as Response, next);

    expect(prismaMock.verificationCode.update).toHaveBeenCalledWith({
      where: { id: 1 },
      data: { used: true, updated_at: expect.any(Date) },
    });
  });

  test("should successfully update the user's verified status", async () => {
    req.body = { email: "test@example.com", code: "123456" };
    const mockedJwtToken = "mocked-jwt-token";

    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      id: 1,
      email: "test@example.com",
      verified: false,
    });
    (prismaMock.verificationCode.findFirst as jest.Mock).mockResolvedValue({
      id: 1,
      type: "Register",
      code: "123456",
      used: false,
    });
    (prismaMock.verificationCode.update as jest.Mock).mockResolvedValue({
      id: 1,
      type: "Register",
      code: "123456",
      used: true,
    });
    (prismaMock.user.update as jest.Mock).mockResolvedValue({
      id: 1,
      email: "test@example.com",
      verified: true,
    });
    (jwt.sign as jest.Mock).mockReturnValue(mockedJwtToken);

    await verifyRegistration(req as Request, res as Response, next);

    expect(prismaMock.user.update).toHaveBeenCalledWith({
      where: { email: "test@example.com" },
      data: { verified: true },
    });

    expect(jwt.sign).toHaveBeenCalledWith(
      { userId: 1, email: req.body.email },
      process.env.JWT_SECRET || "",
      { expiresIn: "1h" }
    );

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      id: 1,
      email: "test@example.com",
      verified: true,
      token: mockedJwtToken,
    });
  });
});
