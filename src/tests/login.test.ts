import { login } from "../controllers/authController";
import { prismaMock } from "../prisma/singleton";
import { Request, Response, NextFunction } from "express";
import HttpError from "../custom-errors/httpError";
import { comparePassword } from "../utils";
import jwt from "jsonwebtoken";

jest.mock("jsonwebtoken", () => ({
  sign: jest.fn(),
}));

jest.mock("../utils", () => ({
  comparePassword: jest.fn(),
}));

describe("User Login", () => {
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
    await login(req as Request, res as Response, next);

    expect(next).toHaveBeenCalledWith(
      new HttpError(`Missing field(s): email, password.`, 404)
    );
  });

  test("should throw an error if one field is missing", async () => {
    req.body = { email: "test@test.com" };
    await login(req as Request, res as Response, next);

    expect(next).toHaveBeenCalledWith(
      new HttpError(`Missing field(s): password.`, 404)
    );
  });

  test("should throw an error if user doesn't exists", async () => {
    req.body = { email: "test@test.com", password: "password" };

    prismaMock.user.findFirst.mockResolvedValue(null);
    await login(req as Request, res as Response, next);

    expect(prismaMock.user.findFirst).toHaveBeenCalledWith({
      where: { email: req.body.email },
    });
    expect(next).toHaveBeenCalledWith(
      new HttpError(`User ${req.body.email} doesn't exists.`, 404)
    );
  });

  test("should throw an error if password doesn't match", async () => {
    req.body = { email: "test@test.com", password: "password" };

    (comparePassword as jest.Mock).mockResolvedValue(false);

    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      email: req.body.email,
      password: "wrongPassword",
    });

    await login(req as Request, res as Response, next);

    expect(comparePassword).toHaveBeenCalledWith(
      req.body.password,
      "wrongPassword"
    );
    expect(next).toHaveBeenCalledWith(
      new HttpError(`The password doesn't match.`, 409)
    );
  });

  test("should login successfully", async () => {
    req.body = { email: "test@test.com", password: "password" };

    const mockedJwtToken = "mocked-jwt-token";

    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      id: 1,
      email: req.body.email,
      password: req.body.password,
    });
    (comparePassword as jest.Mock).mockResolvedValue(true);
    (jwt.sign as jest.Mock).mockReturnValue(mockedJwtToken);

    await login(req as Request, res as Response, next);

    expect(prismaMock.user.findFirst).toHaveBeenCalledWith({
      where: {
        email: req.body.email,
      },
    });
    expect(comparePassword).toHaveBeenCalledWith(req.body.password, "password");
    expect(jwt.sign).toHaveBeenCalledWith(
      { userId: 1, email: req.body.email },
      process.env.JWT_SECRET || "",
      { expiresIn: "1h" }
    );
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      user: {
        id: 1,
        email: req.body.email,
        password: req.body.password,
      },
      token: mockedJwtToken,
    });
  });
});
