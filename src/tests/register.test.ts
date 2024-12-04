import { register } from "../controllers/authController";
import { prismaMock } from "../prisma/singleton";
import { Request, Response, NextFunction } from "express";
import HttpError from "../custom-errors/httpError";
import { emailValidator, hashPassword, generateRandomSecret } from "../utils";

jest.mock("../utils", () => ({
  emailValidator: jest.fn(),
  hashPassword: jest.fn(),
  generateRandomSecret: jest.fn(),
}));

describe("User Registration", () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;

  beforeEach(() => {
    req = { body: {} };
    res = { json: jest.fn(), status: jest.fn().mockReturnThis() };
    next = jest.fn();
  });

  it("should throw an error if 3 fields are missing", async () => {
    await register(req as Request, res as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("Field(s) username password email missing.", 404)
    );
  });

  it("should throw an error if 2 fields are missing", async () => {
    req.body = { username: "test" };
    await register(req as Request, res as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("Field(s) password email missing.", 404)
    );
  });

  it("should throw an error if 1 field is missing", async () => {
    req.body = { username: "test", password: "test123" };
    await register(req as Request, res as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("Field(s) email missing.", 404)
    );
  });

  it("should throw an error if username or password is too short", async () => {
    req.body = { username: "abc", password: "abc", email: "test@test.com" };
    (emailValidator as jest.Mock).mockReturnValue(true);
    await register(req as Request, res as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("Username must be at least 4 characters long.", 400)
    );
  });

  it("should throw an error if email is in invalid format", async () => {
    req.body = {
      username: "validUser",
      password: "validPass",
      email: "bademail",
    };
    (emailValidator as jest.Mock).mockReturnValue(false);
    await register(req as Request, res as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("Email format is invalid.", 400)
    );
  });

  it("should throw an error if user or email already exists", async () => {
    req.body = {
      username: "existingUser",
      password: "password",
      email: "existing@user.com",
    };

    (emailValidator as jest.Mock).mockReturnValue(true);

    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      id: "1",
      username: "existingUser",
      email: "existing@user.com",
      verified: true,
    });

    await register(req as Request, res as Response, next);

    expect(next).toHaveBeenCalledWith(
      new HttpError(`User 'existingUser' already exists.`, 409)
    );
  });

  it("should throw an error if verification code is already used", async () => {
    req.body = {
      email: "test@test.com",
      username: "test",
      password: "password",
    };

    const mockCode = "mockCode123";

    (emailValidator as jest.Mock).mockReturnValue(true);

    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      id: "1",
      username: req.body.username,
      email: req.body.email,
      password: req.body.password,
    });

    (prismaMock.verificationCode.findFirst as jest.Mock).mockResolvedValue({
      userId: "1",
      code: mockCode,
      used: true,
      type: "Register",
    });

    await register(req as Request, res as Response, next);

    expect(prismaMock.user.findFirst).toHaveBeenCalledWith({
      where: {
        OR: [{ username: req.body.username }, { email: req.body.email }],
      },
    });

    expect(prismaMock.verificationCode.findFirst).toHaveBeenCalledWith({
      where: {
        type: "Register",
        user: {
          username: req.body.username,
          verified: false,
        },
      },
    });
    expect(next).toHaveBeenCalledWith(
      new HttpError(
        `User '${req.body.username}' isn't verified but the code: '${mockCode}' is already used.`,
        409
      )
    );
  });

  it("should update the code if verification code is expired", async () => {
    const expiredTime = new Date();
    expiredTime.setMinutes(expiredTime.getMinutes() - 1);

    req.body = {
      username: "unverifiedUser",
      password: "password",
      email: "unverified@user.com",
    };
    (emailValidator as jest.Mock).mockReturnValue(true);
    (generateRandomSecret as jest.Mock).mockReturnValue("newCode");

    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      id: "1",
      username: "unverifiedUser",
      email: "unverified@user.com",
      verified: false,
    });
    (prismaMock.verificationCode.findFirst as jest.Mock).mockResolvedValue({
      id: "1",
      user_id: "1",
      type: "Register",
      code: "oldCode",
      expiration_time: expiredTime,
      used: false,
    });
    (prismaMock.verificationCode.update as jest.Mock).mockResolvedValue({
      id: "1",
      user_id: "1",
      type: "Register",
      code: "newCode",
      expiration_time: new Date(),
      used: false,
    });

    await register(req as Request, res as Response, next);
    expect(prismaMock.verificationCode.update).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ code: "newCode" })
    );
  });

  it("should remind the code if verification code isn't expired", async () => {
    const validTime = new Date();
    validTime.setMinutes(validTime.getMinutes() + 10);

    req.body = {
      username: "unverifiedUser",
      password: "password",
      email: "unverified@user.com",
    };
    (emailValidator as jest.Mock).mockReturnValue(true);

    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      id: "1",
      username: "unverifiedUser",
      email: "unverified@user.com",
      verified: false,
    });
    (prismaMock.verificationCode.findFirst as jest.Mock).mockResolvedValue({
      id: "1",
      user_id: "1",
      type: "Register",
      code: "existingCode",
      expiration_time: validTime,
      used: false,
    });

    await register(req as Request, res as Response, next);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ type: "Register", code: "existingCode" })
    );
  });

  it("should create a new user and verification code", async () => {
    req.body = {
      username: "newUser",
      password: "newPass123",
      email: "new@user.com",
    };
    (emailValidator as jest.Mock).mockReturnValue(true);
    (hashPassword as jest.Mock).mockResolvedValue("hashedPassword");
    (generateRandomSecret as jest.Mock).mockReturnValue("verificationCode");

    (prismaMock.user.create as jest.Mock).mockResolvedValue({
      id: "1",
      username: "newUser",
      email: "new@user.com",
      verified: false,
    });
    (prismaMock.verificationCode.create as jest.Mock).mockResolvedValue({
      id: "1",
      user_id: "1",
      type: "Register",
      code: "verificationCode",
      expiration_time: new Date(),
      used: false,
    });

    await register(req as Request, res as Response, next);
    expect(prismaMock.user.create).toHaveBeenCalled();
    expect(prismaMock.verificationCode.create).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        email: "new@user.com",
        code: "verificationCode",
      })
    );
  });
});
