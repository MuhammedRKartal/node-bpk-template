import { register } from "../controllers/userController";
import { prismaMock } from "../prisma/singleton";
import { Request, Response, NextFunction } from "express";
import HttpError from "../custom-errors/httpError";
import { emailValidator, hashPassword, generateRandomSecret } from "../utils";

jest.mock("../utils", () => ({
  ...jest.requireActual("../utils"),
  emailValidator: jest.fn(),
  hashPassword: jest.fn(),
  generateRandomSecret: jest.fn(),
}));

describe("User Registration", () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let next: NextFunction;

  beforeEach(() => {
    mockReq = { body: {} };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    next = jest.fn();
    jest.clearAllMocks();
  });

  it("should throw an error if 3 fields are missing", async () => {
    await register(mockReq as Request, mockRes as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("Field(s) username password email missing.", 404)
    );
  });

  it("should throw an error if 2 fields are missing", async () => {
    mockReq.body = { username: "test" };
    await register(mockReq as Request, mockRes as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("Field(s) password email missing.", 404)
    );
  });

  it("should throw an error if 1 field is missing", async () => {
    mockReq.body = { username: "test", password: "test123" };
    await register(mockReq as Request, mockRes as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("Field(s) email missing.", 404)
    );
  });

  it("should throw an error if username or password is too short", async () => {
    mockReq.body = { username: "abc", password: "abc", email: "test@test.com" };
    (emailValidator as jest.Mock).mockReturnValue(true);
    await register(mockReq as Request, mockRes as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("Username must be at least 4 characters long.", 400)
    );
  });

  it("should throw an error if email is in invalid format", async () => {
    mockReq.body = {
      username: "validUser",
      password: "validPass",
      email: "bademail",
    };
    (emailValidator as jest.Mock).mockReturnValue(false);
    await register(mockReq as Request, mockRes as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError("Email format is invalid.", 400)
    );
  });

  it("should create a new user and verification code", async () => {
    mockReq.body = {
      username: "newUser",
      password: "newPass123",
      email: "new@user.com",
    };
    (emailValidator as jest.Mock).mockReturnValue(true);
    (hashPassword as jest.Mock).mockResolvedValue("hashedPassword");
    (generateRandomSecret as jest.Mock).mockReturnValue("verificationCode");

    prismaMock.user.findFirst.mockResolvedValue(null);
    (prismaMock.user.create as jest.Mock).mockResolvedValue({
      id: "1",
      username: "newUser",
      email: "new@user.com",
      verified: false,
    });
    (prismaMock.verificationCode.create as jest.Mock).mockResolvedValue({
      id: "1",
      user_id: "1",
      code: "verificationCode",
      expiration_time: new Date(),
      used: false,
    });

    await register(mockReq as Request, mockRes as Response, next);
    expect(prismaMock.user.create).toHaveBeenCalled();
    expect(prismaMock.verificationCode.create).toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({
        username: "newUser",
        code: "verificationCode",
      })
    );
  });

  it("should throw an error if user or email already exists but not in verificationCode table", async () => {
    mockReq.body = {
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
    prismaMock.verificationCode.findFirst.mockResolvedValue(null);

    await register(mockReq as Request, mockRes as Response, next);
    expect(next).toHaveBeenCalledWith(
      new HttpError(`User 'existingUser' already exists.`, 409)
    );
  });

  it("should update the code if verification code is expired", async () => {
    const expiredTime = new Date();
    expiredTime.setMinutes(expiredTime.getMinutes() - 1);

    mockReq.body = {
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
      code: "oldCode",
      expiration_time: expiredTime,
      used: false,
    });
    (prismaMock.verificationCode.update as jest.Mock).mockResolvedValue({
      id: "1",
      user_id: "1",
      code: "newCode",
      expiration_time: new Date(),
      used: false,
    });

    await register(mockReq as Request, mockRes as Response, next);
    expect(prismaMock.verificationCode.update).toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(200);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({ code: "newCode" })
    );
  });

  it("should remind the code if verification code isn't expired", async () => {
    const validTime = new Date();
    validTime.setMinutes(validTime.getMinutes() + 10);

    mockReq.body = {
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
      code: "existingCode",
      expiration_time: validTime,
      used: false,
    });

    await register(mockReq as Request, mockRes as Response, next);
    expect(mockRes.status).toHaveBeenCalledWith(200);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({ code: "existingCode" })
    );
  });
});