import { register } from "../controllers/userController";
import prisma from "../prisma/client";
import { emailValidator, generateRandomSecret, hashPassword } from "../utils";
import HttpError from "../custom-errors/httpError";

jest.mock("../prisma/client", () => ({
  user: {
    findFirst: jest.fn(),
    create: jest.fn(),
  },
  verificationCode: {
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  },
}));

jest.mock("../logger", () => ({
  info: jest.fn(),
  error: jest.fn(),
}));

jest.mock("../utils", () => ({
  emailValidator: jest.fn(),
  generateRandomSecret: jest.fn(),
  hashPassword: jest.fn(),
}));

jest.mock("../custom-errors/httpError");

describe("register", () => {
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    jest.clearAllMocks();
    mockReq = { body: {} };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    mockNext = jest.fn();
  });

  it("should throw an error if required fields are missing", async () => {
    mockReq.body = { username: "user", password: "" };

    await register(mockReq, mockRes, mockNext);

    expect(mockNext).toHaveBeenCalledWith(expect.any(HttpError));
    expect(HttpError).toHaveBeenCalledWith(
      expect.stringContaining("Field(s)"),
      404
    );
  });

  it("should throw an error if username is too short", async () => {
    mockReq.body = {
      username: "usr",
      password: "password",
      email: "email@test.com",
    };

    await register(mockReq, mockRes, mockNext);

    expect(mockNext).toHaveBeenCalledWith(expect.any(HttpError));
    expect(HttpError).toHaveBeenCalledWith(
      "Username must be at least 4 characters long.",
      400
    );
  });

  it("should throw an error for invalid email format", async () => {
    mockReq.body = {
      username: "user",
      password: "password",
      email: "invalid-email",
    };
    (emailValidator as jest.Mock).mockReturnValue(false);

    await register(mockReq, mockRes, mockNext);

    expect(emailValidator).toHaveBeenCalledWith("invalid-email");
    expect(mockNext).toHaveBeenCalledWith(expect.any(HttpError));
    expect(HttpError).toHaveBeenCalledWith("Email format is invalid.", 400);
  });

  it("should return conflict if user or email already exists", async () => {
    // Mock request body
    mockReq.body = {
      username: "user",
      email: "email@test.com",
      password: "password",
    };

    // Mock prisma.user.findFirst
    (prisma.user.findFirst as jest.Mock).mockResolvedValue({
      username: "user",
      email: "email@test.com",
    });

    // Mock prisma.verificationCode.findFirst
    (prisma.verificationCode.findFirst as jest.Mock).mockResolvedValue(null);

    // Call the function
    await register(mockReq, mockRes, mockNext);

    // Assertions
    expect(prisma.user.findFirst).toHaveBeenCalledWith({
      where: {
        OR: [{ username: "user" }, { email: "email@test.com" }],
      },
    });

    expect(mockNext).toHaveBeenCalledWith(expect.any(HttpError));
    expect(HttpError).toHaveBeenCalledWith(
      expect.stringContaining("already"),
      409
    );
  });

  it("should create a new user and verification code", async () => {
    const mockUser = {
      id: 1,
      username: "user",
      email: "email@test.com",
      verified: false,
    };

    const mockDate = new Date();
    const currentDate = new Date();
    mockDate.setMinutes(mockDate.getMinutes() + 1);

    const mockVerification = {
      code: "verificationCode123",
      used: false,
      user_id: 1,
    };

    const mockCode = "verificationCode123";

    mockReq.body = {
      username: "user",
      password: "password",
      email: "email@test.com",
    };
    (emailValidator as jest.Mock).mockReturnValue(true);
    (hashPassword as jest.Mock).mockResolvedValue("hashedPassword");
    (prisma.user.findFirst as jest.Mock).mockResolvedValue(null);
    (prisma.user.create as jest.Mock).mockResolvedValue(mockUser);
    (generateRandomSecret as jest.Mock).mockReturnValue(mockCode);
    (prisma.verificationCode.create as jest.Mock).mockResolvedValue({
      id: 1,
      code: mockCode,
      expiration_time: new Date(),
    });

    await register(mockReq, mockRes, mockNext);

    expect(prisma.user.create).toHaveBeenCalled();
    expect(prisma.verificationCode.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          ...mockVerification,
        }),
      })
    );
    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({
        id: mockUser.id,
        username: mockUser.username,
        email: mockUser.email,
        verified: mockUser.verified,
        code: mockCode,
      })
    );
  });
});
