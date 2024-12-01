import { register } from "../controllers/userController";
import { emailValidator, generateRandomSecret, hashPassword } from "../utils";
import HttpError from "../custom-errors/httpError";
import { prismaMock } from "../prisma/singleton";

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

  it("should create a new user and verification code", async () => {
    const mockUser = {
      id: 1,
      username: "user",
      email: "email@test.com",
      verified: false,
    };

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
    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue(null);
    (prismaMock.user.create as jest.Mock).mockResolvedValue(mockUser);
    (generateRandomSecret as jest.Mock).mockReturnValue(mockCode);
    (prismaMock.verificationCode.create as jest.Mock).mockResolvedValue({
      id: 1,
      code: mockCode,
      expiration_time: new Date(),
    });

    await register(mockReq, mockRes, mockNext);

    expect(prismaMock.user.create).toHaveBeenCalled();
    expect(prismaMock.verificationCode.create).toHaveBeenCalledWith(
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

  it("should return conflict if user or email already exists", async () => {
    mockReq.body = {
      username: "user",
      email: "email@test.com",
      password: "password",
    };

    //Waiting for username: user and email: email@test.com as the output.
    // Expected value
    (prismaMock.user.findFirst as jest.Mock).mockResolvedValue({
      username: "user",
      email: "email@test.com",
    });

    // Waiting for null as output.
    (prismaMock.verificationCode.findFirst as jest.Mock).mockResolvedValue(
      null
    );

    await register(mockReq, mockRes, mockNext);

    // If we call it with these inputs, compare with the given info above.
    // this function will call the real function
    // top function is the expected value
    expect(prismaMock.user.findFirst).toHaveBeenCalledWith({
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
});
