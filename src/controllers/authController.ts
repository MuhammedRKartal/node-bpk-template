import { NextFunction, Request, Response } from "express";
import prisma from "../prisma/client";
import logger from "../logger";
import {
  comparePassword,
  emailValidator,
  generateRandomSecret,
  hashPassword,
} from "../utils";
import HttpError from "../custom-errors/httpError";
import jwt, { JwtPayload } from "jsonwebtoken";
import { CustomRequest } from "../authMiddleware";

export const register = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { username, password, email } = req.body;

  try {
    if (!username || !password || !email) {
      const missingFields = [
        !username && "username",
        !password && "password",
        !email && "email",
      ]
        .filter(Boolean)
        .join(", ");
      throw new HttpError(`Missing field(s): ${missingFields}.`, 404);
    }

    if (username.length < 4)
      throw new HttpError("Username must be at least 4 characters long.", 400);
    if (password.length < 4)
      throw new HttpError("Password must be at least 4 characters long.", 400);
    if (!emailValidator(email))
      throw new HttpError("Email format is invalid.", 400);

    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ username: username }, { email: email }],
      },
    });

    if (existingUser) {
      if (existingUser.verified) {
        if (existingUser.username === username) {
          throw new HttpError(`User '${username}' already exists.`, 409);
        } else if (existingUser.email === email) {
          throw new HttpError(`Email '${email}' is already in use.`, 409);
        }
      }

      const verificationCodeEntry = await prisma.verificationCode.findFirst({
        where: {
          type: "Register",
          user: {
            username,
            verified: false,
          },
        },
      });

      if (verificationCodeEntry) {
        if (verificationCodeEntry.used) {
          throw new HttpError(
            `User '${username}' isn't verified but the code: '${verificationCodeEntry.code}' is already used.`,
            409
          );
        }

        const currentTime = new Date();

        if (verificationCodeEntry.expiration_time > currentTime) {
          logger.info(
            `A verification code already exists for user '${username}', existing code: ${verificationCodeEntry.code}.`
          );

          res.status(200).json({
            email: email,
            type: "Register",
            code: verificationCodeEntry.code,
            expiration_time: verificationCodeEntry.expiration_time,
          });
          return;
        } else {
          const newVerificationCode = generateRandomSecret();
          const newExpirationTime = new Date();
          newExpirationTime.setMinutes(newExpirationTime.getMinutes() + 1);

          const updatedVerificationCode = await prisma.verificationCode.update({
            where: {
              id: verificationCodeEntry.id,
            },
            data: {
              code: newVerificationCode,
              expiration_time: newExpirationTime,
              used: false,
              updated_at: currentTime,
            },
          });

          logger.info(
            `Updated verification code for user '${username}', new code: ${newVerificationCode}, expires at: ${newExpirationTime}.`
          );

          res.status(200).json({
            email: email,
            type: "Register",
            code: updatedVerificationCode.code,
            expiration_time: updatedVerificationCode.expiration_time,
          });
          return;
        }
      }
    }

    if (!existingUser) {
      const hashedPassword = await hashPassword(password);

      const newUser = await prisma.user.create({
        data: {
          username: username,
          email: email,
          password: hashedPassword,
          verified: false,
          eula_accepted: false,
          date_joined: new Date(),
        },
      });

      if (!newUser) {
        throw new HttpError("Error while creating the user", 400);
      }

      logger.info(
        `Successfully created user '${newUser.username}' with verified status ${newUser.verified}.`
      );

      const verificationCode = generateRandomSecret();
      const currentTime = new Date();

      const expirationTime = new Date();
      expirationTime.setMinutes(expirationTime.getMinutes() + 1);

      const newVerificationCodeEntry = await prisma.verificationCode.create({
        data: {
          user_id: newUser.id,
          code: verificationCode,
          type: "Register",
          expiration_time: expirationTime,
          used: false,
          created_at: currentTime,
          updated_at: currentTime,
        },
      });

      if (!newVerificationCodeEntry) {
        throw new HttpError(
          `Error while creating the verification code of ${newUser.username}`,
          400
        );
      }

      logger.info(
        `Successfully created user verification code for '${newUser.username}' with type:'Register', code is: ${newVerificationCodeEntry.code}, timer for that is ${newVerificationCodeEntry.expiration_time}.`
      );

      res.status(201).json({
        email: email,
        type: newVerificationCodeEntry.type,
        code: newVerificationCodeEntry.code,
        expiration_time: newVerificationCodeEntry.expiration_time,
      });
      return;
    }
  } catch (error) {
    next(error);
  }
};

export const verifyRegistration = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { email, code } = req.body;

  const JWT_SECRET = process.env.JWT_SECRET || "";

  try {
    if (!email || !code) {
      const missingFields = [!email && "email", !code && "code"]
        .filter(Boolean)
        .join(", ");
      throw new HttpError(`Missing field(s): ${missingFields}.`, 404);
    }

    const user = await prisma.user.findFirst({
      where: {
        email,
      },
    });

    if (!user) {
      throw new HttpError(`User ${email} doesn't exists.`, 404);
    }

    if (user.verified) {
      throw new HttpError(`User ${email} is already verified.`, 400);
    }

    const verificationCodeEntry = await prisma.verificationCode.findFirst({
      where: {
        type: "Register",
        user: {
          email: email,
        },
      },
    });

    if (!verificationCodeEntry) {
      throw new HttpError(`Verification code for ${email} doesn't exist.`, 404);
    }

    if (verificationCodeEntry.code !== code) {
      throw new HttpError(
        `The verification code '${code}' doesn't match with ${email}.`,
        400
      );
    }

    if (verificationCodeEntry.used) {
      throw new HttpError(
        `The verification code is already used for ${email}.`,
        400
      );
    }

    const updatedEntry = await prisma.verificationCode.update({
      where: {
        id: verificationCodeEntry.id,
      },
      data: {
        used: true,
        updated_at: new Date(),
      },
    });

    if (!updatedEntry) {
      throw new HttpError(`Failed to update used status of ${email}`, 400);
    }
    logger.info(
      `Successfully updated the verification code used status to true for ${email}`
    );

    const updatedUser = await prisma.user.update({
      where: {
        email,
      },
      data: {
        verified: true,
      },
    });

    if (!updatedUser) {
      throw new HttpError(`Failed to update verified status of ${email}`, 400);
    }

    const token = jwt.sign(
      { userId: updatedUser.id, email: updatedUser.email },
      JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    logger.info(`Successfully created the jwt token.`);
    logger.info(
      `Successfully updated the user verified status to true for ${email}`
    );

    res.status(200).json({
      ...updatedUser,
      token,
    });
    return;
  } catch (error) {
    next(error);
  }
};

export const login = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { email, password } = req.body;

  const JWT_SECRET = process.env.JWT_SECRET || "";

  try {
    if (!email || !password) {
      const missingFields = [!email && "email", !password && "password"]
        .filter(Boolean)
        .join(", ");
      throw new HttpError(`Missing field(s): ${missingFields}.`, 404);
    }

    const user = await prisma.user.findFirst({
      where: {
        email,
      },
    });

    if (!user) {
      throw new HttpError(`User ${email} doesn't exists.`, 404);
    }

    const passwordsMatching = await comparePassword(password, user.password);

    if (!passwordsMatching) {
      throw new HttpError(`The password doesn't match.`, 409);
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "1h",
    });

    logger.info(`Successfully created the jwt token.`);
    logger.info(`User ${email} successfully logged in.`);
    res.status(200).json({ user: user, token: token });
  } catch (error) {
    next(error);
  }
};

export const currentUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const userInfo = (req as CustomRequest).user as JwtPayload;

    if (!userInfo || !userInfo.email) {
      throw new HttpError(`Invalid token payload.`, 400);
    }

    const user = await prisma.user.findFirst({
      where: { email: userInfo.email },
    });

    if (!user) {
      throw new HttpError(`User with current access token doesn't exist.`, 404);
    }

    logger.info(`Successfully returned the user: '${user.username}'`);

    res.status(200).json(user);
  } catch (error) {
    next(error);
  }
};

export const changePassword = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const userInfo = (req as CustomRequest).user as JwtPayload;

    if (!currentPassword || !newPassword || !confirmPassword) {
      const missingFields = [
        !currentPassword && "currentPassword",
        !newPassword && "newPassword",
        !confirmPassword && "confirmPassword",
      ]
        .filter(Boolean)
        .join(", ");
      throw new HttpError(`Missing field(s): ${missingFields}.`, 404);
    }

    if (!userInfo?.email) {
      throw new HttpError("Invalid token payload.", 400);
    }

    if (newPassword.length < 4) {
      throw new HttpError(
        "New password must be at least 4 characters long.",
        400
      );
    }
    if (currentPassword === newPassword) {
      throw new HttpError("Current and new passwords cannot be the same.", 400);
    }
    if (newPassword !== confirmPassword) {
      throw new HttpError("New password and confirmation do not match.", 400);
    }

    const user = await prisma.user.findFirst({
      where: { email: userInfo.email },
    });
    if (!user) {
      throw new HttpError("User not found with the current access token.", 404);
    }

    const passwordsMatching = await comparePassword(
      currentPassword,
      user.password
    );
    if (!passwordsMatching) {
      throw new HttpError("Current password is incorrect.", 400);
    }

    const verificationCodeEntry = await prisma.verificationCode.findFirst({
      where: {
        type: "PasswordChange",
        user: { username: user.username },
        used: false,
      },
    });

    console.log(verificationCodeEntry);

    if (verificationCodeEntry) {
      const currentTime = new Date();

      if (verificationCodeEntry.expiration_time > currentTime) {
        logger.info(
          `A verification code already exists for user '${user.username}', existing code: ${verificationCodeEntry.code}.`
        );

        res.status(200).json({
          email: user.email,
          type: "PasswordChange",
          code: verificationCodeEntry.code,
          expiration_time: verificationCodeEntry.expiration_time,
        });
        return;
      } else {
        const newVerificationCode = generateRandomSecret();
        const newExpirationTime = new Date();
        newExpirationTime.setMinutes(newExpirationTime.getMinutes() + 1);

        const updatedVerificationCode = await prisma.verificationCode.update({
          where: {
            id: verificationCodeEntry.id,
          },
          data: {
            code: newVerificationCode,
            expiration_time: newExpirationTime,
            used: false,
            updated_at: currentTime,
          },
        });

        logger.info(
          `Updated verification code for user '${user.username}', new code: ${newVerificationCode}, expires at: ${newExpirationTime}.`
        );

        res.status(200).json({
          email: user.email,
          type: "PasswordChange",
          code: updatedVerificationCode.code,
          expiration_time: updatedVerificationCode.expiration_time,
        });
        return;
      }
    }

    if (!verificationCodeEntry) {
      const verificationCode = generateRandomSecret();
      const currentTime = new Date();

      const expirationTime = new Date();
      expirationTime.setMinutes(expirationTime.getMinutes() + 1);

      const newVerificationCodeEntry = await prisma.verificationCode.create({
        data: {
          user_id: user.id,
          code: verificationCode,
          type: "PasswordChange",
          expiration_time: expirationTime,
          used: false,
          created_at: currentTime,
          updated_at: currentTime,
        },
      });

      if (!newVerificationCodeEntry) {
        throw new HttpError(
          `Couldn't create verification code entry with type: 'PasswordChange' for '${user.email}'`,
          400
        );
      }

      logger.info(
        `Successfully created user verification code for '${user.username}' with type:'PasswordChange', code is: ${newVerificationCodeEntry.code}, timer for that is ${newVerificationCodeEntry.expiration_time}.`
      );
      res.status(201).json({
        email: user.email,
        type: "Register",
        code: newVerificationCodeEntry.code,
        expiration_time: newVerificationCodeEntry.expiration_time,
      });
      return;
    }
  } catch (error) {
    next(error);
  }
};
