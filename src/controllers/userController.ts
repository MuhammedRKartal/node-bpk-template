import { NextFunction, Request, Response } from "express";
import prisma from "../prisma/client";
import logger from "../logger";
import { emailValidator, generateRandomSecret, hashPassword } from "../utils";
import HttpError from "../custom-errors/httpError";

export const register = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { username, password, email } = req.body;
  12;
  try {
    if (!username || !password || !email) {
      throw new HttpError(
        `Field(s) ${!username ? "username " : ""}${
          !password ? "password " : ""
        }${!email ? "email" : ""} missing.`,
        404
      );
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

    console.log("Found user:", existingUser);

    if (existingUser) {
      const verificationCodeEntry = await prisma.verificationCode.findFirst({
        where: {
          user: {
            username,
            verified: false,
          },
        },
      });

      if (!verificationCodeEntry) {
        if (existingUser.username === username) {
          throw new HttpError(`User '${username}' already exists.`, 409);
        } else if (existingUser.email === email) {
          throw new HttpError(`Email '${email}' is already in use.`, 409);
        }
      }

      if (verificationCodeEntry) {
        const currentTime = new Date();

        if (verificationCodeEntry.expiration_time > currentTime) {
          logger.info(
            `A verification code already exists for user '${username}', existing code: ${verificationCodeEntry.code}.`
          );

          res.status(200).json({
            ...existingUser,
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
            ...existingUser,
            code: updatedVerificationCode.code,
            expiration_time: updatedVerificationCode.expiration_time,
          });
          return;
        }
      }
    }

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
      `Successfully created user verification code for '${newUser.username}',code is: ${newVerificationCodeEntry.code}, timer for that is ${newVerificationCodeEntry.expiration_time}.`
    );

    res.status(201).json({
      ...newUser,
      code: newVerificationCodeEntry.code,
      expiration_time: newVerificationCodeEntry.expiration_time,
    });
  } catch (error) {
    next(error);
  }
};
