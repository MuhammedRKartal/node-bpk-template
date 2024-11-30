import bcrypt from "bcrypt";
import crypto from "crypto";

/**
 * Validates if an email is in a correct format using a regular expression.
 * @param email - The email to validate.
 * @returns true if the email is valid, otherwise false.
 */
export const emailValidator = (email: string): boolean => {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email);
};

/**
 * Hashes a plain-text password.
 * @param password - The plain-text password to hash.
 * @returns The hashed password.
 */
export const hashPassword = async (password: string): Promise<string> => {
  try {
    const saltRounds = 10; // You can adjust the salt rounds for security
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
  } catch (error) {
    console.error("Error hashing password:", error);
    throw new Error("Error hashing password");
  }
};

/**
 * Compares a plain-text password with a hashed password.
 * @param plainPassword - The plain-text password entered by the user.
 * @param hashedPassword - The hashed password stored in the database.
 * @returns true if the passwords match, otherwise false.
 */
export const comparePassword = async (
  plainPassword: string,
  hashedPassword: string
): Promise<boolean> => {
  try {
    const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
    return isMatch;
  } catch (error) {
    console.error("Error comparing passwords:", error);
    throw new Error("Error comparing passwords");
  }
};

/**
 * Generates a random HS256 code (HMAC SHA-256)
 * @param data - The data to be hashed.
 * @param secret - The secret key used to generate the HMAC.
 * @returns The generated HMAC (HS256) code.
 */
export const generateHS256Code = (
  data: string | Buffer,
  secret: string | Buffer
): string => {
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(data);
  return hmac.digest("hex");
};

/**
 * Generates a random numeric secret key for HS256
 * @param length - The length of the random key.
 * @returns The generated random numeric secret key.
 */
export const generateRandomSecret = (length = 6) => {
  let randomSecret = "";

  for (let i = 0; i < length; i++) {
    randomSecret += crypto.randomInt(0, 10);
  }

  return randomSecret;
};
