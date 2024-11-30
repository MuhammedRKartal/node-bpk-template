import { PrismaClient, Prisma } from "@prisma/client";
import logger from "../logger";

const prisma = new PrismaClient();

prisma.$use(async (params, next) => {
  const start = Date.now();
  const result = await next(params);
  const duration = Date.now() - start;

  logger.info({
    query: params.model + "." + params.action,
    params: params.args,
    duration: `${duration}ms`, // Corrected template string
  });

  return result;
});

export default prisma;
