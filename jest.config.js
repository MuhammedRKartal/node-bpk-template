module.exports = {
  clearMocks: true,
  testEnvironment: "node",
  setupFilesAfterEnv: ["./src/prisma/singleton.ts"],
  transform: {
    "^.+.tsx?$": ["ts-jest", {}],
  },
};
