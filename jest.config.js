module.exports = {
  testMatch: ['**/__tests__/**/*-test.ts'],
  coveragePathIgnorePatterns: ['testfixtures'],
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        diagnostics: {
          warnOnly: true,
        },
      },
    ],
  },
  rootDir: __dirname,
  roots: ['src'],
};
