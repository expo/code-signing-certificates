import { defineConfig } from 'oxlint';
import node from 'oxlint-config-universe/node';
import typescriptAnalysis from 'oxlint-config-universe/typescript-analysis';

export default defineConfig({
  extends: [node, typescriptAnalysis],
  plugins: ['jest'],
  options: {
    typeAware: true,
  },
  rules: {
    // Overrides from oxlint-config-universe defaults
    'no-restricted-properties': [
      'warn',
      {
        object: 'it',
        property: 'only',
        message: 'it.only should not be committed to main.',
      },
      {
        object: 'test',
        property: 'only',
        message: 'test.only should not be committed to main.',
      },
      {
        object: 'describe',
        property: 'only',
        message: 'describe.only should not be committed to main.',
      },
    ],
    'no-console': 'warn',
    'no-void': ['warn', { allowAsStatement: true }],

    // TypeScript rules
    'typescript/explicit-function-return-type': ['warn', { allowExpressions: true }],

    // Jest rules
    'jest/valid-title': 'off',
    'jest/expect-expect': 'off',
  },
  overrides: [
    {
      files: ['scripts/**/*.ts'],
      rules: {
        'no-console': 'off',
      },
    },
    {
      files: ['**/__tests__/**/*.ts'],
      rules: {
        'typescript/no-confusing-void-expression': 'off',
        'typescript/unbound-method': 'off',
      },
    },
    {
      files: ['*.config.js', 'jest.setup.js'],
      env: { node: true },
    },
  ],
  ignorePatterns: [
    'build',
    'coverage',
    'coverage-integration',
    'doc',
    'keys',
    'generated-test-data',
  ],
});
