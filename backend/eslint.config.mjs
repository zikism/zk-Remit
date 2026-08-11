import js from '@eslint/js';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';

export default [
  {
    ignores: ['dist/**', 'node_modules/**', 'coverage/**', 'jest.config.js', 'jest.config.e2e.js'],
  },
  js.configs.recommended,
  {
    files: ['{src,test}/**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        sourceType: 'module',
        ecmaVersion: 2022,
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      // TypeScript already resolves identifiers at compile time; the base
      // no-undef rule false-positives on globals like Buffer/process.
      'no-undef': 'off',
      // Keep the codebase explicit about where dynamic access is intentional,
      // but surface `any` so it stays a conscious choice rather than a habit.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
  {
    // Integration specs dynamically load mocked modules (jest.mock factories
    // and @stellar/stellar-sdk internals) with `require`, which is intentional.
    files: ['test/integration/**/*.spec.ts'],
    rules: {
      '@typescript-eslint/no-var-requires': 'off',
    },
  },
];
