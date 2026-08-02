module.exports = {
  moduleFileExtensions: ['js', 'ts', 'json'],
  roots: ['<rootDir>/src', '<rootDir>/test'],
  testRegex: '.*\\.spec\\.ts$',
  transform: {
    '^.+\\.(ts|js)$': 'ts-jest',
  },
  // @noble/curves ships ESM only; transpile it so jest's CJS loader can use it.
  transformIgnorePatterns: ['/node_modules/(?!@noble)'],
  testEnvironment: 'node',
};
