/** ts-jest over the pure mesh core. Nothing here needs a Homey runtime. */
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/lib'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  transform: { '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.json' }] },
};
