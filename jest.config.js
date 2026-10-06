/** ts-jest over lib/ only (mesh core + adapter). The app layer (app.ts, drivers/)
 *  needs the Homey runtime and is exercised via the Homey CLI, not jest — see
 *  tsconfig.engine.json, which this points at instead of the full tsconfig.json
 *  so tests never need @types/homey or a DOM lib to compile. */
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/lib'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  transform: { '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.engine.json' }] },
};
