/** ts-jest over lib/ (mesh core + adapter) PLUS drivers/light/pairing.ts
 *  (task 6) and drivers/light/meshLight.ts (task 7): those two files, and
 *  only those two, are pure orchestration with no `homey` import — see each
 *  one's own module header — so they and their tests
 *  (`drivers/light/__tests__/{pairing,meshLight}.test.ts`) are listed
 *  explicitly in tsconfig.engine.json's "include" alongside them, the same
 *  tsconfig this config already points at. `drivers/light/driver.ts` and
 *  `drivers/light/device.ts` (the actual `Homey.Driver`/`Homey.Device`
 *  subclasses) and the rest of the app layer (app.ts) still need the Homey
 *  runtime and are exercised via the Homey CLI, not jest — hence `roots`
 *  below lists `drivers/light/__tests__` explicitly rather than all of
 *  `drivers`, so jest's own test discovery never has a reason to import
 *  driver.ts/device.ts and go looking for `@types/homey`/a DOM lib. */
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/lib', '<rootDir>/drivers/light/__tests__'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  transform: { '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.engine.json' }] },
};
