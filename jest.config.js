/** ts-jest over lib/ (mesh core + adapter) PLUS drivers/light/pairing.ts
 *  (task 6): that one file, and only that one, is pure orchestration with no
 *  `homey` import — see its own module header — so it and its test
 *  (`drivers/light/__tests__/pairing.test.ts`) are listed explicitly in
 *  tsconfig.engine.json's "include" alongside it, the same tsconfig this
 *  config already points at. `drivers/light/driver.ts` (the actual
 *  `Homey.Driver` subclass) and the rest of the app layer (app.ts) still need
 *  the Homey runtime and are exercised via the Homey CLI, not jest — hence
 *  `roots` below lists `drivers/light/__tests__` explicitly rather than all
 *  of `drivers`, so jest's own test discovery never has a reason to import
 *  driver.ts and go looking for `@types/homey`/a DOM lib. */
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/lib', '<rootDir>/drivers/light/__tests__'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  transform: { '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.engine.json' }] },
};
