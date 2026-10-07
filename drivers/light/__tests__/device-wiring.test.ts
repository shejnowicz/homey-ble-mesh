import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Review finding: "the seam itself is defensible, but 'outside the gate'
 * has quietly grown from 'calls into Homey's API' to 'the only place three
 * design clauses are actually connected'." `device.ts` cannot be imported
 * by a jest test (it imports `homey` — see its own module header, and
 * `import-boundary.test.ts`'s identical reasoning for `pairing.ts`), so
 * nothing previously checked that it actually WIRES `meshLight.ts`'s own,
 * already-tested behaviour to anything — three mutations deleting that
 * wiring entirely (no capability listeners registered at all, the device
 * never changing availability, and `onDeleted` never calling the removal
 * path) all passed the complete gate.
 *
 * This uses the exact same technique `import-boundary.test.ts` already
 * uses for the identical reason (scan raw source text, never import the
 * file): it is not a substitute for behavioural testing — it cannot prove
 * the wiring is CORRECT, only that it EXISTS — but existing is exactly
 * what three mutations proved nothing was checking at all.
 */

const DEVICE_TS = join(__dirname, '..', 'device.ts');

function readDeviceSource(): string {
  return readFileSync(DEVICE_TS, 'utf8');
}

/** Returns the source between two literal markers — simple and robust
 *  enough here because this file's own structure (one `onInit`, one
 *  `onUninit`, one `onDeleted`, in that order) is fixed and known, unlike
 *  `import-boundary.test.ts`'s general-purpose walk. Throws (a failing
 *  test, not a silently-vacuous one) if either marker is missing. */
function sliceBetween(source: string, startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker);
  if (start === -1) {
    throw new Error(`device-wiring test: could not find "${startMarker}" in device.ts`);
  }
  const end = source.indexOf(endMarker, start + startMarker.length);
  if (end === -1) {
    throw new Error(`device-wiring test: could not find "${endMarker}" after "${startMarker}" in device.ts`);
  }
  return source.slice(start, end);
}

describe('device.ts wires meshLight.ts to Homey (source-text, not behaviour)', () => {
  const source = readDeviceSource();
  const onInitBody = sliceBetween(source, 'async onInit(): Promise<void> {', 'async onUninit(): Promise<void> {');
  const onDeletedBody = sliceBetween(source, 'async onDeleted(): Promise<void> {', 'module.exports');

  test('onInit registers a capability listener calling controller.setOnOff', () => {
    expect(onInitBody).toMatch(/registerCapabilityListener\(\s*'onoff'/);
    expect(onInitBody).toMatch(/controller\.setOnOff\(/);
  });

  test('onInit registers a capability listener calling controller.setDim', () => {
    expect(onInitBody).toMatch(/registerCapabilityListener\(\s*'dim'/);
    expect(onInitBody).toMatch(/controller\.setDim\(/);
  });

  test('onInit registers a capability listener calling controller.setLightTemperature', () => {
    expect(onInitBody).toMatch(/registerCapabilityListener\(\s*'light_temperature'/);
    expect(onInitBody).toMatch(/controller\.setLightTemperature\(/);
  });

  test('onInit registers a MULTIPLE capability listener calling controller.setColor', () => {
    expect(onInitBody).toMatch(/registerMultipleCapabilityListener\(/);
    expect(onInitBody).toMatch(/controller\.setColor\(/);
  });

  test('onInit registers a capability listener for light_mode', () => {
    expect(onInitBody).toMatch(/registerCapabilityListener\(\s*'light_mode'/);
  });

  test('onInit wires the device into the availability mechanism: start() AND registration with the app', () => {
    expect(onInitBody).toMatch(/controller\.start\(\)/);
    expect(onInitBody).toMatch(/registerDeviceController\(/);
  });

  test('onInit calls controller.start() BEFORE registering with the app (review finding: the other order relied on scheduling, not a guarantee)', () => {
    const startIndex = onInitBody.indexOf('controller.start()');
    const registerIndex = onInitBody.indexOf('registerDeviceController(');
    expect(startIndex).toBeGreaterThan(-1);
    expect(registerIndex).toBeGreaterThan(-1);
    expect(startIndex).toBeLessThan(registerIndex);
  });

  test('onDeleted calls the removal path (sends the node reset, not merely lets Homey delete the device)', () => {
    expect(onDeletedBody).toMatch(/controller\.remove\(\)/);
  });

  test('onDeleted also unregisters and stops the controller (review finding: otherwise it keeps re-reading a node that no longer exists)', () => {
    expect(onDeletedBody).toMatch(/unregister\s*\?\.\(\)/);
    expect(onDeletedBody).toMatch(/controller\.stop\(\)/);
  });
});

describe('device.ts wires the per-device colour-temperature range (source-text)', () => {
  const source = readDeviceSource();
  const onInitBody = sliceBetween(source, 'async onInit(): Promise<void> {', 'async onUninit(): Promise<void> {');
  const onSettingsBody = sliceBetween(source, 'async onSettings(', 'async onDeleted(): Promise<void> {');

  test('onInit resolves the range and hands it to the controller — never leaving it on the module default', () => {
    expect(onInitBody).toMatch(/temperatureRange:\s*this\.resolveRange\(/);
  });

  test('resolveRange reads the per-device SETTING and the node\'s own probed range, in that order', () => {
    const resolveBody = sliceBetween(source, 'private resolveRange(', 'async onSettings(');
    expect(resolveBody).toMatch(/getSetting\('temperature_min_kelvin'\)/);
    expect(resolveBody).toMatch(/getSetting\('temperature_max_kelvin'\)/);
    expect(resolveBody).toMatch(/probe\?\.temperatureRange/);
    expect(resolveBody).toMatch(/resolveTemperatureRange\(/);
  });

  test('device.ts NEVER writes the two range settings back — a changed default must not reach a device that already has a value', () => {
    // The owner has deliberately set 800/20000 on his own lamp, and other
    // users may have narrowed theirs. Widening the manifest default is safe
    // only because nothing ever rewrites a stored value, and the way that
    // would quietly stop being true is somebody adding a "migrate old
    // defaults" pass here. Every `setSettings` call in this file is checked,
    // not merely the ones that exist today.
    for (const match of source.matchAll(/setSettings\(([^;]*)/g)) {
      expect(match[1] ?? '').not.toMatch(/temperature_/);
    }
  });

  test('onSettings pushes an edited range into the live controller, and throws on one it refuses', () => {
    // Without the push, a user correcting the range would see no change
    // until the device was reloaded; without the throw, Homey would save a
    // range the controller rejected and the two would silently disagree.
    expect(onSettingsBody).toMatch(/setTemperatureRange\(/);
    expect(onSettingsBody).toMatch(/throw new Error/);
  });
});

describe('driver.ts pauses the shared connection for the duration of pairing (source-text)', () => {
  const source = readFileSync(join(__dirname, '..', 'driver.ts'), 'utf8');
  const pauseHelper = sliceBetween(source, 'const withMeshPaused =', "session.setHandler('pair_node'");
  const handlersBody = sliceBetween(source, "session.setHandler('pair_node'", '\n  }\n}\n\nmodule.exports');

  test('the pause/resume pair brackets pairing in a finally', () => {
    expect(pauseHelper).toMatch(/pauseMeshForPairing\(\)/);
    expect(pauseHelper).toMatch(/resumeMeshAfterPairing\(\)/);
    expect(pauseHelper).toMatch(/finally/);
  });

  test('BOTH pairing handlers go through it — the multi-bulb one is where two live GATT connections would actually happen', () => {
    // The whole reason the pause exists is the second bulb onward, which is
    // precisely what `pair_nodes` is for. A multi-bulb handler that skipped
    // it would reintroduce the hazard the single-bulb one was fixed for.
    expect(handlersBody).toMatch(/setHandler\('pair_nodes'/);
    const withMeshPausedCalls = handlersBody.match(/withMeshPaused\(/g) ?? [];
    expect(withMeshPausedCalls).toHaveLength(2);
  });

  test('pair_nodes delegates the sequencing to pairing.ts and relays progress to the view', () => {
    expect(handlersBody).toMatch(/await pairNodes\(deps/);
    expect(handlersBody).toMatch(/session\.emit\('pair_progress'/);
  });
});
