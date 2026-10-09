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
  // The listener registrations moved out of `onInit` into a named method
  // when the colour-mode setting arrived: a capability ADDED at runtime
  // needs its listener registered then too, so the registrations had to be
  // callable more than once. They are still checked here, in their new
  // home, plus the call from `onInit` that reaches them at all.
  const wireBody = sliceBetween(source, 'private wireCapabilityListeners(', '\n  }\n');

  test('onInit actually calls the thing that registers the capability listeners', () => {
    expect(onInitBody).toMatch(/this\.wireCapabilityListeners\(controller\)/);
  });

  test('a capability listener calls controller.setOnOff', () => {
    expect(wireBody).toMatch(/registerCapabilityListener\(\s*'onoff'/);
    expect(wireBody).toMatch(/controller\.setOnOff\(/);
  });

  test('a capability listener calls controller.setDim', () => {
    expect(wireBody).toMatch(/registerCapabilityListener\(\s*'dim'/);
    expect(wireBody).toMatch(/controller\.setDim\(/);
  });

  test('a capability listener calls controller.setLightTemperature', () => {
    expect(wireBody).toMatch(/registerCapabilityListener\(\s*'light_temperature'/);
    expect(wireBody).toMatch(/controller\.setLightTemperature\(/);
  });

  test('a MULTIPLE capability listener calls controller.setColor', () => {
    expect(wireBody).toMatch(/registerMultipleCapabilityListener\(/);
    expect(wireBody).toMatch(/controller\.setColor\(/);
  });

  test('a capability listener is registered for light_mode', () => {
    expect(wireBody).toMatch(/registerCapabilityListener\(\s*'light_mode'/);
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

describe('device.ts applies the per-device colour mode (source-text)', () => {
  const source = readDeviceSource();
  const onInitBody = sliceBetween(source, 'async onInit(): Promise<void> {', 'async onUninit(): Promise<void> {');
  const onSettingsBody = sliceBetween(source, 'async onSettings(', 'async onDeleted(): Promise<void> {');

  test('onInit resolves the mode and applies it', () => {
    // Without this, the setting would only take effect on a re-pair — and
    // a device seeded `multicolor` by a guess would keep its colour pickers
    // whatever the user said.
    expect(onInitBody).toMatch(/resolveColourMode\(/);
    expect(onInitBody).toMatch(/applyColourMode\(/);
  });

  test('onInit applies the mode BEFORE registering with the app, so a re-read never asks about a capability that is about to go', () => {
    const applyIndex = onInitBody.indexOf('applyColourMode(');
    const registerIndex = onInitBody.indexOf('registerDeviceController(');
    expect(applyIndex).toBeGreaterThan(-1);
    expect(registerIndex).toBeGreaterThan(-1);
    expect(applyIndex).toBeLessThan(registerIndex);
  });

  test('onSettings reacts to the colour-mode setting, not only to the range', () => {
    // The key test is that it looks at `changedKeys` for THIS setting:
    // merely mentioning the constant somewhere in the method would also be
    // true of a version that never acts on it.
    expect(onSettingsBody).toMatch(/changedKeys\.includes\(COLOUR_MODE_SETTING\)/);
    expect(onSettingsBody).toMatch(/applyColourMode\(/);
    // ...and from `newSettings`, because Homey has not persisted the change
    // yet at the point `onSettings` runs.
    expect(onSettingsBody).toMatch(/newSettings\[COLOUR_MODE_SETTING\]/);
  });

  test('applying a mode goes through planCapabilityChange and actually adds AND removes capabilities', () => {
    const applyBody = sliceBetween(source, 'private async applyColourMode(', '\n  }\n');
    expect(applyBody).toMatch(/planCapabilityChange\(/);
    expect(applyBody).toMatch(/this\.removeCapability\(/);
    expect(applyBody).toMatch(/this\.addCapability\(/);
  });

  test('applying a mode removes BEFORE it adds, and re-wires the listeners afterwards', () => {
    // A capability added at runtime has no listener until one is registered
    // for it; without the re-wire, a user correcting monocolor to multicolor
    // would get pickers that do nothing.
    const applyBody = sliceBetween(source, 'private async applyColourMode(', '\n  }\n');
    const removeIndex = applyBody.indexOf('this.removeCapability(');
    const addIndex = applyBody.indexOf('this.addCapability(');
    const wireIndex = applyBody.indexOf('wireCapabilityListeners(');
    expect(removeIndex).toBeLessThan(addIndex);
    expect(addIndex).toBeLessThan(wireIndex);
  });

  test('an ABSENT setting is seeded from the device\'s own capabilities, never from a guess', () => {
    // A bulb paired before this setting existed has nothing stored. Seeding
    // from its own capability list is provably a no-op (colourMode.test.ts
    // pins that), where acting on a manifest default would not be.
    const resolveBody = sliceBetween(source, 'private async resolveColourMode(', '\n  }\n');
    expect(resolveBody).toMatch(/colourModeFromUnknown\(this\.getSetting\(COLOUR_MODE_SETTING\)\)/);
    expect(resolveBody).toMatch(/seedColourMode\(this\.getCapabilities\(\)\)/);
    expect(resolveBody).toMatch(/setSettings\(/);
  });

  test('each capability listener is registered at most once, however often the mode changes', () => {
    // `wireCapabilityListeners` runs again on every mode change; without the
    // guard, flipping the setting back and forth would stack duplicate
    // listeners on the same capability.
    const wireBody = sliceBetween(source, 'private wireCapabilityListeners(', '\n  }\n');
    // BOTH halves, because either one alone is useless: a set that is added
    // to but never consulted guards nothing, and one consulted but never
    // added to guards everything out.
    expect(wireBody).toMatch(/if \(this\.registeredCapabilityListeners\.has\(capability\)\) return;/);
    expect(wireBody).toMatch(/this\.registeredCapabilityListeners\.add\(capability\);/);
  });
});

describe('device.ts leaves the backfill probe\'s TRIGGER to the controller (source-text)', () => {
  const source = readDeviceSource();
  const onInitBody = sliceBetween(source, 'async onInit(): Promise<void> {', 'async onUninit(): Promise<void> {');

  test('onInit does NOT start the probe itself', () => {
    // It used to, and that was the defect: device `onInit` runs while the
    // proxy connection is still coming up (Homey runs the APP's own onInit,
    // which merely starts the scan, to completion first), so a probe started
    // here writes its first message at a link that does not exist yet and
    // survives only on the queue's bounded retry outlasting a scan plus a
    // connect. `meshLight.ts#startBackfillProbe` now triggers it from the
    // first moment the node has actually answered.
    expect(onInitBody).not.toMatch(/backfillProbe\(/);
  });

  test('onInit still gives the controller the app\'s SHARED probe runner', () => {
    // One mesh, one queue, one command at a time: several devices becoming
    // reachable together must not probe concurrently, and a per-device
    // runner would serialise nothing.
    expect(onInitBody).toMatch(/probeRunner:\s*context\.probeRunner/);
  });
});

/**
 * The pause/resume half of this block moved to
 * `./meshPauseWiring.test.ts` on 2026-10-09, when `withMeshPaused` itself
 * moved out of `driver.ts` into `lib/adapter/meshPause.ts` (where jest can
 * run it rather than only read it). What stays here is the part that is
 * about this driver's own pairing handlers and nothing else.
 */
describe('driver.ts wires the pairing handlers to pairing.ts (source-text)', () => {
  const source = readFileSync(join(__dirname, '..', 'driver.ts'), 'utf8');
  const handlersBody = sliceBetween(source, "session.setHandler('pair_node'", '\n  }\n}\n\nmodule.exports');

  test('pair_nodes delegates the sequencing to pairing.ts and relays progress to the view', () => {
    expect(handlersBody).toMatch(/setHandler\('pair_nodes'/);
    expect(handlersBody).toMatch(/await pairNodes\(deps/);
    expect(handlersBody).toMatch(/session\.emit\('pair_progress'/);
  });
});
