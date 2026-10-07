import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DEFAULT_TEMPERATURE_RANGE, MAX_LEGAL_KELVIN, MIN_LEGAL_KELVIN } from '../temperatureRange';
import { COLOUR_MODE_SETTING, COLOUR_MODES } from '../colourMode';

/**
 * THE MANIFEST IS CODE TOO, and nothing was checking it.
 *
 * `drivers/light/driver.compose.json` is outside both the typecheck and the
 * jest gate: it is data, read by the Homey CLI at build time, and the two
 * numbers in it (the colour-temperature range defaults) are the numbers a
 * user's bulb is actually driven with until they edit them. The round this
 * file was written for is exactly what that costs — the defaults, and the
 * prose next to them, were wrong on the owner's own hardware for a week and
 * the complete gate stayed green throughout.
 *
 * This file uses the same technique `device-wiring.test.ts` uses for
 * `device.ts` (read the file, never import it) and asserts the two things
 * source code cannot: that the manifest's own defaults still agree with the
 * constant the code falls back to, and that the WORDING still says what the
 * setting actually is.
 *
 * THE WORDING ASSERTIONS ARE DELIBERATELY NEGATIVE where they can be. The
 * defect was not a missing sentence, it was a confidently WRONG one ("the
 * value printed on the box ... is the one to use"), and a test that only
 * checked for the presence of the new sentence would have passed with the
 * old one still sitting next to it.
 */

const COMPOSE = join(__dirname, '..', 'driver.compose.json');

interface ManifestSetting {
  readonly id?: string;
  readonly type?: string;
  readonly label?: Record<string, string>;
  readonly hint?: Record<string, string>;
  readonly value?: unknown;
  readonly min?: number;
  readonly max?: number;
  readonly values?: ReadonlyArray<{ readonly id: string; readonly label: Record<string, string> }>;
  readonly children?: ReadonlyArray<ManifestSetting>;
}

function readManifest(): { settings: ReadonlyArray<ManifestSetting>; capabilities: ReadonlyArray<string> } {
  return JSON.parse(readFileSync(COMPOSE, 'utf8')) as { settings: ManifestSetting[]; capabilities: string[] };
}

/** Every setting in the manifest, flattened out of its groups — a caller
 *  looking for one setting should not have to know which group it was filed
 *  under, and a reviewer moving one between groups should not break this
 *  file. Throws (a failing test, never a silently-vacuous one) if the id is
 *  not there at all. */
function findSetting(id: string): ManifestSetting {
  const flatten = (settings: ReadonlyArray<ManifestSetting>): ManifestSetting[] =>
    settings.flatMap((setting) => (setting.children === undefined ? [setting] : flatten(setting.children)));
  const found = flatten(readManifest().settings).find((setting) => setting.id === id);
  if (found === undefined) {
    throw new Error(`driver-manifest test: driver.compose.json has no setting with id "${id}"`);
  }
  return found;
}

function englishHint(setting: ManifestSetting): string {
  const hint = setting.hint?.en;
  if (hint === undefined) {
    throw new Error(`driver-manifest test: setting "${String(setting.id)}" has no English hint`);
  }
  return hint;
}

describe('the colour-temperature range settings are the range this app SENDS', () => {
  const min = findSetting('temperature_min_kelvin');
  const max = findSetting('temperature_max_kelvin');

  test('their defaults are the full legal span, and they are the SAME numbers the code falls back to', () => {
    // The two have to agree: `pairing.ts` writes `DEFAULT_TEMPERATURE_RANGE`
    // into these very settings for a node that never reports its own range,
    // so a manifest default that disagreed with the constant would mean a
    // bulb's stored setting and the slider's own fallback said different
    // things depending on which path filled them in.
    expect(min.value).toBe(DEFAULT_TEMPERATURE_RANGE.minKelvin);
    expect(max.value).toBe(DEFAULT_TEMPERATURE_RANGE.maxKelvin);
    expect(min.value).toBe(800);
    expect(max.value).toBe(20000);
  });

  test('the editable bounds are Table 6.6\'s own legal span, so a typo cannot leave it', () => {
    expect(min.min).toBe(MIN_LEGAL_KELVIN);
    expect(min.max).toBe(MAX_LEGAL_KELVIN);
    expect(max.min).toBe(MIN_LEGAL_KELVIN);
    expect(max.max).toBe(MAX_LEGAL_KELVIN);
  });

  test('both hints say these are values this app SENDS, not a description of the lamp', () => {
    for (const hint of [englishHint(min), englishHint(max)]) {
      expect(hint).toMatch(/send/i);
    }
  });

  test('both hints disclose that a compliant bulb reads them as kelvin and some bulbs stretch their whole output across them', () => {
    // The hardware fact this whole round exists for: the owner's bulb
    // produces roughly 3000-6000 K and spreads that across whatever span it
    // is given, so these two sentences are the difference between a slider
    // that sweeps the lamp and one that moves it through a sixth of itself.
    for (const hint of [englishHint(min), englishHint(max)]) {
      expect(hint).toMatch(/kelvin/i);
      expect(hint).toMatch(/stretch/i);
    }
  });

  test('neither hint tells the user to copy a figure off the box any more', () => {
    // The exact advice that produced the worst possible result on a bulb
    // that rescales — a regression test on prose, because prose is what was
    // wrong.
    for (const hint of [englishHint(min), englishHint(max)]) {
      expect(hint).not.toMatch(/box/i);
      expect(hint).not.toMatch(/manufacturer/i);
      expect(hint).not.toMatch(/can produce/i);
    }
  });

  test('both hints say the range should only be NARROWED if the bulb misbehaves', () => {
    for (const hint of [englishHint(min), englishHint(max)]) {
      expect(hint).toMatch(/narrow/i);
    }
  });
});

describe('the colour-mode setting', () => {
  const setting = findSetting(COLOUR_MODE_SETTING);

  test('it is a dropdown offering exactly the three modes the code knows about', () => {
    expect(setting.type).toBe('dropdown');
    expect((setting.values ?? []).map((value) => value.id)).toEqual([...COLOUR_MODES]);
  });

  test('every option is labelled in English', () => {
    for (const value of setting.values ?? []) {
      expect(typeof value.label.en).toBe('string');
      expect(value.label.en?.length ?? 0).toBeGreaterThan(0);
    }
  });

  test('it carries NO manifest default', () => {
    // Load-bearing, not an omission. A bulb paired before this setting
    // existed has nothing stored for it, and a manifest default would be a
    // GUESS Homey hands back from `getSetting` as if it were the user's own
    // answer — `device.ts` would then apply it and add or remove
    // capabilities on a device nobody has said anything about. With no
    // default, "nothing stored" stays distinguishable, and `device.ts`
    // seeds the value from that device's own capabilities instead.
    expect(setting.value).toBeUndefined();
  });

  test('the hint says, in one plain sentence, that multicolor is a guess the user corrects', () => {
    const hint = englishHint(setting);
    expect(hint).toMatch(/multicolor/i);
    expect(hint).toMatch(/guess/i);
    // One sentence: exactly one terminating full stop, at the very end.
    expect(hint.trimEnd().endsWith('.')).toBe(true);
    expect(hint.match(/\.(\s|$)/g) ?? []).toHaveLength(1);
  });
});

describe('the manifest and the capability mapping still agree', () => {
  test('every capability the colour-mode setting can add is one the driver declares', () => {
    // `device.ts` calls `addCapability` for these at runtime; Homey only
    // accepts a capability the driver itself declares, so a mode naming one
    // the manifest does not list would fail on the hub and nowhere else.
    const declared = new Set(readManifest().capabilities);
    for (const capability of ['onoff', 'dim', 'light_temperature', 'light_hue', 'light_saturation', 'light_mode']) {
      expect(declared.has(capability)).toBe(true);
    }
  });
});
