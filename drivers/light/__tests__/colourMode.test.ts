import {
  COLOUR_MODES,
  COLOUR_MODE_SETTING,
  MODE_GOVERNED_CAPABILITIES,
  capabilitiesForMode,
  colourModeFromUnknown,
  planCapabilityChange,
  seedColourMode,
  type ColourMode,
} from '../colourMode';
import { mapCompositionToCapabilities } from '../../../lib/models/capabilities';
import type { CompositionData, ElementDescription } from '../../../lib/mesh/config/composition';

/**
 * WHAT THE LAMP PHYSICALLY HAS, which no wire probe can measure.
 *
 * `lib/models/capabilities.ts`'s own "WHAT THE PROBE CANNOT SETTLE" note has
 * named this gap since the probe was written: the owner's bulb acknowledges
 * `Light HSL Set` with a correct echo and has no colour emitters at all, and
 * the only way to find that out is to look at the lamp. These tests pin the
 * per-device setting that closes it — three nested modes, and the capability
 * change each one implies.
 *
 * SIG MODEL IDS are transcribed here independently of `capabilities.ts` and
 * `modelProbe.ts`, the same discipline `capabilities.test.ts` and
 * `modelProbe.test.ts` both already state for their own copies (Assigned
 * Numbers, Section 4.1.1 "by Value" / 4.1.2 "by Name").
 */
const GENERIC_ONOFF_SERVER = 0x1000;
const LIGHT_LIGHTNESS_SERVER = 0x1300;
const LIGHT_CTL_SERVER = 0x1303;
const LIGHT_HSL_SERVER = 0x1307;

function element(sigModels: ReadonlyArray<number>): ElementDescription {
  return { loc: 0x0000, sigModels, vendorModels: [] };
}

function composition(sigModels: ReadonlyArray<number>): CompositionData {
  return {
    cid: 0x07d0,
    pid: 768,
    vid: 0x0000,
    crpl: 0x0000,
    features: { relay: false, proxy: false, friend: false, lowPower: false },
    elements: [element(sigModels)],
  };
}

/** Exactly what `pairing.ts#finishPairing` hands Homey: the capability
 *  assignments, de-duplicated, in table order. Rebuilt here rather than
 *  imported so this file measures the real mapping and not a restatement of
 *  it. */
function pairedCapabilities(sigModels: ReadonlyArray<number>): string[] {
  const capabilities: string[] = [];
  for (const assignment of mapCompositionToCapabilities(composition(sigModels))) {
    if (!capabilities.includes(assignment.capability)) capabilities.push(assignment.capability);
  }
  return capabilities;
}

describe('colourModeFromUnknown', () => {
  test('the three documented ids parse', () => {
    expect(colourModeFromUnknown('monocolor')).toBe('monocolor');
    expect(colourModeFromUnknown('warm')).toBe('warm');
    expect(colourModeFromUnknown('multicolor')).toBe('multicolor');
  });

  test('anything else is null — a Homey setting is `unknown` until checked, and ABSENT is the case that matters', () => {
    // A device paired before this setting existed has nothing stored. That
    // must stay distinguishable from a real answer, because `device.ts`
    // seeds it from the device's own capabilities instead of acting on a
    // value nobody chose.
    expect(colourModeFromUnknown(null)).toBeNull();
    expect(colourModeFromUnknown(undefined)).toBeNull();
    expect(colourModeFromUnknown('')).toBeNull();
    expect(colourModeFromUnknown('MULTICOLOR')).toBeNull();
    expect(colourModeFromUnknown('colour')).toBeNull();
    expect(colourModeFromUnknown(2)).toBeNull();
    expect(colourModeFromUnknown({ mode: 'warm' })).toBeNull();
  });

  test('the setting id and the list of modes are what the manifest has to match', () => {
    expect(COLOUR_MODE_SETTING).toBe('colour_mode');
    expect(COLOUR_MODES).toEqual(['monocolor', 'warm', 'multicolor']);
  });
});

describe('capabilitiesForMode', () => {
  test('the three modes are NESTED, exactly as the owner specified them', () => {
    expect(capabilitiesForMode('monocolor')).toEqual([]);
    expect(capabilitiesForMode('warm')).toEqual(['light_temperature']);
    expect(capabilitiesForMode('multicolor')).toEqual(['light_temperature', 'light_hue', 'light_saturation', 'light_mode']);
  });

  test('every mode\'s capabilities are a subset of the ones this setting governs at all', () => {
    const governed = new Set<string>(MODE_GOVERNED_CAPABILITIES);
    for (const mode of COLOUR_MODES) {
      for (const capability of capabilitiesForMode(mode)) expect(governed.has(capability)).toBe(true);
    }
  });

  test('`onoff` and `dim` are NOT governed by this setting', () => {
    // Deliberate, and the one place the brief's own "monocolor — on/off and
    // brightness only" is narrower than it reads: this setting says what
    // COLOUR the lamp has. Whether a node has a Generic OnOff Server or a
    // Light Lightness Server at all is the node's own declaration plus the
    // pairing probe, and granting `onoff` to a node that has neither would
    // be inventing a control nothing can serve.
    const governed = new Set<string>(MODE_GOVERNED_CAPABILITIES);
    expect(governed.has('onoff')).toBe(false);
    expect(governed.has('dim')).toBe(false);
  });
});

describe('seedColourMode — what is known at pairing time', () => {
  test('no temperature and no colour measured -> monocolor', () => {
    expect(seedColourMode(pairedCapabilities([GENERIC_ONOFF_SERVER, LIGHT_LIGHTNESS_SERVER]))).toBe('monocolor');
  });

  test('temperature measured -> warm', () => {
    expect(seedColourMode(pairedCapabilities([GENERIC_ONOFF_SERVER, LIGHT_LIGHTNESS_SERVER, LIGHT_CTL_SERVER]))).toBe('warm');
  });

  test('HSL declared -> multicolor, which is the guess the user corrects', () => {
    // The owner's own bulb: it declares a Light HSL Server, answers
    // `Light HSL Set` with a correct echo, and has no colour emitters at
    // all. Nothing on the wire can tell; the setting is how he says so.
    expect(seedColourMode(pairedCapabilities([GENERIC_ONOFF_SERVER, LIGHT_LIGHTNESS_SERVER, LIGHT_CTL_SERVER, LIGHT_HSL_SERVER]))).toBe(
      'multicolor',
    );
  });

  test('a node with nothing at all is monocolor rather than an error', () => {
    expect(seedColourMode([])).toBe('monocolor');
  });

  test('SEEDING IS A NO-OP: applying the seeded mode to the capabilities it was seeded from changes nothing', () => {
    // This is the property that makes it safe to seed a bulb paired long
    // before this setting existed from its own capability list: whatever
    // pairing decided, re-deriving the mode from it and applying that mode
    // must add nothing and remove nothing.
    const cases = [
      [GENERIC_ONOFF_SERVER, LIGHT_LIGHTNESS_SERVER],
      [GENERIC_ONOFF_SERVER, LIGHT_LIGHTNESS_SERVER, LIGHT_CTL_SERVER],
      [GENERIC_ONOFF_SERVER, LIGHT_LIGHTNESS_SERVER, LIGHT_CTL_SERVER, LIGHT_HSL_SERVER],
      [GENERIC_ONOFF_SERVER],
      [],
    ];
    for (const sigModels of cases) {
      const capabilities = pairedCapabilities(sigModels);
      const plan = planCapabilityChange(seedColourMode(capabilities), capabilities);
      expect({ sigModels, ...plan }).toEqual({ sigModels, add: [], remove: [] });
    }
  });
});

describe('planCapabilityChange', () => {
  const multicolour = ['onoff', 'dim', 'light_temperature', 'light_hue', 'light_saturation', 'light_mode'];

  test('multicolor -> warm removes hue, saturation AND light_mode', () => {
    // `light_mode` exists only to switch between the two pickers; leaving it
    // behind would show a mode switch with nothing to switch to.
    const plan = planCapabilityChange('warm', multicolour);
    expect(plan.add).toEqual([]);
    expect(new Set(plan.remove)).toEqual(new Set(['light_hue', 'light_saturation', 'light_mode']));
  });

  test('multicolor -> monocolor removes the temperature slider as well', () => {
    const plan = planCapabilityChange('monocolor', multicolour);
    expect(plan.add).toEqual([]);
    expect(new Set(plan.remove)).toEqual(new Set(['light_temperature', 'light_hue', 'light_saturation', 'light_mode']));
  });

  test('`onoff` and `dim` are never removed, whatever the mode', () => {
    for (const mode of COLOUR_MODES) {
      const plan = planCapabilityChange(mode, multicolour);
      expect(plan.remove).not.toContain('onoff');
      expect(plan.remove).not.toContain('dim');
      expect(plan.add).not.toContain('onoff');
      expect(plan.add).not.toContain('dim');
    }
  });

  test('the change goes BOTH ways — a user correcting a wrong answer gets the controls back', () => {
    // The setting is the user's own word about hardware nothing can measure,
    // so it has to be reversible: a lamp wrongly set to monocolor and then
    // corrected must get its pickers back without re-pairing.
    const plan = planCapabilityChange('multicolor', ['onoff', 'dim']);
    expect(plan.add).toEqual(['light_temperature', 'light_hue', 'light_saturation', 'light_mode']);
    expect(plan.remove).toEqual([]);
  });

  test('monocolor -> warm adds only the temperature slider', () => {
    expect(planCapabilityChange('warm', ['onoff', 'dim'])).toEqual({ add: ['light_temperature'], remove: [] });
  });

  test('applying a mode twice is a no-op the second time', () => {
    const current = ['onoff', 'dim'];
    const first = planCapabilityChange('multicolor', current);
    const after = [...current, ...first.add];
    expect(planCapabilityChange('multicolor', after)).toEqual({ add: [], remove: [] });
  });

  test('`light_mode` is removed BEFORE the two pickers it switches between', () => {
    // Order is not arbitrary: Homey applies these one at a time, and a
    // moment where `light_mode` is still present but `light_hue` is already
    // gone is exactly the broken state this change exists to prevent.
    const plan = planCapabilityChange('monocolor', multicolour);
    expect(plan.remove.indexOf('light_mode')).toBeLessThan(plan.remove.indexOf('light_hue'));
    expect(plan.remove.indexOf('light_mode')).toBeLessThan(plan.remove.indexOf('light_saturation'));
  });

  test('a capability the device does not have is never removed, and one it already has is never added', () => {
    const modes: ColourMode[] = ['monocolor', 'warm', 'multicolor'];
    for (const mode of modes) {
      const current = ['onoff', 'dim', 'light_temperature'];
      const plan = planCapabilityChange(mode, current);
      for (const capability of plan.remove) expect(current).toContain(capability);
      for (const capability of plan.add) expect(current).not.toContain(capability);
    }
  });
});
