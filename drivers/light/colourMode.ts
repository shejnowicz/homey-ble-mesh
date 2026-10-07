import type { HomeyCapability } from '../../lib/models/capabilities';

/**
 * WHAT THE LAMP PHYSICALLY HAS — the one question no wire probe can answer,
 * asked of the only instrument that can: the person looking at the bulb.
 *
 * `lib/models/capabilities.ts`'s own "WHAT THE PROBE CANNOT SETTLE" note has
 * named this gap since the probe was written, and named this setting as the
 * fix: "The owner's bulb acknowledges `Light HSL Set` with a correct echo
 * and emits only white ... No wire probe can see that, so the HSL row stays
 * declaration-driven until the owner's planned per-device
 * monocolor/multicolor/warm setting exists to say so directly." This module
 * is that setting's own logic, kept pure (no `homey` import, no device
 * state) so `__tests__/colourMode.test.ts` can drive every combination;
 * `drivers/light/device.ts` is the only caller and does nothing but apply
 * what `planCapabilityChange` returns.
 *
 * THE THREE MODES ARE NESTED, and that is the owner's own definition rather
 * than this module's invention:
 *
 *   monocolor  — on/off and brightness only.
 *   warm       — on/off, brightness and colour temperature.
 *   multicolor — the above plus hue and saturation.
 *
 * A DISCLOSED CONSEQUENCE of that nesting: a node declaring a Light HSL
 * Server but NO Light CTL Server (a pure RGB lamp with no white channel) has
 * no mode of its own. It seeds to `multicolor`, which also grants the
 * colour-temperature slider it cannot honour, and the user's only correction
 * is `warm` — which would take the colour away instead. This is accepted
 * rather than solved: the three modes are the ones the owner specified, a
 * fourth would be a product decision this module may not take on its own,
 * and nothing in this project has yet met such a lamp. If one ever turns up,
 * this is the comment to come back to.
 *
 * WHAT THIS SETTING DOES NOT TOUCH: `onoff` and `dim`. "Monocolor — on/off
 * and brightness only" describes what is LEFT once the colour controls are
 * gone, not a promise to grant those two. Whether a node has a Generic OnOff
 * Server or a Light Lightness Server at all is its own declaration plus the
 * pairing-time probe (`capabilities.ts#mapCompositionToCapabilities`), and
 * handing a lamp an `onoff` button no model can serve would be inventing a
 * control rather than describing one. Only the four COLOUR capabilities
 * below are governed here.
 *
 * WHY IT MAY ADD AS WELL AS REMOVE. The measurement can be wrong in the
 * other direction too — a `Light CTL Set` probe that went unanswered because
 * a segment was lost, not because the model is absent, removes a slider from
 * a lamp that has one (`modelProbe.ts`'s own "a false `'unsupported'` is
 * possible" disclosure). This setting is the user's own word about hardware
 * nothing can measure, so it has to be reversible in both directions; an
 * add-nothing version would leave such a lamp permanently diminished with no
 * route back short of re-pairing.
 *
 * NULLISH CONVENTION: `null` for "not a mode" (matching every neighbouring
 * module), never `undefined` — and `null` is the case that MATTERS here,
 * because a device paired before this setting existed has nothing stored and
 * must stay distinguishable from one whose owner actually chose something.
 */

/** The three modes, in the order the manifest's own dropdown lists them —
 *  least capable first, which is also the order they nest in. */
export const COLOUR_MODES = ['monocolor', 'warm', 'multicolor'] as const;

export type ColourMode = (typeof COLOUR_MODES)[number];

/** The per-device setting id, in `drivers/light/driver.compose.json`.
 *  Exported so `__tests__/driverManifest.test.ts` checks the manifest
 *  against this constant rather than against a second spelling of it. */
export const COLOUR_MODE_SETTING = 'colour_mode';

/**
 * The capabilities this setting is allowed to add and remove — and ONLY
 * these. In the design table's own row order (`capabilities.ts`), with
 * `light_mode` last because that is where that module appends it.
 */
export const MODE_GOVERNED_CAPABILITIES: ReadonlyArray<HomeyCapability> = [
  'light_temperature',
  'light_hue',
  'light_saturation',
  'light_mode',
];

/** The governed capabilities each mode keeps. Everything else governed is
 *  removed; everything NOT governed is left exactly as it was. */
const MODE_CAPABILITIES: Readonly<Record<ColourMode, ReadonlyArray<HomeyCapability>>> = {
  monocolor: [],
  warm: ['light_temperature'],
  // `light_mode` comes with the pair, never without it: it exists only to
  // switch between the colour wheel and the temperature slider
  // (`meshLight.ts`'s own "`light_mode` CARRIES NO WIRE TRAFFIC" note), so a
  // device that has it while missing either picker shows a switch with
  // nothing to switch to.
  multicolor: ['light_temperature', 'light_hue', 'light_saturation', 'light_mode'],
};

/** Reads a Homey setting value as a mode, or `null` for absent, misspelt or
 *  simply not-a-string — see this module's own NULLISH CONVENTION note for
 *  why `null` is load-bearing rather than defensive here. */
export function colourModeFromUnknown(value: unknown): ColourMode | null {
  if (typeof value !== 'string') return null;
  return (COLOUR_MODES as ReadonlyArray<string>).includes(value) ? (value as ColourMode) : null;
}

export function capabilitiesForMode(mode: ColourMode): ReadonlyArray<HomeyCapability> {
  return MODE_CAPABILITIES[mode];
}

/**
 * The mode to START a device on, derived from what was known when it was
 * paired — the brief's own rule: "no temperature and no colour measured ->
 * monocolor; temperature measured -> warm; HSL declared -> multicolor".
 *
 * It reads the CAPABILITY LIST rather than the composition or the probe
 * directly, deliberately: that list is where
 * `capabilities.ts#mapCompositionToCapabilities` has already merged the
 * declaration with the measurement, so this function cannot drift from it.
 * That also makes it correct for a bulb paired long before this setting
 * existed — its capability list IS what pairing knew — and
 * `__tests__/colourMode.test.ts` pins the property that matters there:
 * seeding from a device's own capabilities and applying the result changes
 * nothing.
 */
export function seedColourMode(capabilities: ReadonlyArray<string>): ColourMode {
  if (capabilities.includes('light_hue') || capabilities.includes('light_saturation')) return 'multicolor';
  if (capabilities.includes('light_temperature')) return 'warm';
  return 'monocolor';
}

/**
 * What a device must gain and lose to be in `mode`, given the capabilities
 * it has right now. Both lists only ever name governed capabilities, so
 * `onoff` and `dim` can never appear in either.
 *
 * REMOVAL ORDER IS NOT ARBITRARY: `light_mode` goes first. Homey applies
 * these one at a time, and the intermediate state where the mode switch
 * still exists but one of the two pickers it switches between has already
 * gone is precisely the broken interface this change exists to prevent —
 * brief, but real, and free to avoid.
 */
export function planCapabilityChange(
  mode: ColourMode,
  current: ReadonlyArray<string>,
): { readonly add: ReadonlyArray<HomeyCapability>; readonly remove: ReadonlyArray<HomeyCapability> } {
  const wanted = new Set<string>(capabilitiesForMode(mode));
  const add = MODE_GOVERNED_CAPABILITIES.filter((capability) => wanted.has(capability) && !current.includes(capability));
  const remove = [...MODE_GOVERNED_CAPABILITIES]
    .reverse()
    .filter((capability) => !wanted.has(capability) && current.includes(capability));
  return { add, remove };
}
