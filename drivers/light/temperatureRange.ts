import type { TemperatureRange } from '../../lib/models/capabilities';

/**
 * WHERE A BULB'S COLOUR-TEMPERATURE RANGE COMES FROM, in order, and why it
 * is not a constant.
 *
 * Homey's `light_temperature` capability is a 0..1 slider; a mesh node's
 * Light CTL Temperature state is kelvin (Mesh Model Table 6.6 "Light CTL
 * Temperature states": `0x0320-0x4E20` is "The color temperature of white
 * light in kelvin", every other value Prohibited; Table 6.7 spells the ends
 * out, "that is, 0x0320 is 800 K and 0x4E20 is 20000 K"). Three sources, in
 * precedence order:
 *
 *   1. THE NODE ITSELF. `Light CTL Temperature Range Get` (`0x8262`) is the
 *      message the Bluetooth SIG defined for exactly this question, and its
 *      Status (`0x8263`) carries Range Min and Range Max. The pairing-time
 *      probe asks every node that declares a Light CTL Server, and stores
 *      the answer (`lib/models/capabilities.ts#NodeProbeResult`). This is
 *      the only source that is a measurement.
 *   2. THE USER. Per-device settings (`drivers/light/driver.compose.json`'s
 *      `temperature_min_kelvin`/`temperature_max_kelvin`), defaulted from
 *      (1) when it answered. A value the user has set WINS over the stored
 *      probe result, because the user can see the lamp and the probe ran
 *      once, months ago.
 *   3. A DOCUMENTED DEFAULT, below.
 *
 * WHAT THESE TWO NUMBERS ACTUALLY ARE, corrected after hardware said
 * otherwise. They were described - in this file, in the manifest's own
 * hints, and in the brief that produced them - as "the warmest/coolest
 * colour temperature this bulb can produce", with the advice to copy the
 * figure off the box. That is wrong, and wrong in the worst direction, for
 * a whole class of bulbs. They are the range of values this app SENDS, and
 * what a bulb does with them is the bulb's business:
 *
 *   - A SPECIFICATION-COMPLIANT bulb reads them as kelvin and clamps at its
 *     own ends. Narrowing the range to that bulb's real span is then an
 *     improvement, because it spreads the slider over what the lamp can
 *     actually do rather than over a span it will mostly clamp away.
 *   - THE OWNER'S BULB DOES NOT. It is a Tuya-made tunable-white lamp that
 *     physically produces roughly 3000-6000 K, and it stretches that whole
 *     output across whatever range it is given. Driven with its TRUE kelvin
 *     range it moved through about one sixth of its scale and the change
 *     was barely visible; driven with the full 800-20000 span it swept end
 *     to end, confirmed by the owner watching the lamp.
 *
 * Nothing on the wire distinguishes the two, which is exactly why the
 * default is the full legal span: it is the only choice that is merely
 * SUBOPTIMAL for a compliant bulb (a slider that clamps at its ends) rather
 * than BROKEN for a rescaling one (a slider that barely moves the lamp).
 * Source (1) still outranks it, so a bulb that reports its own range is
 * unaffected by this choice; source (2) is how a user narrows it if their
 * bulb misbehaves at the extremes.
 *
 * CHANGING THE DEFAULT MUST NEVER REWRITE A DEVICE THAT ALREADY HAS A
 * VALUE. The owner has deliberately set 800/20000 on his own lamp and other
 * users may have narrowed theirs; both must survive. This holds by
 * construction and is worth stating so nobody "helpfully" adds a migration:
 * `pairing.ts#finishPairing` writes these settings ONCE, when a device is
 * created, and nothing in `device.ts` ever writes them back - it only reads
 * them (`__tests__/device-wiring.test.ts` pins that). A manifest default is
 * consulted by Homey only where a device has no stored value at all.
 */

/** Mesh Model Table 6.6 "Light CTL Temperature states": 0x0320-0x4E20 is the kelvin range; all other values are Prohibited. The bounds any range from any source is checked against. */
export const MIN_LEGAL_KELVIN = 0x0320; // 800 K
export const MAX_LEGAL_KELVIN = 0x4e20; // 20000 K

/**
 * The fallback range, used when the node refuses to report its own (as the
 * owner's bulb does) and the user has not narrowed it in settings: the FULL
 * legal span of Table 6.6, deliberately, not any particular lamp's output.
 *
 * It is a SPECIFICATION value, which is the point of it - the previous
 * fallback was one real bulb's measured 3000-6000 K, which looked like the
 * honest choice and turned out to be the wrong one: a lamp that rescales
 * (see this module's header) was then driven across a sixth of its own
 * range. The full span is the only default that cannot be wrong about what
 * a bulb MEANS by these numbers, because it does not claim to know.
 */
export const DEFAULT_TEMPERATURE_RANGE: TemperatureRange = { minKelvin: MIN_LEGAL_KELVIN, maxKelvin: MAX_LEGAL_KELVIN };

/** A range is usable only if both ends are legal kelvin (Table 6.6) and min is genuinely below max - a zero-width or inverted range would make the conversion below divide by zero or run backwards. */
export function isUsableRange(range: TemperatureRange | null | undefined): range is TemperatureRange {
  if (range === null || range === undefined) return false;
  const { minKelvin, maxKelvin } = range;
  if (!Number.isInteger(minKelvin) || !Number.isInteger(maxKelvin)) return false;
  if (minKelvin < MIN_LEGAL_KELVIN || maxKelvin > MAX_LEGAL_KELVIN) return false;
  return minKelvin < maxKelvin;
}

/**
 * Resolves the range for one device from the three sources above, in
 * precedence order: a usable user setting, then the node's own reported
 * range, then the documented default. Pure - every source is passed in, so
 * this never reaches into device state, and `__tests__` can drive every
 * combination directly.
 *
 * An UNUSABLE value from a higher-precedence source falls through to the
 * next rather than being clamped into shape: a user who typed 9000-3000 by
 * mistake, or a node that reported something Prohibited, has not supplied a
 * range, and inventing one from their mistake would hide it rather than
 * fall back to something honest.
 */
export function resolveTemperatureRange(
  fromSettings: TemperatureRange | null | undefined,
  fromNode: TemperatureRange | null | undefined,
): TemperatureRange {
  if (isUsableRange(fromSettings)) return fromSettings;
  if (isUsableRange(fromNode)) return fromNode;
  return DEFAULT_TEMPERATURE_RANGE;
}

/** Builds a range from two values of unknown provenance (Homey settings are `unknown` until checked), or `null` if they are not a usable pair. */
export function rangeFromUnknown(minKelvin: unknown, maxKelvin: unknown): TemperatureRange | null {
  if (typeof minKelvin !== 'number' || typeof maxKelvin !== 'number') return null;
  const range = { minKelvin: Math.round(minKelvin), maxKelvin: Math.round(maxKelvin) };
  return isUsableRange(range) ? range : null;
}
