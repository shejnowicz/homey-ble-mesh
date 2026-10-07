import type { TemperatureRange } from '../../lib/models/capabilities';

/**
 * WHERE A BULB'S COLOUR-TEMPERATURE RANGE COMES FROM, in order, and why it
 * is not a constant.
 *
 * Homey's `light_temperature` capability is a 0..1 slider; a mesh node's
 * Light CTL Temperature state is kelvin (Mesh Model Table 6.6: 800-20000 K
 * is the full legal span). Mapping Homey's slider onto that whole legal
 * span would make the useful middle of it a sliver of the control, so the
 * mapping needs the range THIS bulb actually covers. Three sources, in
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
 *      (1) when it answered, so someone whose bulb stays silent can type in
 *      the range printed on the box. A value the user has set WINS over the
 *      stored probe result, because the user can see the lamp and the probe
 *      ran once, months ago.
 *   3. A DOCUMENTED DEFAULT, below.
 *
 * WHY THERE IS A DEFAULT AT ALL, stated plainly rather than buried: the
 * owner's own bulb never answers `Light CTL Temperature Range Get` - tried
 * on hardware, no reply - so for that bulb there is nothing to read and
 * nothing is going to change that. 3000-6000 K is ITS range, per the
 * manufacturer's own app, and it is the fallback precisely because it is a
 * real measurement of a real bulb rather than an invented round number.
 *
 * THE CONSEQUENCE, which is a real limitation and not a formality: a
 * DIFFERENT bulb, with a different range, that also refuses to report it
 * (and whose owner has not corrected it in settings) is mapped WRONGLY -
 * its slider will reach temperatures the lamp cannot produce, or fail to
 * reach ones it can, and the lamp will clamp or saturate at the ends.
 * Source (2) is the fix for that, and it is why source (2) exists at all
 * rather than this file simply carrying the owner's numbers.
 */

/** Mesh Model Table 6.6 "Light CTL Temperature states": 0x0320-0x4E20 is the kelvin range; all other values are Prohibited. The bounds any range from any source is checked against. */
export const MIN_LEGAL_KELVIN = 0x0320; // 800 K
export const MAX_LEGAL_KELVIN = 0x4e20; // 20000 K

/**
 * The fallback range: the owner's own bulb, measured with the
 * manufacturer's own app, used when the node refuses to report its range
 * (as that bulb does) and the user has not corrected it in settings. NOT a
 * specification value and NOT a general-purpose default - see this module's
 * header for what goes wrong on a bulb with a different range, and which
 * source fixes it.
 */
export const DEFAULT_TEMPERATURE_RANGE: TemperatureRange = { minKelvin: 3000, maxKelvin: 6000 };

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
