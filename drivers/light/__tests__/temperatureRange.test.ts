import {
  DEFAULT_TEMPERATURE_RANGE,
  MAX_LEGAL_KELVIN,
  MIN_LEGAL_KELVIN,
  isUsableRange,
  rangeFromUnknown,
  resolveTemperatureRange,
} from '../temperatureRange';

/**
 * The three sources a bulb's colour-temperature range can come from, and
 * their precedence — the owner's own question answered in code: "how will
 * the algorithm know the range for OTHER bulbs?"
 *
 * The answer is NOT a constant, and these tests are what stop it quietly
 * becoming one again: the only way the documented fallback is reached is
 * when neither the user nor the node supplied a usable range.
 */
describe('resolveTemperatureRange', () => {
  const fromNode = { minKelvin: 2200, maxKelvin: 6500 };
  const fromSettings = { minKelvin: 2700, maxKelvin: 4000 };

  test('1. the user\'s own setting wins over everything, including what the node reported', () => {
    // Deliberate: the probe ran once, at pairing time, possibly months ago;
    // the user can see the lamp.
    expect(resolveTemperatureRange(fromSettings, fromNode)).toEqual(fromSettings);
  });

  test('2. the node\'s own reported range is used when there is no setting', () => {
    expect(resolveTemperatureRange(null, fromNode)).toEqual(fromNode);
    expect(resolveTemperatureRange(undefined, fromNode)).toEqual(fromNode);
  });

  test('3. the documented fallback only when neither supplied one', () => {
    expect(resolveTemperatureRange(null, null)).toEqual(DEFAULT_TEMPERATURE_RANGE);
  });

  test('an UNUSABLE higher-precedence value falls through rather than being clamped into shape', () => {
    // A user who typed the two numbers the wrong way round has not supplied
    // a range; inventing one out of the mistake would hide it.
    expect(resolveTemperatureRange({ minKelvin: 6000, maxKelvin: 3000 }, fromNode)).toEqual(fromNode);
    // ...and a node reporting something Prohibited (Table 6.6) is skipped
    // the same way, all the way down to the fallback.
    expect(resolveTemperatureRange(null, { minKelvin: 100, maxKelvin: 30000 })).toEqual(DEFAULT_TEMPERATURE_RANGE);
  });

  test('the documented fallback is Table 6.6\'s own FULL legal span, 800-20000 K', () => {
    // Pinned as a value, and changed from one bulb's measured 3000-6000 K
    // after hardware showed why that was wrong: a bulb that stretches its
    // whole output across whatever range it is given was driven through a
    // sixth of itself. Only a default that makes no claim about what the
    // numbers MEAN is safe for both kinds of bulb — see temperatureRange.ts's
    // own header.
    expect(DEFAULT_TEMPERATURE_RANGE).toEqual({ minKelvin: 800, maxKelvin: 20000 });
    // ...and it is exactly the legal span, not a wide range that happens to
    // look like one.
    expect(DEFAULT_TEMPERATURE_RANGE).toEqual({ minKelvin: MIN_LEGAL_KELVIN, maxKelvin: MAX_LEGAL_KELVIN });
  });

  test('a user who HAS narrowed the range still wins over the new, wider default', () => {
    // The owner's deliberate 800/20000 is the case that prompted this, but
    // the general rule is what matters: widening the fallback must never
    // reach a device whose own setting says something else.
    expect(resolveTemperatureRange({ minKelvin: 2700, maxKelvin: 4000 }, null)).toEqual({ minKelvin: 2700, maxKelvin: 4000 });
  });
});

describe('isUsableRange', () => {
  test('Table 6.6\'s own boundaries are usable; one step outside either is not', () => {
    expect(isUsableRange({ minKelvin: MIN_LEGAL_KELVIN, maxKelvin: MAX_LEGAL_KELVIN })).toBe(true);
    expect(isUsableRange({ minKelvin: MIN_LEGAL_KELVIN - 1, maxKelvin: MAX_LEGAL_KELVIN })).toBe(false);
    expect(isUsableRange({ minKelvin: MIN_LEGAL_KELVIN, maxKelvin: MAX_LEGAL_KELVIN + 1 })).toBe(false);
  });

  test('Table 6.6\'s own boundary values are 800 K and 20000 K', () => {
    expect(MIN_LEGAL_KELVIN).toBe(0x0320);
    expect(MAX_LEGAL_KELVIN).toBe(0x4e20);
  });

  test('a zero-width or inverted range is refused — the conversion would divide by zero or run backwards', () => {
    expect(isUsableRange({ minKelvin: 4000, maxKelvin: 4000 })).toBe(false);
    expect(isUsableRange({ minKelvin: 6000, maxKelvin: 3000 })).toBe(false);
  });

  test('nothing at all is not a range', () => {
    expect(isUsableRange(null)).toBe(false);
    expect(isUsableRange(undefined)).toBe(false);
  });

  test('a non-integer is refused rather than silently rounded', () => {
    expect(isUsableRange({ minKelvin: 2700.5, maxKelvin: 6500 })).toBe(false);
    expect(isUsableRange({ minKelvin: Number.NaN, maxKelvin: 6500 })).toBe(false);
  });
});

describe('rangeFromUnknown', () => {
  test('two numbers become a range', () => {
    expect(rangeFromUnknown(2700, 6500)).toEqual({ minKelvin: 2700, maxKelvin: 6500 });
  });

  test('anything that is not a pair of numbers is null — a Homey setting is `unknown` until checked', () => {
    expect(rangeFromUnknown(undefined, undefined)).toBeNull();
    expect(rangeFromUnknown(null, 6500)).toBeNull();
    expect(rangeFromUnknown('2700', '6500')).toBeNull();
    expect(rangeFromUnknown(2700, {})).toBeNull();
  });

  test('a fractional setting is rounded, then checked — a usable pair survives, an unusable one still does not', () => {
    expect(rangeFromUnknown(2700.4, 6500.6)).toEqual({ minKelvin: 2700, maxKelvin: 6501 });
    expect(rangeFromUnknown(6500, 2700)).toBeNull();
  });
});
