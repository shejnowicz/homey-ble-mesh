import { decodeAccessMessage, encodeAccessMessage } from '../../mesh/packet/access';
import {
  encodeGenericOnOffGet,
  encodeGenericOnOffSet,
  decodeGenericOnOffStatus,
  encodeLightLightnessGet,
  encodeLightLightnessSet,
  decodeLightLightnessStatus,
  encodeLightCtlGet,
  encodeLightCtlSet,
  decodeLightCtlStatus,
  encodeLightCtlTemperatureSet,
  decodeLightCtlTemperatureStatus,
  encodeLightCtlTemperatureRangeGet,
  decodeLightCtlTemperatureRangeStatus,
  CTL_TEMPERATURE_RANGE_UNKNOWN,
  CTL_TEMPERATURE_RANGE_STATUS_SUCCESS,
  encodeLightHslGet,
  encodeLightHslSet,
  decodeLightHslStatus,
} from '../lighting';
import {
  hex,
  GENERIC_ONOFF_GET,
  GENERIC_ONOFF_SET_FULL,
  GENERIC_ONOFF_SET_MINIMAL,
  GENERIC_ONOFF_STATUS_MINIMAL,
  GENERIC_ONOFF_STATUS_WITH_TARGET,
  LIGHT_LIGHTNESS_GET,
  LIGHT_LIGHTNESS_SET_FULL,
  LIGHT_LIGHTNESS_SET_MINIMAL,
  LIGHT_LIGHTNESS_STATUS_MINIMAL,
  LIGHT_LIGHTNESS_STATUS_WITH_TARGET,
  LIGHT_CTL_GET,
  LIGHT_CTL_SET_FULL,
  LIGHT_CTL_SET_MINIMAL,
  LIGHT_CTL_SET_DELTA_UV_MIN,
  LIGHT_CTL_SET_DELTA_UV_MAX,
  LIGHT_CTL_STATUS_MINIMAL,
  LIGHT_CTL_STATUS_WITH_TARGET,
  LIGHT_CTL_TEMPERATURE_SET_FULL,
  LIGHT_CTL_TEMPERATURE_SET_MINIMAL,
  LIGHT_CTL_TEMPERATURE_SET_DELTA_UV_MIN,
  LIGHT_CTL_TEMPERATURE_SET_DELTA_UV_MAX,
  LIGHT_CTL_TEMPERATURE_STATUS_MINIMAL,
  LIGHT_CTL_TEMPERATURE_STATUS_6000K_MEASURED,
  LIGHT_CTL_TEMPERATURE_STATUS_3000K_MEASURED,
  LIGHT_CTL_TEMPERATURE_RANGE_GET,
  LIGHT_CTL_TEMPERATURE_RANGE_STATUS_OK,
  LIGHT_CTL_TEMPERATURE_RANGE_STATUS_UNKNOWN,
  LIGHT_CTL_TEMPERATURE_RANGE_STATUS_REFUSED,
  LIGHT_HSL_GET,
  LIGHT_HSL_SET_FULL,
  LIGHT_HSL_SET_MINIMAL,
  LIGHT_HSL_STATUS_MINIMAL,
  LIGHT_HSL_STATUS_WITH_REMAINING,
  SECTION_1_5_WORKED_EXAMPLE,
} from './vectors';

/**
 * Section 1.5 "Endianness and field ordering"'s own generic bit-packing
 * procedure (quoted in full in `vectors.ts`'s own header, and in
 * `lighting.ts`'s module header), implemented HERE, independently of
 * `lighting.ts`'s own `encodeTransitionTimeOctet`/`decodeTransitionTimeOctet`,
 * so it can serve as an external check against them rather than being
 * read back from the thing it is meant to verify. `fields` is table row
 * order (first row = LSBs, per Section 1.5's own words: "The least
 * significant bits (LSbs) of the number are set to the value of Field 0
 * (first row of the table)"); the assembled number is then transmitted
 * "in little-endian format (i.e., least significant octet first)" - also
 * Section 1.5's own words. Uses `BigInt` throughout so it is not itself
 * limited to 32 bits the way JS's native bitwise operators are - this is a
 * general-purpose check, not tied to this module's own field widths.
 */
function packFieldsLsbFirst(fields: ReadonlyArray<{ widthBits: number; value: number }>): Buffer {
  let acc = 0n;
  let shift = 0n;
  let totalBits = 0;
  for (const field of fields) {
    acc |= BigInt(field.value) << shift;
    shift += BigInt(field.widthBits);
    totalBits += field.widthBits;
  }
  const totalBytes = Math.ceil(totalBits / 8);
  const buffer = Buffer.alloc(totalBytes);
  for (let i = 0; i < totalBytes; i++) {
    buffer[i] = Number((acc >> BigInt(i * 8)) & 0xffn);
  }
  return buffer;
}

describe('Section 1.5 "Endianness and field ordering" - the one published anchor this task has', () => {
  test('the document\'s own worked example: field ordering + little-endian transmission (PUBLISHED)', () => {
    const packed = packFieldsLsbFirst(SECTION_1_5_WORKED_EXAMPLE.fields);
    expect(packed).toEqual(hex(SECTION_1_5_WORKED_EXAMPLE.message));
    // Cross-check the fixture's own two independent representations of the
    // published value agree with each other, not just with the helper:
    // `message`'s bytes, read back as a 32-bit little-endian unsigned
    // integer, must be the same `0x12349876` the document states directly.
    expect(hex(SECTION_1_5_WORKED_EXAMPLE.message).readUInt32LE(0)).toBe(SECTION_1_5_WORKED_EXAMPLE.assembledNumber);
  });

  test('this generic, independently-implemented procedure agrees with encodeGenericOnOffSet\'s actual Transition Time octet, for every stepResolution/numberOfSteps combination the boundary tests below exercise', () => {
    // Table 3.33 lists Transition Number of Steps FIRST, Transition Step
    // Resolution SECOND - so per Section 1.5's own general rule, Number of
    // Steps occupies the low (LSB) bits. This is the SAME claim
    // `lighting.ts`'s own module header derives from Figure 3.4 (a
    // diagram); this test derives it from Section 1.5's TEXT instead, via
    // a helper that has never seen `encodeTransitionTimeOctet`'s own code,
    // and checks the two independent derivations agree on actual module
    // output, not just on a value computed by hand twice.
    const cases: ReadonlyArray<{ stepResolution: number; numberOfSteps: number }> = [
      { stepResolution: 0, numberOfSteps: 0x00 },
      { stepResolution: 3, numberOfSteps: 0x3f },
      { stepResolution: 1, numberOfSteps: 0x0a },
      { stepResolution: 2, numberOfSteps: 0x15 },
    ];
    for (const { stepResolution, numberOfSteps } of cases) {
      const encoded = encodeGenericOnOffSet({
        onOff: 0x01,
        tid: 0x00,
        transition: { time: { stepResolution, numberOfSteps }, delay: 0x00 },
      });
      // Opcode(2) || OnOff(1) || TID(1) || TransitionTimeOctet(1) || Delay(1).
      const actualOctet = encoded[4] as number;
      const viaSection15 = packFieldsLsbFirst([
        { widthBits: 6, value: numberOfSteps },
        { widthBits: 2, value: stepResolution },
      ]);
      expect(Buffer.from([actualOctet])).toEqual(viaSection15);
    }
  });
});

// ===========================================================================
// Generic OnOff
// ===========================================================================

describe('Generic OnOff', () => {
  test('Get: Table 3.36 - Opcode only (CONSTRUCTED)', () => {
    expect(encodeGenericOnOffGet()).toEqual(hex(GENERIC_ONOFF_GET.message));
  });

  test('Set: Table 3.37, full form (CONSTRUCTED)', () => {
    const encoded = encodeGenericOnOffSet({
      onOff: GENERIC_ONOFF_SET_FULL.onOff,
      tid: GENERIC_ONOFF_SET_FULL.tid,
      transition: {
        time: { stepResolution: GENERIC_ONOFF_SET_FULL.stepResolution, numberOfSteps: GENERIC_ONOFF_SET_FULL.numberOfSteps },
        delay: GENERIC_ONOFF_SET_FULL.delay,
      },
    });
    expect(encoded).toEqual(hex(GENERIC_ONOFF_SET_FULL.message));

    // "The other direction": the generic access-layer decoder (not this
    // module's own encoder) recovers the same opcode/parameters this
    // fixture's hex was hand-assembled from, independently confirming the
    // envelope - see this module's own asymmetric API note in the test
    // file header below the Light HSL section.
    const decoded = decodeAccessMessage(encoded);
    expect(decoded?.opcode).toBe(0x8202);
    expect(decoded?.parameters).toEqual(Buffer.from([0x01, 0x05, 0x4a, 0x14]));
  });

  test('Set: Table 3.37, minimal form - onOff=Off (0x00), tid at its own top value 0xFF (CONSTRUCTED)', () => {
    expect(
      encodeGenericOnOffSet({ onOff: GENERIC_ONOFF_SET_MINIMAL.onOff, tid: GENERIC_ONOFF_SET_MINIMAL.tid }),
    ).toEqual(hex(GENERIC_ONOFF_SET_MINIMAL.message));
  });

  test('Set: TID is load-bearing - two otherwise-identical Set messages with different TID encode to different bytes', () => {
    const a = encodeGenericOnOffSet({ onOff: 0x01, tid: 0x01 });
    const b = encodeGenericOnOffSet({ onOff: 0x01, tid: 0x02 });
    expect(a).not.toEqual(b);
    // And the SAME tid (a retransmission, by this module's own caller) is
    // byte-identical - the module itself has no retry state (see
    // `lighting.ts`'s own JSDoc on `encodeGenericOnOffSet`), but it must at
    // least carry the caller's chosen tid through unchanged, both times.
    const c = encodeGenericOnOffSet({ onOff: 0x01, tid: 0x01 });
    expect(a).toEqual(c);
  });

  test('Set: Table 3.1 - onOff outside {0x00, 0x01} throws (Prohibited)', () => {
    expect(() => encodeGenericOnOffSet({ onOff: 0x02, tid: 0 })).toThrow(/onOff.*0x00 or 0x01/);
    expect(() => encodeGenericOnOffSet({ onOff: 0xff, tid: 0 })).toThrow(/onOff.*0x00 or 0x01/);
  });

  test('Set: tid outside the 1-octet domain throws', () => {
    expect(() => encodeGenericOnOffSet({ onOff: 0x01, tid: 256 })).toThrow(/tid/);
    expect(() => encodeGenericOnOffSet({ onOff: 0x01, tid: -1 })).toThrow(/tid/);
  });

  test('Status: Table 3.39, Present-only (CONSTRUCTED)', () => {
    expect(decodeGenericOnOffStatus(hex(GENERIC_ONOFF_STATUS_MINIMAL.message))).toEqual({
      presentOnOff: GENERIC_ONOFF_STATUS_MINIMAL.presentOnOff,
    });
  });

  test('Status: Table 3.39, with Target/Remaining Time (CONSTRUCTED)', () => {
    expect(decodeGenericOnOffStatus(hex(GENERIC_ONOFF_STATUS_WITH_TARGET.message))).toEqual({
      presentOnOff: GENERIC_ONOFF_STATUS_WITH_TARGET.presentOnOff,
      target: {
        onOff: GENERIC_ONOFF_STATUS_WITH_TARGET.targetOnOff,
        remainingTime: {
          stepResolution: GENERIC_ONOFF_STATUS_WITH_TARGET.stepResolution,
          numberOfSteps: GENERIC_ONOFF_STATUS_WITH_TARGET.numberOfSteps,
        },
      },
    });

    // "The other direction": hand-building the same Parameters bytes
    // through the generic access-layer ENCODER (not this module's own
    // decoder) and confirming it reproduces the fixture's published hex.
    const built = encodeAccessMessage({
      opcode: 0x8204,
      parameters: Buffer.from([
        GENERIC_ONOFF_STATUS_WITH_TARGET.presentOnOff,
        GENERIC_ONOFF_STATUS_WITH_TARGET.targetOnOff,
        0x3f,
      ]),
    });
    expect(built).toEqual(hex(GENERIC_ONOFF_STATUS_WITH_TARGET.message));
  });

  test('Status: wrong opcode decodes to null (a Light Lightness Status PDU handed to the Generic OnOff decoder)', () => {
    expect(decodeGenericOnOffStatus(hex(LIGHT_LIGHTNESS_STATUS_MINIMAL.message))).toBeNull();
  });

  test('Status: malformed Parameters length (2 octets - neither 1 nor 3) decodes to null', () => {
    expect(decodeGenericOnOffStatus(hex('82040001'))).toBeNull();
  });

  test('Status: an empty/too-short PDU decodes to null (propagated from decodeAccessMessage)', () => {
    expect(decodeGenericOnOffStatus(Buffer.alloc(0))).toBeNull();
    expect(decodeGenericOnOffStatus(Buffer.from([0x7f]))).toBeNull(); // Table 3.62's own Reserved opcode.
  });
});

// ===========================================================================
// Light Lightness
// ===========================================================================

describe('Light Lightness', () => {
  test('Get: Table 6.50 - Opcode only (CONSTRUCTED)', () => {
    expect(encodeLightLightnessGet()).toEqual(hex(LIGHT_LIGHTNESS_GET.message));
  });

  test('Set: Table 6.51, full form (CONSTRUCTED)', () => {
    const encoded = encodeLightLightnessSet({
      lightness: LIGHT_LIGHTNESS_SET_FULL.lightness,
      tid: LIGHT_LIGHTNESS_SET_FULL.tid,
      transition: {
        time: { stepResolution: LIGHT_LIGHTNESS_SET_FULL.stepResolution, numberOfSteps: LIGHT_LIGHTNESS_SET_FULL.numberOfSteps },
        delay: LIGHT_LIGHTNESS_SET_FULL.delay,
      },
    });
    expect(encoded).toEqual(hex(LIGHT_LIGHTNESS_SET_FULL.message));
  });

  test('Set: Table 6.51, minimal form - lightness=0x0000 ("not emitted"), tid=0 (CONSTRUCTED)', () => {
    expect(
      encodeLightLightnessSet({ lightness: LIGHT_LIGHTNESS_SET_MINIMAL.lightness, tid: LIGHT_LIGHTNESS_SET_MINIMAL.tid }),
    ).toEqual(hex(LIGHT_LIGHTNESS_SET_MINIMAL.message));
  });

  test('Set: lightness outside the 16-bit domain throws, named by field (review finding: used to report as the generic "u16")', () => {
    expect(() => encodeLightLightnessSet({ lightness: 0x10000, tid: 0 })).toThrow(/lightness/);
    expect(() => encodeLightLightnessSet({ lightness: -1, tid: 0 })).toThrow(/lightness/);
  });

  test('Status: Table 6.53, Present-only, at the domain\'s own top value 0xFFFF (CONSTRUCTED)', () => {
    expect(decodeLightLightnessStatus(hex(LIGHT_LIGHTNESS_STATUS_MINIMAL.message))).toEqual({
      presentLightness: LIGHT_LIGHTNESS_STATUS_MINIMAL.presentLightness,
    });
  });

  test('Status: Table 6.53, with Target/Remaining Time (CONSTRUCTED)', () => {
    expect(decodeLightLightnessStatus(hex(LIGHT_LIGHTNESS_STATUS_WITH_TARGET.message))).toEqual({
      presentLightness: LIGHT_LIGHTNESS_STATUS_WITH_TARGET.presentLightness,
      target: {
        lightness: LIGHT_LIGHTNESS_STATUS_WITH_TARGET.targetLightness,
        remainingTime: {
          stepResolution: LIGHT_LIGHTNESS_STATUS_WITH_TARGET.stepResolution,
          numberOfSteps: LIGHT_LIGHTNESS_STATUS_WITH_TARGET.numberOfSteps,
        },
      },
    });
  });

  test('Status: wrong opcode (a Generic OnOff Status PDU) decodes to null', () => {
    expect(decodeLightLightnessStatus(hex(GENERIC_ONOFF_STATUS_MINIMAL.message))).toBeNull();
  });

  test('Status: malformed Parameters length (3 octets - neither 2 nor 5) decodes to null', () => {
    expect(decodeLightLightnessStatus(hex('824eff0000'))).toBeNull();
  });
});

// ===========================================================================
// Light CTL
// ===========================================================================

describe('Light CTL', () => {
  test('Get: Table 6.68 - Opcode only (CONSTRUCTED)', () => {
    expect(encodeLightCtlGet()).toEqual(hex(LIGHT_CTL_GET.message));
  });

  test('Set: Table 6.69, full form (CONSTRUCTED)', () => {
    const encoded = encodeLightCtlSet({
      lightness: LIGHT_CTL_SET_FULL.lightness,
      temperature: LIGHT_CTL_SET_FULL.temperature,
      deltaUv: LIGHT_CTL_SET_FULL.deltaUv,
      tid: LIGHT_CTL_SET_FULL.tid,
      transition: {
        time: { stepResolution: LIGHT_CTL_SET_FULL.stepResolution, numberOfSteps: LIGHT_CTL_SET_FULL.numberOfSteps },
        delay: LIGHT_CTL_SET_FULL.delay,
      },
    });
    expect(encoded).toEqual(hex(LIGHT_CTL_SET_FULL.message));
  });

  test('Set: Table 6.69, minimal form, Temperature at Table 6.6\'s own lower boundary 0x0320 (800 K) (CONSTRUCTED)', () => {
    expect(
      encodeLightCtlSet({
        lightness: LIGHT_CTL_SET_MINIMAL.lightness,
        temperature: LIGHT_CTL_SET_MINIMAL.temperature,
        deltaUv: LIGHT_CTL_SET_MINIMAL.deltaUv,
        tid: LIGHT_CTL_SET_MINIMAL.tid,
      }),
    ).toEqual(hex(LIGHT_CTL_SET_MINIMAL.message));
  });

  test('Set: Delta UV at the signed 16-bit domain\'s own minimum, -32768 (CONSTRUCTED)', () => {
    expect(
      encodeLightCtlSet({
        lightness: LIGHT_CTL_SET_DELTA_UV_MIN.lightness,
        temperature: LIGHT_CTL_SET_DELTA_UV_MIN.temperature,
        deltaUv: LIGHT_CTL_SET_DELTA_UV_MIN.deltaUv,
        tid: LIGHT_CTL_SET_DELTA_UV_MIN.tid,
        transition: {
          time: { stepResolution: LIGHT_CTL_SET_DELTA_UV_MIN.stepResolution, numberOfSteps: LIGHT_CTL_SET_DELTA_UV_MIN.numberOfSteps },
          delay: LIGHT_CTL_SET_DELTA_UV_MIN.delay,
        },
      }),
    ).toEqual(hex(LIGHT_CTL_SET_DELTA_UV_MIN.message));
  });

  test('Set: Delta UV at the signed 16-bit domain\'s own maximum, 32767 (CONSTRUCTED)', () => {
    expect(
      encodeLightCtlSet({
        lightness: LIGHT_CTL_SET_DELTA_UV_MAX.lightness,
        temperature: LIGHT_CTL_SET_DELTA_UV_MAX.temperature,
        deltaUv: LIGHT_CTL_SET_DELTA_UV_MAX.deltaUv,
        tid: LIGHT_CTL_SET_DELTA_UV_MAX.tid,
      }),
    ).toEqual(hex(LIGHT_CTL_SET_DELTA_UV_MAX.message));
  });

  test('Set: lightness outside the 16-bit domain throws, named by field (review finding)', () => {
    expect(() => encodeLightCtlSet({ lightness: 0x10000, temperature: 0x0320, deltaUv: 0, tid: 0 })).toThrow(/lightness/);
  });

  test('Set: Table 6.6 - temperature outside [0x0320, 0x4E20] throws (Prohibited)', () => {
    expect(() => encodeLightCtlSet({ lightness: 0, temperature: 0x031f, deltaUv: 0, tid: 0 })).toThrow(/temperature/);
    expect(() => encodeLightCtlSet({ lightness: 0, temperature: 0x4e21, deltaUv: 0, tid: 0 })).toThrow(/temperature/);
  });

  test('Set: deltaUv outside the signed 16-bit domain throws', () => {
    expect(() => encodeLightCtlSet({ lightness: 0, temperature: 0x0320, deltaUv: -32769, tid: 0 })).toThrow(/deltaUv/);
    expect(() => encodeLightCtlSet({ lightness: 0, temperature: 0x0320, deltaUv: 32768, tid: 0 })).toThrow(/deltaUv/);
  });

  test('Status: Table 6.71, Present-only, Temperature at Table 6.6\'s own upper boundary 0x4E20 (20000 K) (CONSTRUCTED)', () => {
    expect(decodeLightCtlStatus(hex(LIGHT_CTL_STATUS_MINIMAL.message))).toEqual({
      presentLightness: LIGHT_CTL_STATUS_MINIMAL.presentLightness,
      presentTemperature: LIGHT_CTL_STATUS_MINIMAL.presentTemperature,
    });
  });

  test('Status: Table 6.71, with the full Target group - every field a distinct value, so a pairwise swap among Present/Target Lightness/Temperature is detectable (CONSTRUCTED)', () => {
    expect(decodeLightCtlStatus(hex(LIGHT_CTL_STATUS_WITH_TARGET.message))).toEqual({
      presentLightness: LIGHT_CTL_STATUS_WITH_TARGET.presentLightness,
      presentTemperature: LIGHT_CTL_STATUS_WITH_TARGET.presentTemperature,
      target: {
        lightness: LIGHT_CTL_STATUS_WITH_TARGET.targetLightness,
        temperature: LIGHT_CTL_STATUS_WITH_TARGET.targetTemperature,
        remainingTime: {
          stepResolution: LIGHT_CTL_STATUS_WITH_TARGET.stepResolution,
          numberOfSteps: LIGHT_CTL_STATUS_WITH_TARGET.numberOfSteps,
        },
      },
    });
  });

  test('Status: wrong opcode decodes to null', () => {
    expect(decodeLightCtlStatus(hex(LIGHT_HSL_STATUS_MINIMAL.message))).toBeNull();
  });

  test('Status: malformed Parameters length (5 octets - neither 4 nor 9) decodes to null', () => {
    expect(decodeLightCtlStatus(hex('82605555204e00'))).toBeNull();
  });
});

// ===========================================================================
// Light CTL Temperature (a SEPARATE model from Light CTL - see
// `lighting.ts`'s own section header). The two measured-on-hardware Status
// fixtures are the only checks in this file that did not come from this
// project's own reading of the field table, so they are what catches a
// layout mistake a hand-built fixture would simply share.
// ===========================================================================

describe('Light CTL Temperature', () => {
  test('Set: Table 6.73, full form (CONSTRUCTED)', () => {
    const encoded = encodeLightCtlTemperatureSet({
      temperature: LIGHT_CTL_TEMPERATURE_SET_FULL.temperature,
      deltaUv: LIGHT_CTL_TEMPERATURE_SET_FULL.deltaUv,
      tid: LIGHT_CTL_TEMPERATURE_SET_FULL.tid,
      transition: {
        time: {
          stepResolution: LIGHT_CTL_TEMPERATURE_SET_FULL.stepResolution,
          numberOfSteps: LIGHT_CTL_TEMPERATURE_SET_FULL.numberOfSteps,
        },
        delay: LIGHT_CTL_TEMPERATURE_SET_FULL.delay,
      },
    });
    expect(encoded).toEqual(hex(LIGHT_CTL_TEMPERATURE_SET_FULL.message));
  });

  test('Set: Table 6.73, minimal form (CONSTRUCTED)', () => {
    expect(
      encodeLightCtlTemperatureSet({
        temperature: LIGHT_CTL_TEMPERATURE_SET_MINIMAL.temperature,
        deltaUv: LIGHT_CTL_TEMPERATURE_SET_MINIMAL.deltaUv,
        tid: LIGHT_CTL_TEMPERATURE_SET_MINIMAL.tid,
      }),
    ).toEqual(hex(LIGHT_CTL_TEMPERATURE_SET_MINIMAL.message));
  });

  test('Set: Delta UV at the signed 16-bit domain\'s own minimum and maximum (CONSTRUCTED)', () => {
    for (const fixture of [LIGHT_CTL_TEMPERATURE_SET_DELTA_UV_MIN, LIGHT_CTL_TEMPERATURE_SET_DELTA_UV_MAX]) {
      expect(
        encodeLightCtlTemperatureSet({ temperature: fixture.temperature, deltaUv: fixture.deltaUv, tid: fixture.tid }),
      ).toEqual(hex(fixture.message));
    }
  });

  test('Set: carries NO Lightness field - the whole practical difference from Light CTL Set (Table 6.73 vs Table 6.69)', () => {
    // Parameters are Temperature(2) || DeltaUV(2) || TID(1) = 5 octets, so
    // the whole message is 2 + 5 = 7. Light CTL Set's own minimal form is
    // two octets longer, carrying a Lightness this message has no field
    // for. Pinned as a LENGTH, independently of the byte fixtures above,
    // because "a temperature change cannot disturb brightness" is the
    // reason this model is used at all.
    const encoded = encodeLightCtlTemperatureSet({ temperature: 0x0bb8, deltaUv: 0, tid: 0 });
    expect(encoded).toHaveLength(7);
  });

  test('Set: Table 6.6 - temperature outside [0x0320, 0x4E20] throws (Prohibited)', () => {
    expect(() => encodeLightCtlTemperatureSet({ temperature: 0x031f, deltaUv: 0, tid: 0 })).toThrow(/temperature/);
    expect(() => encodeLightCtlTemperatureSet({ temperature: 0x4e21, deltaUv: 0, tid: 0 })).toThrow(/temperature/);
  });

  test('Set: deltaUv outside the signed 16-bit domain throws, named by field', () => {
    expect(() => encodeLightCtlTemperatureSet({ temperature: 0x0320, deltaUv: -32769, tid: 0 })).toThrow(/deltaUv/);
    expect(() => encodeLightCtlTemperatureSet({ temperature: 0x0320, deltaUv: 32768, tid: 0 })).toThrow(/deltaUv/);
  });

  test('Set: tid outside the 1-octet domain throws, named by field', () => {
    expect(() => encodeLightCtlTemperatureSet({ temperature: 0x0320, deltaUv: 0, tid: 0x100 })).toThrow(/tid/);
  });

  test('Status: Table 6.75, Present-only, Delta UV at the signed minimum (CONSTRUCTED)', () => {
    expect(decodeLightCtlTemperatureStatus(hex(LIGHT_CTL_TEMPERATURE_STATUS_MINIMAL.message))).toEqual({
      presentTemperature: LIGHT_CTL_TEMPERATURE_STATUS_MINIMAL.presentTemperature,
      presentDeltaUv: LIGHT_CTL_TEMPERATURE_STATUS_MINIMAL.presentDeltaUv,
    });
  });

  test.each([
    ['6000 K', LIGHT_CTL_TEMPERATURE_STATUS_6000K_MEASURED],
    ['3000 K', LIGHT_CTL_TEMPERATURE_STATUS_3000K_MEASURED],
  ])('Status: Table 6.75, full form - %s, MEASURED ON THE OWNER\'S BULB', (_label, fixture) => {
    expect(decodeLightCtlTemperatureStatus(hex(fixture.message))).toEqual({
      presentTemperature: fixture.presentTemperature,
      presentDeltaUv: fixture.presentDeltaUv,
      target: {
        temperature: fixture.targetTemperature,
        deltaUv: fixture.targetDeltaUv,
        remainingTime: { stepResolution: fixture.stepResolution, numberOfSteps: fixture.numberOfSteps },
      },
    });
  });

  test('Status: the two measured fixtures decode to the two kelvin values that were actually written (6000 and 3000)', () => {
    // The point of this one is the NUMBER, not the structure: a big-endian
    // read of either fixture produces 0x7017 (28695) / 0xB80B (47115),
    // both outside Table 6.6's legal range entirely - so this is the
    // check that would have caught the byte order even with no field-table
    // reading at all.
    expect(decodeLightCtlTemperatureStatus(hex(LIGHT_CTL_TEMPERATURE_STATUS_6000K_MEASURED.message))?.presentTemperature).toBe(6000);
    expect(decodeLightCtlTemperatureStatus(hex(LIGHT_CTL_TEMPERATURE_STATUS_3000K_MEASURED.message))?.presentTemperature).toBe(3000);
  });

  test('Status: wrong opcode decodes to null - Light CTL Status (0x8260) is NOT a Light CTL Temperature Status (0x8266)', () => {
    expect(decodeLightCtlTemperatureStatus(hex(LIGHT_CTL_STATUS_MINIMAL.message))).toBeNull();
    // ...and the converse, since both decoders accept a 4-octet and a
    // 9-octet Parameters field: the composite decoder must not accept the
    // measured Temperature Status either.
    expect(decodeLightCtlStatus(hex(LIGHT_CTL_TEMPERATURE_STATUS_6000K_MEASURED.message))).toBeNull();
  });

  test('Status: malformed Parameters length (6 octets - neither 4 nor 9) decodes to null', () => {
    expect(decodeLightCtlTemperatureStatus(hex('826620030080ff'))).toBeNull();
  });
});

describe('Light CTL Temperature Range', () => {
  test('Get: Table 6.76 - Opcode only (CONSTRUCTED)', () => {
    expect(encodeLightCtlTemperatureRangeGet()).toEqual(hex(LIGHT_CTL_TEMPERATURE_RANGE_GET.message));
  });

  test('Status: Table 6.79 - Status Code || Range Min || Range Max (CONSTRUCTED)', () => {
    expect(decodeLightCtlTemperatureRangeStatus(hex(LIGHT_CTL_TEMPERATURE_RANGE_STATUS_OK.message))).toEqual({
      statusCode: CTL_TEMPERATURE_RANGE_STATUS_SUCCESS,
      rangeMin: LIGHT_CTL_TEMPERATURE_RANGE_STATUS_OK.rangeMin,
      rangeMax: LIGHT_CTL_TEMPERATURE_RANGE_STATUS_OK.rangeMax,
    });
  });

  test('Status: Table 6.8\'s own 0xFFFF row - a node that answered and still said nothing', () => {
    const decoded = decodeLightCtlTemperatureRangeStatus(hex(LIGHT_CTL_TEMPERATURE_RANGE_STATUS_UNKNOWN.message));
    expect(decoded).toEqual({ statusCode: 0x00, rangeMin: CTL_TEMPERATURE_RANGE_UNKNOWN, rangeMax: CTL_TEMPERATURE_RANGE_UNKNOWN });
  });

  test('Status: a non-success Status Code (Table 7.1) is carried through raw, never rejected on decode', () => {
    expect(decodeLightCtlTemperatureRangeStatus(hex(LIGHT_CTL_TEMPERATURE_RANGE_STATUS_REFUSED.message))).toEqual({
      statusCode: LIGHT_CTL_TEMPERATURE_RANGE_STATUS_REFUSED.statusCode,
      rangeMin: LIGHT_CTL_TEMPERATURE_RANGE_STATUS_REFUSED.rangeMin,
      rangeMax: LIGHT_CTL_TEMPERATURE_RANGE_STATUS_REFUSED.rangeMax,
    });
  });

  test('Status: wrong opcode, and any Parameters length other than 5, decode to null', () => {
    expect(decodeLightCtlTemperatureRangeStatus(hex(LIGHT_CTL_TEMPERATURE_STATUS_MINIMAL.message))).toBeNull();
    expect(decodeLightCtlTemperatureRangeStatus(hex('826300b80b70'))).toBeNull();
    expect(decodeLightCtlTemperatureRangeStatus(hex('826300b80b701700'))).toBeNull();
  });
});

// ===========================================================================
// Light HSL
// ===========================================================================

describe('Light HSL', () => {
  test('Get: Table 6.84 - Opcode only (CONSTRUCTED)', () => {
    expect(encodeLightHslGet()).toEqual(hex(LIGHT_HSL_GET.message));
  });

  test('Set: Table 6.85, full form (CONSTRUCTED)', () => {
    const encoded = encodeLightHslSet({
      lightness: LIGHT_HSL_SET_FULL.lightness,
      hue: LIGHT_HSL_SET_FULL.hue,
      saturation: LIGHT_HSL_SET_FULL.saturation,
      tid: LIGHT_HSL_SET_FULL.tid,
      transition: {
        time: { stepResolution: LIGHT_HSL_SET_FULL.stepResolution, numberOfSteps: LIGHT_HSL_SET_FULL.numberOfSteps },
        delay: LIGHT_HSL_SET_FULL.delay,
      },
    });
    expect(encoded).toEqual(hex(LIGHT_HSL_SET_FULL.message));
  });

  test('Set: Table 6.85, minimal form - all-zero state fields (CONSTRUCTED)', () => {
    expect(
      encodeLightHslSet({
        lightness: LIGHT_HSL_SET_MINIMAL.lightness,
        hue: LIGHT_HSL_SET_MINIMAL.hue,
        saturation: LIGHT_HSL_SET_MINIMAL.saturation,
        tid: LIGHT_HSL_SET_MINIMAL.tid,
      }),
    ).toEqual(hex(LIGHT_HSL_SET_MINIMAL.message));
  });

  test('Set: lightness, hue and saturation each outside the 16-bit domain throw, named by their own field (review finding: hue/saturation had no range test at all)', () => {
    expect(() => encodeLightHslSet({ lightness: 0x10000, hue: 0, saturation: 0, tid: 0 })).toThrow(/lightness/);
    expect(() => encodeLightHslSet({ lightness: 0, hue: 0x10000, saturation: 0, tid: 0 })).toThrow(/hue/);
    expect(() => encodeLightHslSet({ lightness: 0, hue: 0, saturation: 0x10000, tid: 0 })).toThrow(/saturation/);
  });

  test('Status: Table 6.87, without Remaining Time (CONSTRUCTED) - note this model has NO Target field at all, unlike the other three', () => {
    expect(decodeLightHslStatus(hex(LIGHT_HSL_STATUS_MINIMAL.message))).toEqual({
      lightness: LIGHT_HSL_STATUS_MINIMAL.lightness,
      hue: LIGHT_HSL_STATUS_MINIMAL.hue,
      saturation: LIGHT_HSL_STATUS_MINIMAL.saturation,
    });
  });

  test('Status: Table 6.87, with Remaining Time (independently optional, not paired with a Target field) (CONSTRUCTED)', () => {
    expect(decodeLightHslStatus(hex(LIGHT_HSL_STATUS_WITH_REMAINING.message))).toEqual({
      lightness: LIGHT_HSL_STATUS_WITH_REMAINING.lightness,
      hue: LIGHT_HSL_STATUS_WITH_REMAINING.hue,
      saturation: LIGHT_HSL_STATUS_WITH_REMAINING.saturation,
      remainingTime: {
        stepResolution: LIGHT_HSL_STATUS_WITH_REMAINING.stepResolution,
        numberOfSteps: LIGHT_HSL_STATUS_WITH_REMAINING.numberOfSteps,
      },
    });
  });

  test('Status: wrong opcode decodes to null', () => {
    expect(decodeLightHslStatus(hex(LIGHT_CTL_STATUS_MINIMAL.message))).toBeNull();
  });

  test('Status: malformed Parameters length (8 octets - neither 6 nor 7) decodes to null', () => {
    expect(decodeLightHslStatus(hex('8278111122223333' + '0000'))).toBeNull();
  });
});

// ===========================================================================
// Generic Transition Time octet (Table 3.33/3.34/3.35, Figure 3.4) - shared
// by every Set's Transition Time and every Status's Remaining Time, so
// exercised once here across its own full boundary range rather than
// repeated per model above.
// ===========================================================================

describe('Generic Transition Time octet, via Generic OnOff Status (shared format)', () => {
  test('stepResolution=3, numberOfSteps=0x3F both at their own top value packs to 0xFF', () => {
    // Opcode(8204) || PresentOnOff(01) || TargetOnOff(01) || octet(FF).
    expect(decodeGenericOnOffStatus(hex('82040101ff'))).toEqual({
      presentOnOff: 0x01,
      target: { onOff: 0x01, remainingTime: { stepResolution: 3, numberOfSteps: 0x3f } },
    });
  });

  test('stepResolution=0, numberOfSteps=0 both at their own bottom value packs to 0x00', () => {
    expect(decodeGenericOnOffStatus(hex('82040101 00'.replace(/\s+/g, '')))).toEqual({
      presentOnOff: 0x01,
      target: { onOff: 0x01, remainingTime: { stepResolution: 0, numberOfSteps: 0 } },
    });
  });

  test('encodeGenericOnOffSet rejects an out-of-range stepResolution/numberOfSteps', () => {
    expect(() =>
      encodeGenericOnOffSet({ onOff: 1, tid: 0, transition: { time: { stepResolution: 4, numberOfSteps: 0 }, delay: 0 } }),
    ).toThrow(/stepResolution/);
    expect(() =>
      encodeGenericOnOffSet({ onOff: 1, tid: 0, transition: { time: { stepResolution: 0, numberOfSteps: 0x40 }, delay: 0 } }),
    ).toThrow(/numberOfSteps/);
  });

  test('encodeGenericOnOffSet rejects an out-of-range delay', () => {
    expect(() =>
      encodeGenericOnOffSet({ onOff: 1, tid: 0, transition: { time: { stepResolution: 0, numberOfSteps: 0 }, delay: 256 } }),
    ).toThrow(/delay/);
  });
});

/**
 * MODULE API NOTE on "both directions": a Set/Get message has only an
 * ENCODER here (nothing in this project decodes a Set it never sent), and a
 * Status message has only a DECODER (nothing in this project's lighting
 * client ever builds a Status it never received as a server would) - one
 * encoder per outgoing message, one decoder per incoming status, per this
 * TASK'S OWN BRIEF, which asks for exactly these three functions per model
 * (twelve total), not a single dispatcher across all four.
 *
 * CORRECTION (review finding): an earlier version of this note cited
 * `mesh/config/client.ts`'s own DESIGN rationale as the precedent for that
 * split. That was the wrong citation - that rationale argues for the
 * OPPOSITE of what this module ships: `config/client.ts` has ONE decoder,
 * `decodeConfigStatus`, dispatching on the recovered opcode across ALL of
 * its incoming messages and returning a tagged union, specifically because
 * "the caller does NOT know ahead of time which status arrived over the
 * wire." This module ships FOUR separate, non-dispatching decoders
 * instead - correct for THIS task (the brief asks for one per model by
 * name), but not an instance of `config/client.ts`'s pattern, and the
 * numbers are not comparable (four decoders are the deliverable, not a
 * trade-off against one). The actual gap `config/client.ts`'s reasoning
 * DOES predict: nothing in this project yet dispatches across these four
 * opcodes for an UNSOLICITED Status (a node publishing a state change
 * without being polled) - whatever Homey-side adapter receives those will
 * need exactly the single-dispatcher shape `config/client.ts` already has,
 * built over `decodeGenericOnOffStatus`/`decodeLightLightnessStatus`/
 * `decodeLightCtlStatus`/`decodeLightHslStatus`, trying each (or switching
 * on the opcode directly) rather than guessing which model answered. That
 * dispatcher does not exist yet and is out of this task's scope.
 *
 * So "both directions against published bytes" for a Set/Get fixture is
 * checked as: this module's own encoder output against the fixture bytes,
 * AND (where done above, e.g. the Generic OnOff Set/Status tests) the
 * generic `packet/access.ts` encoder/decoder - NOT this module's own
 * function - independently reproducing/recovering the same bytes from the
 * fixture's individually transcribed field values. That is a genuinely
 * independent check (it never calls this module's own encode/decode), just
 * not a round trip through a second lighting-specific function this task's
 * brief does not ask this module to have.
 */
