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
  LIGHT_HSL_GET,
  LIGHT_HSL_SET_FULL,
  LIGHT_HSL_SET_MINIMAL,
  LIGHT_HSL_STATUS_MINIMAL,
  LIGHT_HSL_STATUS_WITH_REMAINING,
} from './vectors';

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

  test('Set: lightness outside the 16-bit domain throws', () => {
    expect(() => encodeLightLightnessSet({ lightness: 0x10000, tid: 0 })).toThrow();
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
 * MODULE API NOTE on "both directions": this module follows
 * `mesh/config/client.ts`'s own established, asymmetric design (its DESIGN
 * note: "one encode function per OUTGOING message... ONE decode function...
 * for every INCOMING status message") - a Set/Get message has only an
 * ENCODER here (nothing in this project decodes a Set it never sent), and a
 * Status message has only a DECODER (nothing in this project's lighting
 * client ever builds a Status it never received as a server would). So
 * "both directions against published bytes" for a Set/Get fixture is
 * checked as: this module's own encoder output against the fixture bytes,
 * AND (where done above, e.g. the Generic OnOff Set/Status tests) the
 * generic `packet/access.ts` encoder/decoder - NOT this module's own
 * function - independently reproducing/recovering the same bytes from the
 * fixture's individually transcribed field values. That is a genuinely
 * independent check (it never calls this module's own encode/decode), just
 * not a round trip through a second lighting-specific function this task's
 * brief does not ask this module to have.
 */
