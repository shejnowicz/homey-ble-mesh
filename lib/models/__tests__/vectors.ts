/**
 * Lighting model fixture data for `lighting.test.ts`.
 *
 * NONE OF THIS IS A PUBLISHED SAMPLE. The Bluetooth SIG "Mesh Model"
 * specification v1.1 HTML document (fetched fresh for this task, 2026-10-06,
 * from
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/MMDL_v1.1/out/en/index-en.html,
 * HTTP 200, 4,170,855 bytes - see `../lighting.ts`'s own module header for
 * the full fetch/version provenance) publishes NO wire-byte message samples
 * anywhere for any of its models - confirmed by searching the entire
 * fetched document for "sample data" (one hit, generic front-matter legal
 * boilerplate, not an actual sample) and for "Message #" (the Mesh Protocol
 * document's own published-sample section-naming convention; zero hits
 * here). Every fixture below is therefore CONSTRUCTED BY HAND from
 * `lighting.ts`'s own transcribed field layout (Tables 3.36/3.37/3.39,
 * 6.50/6.51/6.53, 6.68/6.69/6.71, 6.84/6.85/6.87) and from this document's
 * own Table 3.34/3.35 (Transition Step Resolution/Number of Steps values),
 * Figure 3.4 (Generic Transition Time bit layout) and Section 1.5
 * (Endianness and field ordering, with its own byte-exact worked example -
 * see `SECTION_1_5_WORKED_EXAMPLE` below, the one genuinely PUBLISHED
 * fixture in this file) - NEVER derived by
 * running `lighting.ts`'s own encoder and copying its output, which would
 * make every round-trip test here prove nothing beyond "the encoder and
 * decoder agree with themselves." The arithmetic was independently computed
 * twice: once by hand (shown per fixture group below) and once with a
 * throwaway Python script implementing the SAME transcribed layout from
 * scratch (not calling into this project's TypeScript at all), and the two
 * were compared byte-for-byte before being trusted.
 *
 * OPCODES used throughout (see `lighting.ts`'s own OPCODE PROVENANCE note
 * for the Assigned Numbers document this comes from): Generic OnOff
 * Get/Set/Status = `82 01`/`82 02`/`82 04`; Light Lightness
 * Get/Set/Status = `82 4B`/`82 4C`/`82 4E`; Light CTL Get/Set/Status =
 * `82 5D`/`82 5E`/`82 60`; Light HSL Get/Set/Status = `82 6D`/`82 76`/
 * `82 78`. All twelve are 2-octet SIG opcodes, written MSB-first on the
 * wire (Table 3.62) - e.g. opcode `82 01` is the bytes `0x82, 0x01` in that
 * order, not byte-swapped (the vendor-opcode company-ID byte-swap
 * `packet/access.ts`'s own module header warns about does not apply to the
 * 2-octet SIG form at all).
 *
 * TRANSITION TIME OCTET (Table 3.33/3.34/3.35, Figure 3.4, Section 1.5 -
 * see `lighting.ts`'s own header note for the bit-order derivation from
 * both the figure and Section 1.5's own general text, independently
 * agreeing): `octet = (numberOfSteps & 0x3F) | ((stepResolution & 0x3) << 6)`.
 * Worked example used repeatedly below: stepResolution=1 (Table 3.34's own
 * row for value 0b01: "The Transition Step Resolution is 1 second"),
 * numberOfSteps=0x0A -> octet = 0x0A | (0b01 << 6) = 0x0A | 0x40 = 0x4A.
 *
 * ERRATA NOTE (found while transcribing Section 3.3.1.2.2 "Receiving a
 * Generic OnOff Set / Generic OnOff Set Unacknowledged message" for
 * `lighting.ts`'s own TID-rule citation, not itself fixture data): that
 * section's own cross-reference to the transition-time computation section
 * renders, in the raw fetched HTML, as visible link text "Section
 * 3.2.9.33.2.9.1" - this is the document's OWN authoring artifact, not an
 * extraction mistake on this project's side: the anchor's `title` attribute
 * (the hover tooltip) reads correctly, "3.2.9.3.&nbsp;Computation of
 * transition time", while the rendered link text has "3.2.9.3" immediately
 * followed by a duplicated, truncated "3.2.9.1" with no separator -
 * `3.2.9.3` + `3.2.9.1` = `3.2.9.33.2.9.1`. The real section is 3.2.9.3
 * ("Computation of transition time"); `lighting.ts` cites that corrected
 * number, not the garbled visible text, and does not quote this particular
 * sentence verbatim anywhere (so the garbled text itself never had to be
 * transcribed as a quotation).
 */

export const hex = (s: string): Buffer => Buffer.from(s.replace(/\s+/g, ''), 'hex');

// ===========================================================================
// Generic OnOff (Table 3.36/3.37/3.39). Table 3.1: OnOff is 0x00 (Off) or
// 0x01 (On) only.
// ===========================================================================

/** Table 3.36 "Generic OnOff Get message structure": Opcode only. CONSTRUCTED. */
export const GENERIC_ONOFF_GET = {
  message: '8201',
};

/**
 * Table 3.37 "Generic OnOff Set message structure", full form (Transition
 * Time/Delay present). CONSTRUCTED. onOff=0x01, tid=0x05,
 * transition={stepResolution:1 (1 s), numberOfSteps:0x0A}, delay=0x14.
 * Transition octet = 0x0A | (1<<6) = 0x4A (worked example above).
 * Parameters = OnOff(01) || TID(05) || TransitionTime(4A) || Delay(14).
 */
export const GENERIC_ONOFF_SET_FULL = {
  onOff: 0x01,
  tid: 0x05,
  stepResolution: 1,
  numberOfSteps: 0x0a,
  delay: 0x14,
  message: '820201054a14',
};

/** Table 3.37, minimal form (no Transition Time/Delay). CONSTRUCTED. onOff=0x00 ("Off" - distinct from the full fixture's 0x01, so a field swap with TID is detectable), tid=0xFF (the 1-octet domain's own top value). */
export const GENERIC_ONOFF_SET_MINIMAL = {
  onOff: 0x00,
  tid: 0xff,
  message: '820200ff',
};

/** Table 3.39 "Generic OnOff Status message structure", Present-only. CONSTRUCTED. */
export const GENERIC_ONOFF_STATUS_MINIMAL = {
  presentOnOff: 0x01,
  message: '820401',
};

/** Table 3.39, with Target/Remaining Time. CONSTRUCTED. present=0x00, target=0x01 (distinct, swap-detectable), remainingTime={stepResolution:0 (100 ms), numberOfSteps:0x3F (context-specific, Table 3.35's own top value)}. Remaining Time octet = 0x3F | (0<<6) = 0x3F. */
export const GENERIC_ONOFF_STATUS_WITH_TARGET = {
  presentOnOff: 0x00,
  targetOnOff: 0x01,
  stepResolution: 0,
  numberOfSteps: 0x3f,
  message: '820400013f',
};

// ===========================================================================
// Light Lightness (Table 6.50/6.51/6.53). Table 6.2: Lightness is the full
// 16-bit domain, no Prohibited values.
// ===========================================================================

export const LIGHT_LIGHTNESS_GET = {
  message: '824b',
};

/** Table 6.51, full form. CONSTRUCTED. lightness=0x1234, tid=0x07, transition={stepResolution:2 (10 s), numberOfSteps:0x15}, delay=0x0A. Transition octet = 0x15 | (2<<6) = 0x15 | 0x80 = 0x95. Lightness LE -> `34 12`. */
export const LIGHT_LIGHTNESS_SET_FULL = {
  lightness: 0x1234,
  tid: 0x07,
  stepResolution: 2,
  numberOfSteps: 0x15,
  delay: 0x0a,
  message: '824c341207950a',
};

/** Table 6.51, minimal form. CONSTRUCTED. lightness=0x0000 ("Light is not emitted"), tid=0x00. */
export const LIGHT_LIGHTNESS_SET_MINIMAL = {
  lightness: 0x0000,
  tid: 0x00,
  message: '824c000000',
};

/** Table 6.53, Present-only. CONSTRUCTED. presentLightness=0xFFFF ("highest perceived lightness"). */
export const LIGHT_LIGHTNESS_STATUS_MINIMAL = {
  presentLightness: 0xffff,
  message: '824effff',
};

/** Table 6.53, with Target/Remaining Time. CONSTRUCTED. present=0x0001, target=0xFFFE (distinct, swap-detectable), remainingTime={stepResolution:3 (10 min), numberOfSteps:0x00 (immediate)}. Remaining Time octet = 0x00 | (3<<6) = 0xC0. Present LE `01 00`, Target LE `FE FF`. */
export const LIGHT_LIGHTNESS_STATUS_WITH_TARGET = {
  presentLightness: 0x0001,
  targetLightness: 0xfffe,
  stepResolution: 3,
  numberOfSteps: 0x00,
  message: '824e0100feffc0',
};

// ===========================================================================
// Light CTL (Table 6.68/6.69/6.71). Table 6.11: CTL Lightness full 16-bit
// domain; Table 6.6: CTL Temperature ONLY 0x0320-0x4E20 (800-20000 K) legal;
// Table 6.9: CTL Delta UV signed 16-bit, full domain.
// ===========================================================================

export const LIGHT_CTL_GET = {
  message: '825d',
};

/**
 * Table 6.69, full form. CONSTRUCTED. lightness=0x8000, temperature=0x1000
 * (4096 K, inside [0x0320,0x4E20]), deltaUv=-1 (0xFFFF two's-complement LE
 * `FF FF`), tid=0x42, transition={stepResolution:0 (100 ms),
 * numberOfSteps:0x01}, delay=0x05. Transition octet = 0x01 | (0<<6) = 0x01.
 * Lightness LE `00 80`, Temperature LE `00 10`.
 */
export const LIGHT_CTL_SET_FULL = {
  lightness: 0x8000,
  temperature: 0x1000,
  deltaUv: -1,
  tid: 0x42,
  stepResolution: 0,
  numberOfSteps: 0x01,
  delay: 0x05,
  message: '825e00800010ffff420105',
};

/** Table 6.69, minimal form, at CTL Temperature's own LOWER boundary (0x0320 = 800 K, Table 6.6's own range floor). CONSTRUCTED. lightness=0x0000, deltaUv=0 ("Delta UV equal to 0", Table 6.9), tid=0x00. */
export const LIGHT_CTL_SET_MINIMAL = {
  lightness: 0x0000,
  temperature: 0x0320,
  deltaUv: 0,
  tid: 0x00,
  message: '825e00002003000000',
};

/** Table 6.69, Delta UV at the signed 16-bit domain's own minimum, -32768 (wire `0x8000` LE `00 80`), paired with distinct lightness/temperature/tid/transition values so no adjacent-field swap goes unnoticed. CONSTRUCTED. */
export const LIGHT_CTL_SET_DELTA_UV_MIN = {
  lightness: 0x1111,
  temperature: 0x0320,
  deltaUv: -32768,
  tid: 0x09,
  stepResolution: 3,
  numberOfSteps: 0x3f,
  delay: 0xaa,
  message: '825e11112003008009ffaa',
};

/** Table 6.69, Delta UV at the signed 16-bit domain's own maximum, 32767 (wire `0x7FFF` LE `FF 7F`), minimal form. CONSTRUCTED. */
export const LIGHT_CTL_SET_DELTA_UV_MAX = {
  lightness: 0x2222,
  temperature: 0x4e20,
  deltaUv: 32767,
  tid: 0x0a,
  message: '825e2222204eff7f0a',
};

/** Table 6.71, Present-only. CONSTRUCTED. presentLightness=0x5555, presentTemperature=0x4E20 (20000 K, Table 6.6's own range ceiling). */
export const LIGHT_CTL_STATUS_MINIMAL = {
  presentLightness: 0x5555,
  presentTemperature: 0x4e20,
  message: '82605555204e',
};

/** Table 6.71, with the full Target group (Target CTL Lightness/Temperature/Remaining Time - all three, or none, per Table 6.71's own C.1 footnote). CONSTRUCTED. present=(0x0001,0x0320), target=(0xFFFF,0x4E20) (every one of the four 16-bit fields a distinct value, so ANY pairwise field swap among them is detectable), remainingTime={stepResolution:1 (1 s), numberOfSteps:0x3E (Table 3.35's own top "number of steps" row, distinct from 0x3F "context specific")}. Remaining Time octet = 0x3E | (1<<6) = 0x7E. */
export const LIGHT_CTL_STATUS_WITH_TARGET = {
  presentLightness: 0x0001,
  presentTemperature: 0x0320,
  targetLightness: 0xffff,
  targetTemperature: 0x4e20,
  stepResolution: 1,
  numberOfSteps: 0x3e,
  message: '826001002003ffff204e7e',
};

// ===========================================================================
// Light HSL (Table 6.84/6.85/6.87). Table 6.18/6.12/6.15: Lightness/Hue/
// Saturation all full 16-bit domain, no Prohibited values. Table 6.87 has
// NO Target fields at all (see `lighting.ts`'s own note on this structural
// difference) - Remaining Time is a single, independently optional field.
// ===========================================================================

export const LIGHT_HSL_GET = {
  message: '826d',
};

/** Table 6.85, full form. CONSTRUCTED. lightness=0x2222, hue=0x4000, saturation=0x8000 (three distinct values, swap-detectable), tid=0x11, transition={stepResolution:1 (1 s), numberOfSteps:0x05}, delay=0x03. Transition octet = 0x05 | (1<<6) = 0x45. */
export const LIGHT_HSL_SET_FULL = {
  lightness: 0x2222,
  hue: 0x4000,
  saturation: 0x8000,
  tid: 0x11,
  stepResolution: 1,
  numberOfSteps: 0x05,
  delay: 0x03,
  message: '8276222200400080114503',
};

/** Table 6.85, minimal form (all-zero state fields, to confirm the all-zero case is not mistaken for "absent"). CONSTRUCTED. */
export const LIGHT_HSL_SET_MINIMAL = {
  lightness: 0x0000,
  hue: 0x0000,
  saturation: 0x0000,
  tid: 0x00,
  message: '827600000000000000',
};

/**
 * Table 6.87, without Remaining Time. CONSTRUCTED.
 *
 * REVIEW FINDING, FIXED: the original version of this fixture used
 * 0x1111/0x2222/0x3333 - three DISTINCT values, enough to catch a field
 * swap, but each one is byte-palindromic (its high and low octet are
 * identical), so `readUInt16LE` and `readUInt16BE` produce the exact same
 * NUMBER for every one of them. A reviewer flipped all three reads in
 * `decodeLightHslStatus` to big-endian and the whole suite still passed -
 * for this one message, where there is no published sample to fall back
 * on, the hand-built fixture was the entire safety net, and it was blind
 * to the one failure mode (wrong byte order) that matters most for a hue
 * value: swap the octets and Homey paints the wrong colour. Replaced with
 * 0x1234/0x5678/0x9abc - still three distinct values (swap-detectable),
 * and now each one's own two octets differ from each other too
 * (endianness-detectable): 0x1234 LE is `34 12`, BE would read back as
 * 0x3412 (13330), not 0x1234 (4660).
 */
export const LIGHT_HSL_STATUS_MINIMAL = {
  lightness: 0x1234,
  hue: 0x5678,
  saturation: 0x9abc,
  message: '827834127856bc9a',
};

/** Table 6.87, with Remaining Time. CONSTRUCTED. Same three (now endianness-sensitive - see `LIGHT_HSL_STATUS_MINIMAL`'s own note) state values as the minimal fixture, plus remainingTime={stepResolution:2 (10 s), numberOfSteps:0x10}. Remaining Time octet = 0x10 | (2<<6) = 0x90. */
export const LIGHT_HSL_STATUS_WITH_REMAINING = {
  lightness: 0x1234,
  hue: 0x5678,
  saturation: 0x9abc,
  stepResolution: 2,
  numberOfSteps: 0x10,
  message: '827834127856bc9a90',
};

// ===========================================================================
// Section 1.5 "Endianness and field ordering" - the document's own general
// bit-packing/endianness rule (quoted in full in `lighting.ts`'s own
// module header), WITH a byte-exact worked example. Not a message sample
// (so the NO PUBLISHED MESSAGE SAMPLES note above still stands - nothing
// here is specific to any of the twelve messages this file otherwise
// fixtures), but a genuine published anchor for the exact two rules every
// other fixture in this file depends on: (1) a table's FIRST row occupies
// the LEAST significant bits of a packed multi-field value, and (2) the
// assembled value is transmitted little-endian (least significant octet
// first). `lighting.test.ts` uses this to KAT-test a small helper that
// implements Section 1.5's general procedure from scratch, independently
// of this module's own `encodeTransitionTimeOctet`, and then cross-checks
// that helper against `encodeGenericOnOffSet`'s actual output for the
// Transition Time octet's own two-field layout (Table 3.33: Number of
// Steps first/LSBs, Step Resolution second/MSBs) - so this one published
// example ends up anchoring the implementation too, not just an isolated
// utility.
//
// Quoted in full: "In order to convert the data structure defined in a
// table into a series of octets the following procedure is used. The
// binary number with N unassigned bits is created. The number of bits N
// in the number is equal to the sum of the number of bits of every field
// in the table. The least significant bits (LSbs) of the number are set to
// the value of Field 0 (first row of the table), then the number's
// unassigned LSbs are set to the value of Field 1. This procedure is
// continued for consecutive fields of the table and ends when the most
// significant bits (MSbs) of the number are set to the value of last field
// of the table. As a final step the number is transmitted in little-endian
// format (i.e., least significant octet first)." Then its own worked
// example, quoted in full: "For example, the field 0 is 4 bits wide and
// has a value of 0x6, field 1 is 12 bits wide and has a value of 0x987,
// and field 2 is 16 bits wide and has a value of 0x1234. The value of the
// binary number is 0x12349876 and shall be transmitted as 0x76, 0x98,
// 0x34, 0x12."
//
// Hand-verified independently of the document's own stated result: field0
// (4 bits, 0x6) in bits 0-3, field1 (12 bits, 0x987) in bits 4-15, field2
// (16 bits, 0x1234) in bits 16-31 -> (0x1234 << 16) | (0x987 << 4) | 0x6 =
// 0x12340000 | 0x9870 | 0x6 = 0x12349876, matching the document's own
// stated binary number exactly. Little-endian octets of 0x12349876:
// 0x76, 0x98, 0x34, 0x12 - matching the document's own stated transmission
// exactly.
// ===========================================================================

export const SECTION_1_5_WORKED_EXAMPLE = {
  fields: [
    { widthBits: 4, value: 0x6 },
    { widthBits: 12, value: 0x987 },
    { widthBits: 16, value: 0x1234 },
  ],
  assembledNumber: 0x12349876,
  message: '76983412',
};
