import { assertRange } from '../mesh/packet/ranges';
import { encodeAccessMessage, decodeAccessMessage } from '../mesh/packet/access';

/**
 * The four lighting models this project's Homey app actually drives a bulb
 * with: Generic OnOff, Light Lightness, Light CTL (color temperature) and
 * Light HSL. For each: an encoder for the acknowledged Set message, an
 * encoder for the Get message, and a decoder for the Status message - the
 * brief's own fixed interface. Every message here is built on
 * `mesh/packet/access.ts`'s `encodeAccessMessage`/`decodeAccessMessage` (the
 * Opcode||Parameters envelope); this module never re-derives opcode framing
 * itself, same as `mesh/config/client.ts` one layer below it.
 *
 * DOCUMENT PROVENANCE - READ THIS BEFORE TOUCHING ANY CONSTANT BELOW. These
 * four models are NOT in the Mesh Protocol specification (the document
 * `mesh/packet/**`/`mesh/provisioning/**`/`mesh/config/**` are built from) -
 * they live in a separate publication, the Bluetooth SIG "Mesh Model"
 * specification. Fetched fresh for this task, 2026-10-06, as the HTML
 * document at
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/MMDL_v1.1/out/en/index-en.html
 * (HTTP 200, 4,170,855 bytes). The document's own front-matter Revision
 * History table (not a web search result) gives "v1.1", "2023-09-12",
 * "Adopted by the Bluetooth SIG Board of Directors." - confirmed by reading
 * that table directly out of the fetched HTML, not merely cited from a web
 * search summary.
 *
 * Extraction method (the brief's own required method, used throughout this
 * module and `__tests__/vectors.ts`): `</td>`/`</tr>` converted to
 * separators BEFORE tag-stripping, entities unescaped afterward, every
 * value located by section title with the section number this module
 * reports verbatim. CONFIRMED NEEDED, not assumed: this document separates
 * "Table"/"Figure" from their numbers with a literal `&nbsp;` entity in the
 * raw HTML, exactly as earlier tasks' provenance notes warn for the Mesh
 * Protocol document - grepping the fetched HTML for `Table 3.101` (an
 * ASCII space) finds nothing, while the real caption reads
 * `<div class="table-title">Table&nbsp;3.101.&nbsp;Generic OnOff Server
 * states and bindings</div>`. Every section below was located with a
 * Python extraction (`re` module) whose `\s` is Unicode-aware once the
 * entity is unescaped to an actual U+00A0, not a plain ASCII grep.
 *
 * NO PUBLISHED MESSAGE SAMPLES: unlike the Mesh Protocol document's Section
 * 8.3/8.7 (which this project's `config`/`provisioning` fixtures draw
 * known-answer tests from directly), this Mesh Model v1.1 document publishes
 * NO wire-byte sample data anywhere for any message - confirmed by
 * searching the entire fetched document for "sample data" (one hit, in the
 * front-matter's generic legal boilerplate list of "notes, appendices,
 * figures, tables, ... sample data ..." - not a real sample) and for
 * "Message #" (zero hits, the Mesh Protocol document's own section-naming
 * convention for a published sample). Every fixture in
 * `__tests__/vectors.ts` is therefore CONSTRUCTED by hand from this
 * module's own transcribed field layout, never published - labelled as
 * such throughout that file, per the brief's own instruction for exactly
 * this situation.
 *
 * OPCODE PROVENANCE: every one of these twelve messages' field tables in
 * the Mesh Model document says only that the Opcode field "shall contain
 * the opcode value for the <Message> message defined in the Assigned
 * Numbers document [10]" (verbatim, repeated per message) - so, exactly as
 * `mesh/config/client.ts`'s own OPCODE PROVENANCE note describes for the
 * Configuration messages, the actual numeric values come from the separate
 * Bluetooth SIG "Assigned Numbers" document (fetched fresh for this task,
 * 2026-10-06, from
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Assigned_Numbers/out/en/Assigned_Numbers.pdf,
 * HTTP 200, 1,324,070 bytes, "Version Date: 2026-10-05" - the identical
 * byte count and version date `config/client.ts`'s own fetch recorded,
 * confirming this is the same, unchanged document), Section 4.2.1 "Mesh
 * Model Message Opcodes by Value" and Section 4.2.2 "Mesh Model Message
 * Opcodes by Name" - both tables agree, independently, for all twelve
 * values below (cross-checked by extracting both tables with `pdftotext
 * -layout` and grepping each for every opcode byte pair used here).
 */

// ===========================================================================
// Opcodes (see the module header's OPCODE PROVENANCE note). All twelve are
// 2-octet SIG opcodes (Assigned Numbers' own "0x82 0xNN" form, first octet
// 0x82 = 0b10000010, matching Table 3.62's 2-octet marker "10xxxxxx") -
// packed per `packet/access.ts`'s own in-memory convention,
// `(octet0 << 8) | octet1`, MSB-first (the same convention
// `config/client.ts`'s `OPCODE_COMPOSITION_DATA_GET` etc. already use).
// ===========================================================================

const OPCODE_GENERIC_ONOFF_GET = 0x8201; // "Generic OnOff Get" = `0x82 0x01`.
const OPCODE_GENERIC_ONOFF_SET = 0x8202; // "Generic OnOff Set" = `0x82 0x02`.
const OPCODE_GENERIC_ONOFF_STATUS = 0x8204; // "Generic OnOff Status" = `0x82 0x04`.

const OPCODE_LIGHT_LIGHTNESS_GET = 0x824b; // "Light Lightness Get" = `0x82 0x4B`.
const OPCODE_LIGHT_LIGHTNESS_SET = 0x824c; // "Light Lightness Set" = `0x82 0x4C`.
const OPCODE_LIGHT_LIGHTNESS_STATUS = 0x824e; // "Light Lightness Status" = `0x82 0x4E`.

const OPCODE_LIGHT_CTL_GET = 0x825d; // "Light CTL Get" = `0x82 0x5D`.
const OPCODE_LIGHT_CTL_SET = 0x825e; // "Light CTL Set" = `0x82 0x5E`.
const OPCODE_LIGHT_CTL_STATUS = 0x8260; // "Light CTL Status" = `0x82 0x60`.

const OPCODE_LIGHT_HSL_GET = 0x826d; // "Light HSL Get" = `0x82 0x6D`.
const OPCODE_LIGHT_HSL_SET = 0x8276; // "Light HSL Set" = `0x82 0x76`.
const OPCODE_LIGHT_HSL_STATUS = 0x8278; // "Light HSL Status" = `0x82 0x78`.

// ===========================================================================
// Field widths and protocol-constant values.
// ===========================================================================

const MAX_OCTET = 0xff; // OnOff's own 1-octet wire width (Table 3.1 restricts its legal VALUES further, below); TID, Delay.
const MAX_UINT16 = 0xffff; // 16 bits - Lightness, CTL Lightness/Temperature, HSL Lightness/Hue/Saturation.
const MIN_INT16 = -0x8000;
const MAX_INT16 = 0x7fff; // CTL Delta UV's own 16-bit SIGNED domain (Table 6.9).

/**
 * Table 3.1 "Generic OnOff states" (Section 3.1.1) has three rows: value
 * 0x00 is "Off", value 0x01 is "On", and the range 0x02-0xFF is
 * "Prohibited". Enforced on ENCODE only (the "caller mistake on encode, not
 * malformed on decode" split `packet/access.ts`/`config/client.ts` already
 * draw throughout this project) - a Status decode never rejects whatever
 * raw octet a node actually reports back.
 */
const ONOFF_VALUES: ReadonlySet<number> = new Set([0x00, 0x01]);

/**
 * Table 6.6 "Light CTL Temperature states" (Section 6.1.3.1) has two rows:
 * the range 0x0320-0x4E20 is "The color temperature of white light in
 * kelvin", and "All other values" is "Prohibited". Same encode-only
 * enforcement as `ONOFF_VALUES` above - unlike CTL Lightness/Delta UV
 * (below), which cover their FULL 16-bit domain with no Prohibited values
 * at all, Temperature genuinely restricts the range.
 */
const MIN_CTL_TEMPERATURE = 0x0320; // 800 K.
const MAX_CTL_TEMPERATURE = 0x4e20; // 20000 K.

/**
 * Table 3.34 "Transition Step Resolution values" (Section 3.1.10.1): 2-bit
 * field, all four values meaningful (100 ms/1 s/10 s/10 min) - no Prohibited
 * value in this domain, unlike OnOff/CTL Temperature above.
 */
const MAX_TRANSITION_STEP_RESOLUTION = 0b11;

/**
 * Table 3.35 "Transition Number of Steps values" (Section 3.1.10.2) has
 * three rows: value 0x00 is "The Generic Transition Time is immediate.",
 * the range 0x01-0x3E is "The number of steps.", and value 0x3F is
 * "Interpretation of this value is context specific." Every value in the
 * full 6-bit domain is meaningful (0x3F is context-specific, not
 * Prohibited) - so, like step resolution, this is a plain width check, not
 * a narrower value check.
 */
const MAX_TRANSITION_NUMBER_OF_STEPS = 0x3f;

/** Keeps this module's error messages prefixed consistently with the rest of the package. */
function assertLightingField(field: string, value: number, max: number): void {
  assertRange(`lighting field "${field}"`, value, max);
}

/**
 * `assertRange` (shared, `packet/ranges.ts`) only covers `[0, max]`; CTL
 * Temperature's valid range has a non-zero floor (Table 6.6) and CTL Delta
 * UV is a signed 16-bit value (Table 6.9) - both need an explicit `min`,
 * which is why this module carries its own small range guard rather than
 * stretching the shared one to cover a shape it was not written for.
 */
function assertIntInRange(field: string, value: number, min: number, max: number): void {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`lighting field "${field}" must be an integer in [${min}, ${max}], got ${value}`);
  }
}

/**
 * Every multi-octet field this module encodes/decodes (Lightness, CTL
 * Lightness/Temperature/Delta UV, HSL Lightness/Hue/Saturation) is
 * little-endian - Section 1.5 "Endianness and field ordering", quoted in
 * full: "All multiple-octet numeric values shall be little-endian." This
 * is the Mesh MODEL document's own convention section, stated directly in
 * its own opening chapter - NOT inherited from the Mesh Protocol
 * document's own Section 3.1.1/3.7.1 (a separate publication; nothing
 * there binds this one). See this file's own Section 1.5 worked example
 * for an independent, byte-exact confirmation of this rule
 * (`__tests__/vectors.ts`'s `SECTION_1_5_WORKED_EXAMPLE`).
 *
 * Every caller now names its own field before calling this (review
 * finding: Lightness/Hue/Saturation used to skip that and fall through to
 * this function's own generic "u16" guard below) - so the `assertLightingField`
 * call here is BELT AND BRACES, not the only check, same status
 * `i16le`'s own internal guard already had for `deltaUv`.
 */
function u16le(value: number): Buffer {
  assertLightingField('u16', value, MAX_UINT16);
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16LE(value, 0);
  return buffer;
}

/** Same Section 1.5 little-endian rule as `u16le`, for CTL Delta UV's signed 16-bit domain. */
function i16le(value: number): Buffer {
  assertIntInRange('i16', value, MIN_INT16, MAX_INT16);
  const buffer = Buffer.alloc(2);
  buffer.writeInt16LE(value, 0);
  return buffer;
}

// ===========================================================================
// Generic Transition Time (Mesh Model v1.1 Section 3.1.10 "Generic
// Transition Time", referenced by every Set message's optional Transition
// Time field (Section 3.2.9 "Transition Time field format") and every
// Status message's optional Remaining Time field (Section 3.2.10 "Remaining
// Time field format") alike. Section 3.2.9, quoted: "The Transition Time
// field uses the Generic Transition Time format defined in Section 3.1.10."
// Section 3.2.10, quoted: "The Remaining Time field uses the Generic
// Transition Time format defined in Section 3.1.10." - the two sentences
// differ only in which field they name, so this is ONE wire format shared
// by Set's Transition Time and Status's Remaining Time alike, across all
// four models, which is why it is factored out once here rather than
// repeated per model.
//
// Table 3.33 "Generic Transition Time format": a 1-octet value, "Transition
// Number of Steps" (6 bits) and "Transition Step Resolution" (2 bits). BIT
// ORDER WITHIN THE OCTET - TWO INDEPENDENT CONFIRMATIONS, both cited
// because a load-bearing layout fact deserves more than one leg to stand
// on: Table 3.33's own field table lists the rows in this order but does
// not itself state which end of the octet each occupies - that visual
// confirmation comes from Figure 3.4 "Generic Transition Time format"
// (fetched separately as a PNG, 529x366, image/167196bb5548e0.png under
// the same document root, since this figure is a diagram, not extractable
// table text) which draws bit 0 on the LEFT of "octet 0" under "Transition
// Number of Steps" and bit 7 on the right under "Transition Step
// Resolution", with the boundary at bit 5/6. It is ALSO independently
// derivable from the document's own general TEXT, not only the figure:
// Section 1.5 "Endianness and field ordering" states the generic rule
// every bit-packed table in this document follows, quoted: "The least
// significant bits (LSbs) of the number are set to the value of Field 0
// (first row of the table), then the number's unassigned LSbs are set to
// the value of Field 1." Table 3.33 lists Transition Number of Steps FIRST
// and Transition Step Resolution SECOND, so Section 1.5's own rule alone
// already places Number of Steps in the LSBs - independently agreeing
// with Figure 3.4, not merely repeating it. `__tests__/vectors.ts`'s
// `SECTION_1_5_WORKED_EXAMPLE` carries the document's own byte-exact
// published worked example of this general procedure (plus the
// little-endian transmission rule `u16le`/`i16le` depend on), and
// `lighting.test.ts` cross-checks it directly against this module's own
// `encodeGenericOnOffSet` output for this exact two-field layout. Table
// 3.34/3.35 give each sub-field's own value table (transcribed above as
// `MAX_TRANSITION_STEP_RESOLUTION`/`MAX_TRANSITION_NUMBER_OF_STEPS`).
// ===========================================================================

/** Table 3.33 "Generic Transition Time format" (Section 3.1.10): the Transition Time / Remaining Time octet, decomposed. */
export interface GenericTransitionTime {
  /** Table 3.34: 0b00=100 ms, 0b01=1 s, 0b10=10 s, 0b11=10 min. */
  stepResolution: number;
  /** Table 3.35: 0x00=immediate, 0x01-0x3E=steps, 0x3F=context-specific (Section 3.2.9.2/3.2.10.2 give the per-message meaning). */
  numberOfSteps: number;
}

function assertTransitionTime(t: GenericTransitionTime): void {
  assertLightingField('transitionTime.stepResolution', t.stepResolution, MAX_TRANSITION_STEP_RESOLUTION);
  assertLightingField('transitionTime.numberOfSteps', t.numberOfSteps, MAX_TRANSITION_NUMBER_OF_STEPS);
}

/** Packs a `GenericTransitionTime` into its single wire octet (Figure 3.4's own bit order - see this section's header note). */
function encodeTransitionTimeOctet(t: GenericTransitionTime): number {
  assertTransitionTime(t);
  return (t.numberOfSteps & MAX_TRANSITION_NUMBER_OF_STEPS) | ((t.stepResolution & MAX_TRANSITION_STEP_RESOLUTION) << 6);
}

/** Inverts `encodeTransitionTimeOctet`. Never rejects an octet (decode is lenient, same split as `ONOFF_VALUES` above) - every one of the 256 possible octets is a well-formed, if not always meaningful, Generic Transition Time. */
function decodeTransitionTimeOctet(octet: number): GenericTransitionTime {
  return {
    numberOfSteps: octet & MAX_TRANSITION_NUMBER_OF_STEPS,
    stepResolution: (octet >>> 6) & MAX_TRANSITION_STEP_RESOLUTION,
  };
}

/**
 * Every Set message's own optional-field group (Table 3.37/6.51/6.69/6.85's
 * identical C.1 footnote, quoted in full on each `encode*Set` function
 * below): Transition Time and Delay are present together or not at all.
 * Grouping them into one optional field here makes the invalid
 * "one without the other" state unrepresentable in the type itself, rather
 * than relying on a caller to honour the footnote by convention.
 */
export interface SetTransition {
  time: GenericTransitionTime;
  /** Table 3.37's own field text (quoted exactly, including its own missing trailing period - this document is inconsistent about that period across its many copies of this field, checked directly in the raw HTML rather than assumed): "Message execution delay in 5-millisecond steps". 1 octet, 0-255. */
  delay: number;
}

function encodeSetTransition(transition: SetTransition | undefined): Buffer {
  if (transition === undefined) {
    return Buffer.alloc(0);
  }
  assertLightingField('transition.delay', transition.delay, MAX_OCTET);
  return Buffer.from([encodeTransitionTimeOctet(transition.time), transition.delay]);
}

// ===========================================================================
// Generic OnOff (Section 3.2.1 "Generic OnOff messages" / Section 3.1.1
// "Generic OnOff" for the state's own value table).
// ===========================================================================

export interface GenericOnOffSetParams {
  /** Table 3.1: 0x00 (Off) or 0x01 (On) only - 0x02-0xFF is Prohibited. */
  onOff: number;
  /**
   * Transaction Identifier (Table 3.37's own field text, quoted verbatim:
   * "The TID field is a transaction identifier indicating whether the
   * message is a new message or a retransmission of a previously sent
   * message, as described in Section 3.4.1.2.2.") - see this function's
   * own JSDoc below for the full rule transcribed from that section and
   * from Section 3.3.1.2.2's receiving side.
   */
  tid: number;
  /** Table 3.37's own C.1 footnote, quoted in full: "If the Transition Time field is present, the Delay field shall also be present; otherwise these fields shall not be present." */
  transition?: SetTransition;
}

/**
 * Table 3.37 "Generic OnOff Set message structure": Opcode (2) || OnOff (1,
 * M) || TID (1, M) || [Transition Time (1, O) || Delay (1, C.1)].
 *
 * THE TRANSACTION IDENTIFIER RULE (the brief's own flagged hazard - get this
 * wrong and a retry reads as a second command, which on a dimmer moves the
 * brightness twice). Two sides, transcribed separately because they are
 * genuinely different rules for different roles:
 *
 * SENDER (Section 3.4.1.2.2 "Sending Generic OnOff Set / Generic OnOff Set
 * Unacknowledged messages", quoted): "a Generic OnOff Client shall send a
 * Generic OnOff Set message, setting the OnOff field to the required value
 * and the TID field to the least recently used transaction identifier."
 * "To retransmit the message, a Generic OnOff Client shall use the same
 * value for the TID field as in the previously sent message within 6
 * seconds from sending that message." So: a NEW command gets the next
 * (least recently used) TID value; a RETRANSMISSION of the same command
 * reuses the same TID, and only within 6 seconds of the original send.
 *
 * RECEIVER (Section 3.3.1.2.2 "Receiving a Generic OnOff Set / Generic
 * OnOff Set Unacknowledged message", quoted in full): "When a Generic
 * OnOff Server receives a Generic OnOff Set message or a Generic OnOff Set
 * Unacknowledged message, it shall set the Generic OnOff state to the
 * OnOff field of the message, unless the message has the same value for
 * the SRC, DST, and TID fields as the previous message received within the
 * past 6 seconds." The uniqueness key is the TRIPLE (SRC, DST, TID), not
 * TID alone - a retransmission is recognised, and NOT re-applied, only
 * when all three match a message received in the last 6 seconds; a new
 * TID, a different SRC/DST, or the same TID arriving 6+ seconds later is a
 * genuinely new command and IS applied. This exact SRC/DST/TID/6-second
 * rule is restated IDENTICAL IN SUBSTANCE - not word for word, checked
 * directly rather than assumed - at Section 6.4.1.2.2 (Light Lightness),
 * Section 6.4.3.2.2 (Light CTL) and Section 6.4.6.2.2 (Light HSL). Each of
 * those three differs from the quote above in two words beyond the
 * model's own name: "same value" here becomes "same values" (plural), and
 * "the past 6 seconds" becomes "the last 6 seconds". Each also adds one
 * whole sentence this quote does not have: "If the target state is equal
 * to the current state, the transition shall not be started and is
 * considered complete." (a rule about what a server does with its own
 * state, not something this stateless encoder/decoder module needs to
 * act on). Confirmed by reading all four sections independently rather
 * than assuming symmetry, which is also why this module's own per-model
 * `encode*Set` functions do not repeat the full rule a second time, only
 * point back here.
 *
 * This module itself has no transport/retry state to apply the rule
 * against (that belongs to whatever Homey-side layer calls this encoder
 * repeatedly) - what this function's contract guarantees is only that the
 * `tid` the CALLER supplies ends up in the one wire octet Table 3.37
 * defines for it, unchanged, so that caller's own retry logic is the only
 * place the rule has to be honoured.
 */
export function encodeGenericOnOffSet(params: GenericOnOffSetParams): Buffer {
  if (!ONOFF_VALUES.has(params.onOff)) {
    throw new Error(`lighting field "onOff" must be 0x00 or 0x01 (Table 3.1: 0x02-0xFF Prohibited), got ${params.onOff}`);
  }
  assertLightingField('tid', params.tid, MAX_OCTET);
  const parameters = Buffer.concat([Buffer.from([params.onOff, params.tid]), encodeSetTransition(params.transition)]);
  return encodeAccessMessage({ opcode: OPCODE_GENERIC_ONOFF_SET, parameters });
}

/** Table 3.36 "Generic OnOff Get message structure": Opcode (2) only - no parameters. */
export function encodeGenericOnOffGet(): Buffer {
  return encodeAccessMessage({ opcode: OPCODE_GENERIC_ONOFF_GET, parameters: Buffer.alloc(0) });
}

/** Table 3.39 "Generic OnOff Status message structure": Present OnOff (1, M) || [Target OnOff (1, O) || Remaining Time (1, C.1)]. */
export interface GenericOnOffStatus {
  presentOnOff: number;
  /** Table 3.39's own C.1 footnote: "If the Target OnOff field is present, the Remaining Time field shall also be present; otherwise these fields shall not be present." - grouped for the same reason `SetTransition` is, above. */
  target?: {
    onOff: number;
    remainingTime: GenericTransitionTime;
  };
}

/**
 * Decodes a Generic OnOff Status message. Returns `null` for anything this
 * function cannot resolve to one well-formed message: `decodeAccessMessage`
 * itself returning `null`, a non-matching opcode, or a Parameters length
 * other than the two Table 3.39 actually defines (1 octet Present-only, or
 * 3 octets with the Target/Remaining-Time pair) - the same
 * "message size is wrong for what it claims to carry, therefore not
 * understood" stance `config/client.ts#decodeConfigStatus` already takes.
 */
export function decodeGenericOnOffStatus(pdu: Buffer): GenericOnOffStatus | null {
  const message = decodeAccessMessage(pdu);
  if (message === null || message.opcode !== OPCODE_GENERIC_ONOFF_STATUS) {
    return null;
  }
  const { parameters } = message;
  if (parameters.length === 1) {
    return { presentOnOff: parameters[0] as number };
  }
  if (parameters.length === 3) {
    return {
      presentOnOff: parameters[0] as number,
      target: {
        onOff: parameters[1] as number,
        remainingTime: decodeTransitionTimeOctet(parameters[2] as number),
      },
    };
  }
  return null;
}

// ===========================================================================
// Light Lightness (Section 6.3.1 "Light Lightness messages" / Section
// 6.1.2.2 "Light Lightness Actual" for the state's own value table - this
// module targets the Actual state, the one Get/Set/Status in Table
// 6.50/6.51/6.53 actually carry; Linear/Last/Default/Range are separate
// messages outside this task's four models).
// ===========================================================================

export interface LightLightnessSetParams {
  /** Table 6.2 "Light Lightness Actual states": full 16-bit domain, no Prohibited values (0x0000 "not emitted" through 0xFFFF "highest"). */
  lightness: number;
  /** Transaction Identifier - same rule as `GenericOnOffSetParams.tid`; this message's own field table points to Section 6.6.1.2.2, identical IN SUBSTANCE to Section 3.4.1.2.2 (not word for word - checked directly: e.g. this section's first sentence says "the least recently used value" where 3.4.1.2.2 says "the least recently used transaction identifier" - see `encodeGenericOnOffSet`'s own JSDoc for the full transcription and the same caveat on the receiving side). */
  tid: number;
  /** Table 6.51's own C.1 footnote, identical wording to Table 3.37's. */
  transition?: SetTransition;
}

/** Table 6.51 "Light Lightness Set message structure": Opcode (2) || Lightness (2, M) || TID (1, M) || [Transition Time (1, O) || Delay (1, C.1)]. */
export function encodeLightLightnessSet(params: LightLightnessSetParams): Buffer {
  // Named explicitly (review finding: this used to fall through to `u16le`'s
  // own generic internal guard, reporting as "u16" rather than
  // "lightness" - the same standard `encodeLightCtlSet` already applies to
  // `temperature`/`deltaUv`, extended here).
  assertLightingField('lightness', params.lightness, MAX_UINT16);
  assertLightingField('tid', params.tid, MAX_OCTET);
  const parameters = Buffer.concat([u16le(params.lightness), Buffer.from([params.tid]), encodeSetTransition(params.transition)]);
  return encodeAccessMessage({ opcode: OPCODE_LIGHT_LIGHTNESS_SET, parameters });
}

/** Table 6.50 "Light Lightness Get message structure": Opcode (2) only - no parameters. */
export function encodeLightLightnessGet(): Buffer {
  return encodeAccessMessage({ opcode: OPCODE_LIGHT_LIGHTNESS_GET, parameters: Buffer.alloc(0) });
}

/** Table 6.53 "Light Lightness Status message structure": Present Lightness (2, M) || [Target Lightness (2, O) || Remaining Time (1, C.1)]. */
export interface LightLightnessStatus {
  presentLightness: number;
  /** Table 6.53's own C.1 footnote: same structure as Table 3.39's, with "Target Lightness" where that one reads "Target OnOff" - the two are not byte-for-byte identical text (the field name differs), unlike the Set messages' C.1 footnote, which names no model-specific field and so IS identical across all four models (see `SetTransition`'s own doc comment). */
  target?: {
    lightness: number;
    remainingTime: GenericTransitionTime;
  };
}

/** Same decode stance as `decodeGenericOnOffStatus`: `null` for a non-matching opcode or a Parameters length other than 2 (Present-only) or 5 (with Target/Remaining-Time). */
export function decodeLightLightnessStatus(pdu: Buffer): LightLightnessStatus | null {
  const message = decodeAccessMessage(pdu);
  if (message === null || message.opcode !== OPCODE_LIGHT_LIGHTNESS_STATUS) {
    return null;
  }
  const { parameters } = message;
  if (parameters.length === 2) {
    return { presentLightness: parameters.readUInt16LE(0) };
  }
  if (parameters.length === 5) {
    return {
      presentLightness: parameters.readUInt16LE(0),
      target: {
        lightness: parameters.readUInt16LE(2),
        remainingTime: decodeTransitionTimeOctet(parameters[4] as number),
      },
    };
  }
  return null;
}

// ===========================================================================
// Light CTL (Section 6.3.2 "Light CTL messages" / Section 6.1.3.6 "Light
// CTL Lightness", Section 6.1.3.1 "Light CTL Temperature", Section 6.1.3.4
// "Light CTL Delta UV" for the three states' own value tables).
// ===========================================================================

export interface LightCtlSetParams {
  /** Table 6.11 "Light CTL Lightness states": full 16-bit domain, no Prohibited values (same shape as Light Lightness Actual). */
  lightness: number;
  /** Table 6.6 "Light CTL Temperature states": ONLY 0x0320-0x4E20 (800-20000 K) is legal - its own other row, "All other values", is "Prohibited" - enforced here on encode. */
  temperature: number;
  /** Table 6.9 "Light CTL Delta UV states": signed 16-bit, full domain, 0x0000 = Delta UV of 0. Kept as the raw signed wire integer, not the document's separately-defined "Represented Delta UV" display ratio (`raw / 32768`), which is a UI concern this module does not perform. */
  deltaUv: number;
  /** Transaction Identifier - same rule as `GenericOnOffSetParams.tid`; this message's own field table points to Section 6.6.2.2.2, identical IN SUBSTANCE (not word for word - see `LightLightnessSetParams.tid`'s own doc comment for the specific difference, which is the same here) to Section 3.4.1.2.2. */
  tid: number;
  /** Table 6.69's own C.1 footnote, identical wording to Table 3.37's. */
  transition?: SetTransition;
}

/**
 * Table 6.69 "Light CTL Set message structure": Opcode (2) || CTL Lightness
 * (2, M) || CTL Temperature (2, M) || CTL Delta UV (2, M) || TID (1, M) ||
 * [Transition Time (1, O) || Delay (1, C.1)].
 */
export function encodeLightCtlSet(params: LightCtlSetParams): Buffer {
  assertLightingField('lightness', params.lightness, MAX_UINT16);
  assertIntInRange('temperature', params.temperature, MIN_CTL_TEMPERATURE, MAX_CTL_TEMPERATURE);
  // Named explicitly here (rather than relying only on `i16le`'s own
  // generic internal guard below) so an out-of-range value reports as
  // "deltaUv", not the less helpful generic "i16" - the same reason
  // `temperature`, above, is checked by name before `u16le` ever runs.
  assertIntInRange('deltaUv', params.deltaUv, MIN_INT16, MAX_INT16);
  assertLightingField('tid', params.tid, MAX_OCTET);
  const parameters = Buffer.concat([
    u16le(params.lightness),
    u16le(params.temperature),
    i16le(params.deltaUv),
    Buffer.from([params.tid]),
    encodeSetTransition(params.transition),
  ]);
  return encodeAccessMessage({ opcode: OPCODE_LIGHT_CTL_SET, parameters });
}

/** Table 6.68 "Light CTL Get message structure": Opcode (2) only - no parameters. */
export function encodeLightCtlGet(): Buffer {
  return encodeAccessMessage({ opcode: OPCODE_LIGHT_CTL_GET, parameters: Buffer.alloc(0) });
}

/**
 * Table 6.71 "Light CTL Status message structure": Present CTL Lightness
 * (2, M) || Present CTL Temperature (2, M) || [Target CTL Lightness (2, O)
 * || Target CTL Temperature (2, C.1) || Remaining Time (1, C.1)]. THREE
 * fields share the one conditional group here (Table 6.71's own C.1
 * footnote, quoted in full: "If the Target CTL Lightness field is present,
 * the Target CTL Temperature and the Remaining Time fields shall also be
 * present; otherwise these fields shall not be present.") - unlike Generic
 * OnOff/Light Lightness Status above, where the group is only two fields.
 */
export interface LightCtlStatus {
  presentLightness: number;
  presentTemperature: number;
  target?: {
    lightness: number;
    temperature: number;
    remainingTime: GenericTransitionTime;
  };
}

/** Same decode stance as the other three Status decoders: `null` for a non-matching opcode or a Parameters length other than 4 (Present-only) or 9 (with the full Target group). */
export function decodeLightCtlStatus(pdu: Buffer): LightCtlStatus | null {
  const message = decodeAccessMessage(pdu);
  if (message === null || message.opcode !== OPCODE_LIGHT_CTL_STATUS) {
    return null;
  }
  const { parameters } = message;
  if (parameters.length === 4) {
    return {
      presentLightness: parameters.readUInt16LE(0),
      presentTemperature: parameters.readUInt16LE(2),
    };
  }
  if (parameters.length === 9) {
    return {
      presentLightness: parameters.readUInt16LE(0),
      presentTemperature: parameters.readUInt16LE(2),
      target: {
        lightness: parameters.readUInt16LE(4),
        temperature: parameters.readUInt16LE(6),
        remainingTime: decodeTransitionTimeOctet(parameters[8] as number),
      },
    };
  }
  return null;
}

// ===========================================================================
// Light HSL (Section 6.3.3 "Light HSL messages" / Section 6.1.4.7 "Light
// HSL Lightness", Section 6.1.4.1 "Light HSL Hue", Section 6.1.4.4 "Light
// HSL Saturation" for the three states' own value tables).
// ===========================================================================

export interface LightHslSetParams {
  /** Table 6.18 "Light HSL Lightness states": full 16-bit domain, no Prohibited values. */
  lightness: number;
  /** Table 6.12 "Light HSL Hue states" has exactly one row, covering the range 0x0000-0xFFFF: "The 16-bit value representing the hue" - the ENTIRE domain is that one published row, no Prohibited values and no narrower range than Lightness/Saturation. */
  hue: number;
  /** Table 6.15 "Light HSL Saturation states": full 16-bit domain, no Prohibited values. */
  saturation: number;
  /** Transaction Identifier - same rule as `GenericOnOffSetParams.tid`; this message's own field table points to Section 6.6.3.2.2, identical IN SUBSTANCE (not word for word - see `LightLightnessSetParams.tid`'s own doc comment for the specific difference, which is the same here) to Section 3.4.1.2.2. */
  tid: number;
  /** Table 6.85's own C.1 footnote, identical wording to Table 3.37's. */
  transition?: SetTransition;
}

/**
 * Table 6.85 "Light HSL Set message structure": Opcode (2) || HSL Lightness
 * (2, M) || HSL Hue (2, M) || HSL Saturation (2, M) || TID (1, M) ||
 * [Transition Time (1, O) || Delay (1, C.1)].
 */
export function encodeLightHslSet(params: LightHslSetParams): Buffer {
  assertLightingField('lightness', params.lightness, MAX_UINT16);
  assertLightingField('hue', params.hue, MAX_UINT16);
  assertLightingField('saturation', params.saturation, MAX_UINT16);
  assertLightingField('tid', params.tid, MAX_OCTET);
  const parameters = Buffer.concat([
    u16le(params.lightness),
    u16le(params.hue),
    u16le(params.saturation),
    Buffer.from([params.tid]),
    encodeSetTransition(params.transition),
  ]);
  return encodeAccessMessage({ opcode: OPCODE_LIGHT_HSL_SET, parameters });
}

/** Table 6.84 "Light HSL Get message structure": Opcode (2) only - no parameters. */
export function encodeLightHslGet(): Buffer {
  return encodeAccessMessage({ opcode: OPCODE_LIGHT_HSL_GET, parameters: Buffer.alloc(0) });
}

/**
 * Table 6.87 "Light HSL Status message structure": HSL Lightness (2, M) ||
 * HSL Hue (2, M) || HSL Saturation (2, M) || Remaining Time (1, O).
 * STRUCTURALLY DIFFERENT from the other three models' Status messages:
 * there is no "Target" field at all here (a separate message, Light HSL
 * Target Status - Section 6.3.3.6, Table 6.89 - carries that, and is
 * outside this task's four models), so Remaining Time is a single,
 * independently optional field ("O", not "C.1" paired with anything) -
 * confirmed by this table publishing no C.1 footnote at all, unlike Table
 * 3.39/6.53/6.71 above. Do not generalise the other three models'
 * `target` grouping onto this one; the specification itself does not.
 */
export interface LightHslStatus {
  lightness: number;
  hue: number;
  saturation: number;
  remainingTime?: GenericTransitionTime;
}

/** Same decode stance as the other three: `null` for a non-matching opcode or a Parameters length other than 6 (no Remaining Time) or 7 (with it). */
export function decodeLightHslStatus(pdu: Buffer): LightHslStatus | null {
  const message = decodeAccessMessage(pdu);
  if (message === null || message.opcode !== OPCODE_LIGHT_HSL_STATUS) {
    return null;
  }
  const { parameters } = message;
  if (parameters.length === 6) {
    return {
      lightness: parameters.readUInt16LE(0),
      hue: parameters.readUInt16LE(2),
      saturation: parameters.readUInt16LE(4),
    };
  }
  if (parameters.length === 7) {
    return {
      lightness: parameters.readUInt16LE(0),
      hue: parameters.readUInt16LE(2),
      saturation: parameters.readUInt16LE(4),
      remainingTime: decodeTransitionTimeOctet(parameters[6] as number),
    };
  }
  return null;
}
