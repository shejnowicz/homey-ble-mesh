import { assertRange } from './ranges';

/**
 * The lower transport layer (Mesh Protocol v1.1, Section 3.5.2 "Lower
 * Transport PDU"): the UNSEGMENTED PDUs (both encode and decode), splitting
 * an Upper Transport Access PDU into Segmented Access messages and decoding
 * a single received one back, and the Segment Acknowledgment message
 * (Section 3.5.2.3.1, Table 3.21 - built further down in this same file).
 * REASSEMBLING a complete Upper Transport PDU from several received
 * segments lives in `./reassembly` instead (a separate module, to avoid an
 * import cycle with this one - see that module's own header and
 * `blockAckFrom`'s doc comment there for why). The Segmented Control message
 * (Table 3.15's fourth row) is still a later task - see this file's own
 * closing note.
 *
 * Section 3.5.2 states the shared rule both formats below follow: "The most
 * significant bit of the first octet of the Lower Transport PDU is the SEG
 * field, which is used to determine if the Lower Transport PDU is formatted
 * as a segmented or unsegmented message." Table 3.15 "Lower Transport PDU
 * format types" then gives all four combinations of the Network PDU's CTL
 * field and this SEG field (column headers reproduced verbatim below; the
 * third one, "Lower Transport PDU Format", is that column's own header, not
 * the table's caption):
 *
 *   CTL | SEG | Lower Transport PDU Format
 *   ----|-----|---------------------------
 *    0  |  0  | Unsegmented Access message
 *    0  |  1  | Segmented Access message
 *    1  |  0  | Unsegmented Control message
 *    1  |  1  | Segmented Control message
 *
 * CTL is a Network PDU field (already decoded by `./network` before this
 * module ever sees the bytes), so this module itself only ever has to tell
 * SEG apart - a caller already knows from CTL whether to call the access or
 * the control decoder. `decodeUnsegmentedAccess` returns `null`, not an
 * error, when SEG says the PDU is segmented: that is not malformed input,
 * it is `decodeSegmentedAccess`'s job instead (both live in this same file
 * now). `decodeUnsegmentedControl` still returns `null` for SEG=1 for the
 * same reason, but its sibling (the Segmented Control message, Table 3.15's
 * fourth row) is a later task's decoder to route to.
 *
 * The header bit/field constants just below (`SEG_BIT`, `AKF_BIT`,
 * `MAX_AID`, `MAX_OPCODE`) are hoisted to module scope, ahead of either
 * message format, because they are not unsegmented-specific: AKF/AID are
 * reused unchanged by the Segmented Access message (Table 3.18, Section
 * 3.5.2.2 - built further down in this same file), and the Opcode
 * field/range is shared with the Segment Acknowledgment message (Table
 * 3.21, Section 3.5.2.3.1 - also built further down this file, see that
 * section's own note). Likewise `MAX_SEQ_ZERO` (introduced below for the
 * Segmented Access message's own SeqZero field, Table 3.18) is reused
 * unchanged by the Segment Acknowledgment message's own SeqZero field
 * (Table 3.21) - the same 13-bit field, carried by both message formats for
 * the same Upper Transport PDU. Only the two UNSEGMENTED formats' LENGTH
 * bounds differ from their segmented siblings, so those two stay qualified
 * ("unsegmented") and local to each section below; the Segmented Access
 * message's own length-related constants are local to its own section for
 * the same reason, just not qualified the same way since there is no risk
 * of confusing them with an unsegmented bound of the same name.
 *
 * UNSEGMENTED ACCESS MESSAGE (Section 3.5.2.1, Table 3.17 "Unsegmented
 * Access message format"):
 *
 *   Field                       | Size (bits) | Req.
 *   ----------------------------|-------------|-----
 *   SEG                         | 1           | M (shall be 0, "Unsegmented Message")
 *   AKF                         | 1           | M (Application Key Flag)
 *   AID                         | 6           | M (Application key identifier)
 *   Upper Transport Access PDU  | 40 to 120   | M
 *
 * SEG, AKF and AID share the first octet in that bit order (SEG the most
 * significant bit, matching Section 3.5.2's own statement above); the
 * remaining octets are the Upper Transport Access PDU verbatim - this layer
 * never touches its contents, only prepends/strips the one-octet header.
 * "40 to 120" bits is 5 to 15 octets: Table 3.17 also notes this message
 * "does not have a SZMIC field" and forces a 32-bit TransMIC, so the
 * smallest legal Upper Transport Access PDU here (a 1-octet Access message
 * plus its 4-octet TransMIC, Section 3.6.2.1) is exactly 5 octets, and the
 * largest an Unsegmented message can carry at all is 15 - a strictly
 * tighter bound than `upperTransport.ts`'s own 380-octet ceiling, which
 * applies to the larger payloads only a Segmented message can carry (and
 * than the Segmented Access message's own, different bound, Table 3.18 -
 * hence the "unsegmented" qualifier on the two length constants below).
 *
 * AKF is the single bit this module leans on hardest: it is what tells a
 * device-key Access message (all configuration traffic) apart from an
 * application-key one. Both directions are covered by known-answer tests
 * with AKF on ONE side each - Message #18/#20/#22/#23 (AKF=1) and Message
 * #16 (AKF=0, see `LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY` in
 * `vectors.ts`) - precisely so a decoder/encoder that silently ignored this
 * bit in either direction cannot pass the suite; see this module's own test
 * file for the mutation that confirmed it.
 *
 * UNSEGMENTED CONTROL MESSAGE (Section 3.5.2.3, Table 3.19 "Unsegmented
 * Control message format"):
 *
 *   Field      | Size (bits) | Req.
 *   -----------|--------------|-----
 *   SEG        | 1            | M (shall be 0, "Unsegmented Message")
 *   Opcode     | 7            | M (Opcode of the Upper Transport Control PDU)
 *   Parameters | 0 to 88      | M (Parameters for the Upper Transport Control PDU)
 *
 * SEG and Opcode share the first octet (SEG the most significant bit,
 * Opcode the remaining 7); the rest is the Parameters field verbatim. "0 to
 * 88" bits is 0 to 11 octets, so the complete PDU is 1 to 12 octets - the
 * same bound `network.ts` already enforces on its own `transportPdu` field
 * when `ctl` is set (`MAX_TRANSPORT_PDU_LENGTH_CONTROL`). This is the
 * Unsegmented Control message's own bound; a Segmented Control message
 * (Table 3.19's sibling for SEG=1, a later task) carries a different
 * Parameters length, which is why the two length constants below are also
 * qualified "unsegmented". Table 3.20 ("Opcode field of the Unsegmented
 * Control message values") further marks 0x00 "Reserved" and 0x01-0x7F
 * "Opcode of the Upper Transport Control PDU" - except that 0x00 is not
 * simply unused: Table 3.21 "Segment Acknowledgment message" fixes its own
 * Opcode field to exactly 0x00, i.e. the Unsegmented Control message format
 * above is also how a Segment Acknowledgment message is carried,
 * distinguished from an ordinary Upper Transport Control PDU only by that
 * reserved opcode. Recognising and parsing that specific message's own
 * Parameters is `encodeSegmentAck`/`decodeSegmentAck`'s job (Section
 * 3.5.2.3.1, Table 3.21 - built further down this same file), not this
 * section's: `opcode`/`parameters` here stay a generic envelope, and
 * `encodeUnsegmentedControl`/`decodeUnsegmentedControl` still do not
 * special-case 0x00 themselves - a caller recognises a Segment
 * Acknowledgment message by checking `decodeUnsegmentedControl`'s own
 * `opcode` result for 0x00 and, if so, handing that same result's
 * `parameters` to `decodeSegmentAck`, exactly as `lowerTransport.test.ts`
 * does.
 */

// Shared header bits/fields - see the module header above for why these are
// hoisted here rather than kept local to one format.
const SEG_BIT = 0x80; // bit 7, Section 3.5.2.
const AKF_BIT = 0x40; // bit 6 (Table 3.17; also Table 3.18's Segmented Access message).
const MAX_AID = 0x3f; // 6 bits, bits 5-0 (Table 3.17; also Table 3.18).
const MAX_OPCODE = 0x7f; // 7 bits, bits 6-0 (Table 3.19; shared with Table 3.21's Segment Acknowledgment format).

/** Keeps this module's error messages prefixed consistently with `network.ts`/`upperTransport.ts`. */
function assertLowerTransportField(field: string, value: number, max: number): void {
  assertRange(`lower transport field "${field}"`, value, max);
}

// ===========================================================================
// Unsegmented Access message (Section 3.5.2.1, Table 3.17)
// ===========================================================================

// Table 3.17: Upper Transport Access PDU is 40 to 120 bits (5 to 15 octets)
// for THIS (unsegmented) format specifically - the Segmented Access message
// (Table 3.18, a later task) carries a different range.
const MIN_UNSEGMENTED_UPPER_TRANSPORT_ACCESS_PDU_LENGTH = 5;
const MAX_UNSEGMENTED_UPPER_TRANSPORT_ACCESS_PDU_LENGTH = 15;

export interface UnsegmentedAccessPdu {
  /** Application Key Flag: false = device key, true = application key (Table 3.17). */
  akf: boolean;
  /** 6-bit application key identifier (Table 3.17); meaningless when `akf` is false. */
  aid: number;
  /** The Upper Transport Access PDU this message carries verbatim (5 to 15 octets, Table 3.17). */
  upperTransportPdu: Buffer;
}

function assertUnsegmentedUpperTransportPduLength(upperTransportPdu: Buffer): void {
  if (
    upperTransportPdu.length < MIN_UNSEGMENTED_UPPER_TRANSPORT_ACCESS_PDU_LENGTH ||
    upperTransportPdu.length > MAX_UNSEGMENTED_UPPER_TRANSPORT_ACCESS_PDU_LENGTH
  ) {
    throw new Error(
      `lower transport field "upperTransportPdu" must be ${MIN_UNSEGMENTED_UPPER_TRANSPORT_ACCESS_PDU_LENGTH}-${MAX_UNSEGMENTED_UPPER_TRANSPORT_ACCESS_PDU_LENGTH} bytes, got ${upperTransportPdu.length}`,
    );
  }
}

/**
 * Builds an Unsegmented Access message: one header octet (SEG=0, AKF, AID)
 * followed by `upperTransportPdu` verbatim (Section 3.5.2.1, Table 3.17).
 */
export function encodeUnsegmentedAccess(input: UnsegmentedAccessPdu): Buffer {
  assertLowerTransportField('aid', input.aid, MAX_AID);
  assertUnsegmentedUpperTransportPduLength(input.upperTransportPdu);

  const header = (input.akf ? AKF_BIT : 0) | input.aid; // SEG left at 0 ("Unsegmented Message").
  return Buffer.concat([Buffer.from([header]), input.upperTransportPdu]);
}

/**
 * Inverts `encodeUnsegmentedAccess`. Returns `null`, rather than throwing,
 * in two cases that are both "not this function's job", not malformed
 * input:
 *
 * - SEG is set: this is a Segmented Access message (Table 3.15), which a
 *   later task's decoder handles.
 * - The recovered Upper Transport Access PDU falls outside Table 3.17's own
 *   5-15 octet bound: no compliant sender produces that as an Unsegmented
 *   Access message, so treating it as "not decodable here" is the same
 *   stance `decodeNetworkPdu` takes on a TransportPDU length its own CTL
 *   value rules out.
 *
 * Returns a COPY of the recovered Upper Transport Access PDU, not a view
 * onto `pdu` (`Buffer.from(view)` copies; `subarray` would not). `pdu` here
 * is typically a slice the network layer just produced from decrypting a
 * received packet - often into a buffer the transport reuses for the next
 * receive - so handing back an alias would let a later write to either one
 * silently corrupt the other, well after this function returned.
 */
export function decodeUnsegmentedAccess(pdu: Buffer): UnsegmentedAccessPdu | null {
  if (pdu.length < 1) {
    return null;
  }
  const header = pdu[0] as number;
  if ((header & SEG_BIT) !== 0) {
    return null;
  }

  const upperTransportPduLength = pdu.length - 1;
  if (
    upperTransportPduLength < MIN_UNSEGMENTED_UPPER_TRANSPORT_ACCESS_PDU_LENGTH ||
    upperTransportPduLength > MAX_UNSEGMENTED_UPPER_TRANSPORT_ACCESS_PDU_LENGTH
  ) {
    return null;
  }

  return {
    akf: (header & AKF_BIT) !== 0,
    aid: header & MAX_AID,
    upperTransportPdu: Buffer.from(pdu.subarray(1)),
  };
}

// ===========================================================================
// Unsegmented Control message (Section 3.5.2.3, Table 3.19)
// ===========================================================================

// Table 3.19: Parameters is 0 to 88 bits (0 to 11 octets) for THIS
// (unsegmented) format specifically - a Segmented Control message (a later
// task) carries a different range. The lower bound is 0, so only the upper
// bound is ever a live comparison (a Buffer's length cannot be negative);
// 0 is documented in this comment rather than as a dead `< 0` check.
const MAX_UNSEGMENTED_CONTROL_PARAMETERS_LENGTH = 11;

export interface UnsegmentedControlPdu {
  /**
   * 7-bit opcode of the Upper Transport Control PDU this message carries
   * (Table 3.19; the valid range is 0x01-0x7F per Table 3.20, with 0x00
   * reserved for a Segment Acknowledgment message, Table 3.21 - a later
   * task's concern, not enforced here; see the module header).
   */
  opcode: number;
  /** Parameters for the Upper Transport Control PDU (0 to 11 octets, Table 3.19). */
  parameters: Buffer;
}

function assertUnsegmentedControlParametersLength(parameters: Buffer): void {
  if (parameters.length > MAX_UNSEGMENTED_CONTROL_PARAMETERS_LENGTH) {
    throw new Error(
      `lower transport field "parameters" must be 0-${MAX_UNSEGMENTED_CONTROL_PARAMETERS_LENGTH} bytes, got ${parameters.length}`,
    );
  }
}

/**
 * Builds an Unsegmented Control message: one header octet (SEG=0, Opcode)
 * followed by `parameters` verbatim (Section 3.5.2.3, Table 3.19).
 */
export function encodeUnsegmentedControl(input: UnsegmentedControlPdu): Buffer {
  assertLowerTransportField('opcode', input.opcode, MAX_OPCODE);
  assertUnsegmentedControlParametersLength(input.parameters);

  const header = input.opcode; // SEG left at 0 ("Unsegmented Message"); Opcode occupies bits 6-0.
  return Buffer.concat([Buffer.from([header]), input.parameters]);
}

/**
 * Inverts `encodeUnsegmentedControl`. Returns `null`, not an error, for the
 * same two reasons as `decodeUnsegmentedAccess`: SEG set (a Segmented
 * Control message, Table 3.15, left to a later task), or a recovered
 * Parameters field longer than Table 3.19's own 11-octet bound.
 *
 * Returns a COPY of the recovered Parameters field, not a view onto `pdu` -
 * same reasoning as `decodeUnsegmentedAccess`'s own JSDoc.
 */
export function decodeUnsegmentedControl(pdu: Buffer): UnsegmentedControlPdu | null {
  if (pdu.length < 1) {
    return null;
  }
  const header = pdu[0] as number;
  if ((header & SEG_BIT) !== 0) {
    return null;
  }

  const parametersLength = pdu.length - 1;
  if (parametersLength > MAX_UNSEGMENTED_CONTROL_PARAMETERS_LENGTH) {
    return null;
  }

  return {
    opcode: header & MAX_OPCODE,
    parameters: Buffer.from(pdu.subarray(1)),
  };
}

// ===========================================================================
// Segmented Access message (Section 3.5.2.2, Table 3.18)
// ===========================================================================

// Table 3.18's header is 4 octets (32 bits), not 1 like the unsegmented
// formats above: SEG(1)+AKF(1)+AID(6) share the first octet (same bit
// positions as the unsegmented formats, hence SEG_BIT/AKF_BIT/MAX_AID being
// reused unchanged here - see the module header), and the remaining 3
// octets carry SZMIC(1)+SeqZero(13)+SegO(5)+SegN(5) = 24 bits, MSB-first.
const SEGMENTED_ACCESS_HEADER_LENGTH = 4;
const MAX_SEQ_ZERO = 0x1fff; // 13 bits, bits 22-10 of the 32-bit header (Table 3.18).
const MAX_SEG_NUMBER = 0x1f; // 5 bits, shared by SegO (bits 9-5) and SegN (bits 4-0) (Table 3.18).
// Bit 23 of the 32-bit header, i.e. bit 7 of the header's SECOND octet -
// the top bit of the 24-bit SZMIC||SeqZero||SegO||SegN value this module
// builds/reads one octet at a time below.
const SZMIC_BIT = 0x800000;

// Table 3.18: "For all segments except the last segment, Segment m is
// octet 12*m to 12*m+11" - every non-last segment is exactly 12 octets, and
// no segment is ever 0 (the last segment is "octet 12*m through the end of
// the message", i.e. 1 to 12 octets). SegN/SegO are 5 bits (0-31), so at
// most 32 segments - Section 2.3.3 "Messages" states the resulting ceiling
// directly: "The lower transport layer provides a SAR mechanism capable of
// transporting up to 32 Access or Transport Control message segments. The
// maximum Upper Transport Access PDU size when using a SAR is 384 octets."
const MAX_SEGMENT_PAYLOAD_LENGTH = 12;
const MAX_SEGMENTS = MAX_SEG_NUMBER + 1; // 32.
const MAX_SEGMENTED_UPPER_TRANSPORT_PDU_LENGTH = MAX_SEGMENTS * MAX_SEGMENT_PAYLOAD_LENGTH; // 384.

export interface SegmentedAccessInput {
  /** Application Key Flag: false = device key, true = application key (Table 3.18). */
  akf: boolean;
  /** 6-bit application key identifier (Table 3.18); meaningless when `akf` is false. */
  aid: number;
  /** Size of the TransMIC field this Upper Transport Access PDU carries: false = 32-bit, true = 64-bit (Table 3.18). */
  szmic: boolean;
  /**
   * 13-bit least significant bits of SeqAuth (Table 3.18), set by the upper
   * transport layer; carried unchanged on every segment of the same
   * message and taken on trust from the caller, the same trust boundary
   * `upperTransport.ts`'s own `szmic` parameter already documents for
   * ASZMIC (this module does not derive SeqAuth itself - that needs the IV
   * Index and the original SEQ, neither of which this layer has).
   */
  seqZero: number;
  /** The complete Upper Transport Access PDU to split into segments (1 to 384 octets - Section 2.3.3). */
  upperTransportPdu: Buffer;
}

function assertSegmentedUpperTransportPduLength(upperTransportPdu: Buffer): void {
  if (upperTransportPdu.length < 1 || upperTransportPdu.length > MAX_SEGMENTED_UPPER_TRANSPORT_PDU_LENGTH) {
    throw new Error(
      `lower transport field "upperTransportPdu" must be 1-${MAX_SEGMENTED_UPPER_TRANSPORT_PDU_LENGTH} bytes, got ${upperTransportPdu.length}`,
    );
  }
}

/**
 * Builds one Segmented Access message's 4-octet header (Table 3.18),
 * packing SEG=1, AKF, AID into the first octet (same layout as the
 * unsegmented formats above) and SZMIC||SeqZero||SegO||SegN into the
 * remaining three, MSB-first per the table's own field order. Kept as a
 * 24-bit intermediate (`rest`) rather than a single 32-bit value: `SEG_BIT`
 * would have to be shifted into bit 31, the sign bit of a JS 32-bit int,
 * for no benefit - every field this function packs after the first octet
 * fits comfortably under 2^24, so there is no sign-bit hazard to work
 * around in the first place.
 */
function encodeSegmentedAccessHeader(fields: {
  akf: boolean;
  aid: number;
  szmic: boolean;
  seqZero: number;
  segO: number;
  segN: number;
}): Buffer {
  const firstByte = SEG_BIT | (fields.akf ? AKF_BIT : 0) | (fields.aid & MAX_AID);
  const rest =
    (fields.szmic ? SZMIC_BIT : 0) |
    ((fields.seqZero & MAX_SEQ_ZERO) << 10) |
    ((fields.segO & MAX_SEG_NUMBER) << 5) |
    (fields.segN & MAX_SEG_NUMBER);
  return Buffer.from([firstByte, (rest >>> 16) & 0xff, (rest >>> 8) & 0xff, rest & 0xff]);
}

/**
 * Splits `input.upperTransportPdu` into Segmented Access messages (Table
 * 3.18): one complete, ready-to-send Lower Transport PDU (4-octet header
 * plus that segment's share of the payload) per segment, in SegO order
 * from 0 to SegN inclusive - the same "encode produces the wire format"
 * contract `encodeUnsegmentedAccess` above already follows, just one PDU
 * per segment instead of one PDU for the whole message.
 *
 * SegN is derived from the payload length alone, per Table 3.18's own
 * segment-size rule ("For all segments except the last segment, Segment m
 * is octet 12*m to 12*m+11"): `ceil(length / 12) - 1`. A payload that is an
 * exact multiple of 12 therefore produces exactly `length / 12` segments,
 * none of them empty - there is no trailing empty segment for a multiple of
 * the segment size, because the loop below stops at `segN`, not at some
 * fixed count computed before knowing whether the last chunk is a full 12
 * octets or a remainder.
 */
export function segmentAccessMessage(input: SegmentedAccessInput): Buffer[] {
  assertLowerTransportField('aid', input.aid, MAX_AID);
  assertLowerTransportField('seqZero', input.seqZero, MAX_SEQ_ZERO);
  assertSegmentedUpperTransportPduLength(input.upperTransportPdu);

  const segN = Math.ceil(input.upperTransportPdu.length / MAX_SEGMENT_PAYLOAD_LENGTH) - 1;
  const segments: Buffer[] = [];
  for (let segO = 0; segO <= segN; segO++) {
    const start = segO * MAX_SEGMENT_PAYLOAD_LENGTH;
    const end = Math.min(start + MAX_SEGMENT_PAYLOAD_LENGTH, input.upperTransportPdu.length);
    const header = encodeSegmentedAccessHeader({
      akf: input.akf,
      aid: input.aid,
      szmic: input.szmic,
      seqZero: input.seqZero,
      segO,
      segN,
    });
    // Buffer.concat always copies into a freshly allocated buffer (it never
    // shares memory with its inputs), so this segment does not alias
    // `input.upperTransportPdu` even though the slice passed to it is a
    // view, not a copy, on its own.
    segments.push(Buffer.concat([header, input.upperTransportPdu.subarray(start, end)]));
  }
  return segments;
}

export interface SegmentedAccessPdu {
  /** Application Key Flag: false = device key, true = application key (Table 3.18). */
  akf: boolean;
  /** 6-bit application key identifier (Table 3.18); meaningless when `akf` is false. */
  aid: number;
  /** Size of the TransMIC field this Upper Transport Access PDU carries: false = 32-bit, true = 64-bit (Table 3.18). */
  szmic: boolean;
  /** 13-bit least significant bits of SeqAuth (Table 3.18); the same value on every segment of one message. */
  seqZero: number;
  /** Zero-based segment number of this segment (Table 3.18). */
  segO: number;
  /** Zero-based number of the LAST segment of this message (Table 3.18); the same value on every segment of one message. */
  segN: number;
  /** This segment's share of the Upper Transport Access PDU (1 to 12 octets, Table 3.18). */
  segment: Buffer;
}

/**
 * Inverts `encodeSegmentedAccessHeader` plus the one segment it is attached
 * to, decoding a SINGLE received Segmented Access message - reassembling
 * the segments of one message back into a complete Upper Transport Access
 * PDU is the next task's job (the module header's "Reassembly is the next
 * task" note), not this function's.
 *
 * Returns `null`, not an error, in the same spirit as
 * `decodeUnsegmentedAccess`/`decodeUnsegmentedControl` above - none of
 * these are malformed input, they are "not decodable by this function":
 *
 * - SEG is clear: this is an Unsegmented Access message (Table 3.15),
 *   decoded by `decodeUnsegmentedAccess` instead.
 * - `pdu` has no room for a non-empty segment (at most the 4-octet header
 *   and nothing else): Table 3.18's own Segment m field is never 0 octets
 *   (minimum 8 bits), so no compliant sender produces this.
 * - The recovered segment is longer than Table 3.18's own 12-octet bound:
 *   same reasoning, from the other direction.
 * - The recovered SegO is greater than the recovered SegN: Table 3.18
 *   defines SegO as "the segment number (zero-based) of the segment m of
 *   this Upper Transport PDU" and SegN as "the last segment number
 *   (zero-based)" of that same PDU - SegO can therefore never legitimately
 *   exceed SegN, and both fields come from the SAME four header octets of
 *   this SAME segment, so this is an invariant of one segment read in
 *   isolation, not a cross-segment consistency check reassembly would have
 *   to do instead. Left unchecked, a garbled or hostile SegO/SegN pair
 *   would otherwise flow into reassembly as an unvalidated array index.
 *
 * Returns a COPY of the recovered segment, not a view onto `pdu` - the same
 * reused-receive-buffer hazard `decodeUnsegmentedAccess`'s own JSDoc
 * explains, and the same reason that decoder's own tests are mirrored for
 * this one below.
 */
export function decodeSegmentedAccess(pdu: Buffer): SegmentedAccessPdu | null {
  if (pdu.length <= SEGMENTED_ACCESS_HEADER_LENGTH) {
    return null;
  }
  const firstByte = pdu[0] as number;
  if ((firstByte & SEG_BIT) === 0) {
    return null;
  }

  const segmentLength = pdu.length - SEGMENTED_ACCESS_HEADER_LENGTH;
  if (segmentLength > MAX_SEGMENT_PAYLOAD_LENGTH) {
    return null;
  }

  const rest = ((pdu[1] as number) << 16) | ((pdu[2] as number) << 8) | (pdu[3] as number);
  const segO = (rest >>> 5) & MAX_SEG_NUMBER;
  const segN = rest & MAX_SEG_NUMBER;
  if (segO > segN) {
    return null;
  }

  return {
    akf: (firstByte & AKF_BIT) !== 0,
    aid: firstByte & MAX_AID,
    szmic: (rest & SZMIC_BIT) !== 0,
    seqZero: (rest >>> 10) & MAX_SEQ_ZERO,
    segO,
    segN,
    segment: Buffer.from(pdu.subarray(SEGMENTED_ACCESS_HEADER_LENGTH)),
  };
}

// ===========================================================================
// Segment Acknowledgment message (Section 3.5.2.3.1, Table 3.21)
// ===========================================================================

// Table 3.21's own Figure 3.14 lists SEG(1)+Opcode(7) first, exactly the
// Unsegmented Control message's header octet above (reused unchanged,
// SEG=0/Opcode=0x00 fixed by Table 3.21 itself) - `encodeSegmentAck`/
// `decodeSegmentAck` below do NOT touch that header octet at all, only the
// Parameters that follow it (see the Unsegmented Control section's own
// closing note on this split). Those Parameters are OBO(1)+SeqZero(13)+
// RFU(2)+AckedSegments(32) = 48 bits = 6 octets, packed MSB-first in that
// field order (the same convention already used for Table 3.18's header
// above): OBO occupies bit 7 of the first Parameters octet, SeqZero's 13
// bits follow immediately (the remaining 7 bits of that first octet, then
// the top 6 bits of the second), RFU is the second octet's bottom 2 bits
// (always written as 0, per Table 3.21: "Reserved for Future Use"), and
// AckedSegments fills the remaining 4 octets as a single big-endian 32-bit
// integer - `Buffer.prototype.writeUInt32BE`/`readUInt32BE` do exactly that
// packing/unpacking, so there is no need to hand-roll it in three more
// shift-and-mask lines the way Table 3.18's header above has to (that
// header interleaves several sub-8-bit fields across octet boundaries in a
// way no single built-in Buffer method covers; Table 3.21's own last field
// is, by contrast, one whole 32-bit integer with nothing else sharing its
// octets).
const SEGMENT_ACK_PARAMETERS_LENGTH = 6;
const OBO_BIT = 0x80; // bit 7 of Parameters octet 0 (Table 3.21).
const MAX_BLOCK_ACK = 0xffffffff; // 32 bits (Table 3.21's AckedSegments field) - comfortably inside Number's exact-integer range.

export interface SegmentAck {
  /**
   * Table 3.21's OBO field: "set to 0 by a node that is directly addressed
   * by the received message and ... set to 1 by a Friend node that is
   * acknowledging this message on behalf of a Low Power node." Section
   * 8.3.7 "Message #7" ("A friend of the destination acknowledges only one
   * of the segments") and Section 8.3.9 "Message #9" are both OBO=1
   * samples - no Section 8.3 sample publishes an OBO=0 Segment
   * Acknowledgment message, so that half of the bit is pinned only by
   * Table 3.21's own text above, not by a published wire sample (recorded
   * here rather than silently relied on).
   */
  obo: boolean;
  /**
   * 13-bit SeqZero of the Upper Transport PDU being acknowledged (Table
   * 3.21) - the same field, same width, same value as the segmented
   * message's own SeqZero (Table 3.18, `SegmentedAccessPdu.seqZero`'s own
   * doc comment above): "the SeqZero field is included in the segmented
   * message and Segment Acknowledgment message to identify the Upper
   * Transport PDU" (Section 3.5.3.1).
   */
  seqZero: number;
  /**
   * Table 3.21's own name for this field is AckedSegments; Section 8.3's
   * worked examples caption the identical bits "BlockAck" instead (Messages
   * #7 and #9 below) - both names refer to the same 32-bit value, and
   * `blockAckFrom` (`./reassembly`) is named after the sample caption, not
   * the table. "The least significant bit, bit 0, shall represent segment
   * 0; and the most significant bit, bit 31, shall represent segment 31. If
   * bit n is set to 1, then segment n is being acknowledged" (Table 3.21) -
   * the exact convention `blockAckFrom` already builds its return value
   * under, so that function's output can be passed straight through as this
   * field, as `lowerTransport.test.ts` does. "Any bits for segments larger
   * than the SegN field value of the upper transport layer message being
   * acknowledged shall be set to 0 and ignored upon receipt" (same table) -
   * a rule about how a SENDER populates this field (and how a receiver
   * matching it against its OWN in-flight SegN should treat any surplus
   * bits), not something `encodeSegmentAck`/`decodeSegmentAck` enforce
   * themselves: a Segment Acknowledgment message carries no SegN field of
   * its own, so neither function has one to mask against here.
   */
  blockAck: number;
}

/**
 * Builds a Segment Acknowledgment message's 6-octet Parameters field (Table
 * 3.21) - NOT the complete Lower Transport PDU, which also needs the
 * generic SEG=0/Opcode=0x00 header octet
 * `encodeUnsegmentedControl({ opcode: 0x00, parameters: encodeSegmentAck(ack) })`
 * already builds unchanged (see the Unsegmented Control section's own
 * closing note on why that header is not duplicated here).
 */
export function encodeSegmentAck(ack: SegmentAck): Buffer {
  assertLowerTransportField('seqZero', ack.seqZero, MAX_SEQ_ZERO);
  assertLowerTransportField('blockAck', ack.blockAck, MAX_BLOCK_ACK);

  const parameters = Buffer.alloc(SEGMENT_ACK_PARAMETERS_LENGTH);
  parameters[0] = (ack.obo ? OBO_BIT : 0) | ((ack.seqZero >>> 6) & 0x7f);
  parameters[1] = (ack.seqZero & 0x3f) << 2; // bits 1-0 (RFU) left at 0.
  parameters.writeUInt32BE(ack.blockAck, 2);
  return parameters;
}

/**
 * Inverts `encodeSegmentAck`. Takes the 6-octet Parameters field ALONE
 * (typically `decodeUnsegmentedControl(pdu)`'s own `parameters` result,
 * once that same call's `opcode` has already been checked for 0x00 - the
 * generic envelope is `decodeUnsegmentedControl`'s job, not this
 * function's, same split as the encode direction above).
 *
 * Returns `null`, not an error, for a Parameters field that is not exactly
 * 6 octets - the same "not decodable by this function" stance every other
 * decoder in this file takes (Table 3.21's own fields sum to exactly 48
 * bits/6 octets, with no variable-length component, so any other length is
 * not a compliant sender's output; Section 3.5.4.3 "Message error
 * procedure" states the matching receive-side rule directly: "A Segment
 * Acknowledgment message that is not understood includes messages that
 * have incorrect size").
 */
export function decodeSegmentAck(parameters: Buffer): SegmentAck | null {
  if (parameters.length !== SEGMENT_ACK_PARAMETERS_LENGTH) {
    return null;
  }
  const firstByte = parameters[0] as number;
  const secondByte = parameters[1] as number;

  return {
    obo: (firstByte & OBO_BIT) !== 0,
    seqZero: ((firstByte & 0x7f) << 6) | ((secondByte >>> 2) & 0x3f),
    blockAck: parameters.readUInt32BE(2),
  };
}

// ===========================================================================
// Segmented Control message (Section 3.5.2.4) is the one remaining later
// task. Append its code below this line, grouped the same way as above.
// ===========================================================================
