import { assertRange } from './ranges';

/**
 * The lower transport layer's UNSEGMENTED PDUs (Mesh Protocol v1.1, Section
 * 3.5.2 "Lower Transport PDU"). Segmentation (Segmented Access/Control
 * messages) and segment acknowledgement are later tasks and are not built
 * here - this module only encodes/decodes a Lower Transport PDU that
 * already fits in a single Network PDU.
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
 * the control decoder. Both decoders below return `null`, not an error, when
 * SEG says the PDU is segmented: that is not malformed input, it is a
 * different message type for a later task's decoder to route to instead.
 *
 * The header bit/field constants just below (`SEG_BIT`, `AKF_BIT`,
 * `MAX_AID`, `MAX_OPCODE`) are hoisted to module scope, ahead of either
 * message format, because they are not unsegmented-specific: AKF/AID are
 * reused unchanged by the Segmented Access message (Table 3.18, Section
 * 3.5.2.2 - a later task), and the Opcode field/range is shared with the
 * Segment Acknowledgment message (Table 3.21, Section 3.5.2.3.1 - also a
 * later task, see that section's own note below). Only the two formats'
 * LENGTH bounds differ between segmented and unsegmented, so those stay
 * qualified ("unsegmented") and local to each section below.
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
 * reserved opcode. Recognising and parsing that specific message is the
 * segment-acknowledgement task's job, not this one's - `opcode`/`parameters`
 * here are a generic envelope, and this module does not special-case 0x00.
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
// Segmented Access message (Section 3.5.2.2) and Segmented Control message
// (Section 3.5.2.4), plus the Segment Acknowledgment message (Section
// 3.5.2.3.1, opcode 0x00 of the control format above), are later tasks.
// Append their code below this line, grouped the same way as above.
// ===========================================================================
