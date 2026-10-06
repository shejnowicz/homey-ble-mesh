import { assertRange } from './ranges';

/**
 * The access layer's outermost encoding: an Access message is `Opcode ||
 * Parameters` (Mesh Protocol v1.1, Section 3.7.2 "Access message", Table
 * 3.60 "Access message fields": Opcode 1, 2 or 3 octets; Parameters 0 to
 * 379 octets). This module only builds/reads that envelope - the opcode and
 * the raw parameter bytes - and never looks inside Parameters, whose layout
 * is defined per opcode by a model (Section 4.3, or another specification)
 * in a later plan. Everything below it (upper transport encryption, lower
 * transport segmentation, the network layer) is already built; nothing
 * above it (models) exists yet, so nothing else in this codebase imports
 * this module.
 *
 * OPCODE FORMAT (Section 3.7.2.1 "Opcode field", Table 3.62 "Opcode
 * formats"): "The opcode is an array of octets comprising 1, 2, or 3
 * octets. The first octet of the opcode determines the number of octets of
 * the opcode ... If the most significant bit of the first octet of the
 * opcode is zero, then the opcode contains a single octet. If the two most
 * significant bits of the first octet are 0b10, then the opcode contains
 * two octets. If the two most significant bits of the first octet are
 * 0b11, then the opcode contains three octets." Table 3.62 itself:
 *
 *   Opcode Format                      | Description
 *   -----------------------------------|---------------------
 *   0xxxxxxx (excluding 01111111)      | 1-octet Opcodes
 *   01111111                           | Reserved for Future Use
 *   10xxxxxx xxxxxxxx                  | 2-octet Opcodes
 *   11xxxxxx zzzzzzzz zzzzzzzz         | 3-octet Opcodes
 *
 * "The 1-octet opcodes are used for Bluetooth SIG defined models. There are
 * 127 1-octet opcodes that can be defined and allocated by the Bluetooth
 * SIG. Opcode 0x7F is reserved for future possible extension." "The 2-octet
 * opcodes are used for Bluetooth SIG defined models. There are 16384
 * 2-octet opcodes ..." "The 3-octet opcodes are used for manufacturer-
 * specific opcodes. There are 64 3-octet opcodes available per company
 * identifier ... identified using "x" in Table 3.62 ... The company
 * identifiers are 16-bit values defined by the Bluetooth SIG and are coded
 * into the second and third octets of the 3-octet opcodes, identified
 * using "z" in Table 3.62, using endianness as defined in Section 3.7.1."
 *
 * Per Section 3.7.3.4 "Message error procedure", an opcode nothing
 * recognises - the reserved value included, since no model is ever bound to
 * it - is simply ignored by a receiver ("When receiving a message that is
 * not understood by an element, it shall ignore the message ... [including
 * when] the opcode field of the Access message is unknown");
 * `decodeAccessMessage` mirrors that by returning `null`, not throwing, for
 * 0x7F and for any PDU too short for the form its first octet selects.
 *
 * BYTE ORDER - THE PART THAT NEEDS CARE: Section 3.7.1 ("Endianness", inside
 * this same Section 3.7 "Access layer" chapter): "All multiple-octet
 * numeric values in this layer shall be little-endian as described in
 * Section 3.1.1.2." Section 3.1.1 ("Endianness and field ordering") states
 * the contrast directly: "For the network layer, lower transport layer,
 * upper transport layer, mesh beacons, and Provisioning, all multiple-octet
 * numeric values shall be sent in big-endian ... For the access layer and
 * Foundation Models, all multiple-octet numeric values shall be
 * little-endian." Every SRC/DST/SEQ/IV Index this project's lower layers
 * already encode (`network.ts`, `nonce.ts`) is big-endian; the company
 * identifier embedded in a vendor opcode is little-endian - least
 * significant octet first. Section 3.7.2.1's own worked example proves the
 * direction, not just the general rule: "when the manufacturer-specific
 * opcode is equal to 0x23 and the company identifier is equal to 0x0136
 * [4], then the 3-octet opcode is equal to 0xE3 0x36 0x01" - 0x0136's LOW
 * byte (0x36) first, HIGH byte (0x01) second. `vectors.ts`'s own header
 * comment on `ACCESS_SAMPLE_CONFIG_APPKEY_STATUS` records three published
 * Section 8.3 samples (#16, #22/#23, #24) that confirm this independently -
 * #22/#23 and #24 explicitly publish their decoded company identifier
 * (0x000A, "Cambridge Silicon Radio" for #24) beside the wire bytes `0a 00`,
 * which only reads as 0x000A little-endian (big-endian would read 0x0A00 =
 * 2560). The 2-octet SIG opcode form is NOT byte-swapped the same way: Table
 * 3.62 displays its two octets "10xxxxxx xxxxxxxx" MSB-first, and Message
 * #16's own published "Opcode : 8003" (wire bytes `80 03`) confirms reading
 * them in that same, undisturbed order.
 *
 * IN-MEMORY `opcode` ENCODING (this module's own choice - the specification
 * defines the WIRE bytes, not a single JS `number` to hold them, and
 * `AccessMessage.opcode` must be one `number` per the brief's fixed
 * interface): the three forms' numeric ranges are kept disjoint so a bare
 * `opcode` value alone determines which wire form `encodeAccessMessage`
 * must emit, mirroring how a wire PDU's leading bits alone determine which
 * form `decodeAccessMessage` must parse:
 *
 *   Form               | `opcode` range          | Built from
 *   -------------------|--------------------------|---------------------------------
 *   1-octet            | 0x000000-0x00007E        | the single octet, verbatim
 *   2-octet            | 0x008000-0x00BFFF        | (octet0 << 8) | octet1, MSB-first
 *   3-octet (vendor)   | 0xC00000-0xFFFFFF        | (octet0 << 16) | companyId
 *
 * For the vendor form, `companyId` is the ALREADY little-endian-corrected
 * 16-bit value (`octet1 | (octet2 << 8)`), not the raw bytes read MSB-first -
 * so `opcode & 0xffff` is directly the real company identifier (e.g.
 * 0x000a, matching the published "Cambridge Silicon Radio" sample above),
 * and `(opcode >>> 16) & 0x3f` is the 6-bit vendor-specific sub-opcode.
 * Choosing to decode the company ID correctly here - rather than carrying
 * the raw wire bytes through unexamined - is what makes the byte-order rule
 * actually testable: a decoder that silently swapped the two company-ID
 * octets would still round-trip through this module's own
 * encode/decode pair (both sides would be equally wrong), but it could
 * never reproduce the SPECIFICATION's own published company identifier for
 * a known wire sample, which is what this module's tests check against.
 */

// Table 3.62: 1-octet opcodes are 0x00-0x7E; 0x7F is reserved.
const MAX_1_OCTET_OPCODE = 0x7e;
const RESERVED_OPCODE = 0x7f;

// Table 3.62: a 2-octet opcode's first octet is 0x80-0xBF; the full 2-octet
// value (first octet most significant, per the table's own display order
// and Message #16's published "8003") therefore ranges 0x8000-0xBFFF.
const MIN_2_OCTET_OPCODE = 0x8000;
const MAX_2_OCTET_OPCODE = 0xbfff;

// Table 3.62: a 3-octet (vendor) opcode's first octet is 0xC0-0xFF. This
// module's own `opcode` packing (module header) keeps that same first octet
// in bits 23-16 and the little-endian-corrected 16-bit company identifier in
// bits 15-0, so the full range is 0xC00000-0xFFFFFF.
const MIN_VENDOR_OPCODE = 0xc00000;
const MAX_VENDOR_OPCODE = 0xffffff;
const VENDOR_COMPANY_ID_MASK = 0xffff;

export interface AccessMessage {
  /**
   * Operation code, packed into a single `number` per this module's own
   * convention - see the module header's "IN-MEMORY `opcode` ENCODING"
   * table for the three forms' ranges and how the 3-octet (vendor) form's
   * company identifier is packed.
   */
  opcode: number;
  /** Parameters for the operation (Table 3.60); this module never interprets its contents. */
  parameters: Buffer;
}

/** Keeps this module's error messages prefixed consistently with the rest of the packet layer. */
function assertAccessField(field: string, value: number, max: number): void {
  assertRange(`access field "${field}"`, value, max);
}

/**
 * Builds the wire Opcode field (1, 2 or 3 octets, Table 3.62) from this
 * module's packed `opcode` number. `opcode` has already passed
 * `assertAccessField` (a non-negative integer within [0, MAX_VENDOR_OPCODE])
 * by the time this runs; what is checked here is which of the three forms'
 * narrower ranges it actually falls in. Throws for 0x7F (Table 3.62:
 * "Reserved for Future Use") and for any value in one of the gaps between
 * forms (e.g. 0x7FFF, between the 1-octet and 2-octet ranges) - there is no
 * wire form `encodeAccessMessage` could produce for such a value, so this is
 * a caller mistake, not "not decodable" (the `null`-returning stance belongs
 * to the decode direction only, same split `upperTransport.ts`/
 * `lowerTransport.ts` already use throughout this package).
 */
function encodeOpcode(opcode: number): Buffer {
  if (opcode <= MAX_1_OCTET_OPCODE) {
    return Buffer.from([opcode]);
  }
  if (opcode === RESERVED_OPCODE) {
    throw new Error('access field "opcode" 0x7F is Reserved for Future Use (Table 3.62) and cannot be encoded');
  }
  if (opcode >= MIN_2_OCTET_OPCODE && opcode <= MAX_2_OCTET_OPCODE) {
    return Buffer.from([(opcode >>> 8) & 0xff, opcode & 0xff]);
  }
  if (opcode >= MIN_VENDOR_OPCODE && opcode <= MAX_VENDOR_OPCODE) {
    const firstOctet = (opcode >>> 16) & 0xff;
    const companyId = opcode & VENDOR_COMPANY_ID_MASK;
    // Little-endian company identifier (Section 3.7.1/3.7.2.1): low octet
    // of the 16-bit value first, high octet second - see the module header.
    return Buffer.from([firstOctet, companyId & 0xff, (companyId >>> 8) & 0xff]);
  }

  throw new Error(
    `access field "opcode" must be a valid 1-, 2- or 3-octet opcode (Table 3.62), got 0x${opcode.toString(16)}`,
  );
}

/** Builds a complete Access message: `Opcode || Parameters` (Table 3.60). */
export function encodeAccessMessage(message: AccessMessage): Buffer {
  assertAccessField('opcode', message.opcode, MAX_VENDOR_OPCODE);
  const opcode = encodeOpcode(message.opcode);
  return Buffer.concat([opcode, message.parameters]);
}

/**
 * Inverts `encodeAccessMessage`. Returns `null`, not an error, in the same
 * spirit as this package's other decoders (`decodeUnsegmentedAccess` et
 * al.): a PDU this function cannot parse is not necessarily malformed -
 * Section 3.7.3.4's "a message that is not understood ... shall [be]
 * ignore[d]" covers exactly the reserved opcode and a truncated opcode
 * field, neither of which is this layer's job to reject loudly.
 *
 * - `pdu` empty, or too short for the form its first octet selects (2
 *   octets for a 2-octet opcode, 3 for a vendor opcode): nothing to decode.
 * - First octet exactly 0x7F: the reserved value (Table 3.62).
 *
 * Returns a COPY of the recovered Parameters field, not a view onto `pdu` -
 * the same reused-receive-buffer reasoning `decodeUnsegmentedAccess`'s own
 * JSDoc explains.
 */
export function decodeAccessMessage(pdu: Buffer): AccessMessage | null {
  if (pdu.length < 1) {
    return null;
  }
  const firstOctet = pdu[0] as number;

  if (firstOctet === RESERVED_OPCODE) {
    return null;
  }

  if ((firstOctet & 0x80) === 0) {
    // 1-octet opcode (Table 3.62: "0xxxxxxx (excluding 01111111)").
    return {
      opcode: firstOctet,
      parameters: Buffer.from(pdu.subarray(1)),
    };
  }

  if ((firstOctet & 0xc0) === 0x80) {
    // 2-octet opcode (Table 3.62: "10xxxxxx xxxxxxxx"), MSB-first - NOT
    // byte-swapped, unlike the vendor form's company identifier below.
    if (pdu.length < 2) {
      return null;
    }
    const secondOctet = pdu[1] as number;
    return {
      opcode: (firstOctet << 8) | secondOctet,
      parameters: Buffer.from(pdu.subarray(2)),
    };
  }

  // 3-octet vendor opcode (Table 3.62: "11xxxxxx zzzzzzzz zzzzzzzz").
  if (pdu.length < 3) {
    return null;
  }
  const companyLowOctet = pdu[1] as number;
  const companyHighOctet = pdu[2] as number;
  // Little-endian company identifier (Section 3.7.1/3.7.2.1) - see the
  // module header's worked example and published-sample cross-check.
  const companyId = companyLowOctet | (companyHighOctet << 8);
  return {
    opcode: (firstOctet << 16) | companyId,
    parameters: Buffer.from(pdu.subarray(3)),
  };
}
