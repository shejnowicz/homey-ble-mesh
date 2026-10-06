import { assertRange } from '../packet/ranges';

/**
 * Provisioning PDUs: the messages exchanged directly between a Provisioner
 * and a Provisionee while bringing an unprovisioned device into a network
 * (Mesh Protocol v1.1, Section 5.4.1 "Provisioning PDUs"). This module only
 * builds/reads the PDU itself - the Type octet and its Parameters - exactly
 * as `access.ts` only builds/reads the Access layer's Opcode/Parameters
 * envelope. What carries these bytes (PB-ADV's Generic Provisioning
 * transport with its own segmentation, or PB-GATT) and the state machine
 * that decides which PDU to send next are later tasks' concerns, not this
 * module's.
 *
 * PDU FORMAT (Table 5.17 "Provisioning PDU format", Figure 5.14): the first
 * octet is `Padding (2 bits, MUST be 0b00, all other values Prohibited) ||
 * Type (6 bits)`, listed MSB-first exactly as Table 3.67's `CTL (1 bit) ||
 * TTL (7 bits)` is - `network.ts`'s own `(ctl ? 0x80 : 0x00) | ttl` packing
 * confirms that reading direction for this document's bit-field tables, and
 * every sample below (the Type octet always appears as the PDU's one plain,
 * un-shifted leading byte - e.g. `05...` for a Confirmation PDU) confirms it
 * again here: Padding is always 0 in practice, so Type occupies the WHOLE
 * first octet's low 6 bits with the high 2 bits clear. The remaining octets
 * are the Parameters field (Table 5.17), whose layout is per-Type and
 * defined in each Type's own subsection (Tables 5.18, 5.19, 5.28, 5.36,
 * 5.37, 5.38, 5.39, 5.40 below).
 *
 * The specification itself states the Type values are "defined in the
 * Assigned Numbers document [4]" (end of Section 5.4.1's own intro, not
 * reproduced in a table in THIS document) - reference [4] resolves (this
 * document's own bibliography) to the Bluetooth SIG "Assigned Numbers"
 * document, fetched independently
 * (https://www.bluetooth.com/wp-content/uploads/Files/Specification/Assigned_Numbers.pdf,
 * Version Date 2023-12-20, 1,177,759 bytes, sha256
 * b7949eae4a10ee810c498929b3f4d18f8b88dfab1180e9cfaa39fde47d792910) for its
 * Section 4.3.3 "Mesh Provisioning PDU Types" (page 163, "Last Modified:
 * 2023-09-13", filename `assigned_numbers/mesh/mesh_provisioning_pdu_types.yaml`),
 * which lists 0x00 Provisioning Invite, 0x01 Provisioning Capabilities,
 * 0x02 Provisioning Start, 0x03 Provisioning Public Key, 0x04 Provisioning
 * Input Complete, 0x05 Provisioning Confirmation, 0x06 Provisioning Random,
 * 0x07 Provisioning Data, 0x08 Provisioning Complete, 0x09 Provisioning
 * Failed, 0x0A-0x0D four more "Provisioning Record(s)" types for fetching
 * provisioning records - mostly device certificates and a certificate-based
 * provisioning URI (Section 5.4.2.6.3 "Provisioning records", Table 5.52:
 * 0x0000 Certificate-Based Provisioning Base URI, 0x0001 Device Certificate,
 * 0x0002-0x0010 up to fifteen Intermediate Certificates, plus a Complete
 * Local Name and an Appearance record) - added after Mesh Profile 1.0.1, a
 * feature this design does not use - see below. EVERY value 0x00-0x09 this
 * module uses is independently confirmed by this same Mesh Protocol
 * document's own Section 8.7 "PB-ADV provisioning sample data" (fetched the
 * same way, see `__tests__/vectors.ts`): each worked message's own published
 * `Message` hex leads with exactly that type octet (`00` Invite, `01`
 * Capabilities, `02` Start, `03` Public Key, `05` Confirmation, `06` Random,
 * `07` Data, `08` Complete) - so for 0x00-0x03 and 0x05-0x08 the type value
 * is wire-confirmed by THIS document, not merely asserted by the Assigned
 * Numbers reference; only 0x04 (Input Complete, which never appears on the
 * wire in a no-OOB exchange - see below) and 0x09 (Failed, which the success
 * sample naturally never sends) rest on the Assigned Numbers document alone
 * (consistent with, and filling the one gap in, the wire-confirmed
 * sequence).
 *
 * SCOPE: this design (docs/superpowers/specs/2026-10-06-ble-mesh-provisioner-design.md
 * in the homtelli project) commits to the no-out-of-band provisioning path
 * only. This module nonetheless implements all ten Types a no-OOB exchange
 * can actually see on the wire (0x00-0x09): Capabilities and Start still
 * carry the OOB/Public-Key/Algorithm negotiation fields even when OOB itself
 * is unused, because a real Provisionee announces its own OOB capabilities
 * in its Capabilities PDU regardless of what WE intend to use, and we must
 * decode what it says rather than assume a shape - "[I]f one demands an
 * out-of-band code, the wizard says so", which requires actually reading
 * that field.
 *
 * Deliberately NOT implemented: Types 0x0A-0x0D, the certificate-based
 * provisioning record exchange (Section 5.4.2.6 "Provisioning record
 * retrieval over a provisioning bearer"). Transcribed here in full (so a
 * later task never has to re-read Section 5.4.1.11-5.4.1.14 to find out what
 * it chose to skip), even though no codec is implemented for them:
 *
 *   - 0x0A Provisioning Record Request (Section 5.4.1.11, Table 5.42):
 *     Record ID (2 octets) || Fragment Offset (2 octets) || Fragment
 *     Maximum Size (2 octets) - 6 octets of Parameters.
 *   - 0x0B Provisioning Record Response (Section 5.4.1.12, Table 5.43):
 *     Status (1 octet, Table 5.44: 0x00 Success, 0x01 Requested Record Is
 *     Not Present, 0x02 Requested Offset Is Out Of Bounds, 0x03-0xFF RFU)
 *     || Record ID (2 octets) || Fragment Offset (2 octets) || Total Length
 *     (2 octets) || Data (N octets, OPTIONAL - empty unless Status is
 *     Success) - 7+N octets of Parameters.
 *   - 0x0C Provisioning Records Get (Section 5.4.1.13): no parameters, same
 *     empty shape as Input Complete/Complete above.
 *   - 0x0D Provisioning Records List (Section 5.4.1.14, Table 5.45):
 *     Provisioning Extensions (2 octets, a bitmask - Table 5.46 currently
 *     defines every bit 0-15 as Reserved for Future Use) || Records List
 *     (variable, OPTIONAL - a packed list of 16-bit Record IDs, empty if
 *     the Provisionee stores none) - 2+N octets of Parameters.
 *
 * The LOAD-BEARING reason this design can treat these four as unreachable,
 * not merely unused, is ordering, not intent: Section 5.4.2.6.1 states
 * plainly "the Provisioner shall send a Provisioning Records Get PDU before
 * it sends a Provisioning Invite PDU", and Section 5.4.2.6.2 states the same
 * for Record Request ("the Provisioner shall send Provisioning Record
 * Request PDUs before sending a Provisioning Invite PDU") - both Get and
 * Request are Provisioner-INITIATED, and a Provisionee never sends Response
 * or List except in reply to one. Table 5.49/5.51 make the enforcement
 * concrete: a Provisionee that receives a Records Get or Record Request
 * AFTER it has already received the Invite PDU treats that as "provisioning
 * failed" ("Unexpected PDU"), not as a normal request - so this exchange, if
 * it happens at all, is strictly confined to BEFORE Invite starts. A state
 * machine built around this no-OOB design's fixed order (this module
 * header's own DIRECTION table below, which begins at Invite) therefore
 * never has a point in its own run where a 0x0A-0x0D PDU would be a valid
 * NEXT message to accept, independent of whether this design ever intends
 * to use certificate-based provisioning - the earlier, intent-only framing
 * ("nothing in this design ever does [send one]") is also true but is the
 * weaker of the two reasons. `decodeProvisioningPdu` treats 0x0A-0x0D the
 * same as every other value it does not recognise - `null`, not a thrown
 * error - should one ever arrive regardless.
 *
 * DIRECTION (needed by the provisioning state machine, a later task - noted
 * here while reading the section rather than re-reading it later):
 *
 *   Type          | Sent by      | Section
 *   --------------|--------------|----------
 *   Invite        | Provisioner  | 5.4.1.1
 *   Capabilities  | Provisionee  | 5.4.1.2
 *   Start         | Provisioner  | 5.4.1.3
 *   Public Key    | EITHER - the Provisioner sends its own, then the
 *                   Provisionee sends its own; same PDU Type both ways,
 *                   distinguished only by which link direction it arrives
 *                   on, never by a field inside the PDU | 5.4.1.4
 *   Input Complete| Provisionee (only when Authentication Method is
 *                   "Authentication with Input OOB", so never in the
 *                   no-OOB path this design uses) | 5.4.1.5
 *   Confirmation  | EITHER - Provisioner's ConfirmationProvisioner value
 *                   first, then Provisionee's ConfirmationDevice value,
 *                   same PDU Type both ways (Section 5.4.2.4.2) | 5.4.1.6
 *   Random        | EITHER - same pattern as Confirmation, Provisioner's
 *                   RandomProvisioner then Provisionee's RandomDevice |
 *                   5.4.1.7
 *   Data          | Provisioner  | 5.4.1.8
 *   Complete      | Provisionee  | 5.4.1.9
 *   Failed        | Provisionee  | 5.4.1.10 (sent instead of the next
 *                   expected PDU at any point once something goes wrong -
 *                   Section 5.4.4 "Provisioning errors")
 *
 * The fixed ORDER for the no-OOB path (Section 5.4.2, read alongside the
 * worked Section 8.7 exchange) is: Invite, Capabilities, Start, Public Key
 * (Provisioner), Public Key (Device), Confirmation (Provisioner),
 * Confirmation (Device), Random (Provisioner), Random (Device), Data,
 * Complete - with a Failed PDU able to replace whatever the Provisionee was
 * about to send next, at any point from Invite onward.
 *
 * BIT-FIELD / NUMBER-FIELD WIDTH CHECKS: `assertRange` here, same as
 * everywhere else in the packet layer, only enforces each field's own bit
 * width (Tables 5.18/5.19/5.28/5.40's own "Size" column) - it does NOT
 * reject every individual value a table separately marks "Prohibited" or
 * "RFU" (e.g. Capabilities' `numberOfElements=0x00`, Start's
 * `authenticationMethod` values 0x04-0xFF). That narrower policing is this
 * project's established division of labour (see `ranges.ts`'s own `MAX_TTL`
 * comment and ranges.test.ts): the field-width guard belongs here, a
 * stricter semantic check belongs to whatever layer actually interprets the
 * value, same as this project already does for TTL's own "0x7F means use
 * the default" special case.
 *
 * ENDIANNESS: Section 3.1.1 "Endianness and field ordering": "For ... mesh
 * beacons, and Provisioning, all multiple-octet numeric values shall be sent
 * in big-endian" (the same sentence `access.ts`'s module header already
 * quotes for the Access layer's opposite, little-endian rule). The only
 * multiple-octet NUMERIC fields among the ten Types this module encodes are
 * Capabilities' `algorithms`, `outputOobAction` and `inputOobAction` (each 2
 * octets) - all three big-endian here. Every other multi-octet field in
 * this module (Public Key X/Y, Confirmation, Random, the encrypted
 * Provisioning Data block and its MIC) is an opaque byte string, not a
 * numeric value Section 3.1.1's rule applies to, and is therefore copied
 * verbatim with no byte reordering - exactly like `upperTransport.ts`
 * already treats a Label UUID or an encrypted PDU as opaque bytes, not a
 * number.
 *
 * NULLISH CONVENTION: `decodeProvisioningPdu` returns `null` for anything it
 * cannot parse (non-zero Padding bits, an unrecognised Type, or a
 * Parameters field the wrong length for its Type) rather than throwing -
 * this layer's traffic includes bytes from other networks and from PDU
 * types this module does not implement (0x0A-0x0D above), and Section
 * 3.7.3.4's "ignore what you do not understand" principle, already followed
 * by `access.ts`/`lowerTransport.ts`, applies here too. `encodeProvisioningPdu`
 * takes exactly the type the decoder returns - every one of the ten
 * variants is fully mandatory-fielded (every row in Tables 5.18, 5.19,
 * 5.28, 5.36, 5.37, 5.38, 5.39, 5.40 is marked "M", never "O"), so there is
 * no optional field for the two functions to disagree about: whatever
 * `decodeProvisioningPdu` can produce, `encodeProvisioningPdu` can consume,
 * and vice versa.
 */

// Table 5.17's six-bit Type field, confirmed per the module header's
// provenance note above.
const TYPE_INVITE = 0x00;
const TYPE_CAPABILITIES = 0x01;
const TYPE_START = 0x02;
const TYPE_PUBLIC_KEY = 0x03;
const TYPE_INPUT_COMPLETE = 0x04;
const TYPE_CONFIRMATION = 0x05;
const TYPE_RANDOM = 0x06;
const TYPE_DATA = 0x07;
const TYPE_COMPLETE = 0x08;
const TYPE_FAILED = 0x09;

// Table 5.17: Padding occupies the top 2 bits and must be 0b00.
const PADDING_MASK = 0xc0;
const TYPE_MASK = 0x3f;

const MAX_OCTET = 0xff; // 8 bits - every single-octet field below.
const MAX_2_OCTET = 0xffff; // 16 bits - Capabilities' three bitfield fields.

const PUBLIC_KEY_COORD_LENGTH = 32; // Table 5.36: Public Key X, Public Key Y.
const CONFIRMATION_RANDOM_LENGTH_SHORT = 16; // Table 5.37/5.38: 128-bit (BTM_ECDH_P256_CMAC_AES128_AES_CCM).
const CONFIRMATION_RANDOM_LENGTH_LONG = 32; // Table 5.37/5.38: 256-bit (BTM_ECDH_P256_HMAC_SHA256_AES_CCM).
const ENCRYPTED_DATA_LENGTH = 25; // Table 5.39: Encrypted Provisioning Data.
const DATA_MIC_LENGTH = 8; // Table 5.39: Provisioning Data MIC.

/** Table 5.18 "Provisioning Invite PDU parameters format". */
export interface ProvisioningInvite {
  type: 'invite';
  /** Attention Timer state in seconds, 0 = off (Table 4.25, Section 4.2.10). */
  attentionDuration: number;
}

/**
 * Table 5.19 "Provisioning Capabilities PDU parameters format". Field
 * meanings: `algorithms` is a bitmask over Table 5.21 (bit 0
 * BTM_ECDH_P256_CMAC_AES128_AES_CCM, bit 1 BTM_ECDH_P256_HMAC_SHA256_AES_CCM);
 * `publicKeyType` is a bitmask over Table 5.22 (bit 0: OOB public key
 * information available); `oobType` is a bitmask over Table 5.23 (bit 0:
 * static OOB available, bit 1: only OOB-authenticated provisioning
 * supported); `outputOobSize`/`inputOobSize` are Table 5.24/5.26 (0 = not
 * supported, 1-8 = the supported size); `outputOobAction`/`inputOobAction`
 * are bitmasks over Table 5.25/5.27 (Output: bit0 Blink, bit1 Beep, bit2
 * Vibrate, bit3 Output Numeric, bit4 Output Alphanumeric; Input: bit0 Push,
 * bit1 Twist, bit2 Input Numeric, bit3 Input Alphanumeric).
 */
export interface ProvisioningCapabilities {
  type: 'capabilities';
  numberOfElements: number;
  algorithms: number;
  publicKeyType: number;
  oobType: number;
  outputOobSize: number;
  outputOobAction: number;
  inputOobSize: number;
  inputOobAction: number;
}

/**
 * Table 5.28 "Provisioning Start PDU parameters format". `algorithm` is
 * Table 5.29 (0x00 BTM_ECDH_P256_CMAC_AES128_AES_CCM, 0x01
 * BTM_ECDH_P256_HMAC_SHA256_AES_CCM); `publicKey` is Table 5.30 (0x00 no OOB
 * public key, 0x01 OOB public key); `authenticationMethod` is Table 5.31
 * (0x00 No OOB, 0x01 Static OOB, 0x02 Output OOB, 0x03 Input OOB);
 * `authenticationAction`/`authenticationSize` are the selected Output OOB
 * Action/Size (Tables 5.32/5.33) or Input OOB Action/Size (Tables 5.34/5.35)
 * or 0x00 when Authentication Method is No OOB or Static OOB.
 */
export interface ProvisioningStart {
  type: 'start';
  algorithm: number;
  publicKey: number;
  authenticationMethod: number;
  authenticationAction: number;
  authenticationSize: number;
}

/** Table 5.36 "Provisioning Public Key PDU Parameters Format". Raw P-256 coordinates, no 0x04 prefix - same wire convention `ecdh.ts` already uses. */
export interface ProvisioningPublicKey {
  type: 'publicKey';
  publicKeyX: Buffer;
  publicKeyY: Buffer;
}

/** Section 5.4.1.5: "There are no parameters for the Provisioning Input Complete PDU." */
export interface ProvisioningInputComplete {
  type: 'inputComplete';
}

/** Table 5.37 "Provisioning Confirmation PDU parameters format": 16 octets under BTM_ECDH_P256_CMAC_AES128_AES_CCM, 32 under BTM_ECDH_P256_HMAC_SHA256_AES_CCM (Section 5.4.2.4.1) - carries ConfirmationProvisioner or ConfirmationDevice depending on which peer sent it. */
export interface ProvisioningConfirmation {
  type: 'confirmation';
  confirmation: Buffer;
}

/** Table 5.38 "Provisioning Random PDU parameters format": same 16-or-32-octet split as Confirmation, carrying RandomProvisioner or RandomDevice. */
export interface ProvisioningRandom {
  type: 'random';
  random: Buffer;
}

/** Table 5.39 "Provisioning Data PDU parameters format". */
export interface ProvisioningData {
  type: 'data';
  /** The encrypted NetKey/NetKeyIndex/Flags/IVIndex/UnicastAddress block (Section 5.4.2.5), 25 octets. */
  encryptedProvisioningData: Buffer;
  /** PDU Integrity Check value, 8 octets. */
  mic: Buffer;
}

/** Section 5.4.1.9: "There are no parameters for the Provisioning Complete PDU." */
export interface ProvisioningComplete {
  type: 'complete';
}

/** Table 5.40 "Provisioning Failed PDU parameters format"; `errorCode` is Table 5.41's provisioning error codes. */
export interface ProvisioningFailed {
  type: 'failed';
  errorCode: number;
}

export type ProvisioningPdu =
  | ProvisioningInvite
  | ProvisioningCapabilities
  | ProvisioningStart
  | ProvisioningPublicKey
  | ProvisioningInputComplete
  | ProvisioningConfirmation
  | ProvisioningRandom
  | ProvisioningData
  | ProvisioningComplete
  | ProvisioningFailed;

/** Keeps this module's error messages prefixed consistently with the rest of the packet layer. */
function assertProvisioningField(field: string, value: number, max: number): void {
  assertRange(`provisioning field "${field}"`, value, max);
}

/** Throws with this module's own message style when a fixed-length Buffer field is the wrong length. */
function assertBufferLength(field: string, value: Buffer, expected: readonly number[]): void {
  if (!expected.includes(value.length)) {
    const sizes = expected.join(' or ');
    throw new Error(`provisioning field "${field}" must be ${sizes} bytes, got ${value.length}`);
  }
}

function buildPdu(type: number, parameters: Buffer): Buffer {
  return Buffer.concat([Buffer.from([type]), parameters]);
}

/**
 * Builds the wire bytes for any Provisioning PDU (Table 5.17: `Padding(0b00)
 * || Type || Parameters`). Throws on out-of-range field values or
 * wrong-length Buffer fields - a caller mistake, not malformed wire data;
 * see `decodeProvisioningPdu` for the opposite, `null`-returning stance on
 * the decode side.
 */
export function encodeProvisioningPdu(pdu: ProvisioningPdu): Buffer {
  switch (pdu.type) {
    case 'invite': {
      assertProvisioningField('attentionDuration', pdu.attentionDuration, MAX_OCTET);
      return buildPdu(TYPE_INVITE, Buffer.from([pdu.attentionDuration]));
    }

    case 'capabilities': {
      assertProvisioningField('numberOfElements', pdu.numberOfElements, MAX_OCTET);
      assertProvisioningField('algorithms', pdu.algorithms, MAX_2_OCTET);
      assertProvisioningField('publicKeyType', pdu.publicKeyType, MAX_OCTET);
      assertProvisioningField('oobType', pdu.oobType, MAX_OCTET);
      assertProvisioningField('outputOobSize', pdu.outputOobSize, MAX_OCTET);
      assertProvisioningField('outputOobAction', pdu.outputOobAction, MAX_2_OCTET);
      assertProvisioningField('inputOobSize', pdu.inputOobSize, MAX_OCTET);
      assertProvisioningField('inputOobAction', pdu.inputOobAction, MAX_2_OCTET);
      const parameters = Buffer.alloc(11);
      parameters.writeUInt8(pdu.numberOfElements, 0);
      parameters.writeUInt16BE(pdu.algorithms, 1);
      parameters.writeUInt8(pdu.publicKeyType, 3);
      parameters.writeUInt8(pdu.oobType, 4);
      parameters.writeUInt8(pdu.outputOobSize, 5);
      parameters.writeUInt16BE(pdu.outputOobAction, 6);
      parameters.writeUInt8(pdu.inputOobSize, 8);
      parameters.writeUInt16BE(pdu.inputOobAction, 9);
      return buildPdu(TYPE_CAPABILITIES, parameters);
    }

    case 'start': {
      assertProvisioningField('algorithm', pdu.algorithm, MAX_OCTET);
      assertProvisioningField('publicKey', pdu.publicKey, MAX_OCTET);
      assertProvisioningField('authenticationMethod', pdu.authenticationMethod, MAX_OCTET);
      assertProvisioningField('authenticationAction', pdu.authenticationAction, MAX_OCTET);
      assertProvisioningField('authenticationSize', pdu.authenticationSize, MAX_OCTET);
      const parameters = Buffer.from([
        pdu.algorithm,
        pdu.publicKey,
        pdu.authenticationMethod,
        pdu.authenticationAction,
        pdu.authenticationSize,
      ]);
      return buildPdu(TYPE_START, parameters);
    }

    case 'publicKey': {
      assertBufferLength('publicKeyX', pdu.publicKeyX, [PUBLIC_KEY_COORD_LENGTH]);
      assertBufferLength('publicKeyY', pdu.publicKeyY, [PUBLIC_KEY_COORD_LENGTH]);
      return buildPdu(TYPE_PUBLIC_KEY, Buffer.concat([pdu.publicKeyX, pdu.publicKeyY]));
    }

    case 'inputComplete': {
      return buildPdu(TYPE_INPUT_COMPLETE, Buffer.alloc(0));
    }

    case 'confirmation': {
      assertBufferLength('confirmation', pdu.confirmation, [
        CONFIRMATION_RANDOM_LENGTH_SHORT,
        CONFIRMATION_RANDOM_LENGTH_LONG,
      ]);
      return buildPdu(TYPE_CONFIRMATION, pdu.confirmation);
    }

    case 'random': {
      assertBufferLength('random', pdu.random, [
        CONFIRMATION_RANDOM_LENGTH_SHORT,
        CONFIRMATION_RANDOM_LENGTH_LONG,
      ]);
      return buildPdu(TYPE_RANDOM, pdu.random);
    }

    case 'data': {
      assertBufferLength('encryptedProvisioningData', pdu.encryptedProvisioningData, [ENCRYPTED_DATA_LENGTH]);
      assertBufferLength('mic', pdu.mic, [DATA_MIC_LENGTH]);
      return buildPdu(TYPE_DATA, Buffer.concat([pdu.encryptedProvisioningData, pdu.mic]));
    }

    case 'complete': {
      return buildPdu(TYPE_COMPLETE, Buffer.alloc(0));
    }

    case 'failed': {
      assertProvisioningField('errorCode', pdu.errorCode, MAX_OCTET);
      return buildPdu(TYPE_FAILED, Buffer.from([pdu.errorCode]));
    }
  }
}

/**
 * Inverts `encodeProvisioningPdu`. Returns `null`, not an error, for
 * anything this module cannot parse: a PDU shorter than 1 octet, non-zero
 * Padding bits (Table 5.17: "All other values are Prohibited"), a Type this
 * module does not implement (including 0x0A-0x0D's provisioning records,
 * and any unassigned value), or a Parameters field the wrong length for its
 * Type - see the module header's NULLISH CONVENTION note for why this
 * mirrors `decodeAccessMessage`/`decodeUnsegmentedAccess` rather than
 * throwing.
 *
 * Every Buffer field returned is a COPY of the recovered bytes, not a view
 * onto `pdu` - the same reused-receive-buffer reasoning `decodeAccessMessage`
 * documents for its own `parameters` field.
 */
export function decodeProvisioningPdu(pdu: Buffer): ProvisioningPdu | null {
  if (pdu.length < 1) {
    return null;
  }
  const firstOctet = pdu[0] as number;
  if ((firstOctet & PADDING_MASK) !== 0) {
    return null;
  }
  const type = firstOctet & TYPE_MASK;
  const parameters = pdu.subarray(1);

  switch (type) {
    case TYPE_INVITE: {
      if (parameters.length !== 1) {
        return null;
      }
      return { type: 'invite', attentionDuration: parameters[0] as number };
    }

    case TYPE_CAPABILITIES: {
      if (parameters.length !== 11) {
        return null;
      }
      return {
        type: 'capabilities',
        numberOfElements: parameters[0] as number,
        algorithms: parameters.readUInt16BE(1),
        publicKeyType: parameters[3] as number,
        oobType: parameters[4] as number,
        outputOobSize: parameters[5] as number,
        outputOobAction: parameters.readUInt16BE(6),
        inputOobSize: parameters[8] as number,
        inputOobAction: parameters.readUInt16BE(9),
      };
    }

    case TYPE_START: {
      if (parameters.length !== 5) {
        return null;
      }
      return {
        type: 'start',
        algorithm: parameters[0] as number,
        publicKey: parameters[1] as number,
        authenticationMethod: parameters[2] as number,
        authenticationAction: parameters[3] as number,
        authenticationSize: parameters[4] as number,
      };
    }

    case TYPE_PUBLIC_KEY: {
      if (parameters.length !== 2 * PUBLIC_KEY_COORD_LENGTH) {
        return null;
      }
      return {
        type: 'publicKey',
        publicKeyX: Buffer.from(parameters.subarray(0, PUBLIC_KEY_COORD_LENGTH)),
        publicKeyY: Buffer.from(parameters.subarray(PUBLIC_KEY_COORD_LENGTH)),
      };
    }

    case TYPE_INPUT_COMPLETE: {
      if (parameters.length !== 0) {
        return null;
      }
      return { type: 'inputComplete' };
    }

    case TYPE_CONFIRMATION: {
      if (
        parameters.length !== CONFIRMATION_RANDOM_LENGTH_SHORT &&
        parameters.length !== CONFIRMATION_RANDOM_LENGTH_LONG
      ) {
        return null;
      }
      return { type: 'confirmation', confirmation: Buffer.from(parameters) };
    }

    case TYPE_RANDOM: {
      if (
        parameters.length !== CONFIRMATION_RANDOM_LENGTH_SHORT &&
        parameters.length !== CONFIRMATION_RANDOM_LENGTH_LONG
      ) {
        return null;
      }
      return { type: 'random', random: Buffer.from(parameters) };
    }

    case TYPE_DATA: {
      if (parameters.length !== ENCRYPTED_DATA_LENGTH + DATA_MIC_LENGTH) {
        return null;
      }
      return {
        type: 'data',
        encryptedProvisioningData: Buffer.from(parameters.subarray(0, ENCRYPTED_DATA_LENGTH)),
        mic: Buffer.from(parameters.subarray(ENCRYPTED_DATA_LENGTH)),
      };
    }

    case TYPE_COMPLETE: {
      if (parameters.length !== 0) {
        return null;
      }
      return { type: 'complete' };
    }

    case TYPE_FAILED: {
      if (parameters.length !== 1) {
        return null;
      }
      return { type: 'failed', errorCode: parameters[0] as number };
    }

    default:
      // Unassigned, RFU, or one of the out-of-scope 0x0A-0x0D provisioning
      // record types (module header "SCOPE") - foreign/future traffic,
      // ignored like everything else this layer does not recognise.
      return null;
  }
}
