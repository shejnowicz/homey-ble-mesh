import { applicationNonce, deviceNonce } from './nonce';
import { ccmEncrypt, ccmDecrypt } from '../crypto/ccm';
import { assertRange, MAX_SEQ, MAX_ADDRESS, MAX_IV_INDEX } from './ranges';

/**
 * The upper transport layer: encrypts and authenticates an Access message
 * under an application key or a device key, producing the Upper Transport
 * Access PDU (Mesh Protocol v1.1, Section 3.6.2 "Upper Transport Access
 * PDU", Table 3.25 / Figure 3.17: `EncAccessMessage || TransMIC`). The
 * actual AES-CCM call and the choice of key/nonce family are specified in
 * Section 3.9.7.1 "Upper transport layer authentication and encryption":
 *
 *   EncAccessMessage, TransMIC = AES-CCM_AppKey(application nonce, Access message)
 *   EncAccessMessage, TransMIC = AES-CCM_DevKey(device nonce, Access message)
 *
 * (both for a unicast/group destination; see the virtual-address case below).
 * `applicationNonce`/`deviceNonce` (`./nonce`) build the 13-octet nonce;
 * `ccmEncrypt`/`ccmDecrypt` (`../crypto/ccm`) do the AES-CCM itself. This
 * layer never touches the transport-control, segmentation or network layers
 * - it only turns an access payload into an authenticated blob and back.
 *
 * TWO TRANSMIC LENGTHS (Section 3.6.2.2 "TransMIC"): "a 32-bit or 64-bit
 * field". The two are not freely interchangeable: "For a Segmented Access
 * message, where the SEG field is set to 1, the size of the TransMIC field
 * is determined by the value of the SZMIC field in the Lower Transport PDU.
 * For Unsegmented Access messages, the TransMIC field is a 32-bit field."
 * Table 3.61 (Section 3.7.2 "Access message") makes the same point from the
 * opposite direction: for a single-packet message sent unsegmented, the
 * 64-bit-TransMIC column reads "n/a". The 64-bit TransMIC exists ONLY for
 * messages that will be carried as a Segmented Access message - which this
 * layer does not decide (that is the lower transport layer's job, a later
 * task) and so cannot itself enforce; `szmic` here is taken on trust from
 * the caller, exactly as `nonce.ts`'s own `aszmic` parameter already is
 * (Table 3.69/3.71 "ASZMIC and Pad field format": "SZMIC field value if a
 * Segmented Access message, or 0 for all other message formats" - the same
 * trust boundary, one layer up).
 *
 * What this layer CAN and does enforce, because it depends on nothing but
 * the access payload itself, is Section 3.6.2.1 "EncAccessMessage"'s length
 * bound, which differs by exactly the difference between the two MIC sizes:
 * "If the TransMIC is a 32-bit field, the Access message can be from a
 * single octet to 380 octets in length. If the TransMIC is a 64-bit field,
 * the Access message can be from a single octet to 376 octets in length."
 * (Both derive from one fixed ceiling: Section 3.7.2's Table 3.61 caps a
 * complete Upper Transport Access PDU at 384 octets - 32 segments of 12
 * octets each - so the MIC's own size is what it costs out of that budget.)
 *
 * VIRTUAL ADDRESSES AND THE LABEL UUID (Section 3.4.2.3 "Virtual address"):
 * "The Label UUID is not transmitted and shall be used as the Additional
 * Data field of the message integrity check value in the upper transport
 * layer (see Section 3.9.7.1)." Section 3.9.7.1 states the virtual-address
 * case explicitly: "When using an application key and the destination
 * address is a virtual address: EncAccessMessage, TransMIC=AES-CCM_AppKey
 * (application nonce, Access message, Label UUID)" - i.e. AES-CCM's
 * additional authenticated data parameter, not part of the plaintext.
 * `labelUuid` on `UpperTransportInput` is NOT part of the brief this module
 * was built from, which specifies only accessPayload/key/keyKind/seq/src/
 * dst/ivIndex/szmic - deliberately added anyway, because the only published
 * Section 8.3 sample with SZMIC set (Message #24, the one case this task
 * must reproduce exactly to exercise the long-MIC path) is addressed to a
 * virtual address and its published TransMIC depends on exactly this AAD;
 * without it `encryptUpperTransport` cannot reproduce that sample's
 * published bytes at all (verified directly: encrypting without any AAD
 * gives TransMIC c77bf543bdb352c1, not the published aa5001f31c01cea6 - a
 * standalone check against `node:crypto`, independent of this module, done
 * before writing it). Device-key messages never reach this case - Section
 * 3.9.7.1 defines only the unicast destination for DevKey - so `labelUuid`
 * is rejected outright when `keyKind` is `'device'`.
 *
 * A receiver with several candidate Label UUIDs for one virtual-address hash
 * is expected to try each one until authentication succeeds ("each
 * corresponding Label UUID is used by the upper transport layer as
 * additional data ... until a match is found", Section 3.4.2.3); this module
 * takes exactly one candidate per call and leaves that iteration to whatever
 * calls it, same as it leaves segmentation and reassembly to the lower
 * transport layer.
 *
 * A first review of this task found two more gaps, both closed below:
 * (1) Message #24 was simultaneously the only SZMIC=1 sample AND the only
 * virtual-address sample, so nothing exercised the two independently - a
 * live mutation (applying `labelUuid` only when `szmic` was set, at both
 * `ccmEncrypt`/`ccmDecrypt` call sites) passed the whole suite. Closed by
 * transcribing Messages #22 and #23 (also virtual-address, but SZMIC=0) -
 * see `vectors.ts`. (2) `dst` falling in the virtual address range with no
 * `labelUuid` was accepted silently, producing a PDU that authenticates
 * against nothing - closed by `isVirtualAddress`/`assertLabelUuidRules`
 * below, which transcribes the range itself (0x8000-0xBFFF) rather than
 * only checking a UUID's width once supplied.
 */

export type UpperTransportKeyKind = 'application' | 'device';

export interface UpperTransportInput {
  /** The plaintext Access message supplied by the access layer. */
  accessPayload: Buffer;
  /** 128-bit application key or device key the message is secured under. */
  key: Buffer;
  /** Which nonce family and key `key` is: an application key or a device key. */
  keyKind: UpperTransportKeyKind;
  /** 24-bit sequence number (the 24 lowest bits of SeqAuth when segmented). */
  seq: number;
  /** 16-bit source address. */
  src: number;
  /** 16-bit destination address (unicast, group, or the 16-bit hash of a virtual address). */
  dst: number;
  /** 32-bit IV Index. */
  ivIndex: number;
  /** Segmented-message long-MIC flag: false selects the 32-bit TransMIC, true the 64-bit one. */
  szmic: boolean;
  /**
   * The 128-bit Label UUID `dst` was hashed from. REQUIRED as AES-CCM
   * additional data whenever `dst` falls in the virtual address range
   * (0x8000-0xBFFF, Section 3.4.2.3) and `keyKind` is `'application'` -
   * enforced below, not merely documented: a virtual `dst` with no
   * `labelUuid` throws, rather than silently producing a PDU nothing can
   * authenticate. Must be omitted for a unicast or group `dst`, and must be
   * omitted entirely when `keyKind` is `'device'` - see the module header.
   */
  labelUuid?: Buffer;
}

const KEY_LENGTH = 16; // 128-bit AppKey/DevKey.
const LABEL_UUID_LENGTH = 16; // 128-bit Label UUID (Section 3.4.2.3).

// Section 3.4.2.3 "Virtual address": "A virtual address can have any value
// from 0x8000 to 0xBFFF" (bit 15 set, bit 14 clear, Figure 3.7). This is the
// range `labelUuid` is required for (application key) or forbidden outside
// of (any key).
const MIN_VIRTUAL_ADDRESS = 0x8000;
const MAX_VIRTUAL_ADDRESS = 0xbfff;

const TRANS_MIC_LENGTH_SHORT = 4; // 32 bits (Section 3.6.2.2).
const TRANS_MIC_LENGTH_LONG = 8; // 64 bits (Section 3.6.2.2; Segmented Access messages only).

// Section 3.6.2.1 "EncAccessMessage": the Access message length bound
// depends on which TransMIC size it is paired with, because both share one
// 384-octet ceiling on the complete Upper Transport Access PDU (Section
// 3.7.2, Table 3.61: 32 segments x 12 octets).
const MIN_ACCESS_PAYLOAD_LENGTH = 1;
const MAX_ACCESS_PAYLOAD_LENGTH_SHORT_MIC = 380; // 384 - 4 (Section 3.6.2.1).
const MAX_ACCESS_PAYLOAD_LENGTH_LONG_MIC = 376; // 384 - 8 (Section 3.6.2.1).

/** Keeps this module's error messages prefixed consistently with `network.ts`/`nonce.ts`. */
function assertUpperTransportField(field: string, value: number, max: number): void {
  assertRange(`upper transport field "${field}"`, value, max);
}

function assertKeyLength(key: Buffer): void {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`upper transport field "key" must be ${KEY_LENGTH} bytes, got ${key.length}`);
  }
}

function isVirtualAddress(dst: number): boolean {
  return dst >= MIN_VIRTUAL_ADDRESS && dst <= MAX_VIRTUAL_ADDRESS;
}

/**
 * Enforces the pairing between `dst`, `keyKind` and `labelUuid` (Sections
 * 3.4.2.3, 3.9.7.1): a device-key message never uses a virtual address at
 * all and so never carries a `labelUuid`; an application-key message MUST
 * carry one when `dst` is virtual (otherwise the produced/expected PDU
 * authenticates against the wrong additional data - see the module header's
 * account of Message #24) and MUST NOT carry one otherwise.
 */
function assertLabelUuidRules(keyKind: UpperTransportKeyKind, dst: number, labelUuid: Buffer | undefined): void {
  if (keyKind === 'device') {
    if (labelUuid !== undefined) {
      throw new Error(
        'upper transport field "labelUuid" must not be set for a device-key message (Section 3.9.7.1 defines only the unicast destination for DevKey)',
      );
    }
    if (isVirtualAddress(dst)) {
      throw new Error(
        `upper transport field "dst" must not be a virtual address (0x${MIN_VIRTUAL_ADDRESS.toString(16)}-0x${MAX_VIRTUAL_ADDRESS.toString(16)}, Section 3.4.2.3) for a device-key message (Section 3.9.7.1 defines only the unicast destination for DevKey)`,
      );
    }
    return;
  }

  if (isVirtualAddress(dst)) {
    if (labelUuid === undefined) {
      throw new Error(
        `upper transport field "labelUuid" is required when "dst" is a virtual address (0x${MIN_VIRTUAL_ADDRESS.toString(16)}-0x${MAX_VIRTUAL_ADDRESS.toString(16)}, Section 3.4.2.3)`,
      );
    }
    if (labelUuid.length !== LABEL_UUID_LENGTH) {
      throw new Error(`upper transport field "labelUuid" must be ${LABEL_UUID_LENGTH} bytes, got ${labelUuid.length}`);
    }
    return;
  }

  if (labelUuid !== undefined) {
    throw new Error(
      `upper transport field "labelUuid" must not be set when "dst" is not a virtual address (0x${MIN_VIRTUAL_ADDRESS.toString(16)}-0x${MAX_VIRTUAL_ADDRESS.toString(16)}, Section 3.4.2.3)`,
    );
  }
}

function assertAccessPayloadLength(accessPayload: Buffer, szmic: boolean): void {
  const max = szmic ? MAX_ACCESS_PAYLOAD_LENGTH_LONG_MIC : MAX_ACCESS_PAYLOAD_LENGTH_SHORT_MIC;
  if (accessPayload.length < MIN_ACCESS_PAYLOAD_LENGTH || accessPayload.length > max) {
    throw new Error(
      `upper transport field "accessPayload" must be ${MIN_ACCESS_PAYLOAD_LENGTH}-${max} bytes when szmic=${szmic}, got ${accessPayload.length}`,
    );
  }
}

interface NonceFields {
  keyKind: UpperTransportKeyKind;
  szmic: boolean;
  seq: number;
  src: number;
  dst: number;
  ivIndex: number;
}

/** Selects the application or device nonce builder from `keyKind` (Section 3.9.5.2/3.9.5.3). */
function buildNonce(fields: NonceFields): Buffer {
  const nonceInput = { aszmic: fields.szmic, seq: fields.seq, src: fields.src, dst: fields.dst, ivIndex: fields.ivIndex };
  return fields.keyKind === 'application' ? applicationNonce(nonceInput) : deviceNonce(nonceInput);
}

/** Common range/width guards shared by encryption and decryption. */
function assertCommonFields(input: {
  key: Buffer;
  keyKind: UpperTransportKeyKind;
  seq: number;
  src: number;
  dst: number;
  ivIndex: number;
  labelUuid?: Buffer;
}): void {
  assertKeyLength(input.key);
  assertUpperTransportField('seq', input.seq, MAX_SEQ);
  assertUpperTransportField('src', input.src, MAX_ADDRESS);
  assertUpperTransportField('dst', input.dst, MAX_ADDRESS);
  assertUpperTransportField('ivIndex', input.ivIndex, MAX_IV_INDEX);
  assertLabelUuidRules(input.keyKind, input.dst, input.labelUuid);
}

/**
 * Encrypts and authenticates an Access message into an Upper Transport
 * Access PDU: `EncAccessMessage || TransMIC` (Section 3.6.2, Table 3.25).
 */
export function encryptUpperTransport(input: UpperTransportInput): Buffer {
  assertCommonFields(input);
  assertAccessPayloadLength(input.accessPayload, input.szmic);

  const nonce = buildNonce(input);
  const micLength = input.szmic ? TRANS_MIC_LENGTH_LONG : TRANS_MIC_LENGTH_SHORT;
  const { ciphertext, tag } = ccmEncrypt(input.key, nonce, input.accessPayload, micLength, input.labelUuid);
  return Buffer.concat([ciphertext, tag]);
}

/**
 * Inverts `encryptUpperTransport`: recovers the plaintext Access message
 * from a received Upper Transport Access PDU, or returns `null` when the
 * TransMIC does not verify. That is ordinary, not exceptional - traffic
 * under a different key, or a candidate Label UUID that was not the right
 * one for this virtual address (Section 3.4.2.3's "until a match is
 * found") - so it is returned, not thrown, exactly as `ccmDecrypt` and
 * `decodeNetworkPdu` already distinguish that from a caller's own mistake
 * (wrong key width, an out-of-range field), which throws.
 *
 * Deliberately asymmetric with `encryptUpperTransport` in one respect: it
 * does NOT re-apply Section 3.6.2.1's minimum access-payload length (one
 * octet) to the recovered plaintext. `encryptUpperTransport` refuses to
 * ever produce a zero-length Access message, but a receiver's job is to
 * accept whatever successfully authenticates, not to second-guess a sender
 * - the specification places that minimum on what is sent, not on what a
 * receiver is allowed to accept. In practice this never fires against a
 * compliant sender, since nothing produced by `encryptUpperTransport` is
 * zero-length.
 */
export function decryptUpperTransport(
  input: Omit<UpperTransportInput, 'accessPayload'> & { upperTransportPdu: Buffer },
): Buffer | null {
  assertCommonFields(input);

  const nonce = buildNonce(input);
  const micLength = input.szmic ? TRANS_MIC_LENGTH_LONG : TRANS_MIC_LENGTH_SHORT;
  // `subarray` clamps rather than throwing on a PDU shorter than micLength
  // (verified directly), leaving a tag of some other length for
  // `ccmDecrypt`'s own MESH_MIC_LENGTHS check to drop quietly - the same
  // "truncated foreign packet" case that check is already built for.
  const ciphertext = input.upperTransportPdu.subarray(0, input.upperTransportPdu.length - micLength);
  const tag = input.upperTransportPdu.subarray(ciphertext.length);
  return ccmDecrypt(input.key, nonce, ciphertext, tag, input.labelUuid);
}
