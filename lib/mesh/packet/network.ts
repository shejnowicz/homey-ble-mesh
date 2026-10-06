import { e } from '../crypto/cmac';
import { ccmEncrypt, ccmDecrypt } from '../crypto/ccm';
import { k2 } from '../crypto/derive';
import { networkNonce } from './nonce';

/**
 * Builds the on-the-wire Network PDU for a message leaving this node,
 * following the network layer's own procedure (Mesh Protocol v1.1, Section
 * 3.4.4 "Network PDU" for the wire format, Section 3.9.6.3.1 "NID,
 * EncryptionKey, and PrivacyKey" for key derivation, Section 3.9.7.2
 * "Network layer authentication and encryption" for the encrypted part, and
 * Section 3.9.7.3 "Network layer obfuscation" for the header masking).
 *
 * The network layer never encrypts with the NetKey itself. Instead it first
 * derives three values from it with k2(NetKey, 0x00) — the fixed 0x00 is
 * the "P" input the specification assigns to managed-flooding security
 * material, as opposed to the different P values used for friendship or
 * directed-forwarding credentials, neither of which this encoder handles:
 * a 7-bit NID carried in clear, which only narrows down which NetKey was
 * used rather than identifying it outright — Section 3.9.6.3.1 itself notes
 * there are up to 2^121 possible keys for each NID, so a receiver still has
 * to try every NetKey sharing that NID; a 128-bit EncryptionKey for the
 * payload; and a 128-bit PrivacyKey used only to obscure the header, kept
 * separate so that compromising one does not expose the other.
 *
 * Only two fields are ever encrypted and authenticated: the destination
 * address (DST) and the Lower Transport PDU. Together they are run through
 * AES-CCM under the EncryptionKey, using a nonce built from the message's
 * own CTL/TTL/SEQ/SRC/IV-Index (Section 3.9.5's network nonce, already
 * implemented in `./nonce`). This is why DST travels encrypted but
 * authenticated while SRC, by contrast, stays in the clear (obfuscated, not
 * encrypted) — the nonce authenticates SRC implicitly, since a wrong SRC in
 * the nonce would make the receiver compute the wrong nonce and fail the
 * check, so SRC does not also need hiding behind AES-CCM to be trustworthy.
 * The resulting authentication tag is the NetMIC. Its length is not fixed:
 * Table 3.11 ties it to the CTL flag alone, independent of anything else in
 * the message — 32 bits (4 octets) when CTL is clear (an Access message,
 * already carrying its own upper-transport MIC) and 64 bits (8 octets) when
 * CTL is set (a Transport Control message, which carries no upper-transport
 * MIC of its own and so needs the network layer's MIC to be longer to keep
 * the same minimum 64 bits of total authentication the specification
 * guarantees every message).
 *
 * The remaining header fields — CTL, TTL, SEQ and SRC — are never encrypted,
 * only obfuscated, so that relaying nodes can still read TTL without holding
 * the EncryptionKey, while a passive eavesdropper still cannot read SRC or
 * SEQ directly off the air. Obfuscation builds a one-block AES input called
 * the Privacy Plaintext: five zero octets, then the 32-bit IV Index, then a
 * 7-octet "Privacy Random" taken as the first seven octets of whatever was
 * just produced by encryption (EncDST || EncTransportPDU || NetMIC — at
 * least seven octets always exist there because EncDST is two octets,
 * TransportPDU is never empty (Table 3.10's width is "8 to 128" bits, i.e.
 * at least one octet, so EncTransportPDU contributes at least one), and
 * NetMIC is at least four). Running that 16-octet Privacy
 * Plaintext through the single-block cipher `e` under the PrivacyKey yields
 * the PECB; only its first six octets are used. XOR-ing those six octets
 * against the six plain octets CTL||TTL||SEQ||SRC (in that order — CTL and
 * TTL share one octet, as in the nonce) produces the ObfuscatedData that
 * actually goes on the wire in their place. Folding the IV Index into the
 * Privacy Plaintext means an eavesdropper's accumulated obfuscation patterns
 * become useless the moment the network's IV Index changes.
 *
 * The transmitted Network PDU is finally the concatenation, in this order,
 * of: one octet combining IVI (the IV Index's least significant bit, bit 7)
 * and NID (bits 6-0), the 6-octet ObfuscatedData, EncDST || EncTransportPDU,
 * and the NetMIC. Note this places the derived NID (not the caller's IV
 * Index) in the leading octet, while the actual IV Index only appears
 * indirectly, folded into the obfuscation mask.
 *
 * The TransportPDU's own width is bounded in two places: Table 3.10 gives
 * its generic range as 8 to 128 bits (1 to 16 octets), and Section 3.4.4.8
 * narrows the maximum by CTL — 128 bits (16 octets) for an Access message
 * (CTL=0), but only 96 bits (12 octets) for a Transport Control message
 * (CTL=1), because a Transport Control message carries no upper-transport
 * MIC of its own and the network layer already spends more of the fixed
 * PDU budget on its own longer (64-bit) NetMIC. A caller that bypasses this
 * check would silently produce a non-compliant PDU — Node's AES-CCM has no
 * opinion on mesh's own length rules and encrypts whatever it is given.
 */

export interface NetworkPduInput {
  /** 128-bit network key this subnet's traffic is secured with. */
  networkKey: Buffer;
  /** 32-bit IV Index in effect; only its least significant bit is sent in clear (IVI). */
  ivIndex: number;
  /** Network Control flag: false = Access message (32-bit NetMIC), true = Transport Control message (64-bit NetMIC). */
  ctl: boolean;
  /** 7-bit Time To Live. */
  ttl: number;
  /** 24-bit sequence number for this element. */
  seq: number;
  /** 16-bit source address (this element). */
  src: number;
  /** 16-bit destination address; encrypted (not merely obfuscated) on the wire. */
  dst: number;
  /**
   * Lower Transport PDU; encrypted (not merely obfuscated) on the wire.
   * Never empty (Table 3.10: 8 to 128 bits, i.e. 1 to 16 octets), and
   * further capped by `ctl` (Section 3.4.4.8): 1-16 octets for an Access
   * message (ctl=false), 1-12 octets for a Transport Control message
   * (ctl=true).
   */
  transportPdu: Buffer;
}

/** P input fixed by Section 3.9.6.3.1 for managed-flooding security material. */
const MANAGED_FLOODING_P = Buffer.from([0x00]);

const NET_MIC_LENGTH_ACCESS = 4; // 32 bits (Table 3.11, CTL=0).
const NET_MIC_LENGTH_CONTROL = 8; // 64 bits (Table 3.11, CTL=1).

const MAX_TTL = 0x7f;
const MAX_SEQ = 0xffffff;
const MAX_ADDRESS = 0xffff;
const MAX_IV_INDEX = 0xffffffff;

// Table 3.10's generic TransportPDU width is "8 to 128 bits" (1-16 octets);
// Section 3.4.4.8 narrows the maximum by CTL: 128 bits (16 octets) for an
// Access message, 96 bits (12 octets) for a Transport Control message.
const MIN_TRANSPORT_PDU_LENGTH = 1;
const MAX_TRANSPORT_PDU_LENGTH_ACCESS = 16; // 128 bits (Section 3.4.4.8, CTL=0).
const MAX_TRANSPORT_PDU_LENGTH_CONTROL = 12; // 96 bits (Section 3.4.4.8, CTL=1).

const DST_LENGTH = 2;
const HEADER_LENGTH = 7; // 1 (IVI|NID) + 6 (obfuscated CTL/TTL/SEQ/SRC), Section 3.4.4.

// The shortest legal encrypted part is EncDST (2) + a 1-octet EncTransportPDU
// + the shorter 4-octet NetMIC (Table 3.11, Access/CTL=0) - which happens to
// be exactly the 7 octets the Privacy Random is read from (step 4 of
// `encodeNetworkPdu`'s own comment above), so this bound also guarantees
// enough bytes exist to deobfuscate the header before CTL is even known.
const MIN_ENCRYPTED_LENGTH = DST_LENGTH + MIN_TRANSPORT_PDU_LENGTH + NET_MIC_LENGTH_ACCESS;
const MIN_PDU_LENGTH = HEADER_LENGTH + MIN_ENCRYPTED_LENGTH;

function assertRange(field: string, value: number, max: number): void {
  if (!Number.isInteger(value) || value < 0 || value > max) {
    throw new Error(`network PDU field "${field}" must be an integer in [0, ${max}], got ${value}`);
  }
}

function assertTransportPduLength(transportPdu: Buffer, ctl: boolean): void {
  const max = ctl ? MAX_TRANSPORT_PDU_LENGTH_CONTROL : MAX_TRANSPORT_PDU_LENGTH_ACCESS;
  if (transportPdu.length < MIN_TRANSPORT_PDU_LENGTH || transportPdu.length > max) {
    throw new Error(
      `network PDU field "transportPdu" must be ${MIN_TRANSPORT_PDU_LENGTH}-${max} bytes when ctl=${ctl}, got ${transportPdu.length}`,
    );
  }
}

export function encodeNetworkPdu(input: NetworkPduInput): Buffer {
  assertRange('ttl', input.ttl, MAX_TTL);
  assertRange('seq', input.seq, MAX_SEQ);
  assertRange('src', input.src, MAX_ADDRESS);
  assertRange('dst', input.dst, MAX_ADDRESS);
  assertRange('ivIndex', input.ivIndex, MAX_IV_INDEX);
  if (input.networkKey.length !== 16) {
    throw new Error(`network PDU field "networkKey" must be 16 bytes, got ${input.networkKey.length}`);
  }
  assertTransportPduLength(input.transportPdu, input.ctl);

  // Step 1: derive NID, EncryptionKey and PrivacyKey from the network key.
  const { nid, encryptionKey, privacyKey } = k2(input.networkKey, MANAGED_FLOODING_P);

  // Step 2: build the network nonce this message is authenticated under.
  const nonce = networkNonce({
    ctl: input.ctl,
    ttl: input.ttl,
    seq: input.seq,
    src: input.src,
    ivIndex: input.ivIndex,
  });

  // Step 3: encrypt and authenticate DST || TransportPDU under EncryptionKey.
  const dst = Buffer.alloc(2);
  dst.writeUInt16BE(input.dst, 0);
  const micLength = input.ctl ? NET_MIC_LENGTH_CONTROL : NET_MIC_LENGTH_ACCESS;
  const { ciphertext: encDstAndTransportPdu, tag: netMic } = ccmEncrypt(
    encryptionKey,
    nonce,
    Buffer.concat([dst, input.transportPdu]),
    micLength,
  );

  // Step 4: build the obfuscation mask (PECB) from the Privacy Random taken
  // out of what step 3 just produced, and the IV Index.
  const privacyRandom = Buffer.concat([encDstAndTransportPdu, netMic]).subarray(0, 7);
  const privacyPlaintext = Buffer.alloc(16);
  privacyPlaintext.writeUInt32BE(input.ivIndex, 5);
  privacyRandom.copy(privacyPlaintext, 9);
  const pecb = e(privacyKey, privacyPlaintext);

  // Step 5: apply the mask to the six clear header octets (CTL/TTL/SEQ/SRC).
  const clearHeader = Buffer.alloc(6);
  clearHeader.writeUInt8((input.ctl ? 0x80 : 0x00) | input.ttl, 0);
  clearHeader.writeUIntBE(input.seq, 1, 3);
  clearHeader.writeUInt16BE(input.src, 4);
  const obfuscatedData = Buffer.alloc(6);
  for (let i = 0; i < 6; i += 1) {
    obfuscatedData[i] = (clearHeader[i] as number) ^ (pecb[i] as number);
  }

  // Step 6: assemble IVI||NID, ObfuscatedData, EncDST||EncTransportPDU, NetMIC.
  const ivNid = ((input.ivIndex & 0x01) << 7) | nid;
  return Buffer.concat([Buffer.from([ivNid]), obfuscatedData, encDstAndTransportPdu, netMic]);
}

export interface DecodeNetworkPduInput {
  /** 128-bit network key to try this received packet against. */
  networkKey: Buffer;
  /**
   * 32-bit IV Index currently in effect on this subnet - folded into both
   * the network nonce and the obfuscation's Privacy Plaintext, so it must
   * match what the sender used or deobfuscation and authentication both
   * fail.
   */
  ivIndex: number;
  /** The received, on-the-wire Network PDU. */
  pdu: Buffer;
}

/** A successfully decoded, authenticated Network PDU - `NetworkPduInput` minus the NetKey/IV Index used to decode it. */
export interface DecodedNetworkPdu {
  ctl: boolean;
  ttl: number;
  seq: number;
  src: number;
  dst: number;
  transportPdu: Buffer;
}

/**
 * Inverts `encodeNetworkPdu`: recovers a received Network PDU's header and
 * TransportPDU, or returns null when the packet is not this subnet's. This
 * is not error handling bolted on afterwards - it is the design's own stated
 * rule for traffic from other networks ("Messages we cannot decrypt are
 * ignored, since they belong to other networks"). A mesh radio hears
 * neighbouring networks' traffic constantly; a decoder that threw on it
 * would turn that ordinary background noise into a flood of failures in
 * whatever calls this.
 *
 * Checks run cheapest first, so foreign traffic - the common case - is
 * dropped before any AES-CCM work:
 *
 * 1. Derive NID/EncryptionKey/PrivacyKey from the candidate NetKey (the same
 *    k2(NetKey, 0x00) the encoder uses) and compare NID against the low 7
 *    bits of the PDU's leading octet. A mismatch returns null immediately.
 *    NID is only 7 bits and merely narrows which NetKey to try at all
 *    (Section 3.9.6.3.1: up to 2^121 keys can share one NID) - it is a cheap
 *    filter, not authentication, so a NID match alone proves nothing yet.
 * 2. Reject anything too short to possibly hold the header plus the
 *    smallest legal payload (`MIN_PDU_LENGTH`) - below this there also
 *    aren't the 7 octets of encrypted payload the Privacy Random is read
 *    from next, so deobfuscation itself would be reading past the buffer.
 * 3. Deobfuscate the header - PECB from the Privacy Plaintext (IV Index +
 *    Privacy Random), XORed against the six obfuscated octets - to recover
 *    CTL/TTL/SEQ/SRC. CTL fixes the expected NetMIC length (Table 3.11) and,
 *    with it, the TransportPDU's legal length range (Section 3.4.4.8); a
 *    recovered length outside that range returns null rather than slicing a
 *    bogus ciphertext/tag split.
 * 4. Rebuild the network nonce from the recovered CTL/TTL/SEQ/SRC and the
 *    caller's IV Index, then run AES-CCM decryption/authentication
 *    (`ccmDecrypt`) over EncDST||EncTransportPDU against NetMIC. Null here
 *    means the tag did not verify - someone else's traffic under a
 *    different EncryptionKey, however coincidentally its NID matched - and
 *    is returned as-is.
 *
 * A caller's own mistake is not swallowed the same way: a `networkKey` of
 * the wrong length throws (checked explicitly below, matching
 * `encodeNetworkPdu`), exactly as `ccmDecrypt` already distinguishes a
 * genuine programming error from ordinary foreign traffic.
 */
export function decodeNetworkPdu(input: DecodeNetworkPduInput): DecodedNetworkPdu | null {
  if (input.networkKey.length !== 16) {
    throw new Error(`network PDU field "networkKey" must be 16 bytes, got ${input.networkKey.length}`);
  }
  assertRange('ivIndex', input.ivIndex, MAX_IV_INDEX);

  // Step 1: derive NID/EncryptionKey/PrivacyKey and check NID first - cheap,
  // and lets us drop traffic for other networks before any AES-CCM work.
  const { nid, encryptionKey, privacyKey } = k2(input.networkKey, MANAGED_FLOODING_P);
  if (input.pdu.length < 1 || ((input.pdu[0] as number) & 0x7f) !== nid) {
    return null;
  }

  // Step 2: the PDU must be long enough to hold the header plus the
  // smallest legal payload.
  if (input.pdu.length < MIN_PDU_LENGTH) {
    return null;
  }

  // Step 3: deobfuscate the header the same way `encodeNetworkPdu` obfuscated
  // it - PECB from the Privacy Plaintext, XORed against the six obfuscated
  // octets - then use the recovered CTL to fix the NetMIC length and the
  // TransportPDU's legal range.
  const encryptedPart = input.pdu.subarray(HEADER_LENGTH);
  const privacyRandom = encryptedPart.subarray(0, 7);
  const privacyPlaintext = Buffer.alloc(16);
  privacyPlaintext.writeUInt32BE(input.ivIndex, 5);
  privacyRandom.copy(privacyPlaintext, 9);
  const pecb = e(privacyKey, privacyPlaintext);

  const obfuscatedData = input.pdu.subarray(1, HEADER_LENGTH);
  const clearHeader = Buffer.alloc(6);
  for (let i = 0; i < 6; i += 1) {
    clearHeader[i] = (obfuscatedData[i] as number) ^ (pecb[i] as number);
  }
  const ctl = ((clearHeader[0] as number) & 0x80) !== 0;
  const ttl = (clearHeader[0] as number) & 0x7f;
  const seq = clearHeader.readUIntBE(1, 3);
  const src = clearHeader.readUInt16BE(4);

  const micLength = ctl ? NET_MIC_LENGTH_CONTROL : NET_MIC_LENGTH_ACCESS;
  const maxTransportPduLength = ctl ? MAX_TRANSPORT_PDU_LENGTH_CONTROL : MAX_TRANSPORT_PDU_LENGTH_ACCESS;
  const transportPduLength = encryptedPart.length - DST_LENGTH - micLength;
  if (transportPduLength < MIN_TRANSPORT_PDU_LENGTH || transportPduLength > maxTransportPduLength) {
    return null;
  }

  // Step 4: rebuild the nonce from the recovered fields, then decrypt and authenticate.
  const nonce = networkNonce({ ctl, ttl, seq, src, ivIndex: input.ivIndex });
  const encDstAndTransportPdu = encryptedPart.subarray(0, DST_LENGTH + transportPduLength);
  const netMic = encryptedPart.subarray(DST_LENGTH + transportPduLength);
  const decrypted = ccmDecrypt(encryptionKey, nonce, encDstAndTransportPdu, netMic);
  if (decrypted === null) {
    return null;
  }

  return {
    ctl,
    ttl,
    seq,
    src,
    dst: decrypted.readUInt16BE(0),
    transportPdu: decrypted.subarray(DST_LENGTH),
  };
}
