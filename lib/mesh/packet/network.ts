import { e } from '../crypto/cmac';
import { ccmEncrypt } from '../crypto/ccm';
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
