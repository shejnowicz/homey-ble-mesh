/**
 * The three 13-octet AES-CCM nonces built from message metadata rather than
 * derived by a crypto function: network, application and device. Layouts
 * are Mesh Protocol v1.1 Section 3.9.5 Tables 3.66 (network), 3.67 (CTL and
 * TTL), 3.68 (application) and 3.69/3.70/3.71 (ASZMIC/Pad, device, device's
 * ASZMIC/Pad) — see `__tests__/vectors.ts` for the full citation and the
 * worked examples these are tested against.
 *
 * Every field is range-checked and written with `writeUIntBE`/
 * `writeUInt32BE`, which throw on overflow: a silently truncated field would
 * still produce a 13-byte nonce that looks valid but authenticates nothing
 * the sender intended.
 */

const NONCE_LENGTH = 13;

const NONCE_TYPE_NETWORK = 0x00;
const NONCE_TYPE_APPLICATION = 0x01;
const NONCE_TYPE_DEVICE = 0x02;

const MAX_TTL = 0x7f; // 7 bits (Table 3.67)
const MAX_SEQ = 0xffffff; // 24 bits (SEQ is always 3 octets)
const MAX_ADDRESS = 0xffff; // 16 bits (SRC/DST are always 2 octets)
const MAX_IV_INDEX = 0xffffffff; // 32 bits (IV Index is always 4 octets)

function assertRange(field: string, value: number, max: number): void {
  if (!Number.isInteger(value) || value < 0 || value > max) {
    throw new Error(`nonce field "${field}" must be an integer in [0, ${max}], got ${value}`);
  }
}

export interface NetworkNonceInput {
  /** Network Control flag from the Network PDU header (Table 3.10/3.11). */
  ctl: boolean;
  /** 7-bit Time To Live. */
  ttl: number;
  /** 24-bit sequence number. */
  seq: number;
  /** 16-bit source address. */
  src: number;
  /** 32-bit IV Index. */
  ivIndex: number;
}

/**
 * Table 3.66 "Network nonce format": Nonce Type (1, 0x00) | CTL/TTL (1,
 * Table 3.67) | SEQ (3) | SRC (2) | Pad (2, 0x0000) | IV Index (4).
 */
export function networkNonce(input: NetworkNonceInput): Buffer {
  assertRange('ttl', input.ttl, MAX_TTL);
  assertRange('seq', input.seq, MAX_SEQ);
  assertRange('src', input.src, MAX_ADDRESS);
  assertRange('ivIndex', input.ivIndex, MAX_IV_INDEX);

  const nonce = Buffer.alloc(NONCE_LENGTH);
  nonce.writeUInt8(NONCE_TYPE_NETWORK, 0);
  nonce.writeUInt8((input.ctl ? 0x80 : 0x00) | input.ttl, 1); // CTL is bit 7, TTL is bits 6-0.
  nonce.writeUIntBE(input.seq, 2, 3);
  nonce.writeUInt16BE(input.src, 5);
  nonce.writeUInt16BE(0x0000, 7); // Pad.
  nonce.writeUInt32BE(input.ivIndex, 9);
  return nonce;
}

export interface UpperTransportNonceInput {
  /** Segmented-message long-MIC flag (SZMIC), 0 for unsegmented messages. */
  aszmic: boolean;
  /** 24-bit sequence number (the 24 lowest bits of SeqAuth when segmented). */
  seq: number;
  /** 16-bit source address. */
  src: number;
  /** 16-bit destination address. */
  dst: number;
  /** 32-bit IV Index. */
  ivIndex: number;
}

/**
 * Tables 3.68/3.70 "Application"/"Device nonce format" share one layout:
 * Nonce Type (1, 0x01 or 0x02) | ASZMIC/Pad (1, Table 3.69/3.71) | SEQ (3) |
 * SRC (2) | DST (2) | IV Index (4).
 */
function upperTransportNonce(nonceType: number, input: UpperTransportNonceInput): Buffer {
  assertRange('seq', input.seq, MAX_SEQ);
  assertRange('src', input.src, MAX_ADDRESS);
  assertRange('dst', input.dst, MAX_ADDRESS);
  assertRange('ivIndex', input.ivIndex, MAX_IV_INDEX);

  const nonce = Buffer.alloc(NONCE_LENGTH);
  nonce.writeUInt8(nonceType, 0);
  nonce.writeUInt8(input.aszmic ? 0x80 : 0x00, 1); // ASZMIC is bit 7, Pad (bits 6-0) is always 0.
  nonce.writeUIntBE(input.seq, 2, 3);
  nonce.writeUInt16BE(input.src, 5);
  nonce.writeUInt16BE(input.dst, 7);
  nonce.writeUInt32BE(input.ivIndex, 9);
  return nonce;
}

/** Used with an application key for upper transport authentication and encryption. */
export function applicationNonce(input: UpperTransportNonceInput): Buffer {
  return upperTransportNonce(NONCE_TYPE_APPLICATION, input);
}

/** Used with a device key for upper transport authentication and encryption. */
export function deviceNonce(input: UpperTransportNonceInput): Buffer {
  return upperTransportNonce(NONCE_TYPE_DEVICE, input);
}
