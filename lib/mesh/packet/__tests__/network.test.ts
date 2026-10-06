import { e } from '../../crypto/cmac';
import { ccmEncrypt } from '../../crypto/ccm';
import { k2 } from '../../crypto/derive';
import { networkNonce } from '../nonce';
import { encodeNetworkPdu, decodeNetworkPdu } from '../network';
import {
  hex,
  NETWORK_PDU_SAMPLE_1,
  NETWORK_PDU_SAMPLE_2,
  NETWORK_PDU_SAMPLE_3,
  NETWORK_PDU_SAMPLE_ODD_IV,
  FOREIGN_NETWORK_KEY_SAME_NID,
} from './vectors';

// 8.3.1 "Message #1": a Friend Request (Transport Control message, CTL=1,
// so a 64-bit NetMIC). The first sample that exercises obfuscation end to
// end: a single wrong byte in key derivation, encryption or the PECB mask
// changes the published wire PDU.
test('encodeNetworkPdu matches the published Message #1 sample (CTL=1)', () => {
  const pdu = encodeNetworkPdu({
    networkKey: hex(NETWORK_PDU_SAMPLE_1.networkKey),
    ivIndex: NETWORK_PDU_SAMPLE_1.ivIndex,
    ctl: NETWORK_PDU_SAMPLE_1.ctl,
    ttl: NETWORK_PDU_SAMPLE_1.ttl,
    seq: NETWORK_PDU_SAMPLE_1.seq,
    src: NETWORK_PDU_SAMPLE_1.src,
    dst: NETWORK_PDU_SAMPLE_1.dst,
    transportPdu: hex(NETWORK_PDU_SAMPLE_1.transportPdu),
  });
  expect(pdu.toString('hex')).toBe(NETWORK_PDU_SAMPLE_1.expected);
  expect(pdu).toEqual(hex(NETWORK_PDU_SAMPLE_1.expected));
});

// 8.3.2 "Message #2": a second CTL=1 sample with a different SEQ/SRC/DST and
// a shorter TransportPDU than Message #1 — catches an encoder that only
// happens to work for one TransportPDU length.
test('encodeNetworkPdu matches the published Message #2 sample (CTL=1)', () => {
  const pdu = encodeNetworkPdu({
    networkKey: hex(NETWORK_PDU_SAMPLE_2.networkKey),
    ivIndex: NETWORK_PDU_SAMPLE_2.ivIndex,
    ctl: NETWORK_PDU_SAMPLE_2.ctl,
    ttl: NETWORK_PDU_SAMPLE_2.ttl,
    seq: NETWORK_PDU_SAMPLE_2.seq,
    src: NETWORK_PDU_SAMPLE_2.src,
    dst: NETWORK_PDU_SAMPLE_2.dst,
    transportPdu: hex(NETWORK_PDU_SAMPLE_2.transportPdu),
  });
  expect(pdu.toString('hex')).toBe(NETWORK_PDU_SAMPLE_2.expected);
  expect(pdu).toEqual(hex(NETWORK_PDU_SAMPLE_2.expected));
});

// 8.3.18 "Message #18": a Health Current Status Access message, CTL=0, so a
// 32-bit NetMIC — the sample that pins down the shorter MIC length Table
// 3.11 assigns to Access messages, as opposed to the two CTL=1/64-bit
// samples above.
test('encodeNetworkPdu matches the published Message #18 sample (CTL=0)', () => {
  const pdu = encodeNetworkPdu({
    networkKey: hex(NETWORK_PDU_SAMPLE_3.networkKey),
    ivIndex: NETWORK_PDU_SAMPLE_3.ivIndex,
    ctl: NETWORK_PDU_SAMPLE_3.ctl,
    ttl: NETWORK_PDU_SAMPLE_3.ttl,
    seq: NETWORK_PDU_SAMPLE_3.seq,
    src: NETWORK_PDU_SAMPLE_3.src,
    dst: NETWORK_PDU_SAMPLE_3.dst,
    transportPdu: hex(NETWORK_PDU_SAMPLE_3.transportPdu),
  });
  expect(pdu.toString('hex')).toBe(NETWORK_PDU_SAMPLE_3.expected);
  expect(pdu).toEqual(hex(NETWORK_PDU_SAMPLE_3.expected));
});

// 8.3.20 "Message #20": the published sample with an ODD IV Index
// (0x12345677). The three samples above all use 0x12345678, whose least
// significant bit is 0 — and that bit is the only part of the IV Index that
// behaves differently from the rest of it. It is sent in clear as IVI
// (Table 3.10) while the whole 32-bit value is also folded into the network
// nonce (Table 3.66) and into the obfuscation's Privacy Plaintext (Section
// 3.9.7.3). With an even IV Index, an encoder that masked that bit off
// before either of those two uses still reproduces every sample above
// exactly; with this one it does not. Verified by mutation: clearing the IV
// Index's LSB before building the Privacy Plaintext, and clearing it before
// building the network nonce, each leave all of the samples above passing
// and are caught here.
test('encodeNetworkPdu matches the published Message #20 sample (odd IV Index)', () => {
  const pdu = encodeNetworkPdu({
    networkKey: hex(NETWORK_PDU_SAMPLE_ODD_IV.networkKey),
    ivIndex: NETWORK_PDU_SAMPLE_ODD_IV.ivIndex,
    ctl: NETWORK_PDU_SAMPLE_ODD_IV.ctl,
    ttl: NETWORK_PDU_SAMPLE_ODD_IV.ttl,
    seq: NETWORK_PDU_SAMPLE_ODD_IV.seq,
    src: NETWORK_PDU_SAMPLE_ODD_IV.src,
    dst: NETWORK_PDU_SAMPLE_ODD_IV.dst,
    transportPdu: hex(NETWORK_PDU_SAMPLE_ODD_IV.transportPdu),
  });
  expect(pdu.toString('hex')).toBe(NETWORK_PDU_SAMPLE_ODD_IV.expected);
  expect(pdu).toEqual(hex(NETWORK_PDU_SAMPLE_ODD_IV.expected));
  // The document's own "IVI NID" row for this message reads 0xe8 — IVI set,
  // NID 0x68 — so the leading octet is checked against the specification's
  // published value, not merely against the rest of our own output.
  expect(pdu[0]).toBe(0xe8);
});

test('encodeNetworkPdu NetMIC length follows CTL: 8 bytes when set, 4 when clear', () => {
  const ctlSet = encodeNetworkPdu({
    networkKey: hex(NETWORK_PDU_SAMPLE_1.networkKey),
    ivIndex: NETWORK_PDU_SAMPLE_1.ivIndex,
    ctl: true,
    ttl: NETWORK_PDU_SAMPLE_1.ttl,
    seq: NETWORK_PDU_SAMPLE_1.seq,
    src: NETWORK_PDU_SAMPLE_1.src,
    dst: NETWORK_PDU_SAMPLE_1.dst,
    transportPdu: hex(NETWORK_PDU_SAMPLE_1.transportPdu),
  });
  const ctlClear = encodeNetworkPdu({
    networkKey: hex(NETWORK_PDU_SAMPLE_3.networkKey),
    ivIndex: NETWORK_PDU_SAMPLE_3.ivIndex,
    ctl: false,
    ttl: NETWORK_PDU_SAMPLE_3.ttl,
    seq: NETWORK_PDU_SAMPLE_3.seq,
    src: NETWORK_PDU_SAMPLE_3.src,
    dst: NETWORK_PDU_SAMPLE_3.dst,
    transportPdu: hex(NETWORK_PDU_SAMPLE_3.transportPdu),
  });
  // header (1) + obfuscated header (6) + EncDST (2) + EncTransportPDU + NetMIC.
  const overhead = 1 + 6 + 2;
  expect(ctlSet.length - overhead - hex(NETWORK_PDU_SAMPLE_1.transportPdu).length).toBe(8);
  expect(ctlClear.length - overhead - hex(NETWORK_PDU_SAMPLE_3.transportPdu).length).toBe(4);
});

// Table 3.10: the leading octet packs IVI (the IV Index's least significant
// bit) into bit 7 and NID into bits 6-0. All three published samples above
// use IV Index 0x12345678, whose LSB is 0 — so none of their KATs would
// notice a regression that stopped threading IVI into the leading octet at
// all (a mutation that replaced the whole packing with a hardcoded 0 passed
// every one of them). This test forces IVI=1 and checks only the leading
// octet, reasoned from the spec rather than from the encoder's own output:
// Message #1's own NetworkPDU block (8.3.1) publishes NID=0x68 for this
// NetKey, so with IVI's bit set the leading octet must be 0x80 | 0x68 =
// 0xe8 — independent of anything encodeNetworkPdu itself computes.
test("encodeNetworkPdu packs an odd IV Index's LSB into the leading octet (IVI, Table 3.10)", () => {
  const pdu = encodeNetworkPdu({
    networkKey: hex(NETWORK_PDU_SAMPLE_1.networkKey),
    ivIndex: NETWORK_PDU_SAMPLE_1.ivIndex | 1, // force IVI=1; NetKey unchanged, so NID is still 0x68 (8.3.1).
    ctl: NETWORK_PDU_SAMPLE_1.ctl,
    ttl: NETWORK_PDU_SAMPLE_1.ttl,
    seq: NETWORK_PDU_SAMPLE_1.seq,
    src: NETWORK_PDU_SAMPLE_1.src,
    dst: NETWORK_PDU_SAMPLE_1.dst,
    transportPdu: hex(NETWORK_PDU_SAMPLE_1.transportPdu),
  });
  expect(pdu[0]).toBe(0x80 | 0x68);
});

describe('transportPdu length validation', () => {
  // Section 3.4.4.8: a Transport Control message's (CTL=1) TransportPDU is
  // capped at 96 bits = 12 octets, not Table 3.10's generic 128-bit/16-octet
  // maximum, which only applies when CTL=0.
  test('rejects a TransportPDU longer than 12 octets for a control message (CTL=1)', () => {
    expect(() =>
      encodeNetworkPdu({
        networkKey: hex(NETWORK_PDU_SAMPLE_1.networkKey),
        ivIndex: NETWORK_PDU_SAMPLE_1.ivIndex,
        ctl: true,
        ttl: NETWORK_PDU_SAMPLE_1.ttl,
        seq: NETWORK_PDU_SAMPLE_1.seq,
        src: NETWORK_PDU_SAMPLE_1.src,
        dst: NETWORK_PDU_SAMPLE_1.dst,
        transportPdu: Buffer.alloc(13),
      }),
    ).toThrow(/transportPdu/);
  });

  // Section 3.4.4.8: an Access message's (CTL=0) TransportPDU is capped at
  // 128 bits = 16 octets.
  test('rejects a TransportPDU longer than 16 octets for an access message (CTL=0)', () => {
    expect(() =>
      encodeNetworkPdu({
        networkKey: hex(NETWORK_PDU_SAMPLE_3.networkKey),
        ivIndex: NETWORK_PDU_SAMPLE_3.ivIndex,
        ctl: false,
        ttl: NETWORK_PDU_SAMPLE_3.ttl,
        seq: NETWORK_PDU_SAMPLE_3.seq,
        src: NETWORK_PDU_SAMPLE_3.src,
        dst: NETWORK_PDU_SAMPLE_3.dst,
        transportPdu: Buffer.alloc(17),
      }),
    ).toThrow(/transportPdu/);
  });

  // Table 3.10's width is "8 to 128 bits" — never zero, for either CTL value.
  test('rejects an empty TransportPDU', () => {
    expect(() =>
      encodeNetworkPdu({
        networkKey: hex(NETWORK_PDU_SAMPLE_3.networkKey),
        ivIndex: NETWORK_PDU_SAMPLE_3.ivIndex,
        ctl: false,
        ttl: NETWORK_PDU_SAMPLE_3.ttl,
        seq: NETWORK_PDU_SAMPLE_3.seq,
        src: NETWORK_PDU_SAMPLE_3.src,
        dst: NETWORK_PDU_SAMPLE_3.dst,
        transportPdu: Buffer.alloc(0),
      }),
    ).toThrow(/transportPdu/);
  });
});

// Known-answer tests in reverse: feed decodeNetworkPdu the SAME transcribed,
// published wire PDU the encoding tests above produce, and recover the exact
// published header fields and TransportPDU that produced it. Never a round
// trip through our own encoder — that would pass even if encoding and
// decoding shared the same mistake, the single most likely way this layer
// goes wrong.
test('decoding a published PDU recovers its published header and transport PDU', () => {
  // 8.3.1 "Message #1" (CTL=1, so a 64-bit NetMIC).
  const decoded1 = decodeNetworkPdu({
    networkKey: hex(NETWORK_PDU_SAMPLE_1.networkKey),
    ivIndex: NETWORK_PDU_SAMPLE_1.ivIndex,
    pdu: hex(NETWORK_PDU_SAMPLE_1.expected),
  });
  expect(decoded1).not.toBeNull();
  expect(decoded1?.ctl).toBe(NETWORK_PDU_SAMPLE_1.ctl);
  expect(decoded1?.ttl).toBe(NETWORK_PDU_SAMPLE_1.ttl);
  expect(decoded1?.seq).toBe(NETWORK_PDU_SAMPLE_1.seq);
  expect(decoded1?.src).toBe(NETWORK_PDU_SAMPLE_1.src);
  expect(decoded1?.dst).toBe(NETWORK_PDU_SAMPLE_1.dst);
  expect(decoded1?.transportPdu).toEqual(hex(NETWORK_PDU_SAMPLE_1.transportPdu));

  // 8.3.18 "Message #18" (CTL=0, so a 32-bit NetMIC, and a non-zero TTL) —
  // pins down the shorter-MIC-length branch the sample above doesn't reach.
  const decoded3 = decodeNetworkPdu({
    networkKey: hex(NETWORK_PDU_SAMPLE_3.networkKey),
    ivIndex: NETWORK_PDU_SAMPLE_3.ivIndex,
    pdu: hex(NETWORK_PDU_SAMPLE_3.expected),
  });
  expect(decoded3).not.toBeNull();
  expect(decoded3?.ctl).toBe(NETWORK_PDU_SAMPLE_3.ctl);
  expect(decoded3?.ttl).toBe(NETWORK_PDU_SAMPLE_3.ttl);
  expect(decoded3?.seq).toBe(NETWORK_PDU_SAMPLE_3.seq);
  expect(decoded3?.src).toBe(NETWORK_PDU_SAMPLE_3.src);
  expect(decoded3?.dst).toBe(NETWORK_PDU_SAMPLE_3.dst);
  expect(decoded3?.transportPdu).toEqual(hex(NETWORK_PDU_SAMPLE_3.transportPdu));
});

// 8.3.20 "Message #20", the same odd-IV-Index sample the encoding test
// above uses, now driven backwards through the decoder. Using one sample on
// both sides is deliberate: it closes three separate one-line regressions
// that every other test in this file tolerates, because every other sample
// here has an IV Index whose least significant bit is 0.
//
// The third of those is the dangerous one. Step 1 of `decodeNetworkPdu`
// compares the PDU's leading octet against the derived NID after masking
// IVI off with 0x7f (Table 3.10: IVI is bit 7, NID is bits 6-0). Widen that
// mask by one character and the comparison includes IVI — which still
// matches while the IV Index is even, and rejects EVERY inbound packet the
// moment it turns odd, quietly, as if it were another network's traffic.
// The design follows the IV Index from secure network beacons, so it does
// change; this test is what stands between that and a silent, much later
// "the bulbs stopped responding".
test('decoding the published odd-IV-Index PDU recovers its published header and transport PDU', () => {
  const decoded = decodeNetworkPdu({
    networkKey: hex(NETWORK_PDU_SAMPLE_ODD_IV.networkKey),
    ivIndex: NETWORK_PDU_SAMPLE_ODD_IV.ivIndex,
    pdu: hex(NETWORK_PDU_SAMPLE_ODD_IV.expected),
  });
  expect(decoded).not.toBeNull();
  expect(decoded?.ctl).toBe(NETWORK_PDU_SAMPLE_ODD_IV.ctl);
  expect(decoded?.ttl).toBe(NETWORK_PDU_SAMPLE_ODD_IV.ttl);
  expect(decoded?.seq).toBe(NETWORK_PDU_SAMPLE_ODD_IV.seq);
  expect(decoded?.src).toBe(NETWORK_PDU_SAMPLE_ODD_IV.src);
  expect(decoded?.dst).toBe(NETWORK_PDU_SAMPLE_ODD_IV.dst);
  expect(decoded?.transportPdu).toEqual(hex(NETWORK_PDU_SAMPLE_ODD_IV.transportPdu));
});

// The design's own stated rule: "Messages we cannot decrypt are ignored,
// since they belong to other networks." FOREIGN_NETWORK_KEY_SAME_NID was
// picked (see vectors.ts) to derive the SAME NID as Message #1's real
// NetKey, so this exercises AES-CCM authentication rejection itself, not the
// cheap NID short-circuit the next test covers — a foreign key picked at
// random would, 127 times out of 128, already be rejected by NID alone.
test('a PDU encrypted under another network key is rejected', () => {
  const decoded = decodeNetworkPdu({
    networkKey: hex(FOREIGN_NETWORK_KEY_SAME_NID),
    ivIndex: NETWORK_PDU_SAMPLE_1.ivIndex,
    pdu: hex(NETWORK_PDU_SAMPLE_1.expected),
  });
  expect(decoded).toBeNull();
});

// A mesh radio hears truncated/corrupted captures constantly; this must be
// rejected quietly, not thrown on. Far below the minimum length a header
// plus the smallest legal payload could occupy.
test('a truncated PDU is rejected rather than throwing', () => {
  const truncated = hex(NETWORK_PDU_SAMPLE_1.expected).subarray(0, 8);
  const decode = (): unknown =>
    decodeNetworkPdu({
      networkKey: hex(NETWORK_PDU_SAMPLE_1.networkKey),
      ivIndex: NETWORK_PDU_SAMPLE_1.ivIndex,
      pdu: truncated,
    });
  expect(decode).not.toThrow();
  expect(decode()).toBeNull();
});

// Table 3.10: the leading octet's low 7 bits carry NID. Flipping the
// identifier's low nibble (leaving bit 7's IVI alone) on an otherwise
// untouched, correctly-keyed PDU isolates the cheap NID short-circuit from
// the authentication path the previous test covers.
test('a PDU whose network identifier does not match ours is rejected cheaply', () => {
  const pdu = hex(NETWORK_PDU_SAMPLE_1.expected);
  pdu[0] = (pdu[0] as number) ^ 0x0f;
  const decoded = decodeNetworkPdu({
    networkKey: hex(NETWORK_PDU_SAMPLE_1.networkKey),
    ivIndex: NETWORK_PDU_SAMPLE_1.ivIndex,
    pdu,
  });
  expect(decoded).toBeNull();
});

/**
 * Builds a genuinely authenticated Network PDU, bypassing only
 * `encodeNetworkPdu`'s own TransportPDU length guard.
 *
 * `encodeNetworkPdu` refuses to produce an over-long TransportPDU (that
 * guard is a caller-mistake check, tested separately below), so the
 * network layer's own steps are repeated here over the primitives in
 * `lib/mesh/crypto`, each already known-answer-tested against the
 * specification in its own suite. The point is to hand the decoder input it
 * cannot dismiss for any other reason: the NID matches, the header is
 * correctly obfuscated, and the NetMIC verifies. The only thing wrong with
 * it is its length — which is exactly what the check under test is for.
 */
function buildAuthenticatedPdu(input: {
  networkKey: Buffer;
  ivIndex: number;
  ctl: boolean;
  ttl: number;
  seq: number;
  src: number;
  dst: number;
  transportPdu: Buffer;
}): Buffer {
  const { nid, encryptionKey, privacyKey } = k2(input.networkKey, Buffer.from([0x00]));
  const nonce = networkNonce({
    ctl: input.ctl,
    ttl: input.ttl,
    seq: input.seq,
    src: input.src,
    ivIndex: input.ivIndex,
  });
  const dst = Buffer.alloc(2);
  dst.writeUInt16BE(input.dst, 0);
  const { ciphertext, tag } = ccmEncrypt(
    encryptionKey,
    nonce,
    Buffer.concat([dst, input.transportPdu]),
    input.ctl ? 8 : 4, // NetMIC size follows CTL (Table 3.11).
  );
  const privacyPlaintext = Buffer.alloc(16);
  privacyPlaintext.writeUInt32BE(input.ivIndex, 5);
  Buffer.concat([ciphertext, tag]).subarray(0, 7).copy(privacyPlaintext, 9);
  const pecb = e(privacyKey, privacyPlaintext);
  const clearHeader = Buffer.alloc(6);
  clearHeader.writeUInt8((input.ctl ? 0x80 : 0x00) | input.ttl, 0);
  clearHeader.writeUIntBE(input.seq, 1, 3);
  clearHeader.writeUInt16BE(input.src, 4);
  const obfuscated = Buffer.alloc(6);
  for (let i = 0; i < 6; i += 1) {
    obfuscated[i] = (clearHeader[i] as number) ^ (pecb[i] as number);
  }
  const ivNid = ((input.ivIndex & 0x01) << 7) | nid;
  return Buffer.concat([Buffer.from([ivNid]), obfuscated, ciphertext, tag]);
}

// `decodeNetworkPdu`'s post-deobfuscation length-range check bounds the
// recovered TransportPDU against Section 3.4.4.8. Its LOWER bound is
// unreachable in practice - the minimum-length early exit in step 2 and the
// MIC-length guard inside `ccmDecrypt` both already cover short input - but
// its UPPER bound is not dead code, and nothing else in this suite reaches
// it: a well-formed, correctly authenticated PDU can carry a TransportPDU
// longer than the specification allows, and only this check rejects it.
// Without these two tests the whole range check could be deleted and the
// suite would stay green.
//
// Each test builds BOTH a legal-maximum and a one-octet-too-long PDU the
// same way, so the null result below cannot be blamed on a broken builder:
// the legal one decodes and round-trips its TransportPDU exactly.
describe('a correctly authenticated PDU whose TransportPDU exceeds the specification maximum', () => {
  const networkKey = hex(NETWORK_PDU_SAMPLE_3.networkKey);
  const common = {
    networkKey,
    ivIndex: NETWORK_PDU_SAMPLE_3.ivIndex,
    ttl: NETWORK_PDU_SAMPLE_3.ttl,
    seq: NETWORK_PDU_SAMPLE_3.seq,
    src: NETWORK_PDU_SAMPLE_3.src,
    dst: NETWORK_PDU_SAMPLE_3.dst,
  };
  const decode = (pdu: Buffer): unknown =>
    decodeNetworkPdu({ networkKey, ivIndex: NETWORK_PDU_SAMPLE_3.ivIndex, pdu });

  // Section 3.4.4.8 / Table 3.10: 128 bits = 16 octets for an Access message.
  test('is rejected for an Access message (CTL=0) at 17 octets, while 16 decodes', () => {
    const legal = Buffer.alloc(16, 0xa5);
    const decodedLegal = decodeNetworkPdu({
      networkKey,
      ivIndex: NETWORK_PDU_SAMPLE_3.ivIndex,
      pdu: buildAuthenticatedPdu({ ...common, ctl: false, transportPdu: legal }),
    });
    expect(decodedLegal?.transportPdu).toEqual(legal);

    const overlong = buildAuthenticatedPdu({ ...common, ctl: false, transportPdu: Buffer.alloc(17, 0xa5) });
    expect(() => decode(overlong)).not.toThrow();
    expect(decode(overlong)).toBeNull();
  });

  // Section 3.4.4.8: only 96 bits = 12 octets for a Transport Control
  // message, because its 64-bit NetMIC takes more of the same fixed budget.
  test('is rejected for a Transport Control message (CTL=1) at 13 octets, while 12 decodes', () => {
    const legal = Buffer.alloc(12, 0x5a);
    const decodedLegal = decodeNetworkPdu({
      networkKey,
      ivIndex: NETWORK_PDU_SAMPLE_3.ivIndex,
      pdu: buildAuthenticatedPdu({ ...common, ctl: true, transportPdu: legal }),
    });
    expect(decodedLegal?.transportPdu).toEqual(legal);

    const overlong = buildAuthenticatedPdu({ ...common, ctl: true, transportPdu: Buffer.alloc(13, 0x5a) });
    expect(() => decode(overlong)).not.toThrow();
    expect(decode(overlong)).toBeNull();
  });
});

// The other half of this module's contract, stated in its own header and
// mirrored by `ccmDecrypt`: foreign traffic is dropped quietly (null), but a
// CALLER'S mistake throws, because a wrong-length key or an out-of-range
// field is a bug in our own code, not something an attacker can put on the
// air, and silently swallowing it would hide it.
//
// Every assertion below matches the module's own message prefix, `network
// PDU field "..."`, rather than just the field name. That is not
// over-specification, it is the whole point: remove any one of these guards
// and something downstream still throws - `nonce.ts`'s own range checks for
// ttl/seq/src/ivIndex, `k2`'s key-length check, or Node's ERR_OUT_OF_RANGE
// from a Buffer write - so a test asserting only `/ttl/` or only `toThrow()`
// would keep passing and prove nothing. Pinning the prefix is what makes
// each of these tests fail when its guard is deleted.
//
// Unlike `ccmDecrypt`, which rethrows Node's coded errors and whose tests
// assert `code: 'ERR_CRYPTO_INVALID_KEYLEN'`/`'ERR_CRYPTO_INVALID_IV'`,
// `network.ts` raises plain Errors of its own with no `code` property, so
// there is no code to assert here.
describe("caller mistakes throw rather than being dropped as foreign traffic", () => {
  const valid = {
    networkKey: hex(NETWORK_PDU_SAMPLE_1.networkKey),
    ivIndex: NETWORK_PDU_SAMPLE_1.ivIndex,
    ctl: NETWORK_PDU_SAMPLE_1.ctl,
    ttl: NETWORK_PDU_SAMPLE_1.ttl,
    seq: NETWORK_PDU_SAMPLE_1.seq,
    src: NETWORK_PDU_SAMPLE_1.src,
    dst: NETWORK_PDU_SAMPLE_1.dst,
    transportPdu: hex(NETWORK_PDU_SAMPLE_1.transportPdu),
  };

  test('encodeNetworkPdu rejects a network key that is not 128 bits', () => {
    expect(() => encodeNetworkPdu({ ...valid, networkKey: Buffer.alloc(15) })).toThrow(
      /network PDU field "networkKey"/,
    );
    expect(() => encodeNetworkPdu({ ...valid, networkKey: Buffer.alloc(32) })).toThrow(
      /network PDU field "networkKey"/,
    );
  });

  // One case per range guard in `encodeNetworkPdu`, each at the first value
  // outside the width the specification gives that field: TTL is 7 bits
  // (Table 3.67), SEQ 24, SRC/DST 16, IV Index 32.
  test.each([
    ['ttl', { ttl: 0x80 }],
    ['seq', { seq: 0x1000000 }],
    ['src', { src: 0x10000 }],
    ['dst', { dst: 0x10000 }],
    ['ivIndex', { ivIndex: 0x100000000 }],
  ])('encodeNetworkPdu rejects an out-of-range %s', (field, override) => {
    expect(() => encodeNetworkPdu({ ...valid, ...override })).toThrow(
      new RegExp(`network PDU field "${field}"`),
    );
  });

  // Negative and non-integer values are caller mistakes too - `assertRange`
  // checks `Number.isInteger` and the lower bound, not just the upper one.
  test.each([
    ['a negative', -1],
    ['a fractional', 1.5],
  ])('encodeNetworkPdu rejects %s sequence number', (_label, seq) => {
    expect(() => encodeNetworkPdu({ ...valid, seq })).toThrow(/network PDU field "seq"/);
  });

  test('decodeNetworkPdu rejects a network key that is not 128 bits', () => {
    expect(() =>
      decodeNetworkPdu({
        networkKey: Buffer.alloc(15),
        ivIndex: NETWORK_PDU_SAMPLE_1.ivIndex,
        pdu: hex(NETWORK_PDU_SAMPLE_1.expected),
      }),
    ).toThrow(/network PDU field "networkKey"/);
  });

  // Deliberately paired with a PDU this key WOULD otherwise decode, so the
  // guard is reached rather than short-circuited by the NID check.
  test('decodeNetworkPdu rejects an IV Index outside 32 bits', () => {
    expect(() =>
      decodeNetworkPdu({
        networkKey: hex(NETWORK_PDU_SAMPLE_1.networkKey),
        ivIndex: 0x100000000,
        pdu: hex(NETWORK_PDU_SAMPLE_1.expected),
      }),
    ).toThrow(/network PDU field "ivIndex"/);
    expect(() =>
      decodeNetworkPdu({
        networkKey: hex(NETWORK_PDU_SAMPLE_1.networkKey),
        ivIndex: -1,
        pdu: hex(NETWORK_PDU_SAMPLE_1.expected),
      }),
    ).toThrow(/network PDU field "ivIndex"/);
  });
});
