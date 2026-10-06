import { encodeNetworkPdu, decodeNetworkPdu } from '../network';
import {
  hex,
  NETWORK_PDU_SAMPLE_1,
  NETWORK_PDU_SAMPLE_2,
  NETWORK_PDU_SAMPLE_3,
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
