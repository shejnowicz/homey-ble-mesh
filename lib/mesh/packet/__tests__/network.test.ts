import { encodeNetworkPdu } from '../network';
import { hex, NETWORK_PDU_SAMPLE_1, NETWORK_PDU_SAMPLE_2, NETWORK_PDU_SAMPLE_3 } from './vectors';

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
