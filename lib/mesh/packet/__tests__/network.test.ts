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
