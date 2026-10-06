import {
  encodeUnsegmentedAccess,
  decodeUnsegmentedAccess,
  encodeUnsegmentedControl,
  decodeUnsegmentedControl,
} from '../lowerTransport';
import {
  hex,
  LOWER_TRANSPORT_SAMPLE_CONTROL_1,
  LOWER_TRANSPORT_SAMPLE_CONTROL_2,
  LOWER_TRANSPORT_SAMPLE_ACCESS_1,
  LOWER_TRANSPORT_SAMPLE_ACCESS_2,
  LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1,
  LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2,
  LOWER_TRANSPORT_SAMPLE_SEGMENTED,
} from './vectors';

describe('Unsegmented Access message (Section 3.5.2.1, Table 3.17)', () => {
  // 8.3.18 "Message #18": AKF=1, AID=0x26, a non-virtual destination -
  // the baseline access sample.
  test('encodeUnsegmentedAccess matches the published Message #18 sample', () => {
    const pdu = encodeUnsegmentedAccess({
      akf: LOWER_TRANSPORT_SAMPLE_ACCESS_1.akf,
      aid: LOWER_TRANSPORT_SAMPLE_ACCESS_1.aid,
      upperTransportPdu: hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.upperTransportPdu),
    });
    expect(pdu.toString('hex')).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_1.expected);
    expect(pdu).toEqual(hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.expected));
  });

  // Decoded against the PUBLISHED wire PDU, not against
  // encodeUnsegmentedAccess's own output - a round trip through our own
  // encoder would only prove the two functions agree with each other, not
  // with the specification.
  test('decodeUnsegmentedAccess recovers the published Message #18 AKF/AID/payload', () => {
    const decoded = decodeUnsegmentedAccess(hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.expected));
    expect(decoded).toEqual({
      akf: LOWER_TRANSPORT_SAMPLE_ACCESS_1.akf,
      aid: LOWER_TRANSPORT_SAMPLE_ACCESS_1.aid,
      upperTransportPdu: hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.upperTransportPdu),
    });
  });

  // 8.3.20 "Message #20": same AKF/AID (same AppKey) as Message #18, but a
  // longer Upper Transport Access PDU - catches a length-dependent bug
  // Message #18's shorter one wouldn't.
  test('encodeUnsegmentedAccess matches the published Message #20 sample', () => {
    const pdu = encodeUnsegmentedAccess({
      akf: LOWER_TRANSPORT_SAMPLE_ACCESS_2.akf,
      aid: LOWER_TRANSPORT_SAMPLE_ACCESS_2.aid,
      upperTransportPdu: hex(LOWER_TRANSPORT_SAMPLE_ACCESS_2.upperTransportPdu),
    });
    expect(pdu.toString('hex')).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_2.expected);
  });

  test('decodeUnsegmentedAccess recovers the published Message #20 AKF/AID/payload', () => {
    const decoded = decodeUnsegmentedAccess(hex(LOWER_TRANSPORT_SAMPLE_ACCESS_2.expected));
    expect(decoded).toEqual({
      akf: LOWER_TRANSPORT_SAMPLE_ACCESS_2.akf,
      aid: LOWER_TRANSPORT_SAMPLE_ACCESS_2.aid,
      upperTransportPdu: hex(LOWER_TRANSPORT_SAMPLE_ACCESS_2.upperTransportPdu),
    });
  });

  // 8.3.22 "Message #22": a virtual-address Access message - the lower
  // transport layer does not care that the destination is virtual (that is
  // an upper-transport/network-layer concern), so this is really exercising
  // a different AID-bearing sample recovered from Section 8.3's errata-
  // affected messages (see vectors.ts's module header): the LowerTransport
  // block's own Header/UpperTransportPDU rows, not the corrupted leading
  // octet published a few rows away in the same message's NetworkPDU block.
  test('encodeUnsegmentedAccess matches the published Message #22 sample (errata-affected message, correct value)', () => {
    const pdu = encodeUnsegmentedAccess({
      akf: LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1.akf,
      aid: LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1.aid,
      upperTransportPdu: hex(LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1.upperTransportPdu),
    });
    expect(pdu.toString('hex')).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1.expected);
  });

  test('decodeUnsegmentedAccess recovers the published Message #22 AKF/AID/payload', () => {
    const decoded = decodeUnsegmentedAccess(hex(LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1.expected));
    expect(decoded).toEqual({
      akf: LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1.akf,
      aid: LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1.aid,
      upperTransportPdu: hex(LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1.upperTransportPdu),
    });
  });

  // 8.3.23 "Message #23": the second errata-affected message, same caveat.
  test('encodeUnsegmentedAccess matches the published Message #23 sample (errata-affected message, correct value)', () => {
    const pdu = encodeUnsegmentedAccess({
      akf: LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2.akf,
      aid: LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2.aid,
      upperTransportPdu: hex(LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2.upperTransportPdu),
    });
    expect(pdu.toString('hex')).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2.expected);
  });

  test('decodeUnsegmentedAccess recovers the published Message #23 AKF/AID/payload', () => {
    const decoded = decodeUnsegmentedAccess(hex(LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2.expected));
    expect(decoded).toEqual({
      akf: LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2.akf,
      aid: LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2.aid,
      upperTransportPdu: hex(LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2.upperTransportPdu),
    });
  });

  // Table 3.15: SEG=1 means a Segmented Access message - a different
  // message type for a later task, not an error. Message #24's own
  // published Lower Transport PDU genuinely has SEG set (see vectors.ts),
  // so this is real specification data with the bit actually on, not an
  // arbitrary fabricated byte.
  test('decodeUnsegmentedAccess returns null for the published Message #24 sample (SEG=1, segmented)', () => {
    expect(decodeUnsegmentedAccess(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED))).toBeNull();
  });

  test('decodeUnsegmentedAccess returns null for an empty buffer rather than throwing', () => {
    expect(decodeUnsegmentedAccess(Buffer.alloc(0))).toBeNull();
  });

  describe('caller mistakes throw rather than being treated as a verification failure', () => {
    test('encodeUnsegmentedAccess rejects an out-of-range aid', () => {
      expect(() =>
        encodeUnsegmentedAccess({ akf: true, aid: 0x40, upperTransportPdu: Buffer.alloc(5) }),
      ).toThrow(/lower transport field "aid" must be an integer in \[0, 63\], got 64/);
      expect(() =>
        encodeUnsegmentedAccess({ akf: true, aid: -1, upperTransportPdu: Buffer.alloc(5) }),
      ).toThrow(/lower transport field "aid"/);
    });

    test('encodeUnsegmentedAccess rejects an upperTransportPdu shorter than 5 bytes', () => {
      expect(() =>
        encodeUnsegmentedAccess({ akf: true, aid: 0x26, upperTransportPdu: Buffer.alloc(4) }),
      ).toThrow(/lower transport field "upperTransportPdu" must be 5-15 bytes, got 4/);
      expect(() =>
        encodeUnsegmentedAccess({ akf: true, aid: 0x26, upperTransportPdu: Buffer.alloc(5) }),
      ).not.toThrow();
    });

    test('encodeUnsegmentedAccess rejects an upperTransportPdu longer than 15 bytes', () => {
      expect(() =>
        encodeUnsegmentedAccess({ akf: true, aid: 0x26, upperTransportPdu: Buffer.alloc(16) }),
      ).toThrow(/lower transport field "upperTransportPdu" must be 5-15 bytes, got 16/);
      expect(() =>
        encodeUnsegmentedAccess({ akf: true, aid: 0x26, upperTransportPdu: Buffer.alloc(15) }),
      ).not.toThrow();
    });
  });

  // A received PDU whose Upper Transport Access PDU falls outside Table
  // 3.17's own 5-15 octet bound cannot have come from a compliant sender as
  // an Unsegmented Access message - rejected as "not decodable here"
  // (null), the same stance decodeNetworkPdu takes on an out-of-range
  // TransportPDU length.
  test('decodeUnsegmentedAccess returns null for a payload shorter than 5 bytes', () => {
    const pdu = Buffer.concat([Buffer.from([0x26]), Buffer.alloc(4)]); // SEG=0, AKF=0, AID=0x26, 4-byte payload.
    expect(decodeUnsegmentedAccess(pdu)).toBeNull();
  });

  test('decodeUnsegmentedAccess returns null for a payload longer than 15 bytes', () => {
    const pdu = Buffer.concat([Buffer.from([0x26]), Buffer.alloc(16)]);
    expect(decodeUnsegmentedAccess(pdu)).toBeNull();
  });
});

describe('Unsegmented Control message (Section 3.5.2.3, Table 3.19)', () => {
  // 8.3.1 "Message #1": a Friend Request, Opcode 0x03.
  test('encodeUnsegmentedControl matches the published Message #1 sample', () => {
    const pdu = encodeUnsegmentedControl({
      opcode: LOWER_TRANSPORT_SAMPLE_CONTROL_1.opcode,
      parameters: hex(LOWER_TRANSPORT_SAMPLE_CONTROL_1.parameters),
    });
    expect(pdu.toString('hex')).toBe(LOWER_TRANSPORT_SAMPLE_CONTROL_1.expected);
    expect(pdu).toEqual(hex(LOWER_TRANSPORT_SAMPLE_CONTROL_1.expected));
  });

  test('decodeUnsegmentedControl recovers the published Message #1 opcode/parameters', () => {
    const decoded = decodeUnsegmentedControl(hex(LOWER_TRANSPORT_SAMPLE_CONTROL_1.expected));
    expect(decoded).toEqual({
      opcode: LOWER_TRANSPORT_SAMPLE_CONTROL_1.opcode,
      parameters: hex(LOWER_TRANSPORT_SAMPLE_CONTROL_1.parameters),
    });
  });

  // 8.3.2 "Message #2": a Friend Offer, Opcode 0x04 - a different opcode and
  // a shorter Parameters field than Message #1's.
  test('encodeUnsegmentedControl matches the published Message #2 sample', () => {
    const pdu = encodeUnsegmentedControl({
      opcode: LOWER_TRANSPORT_SAMPLE_CONTROL_2.opcode,
      parameters: hex(LOWER_TRANSPORT_SAMPLE_CONTROL_2.parameters),
    });
    expect(pdu.toString('hex')).toBe(LOWER_TRANSPORT_SAMPLE_CONTROL_2.expected);
    expect(pdu).toEqual(hex(LOWER_TRANSPORT_SAMPLE_CONTROL_2.expected));
  });

  test('decodeUnsegmentedControl recovers the published Message #2 opcode/parameters', () => {
    const decoded = decodeUnsegmentedControl(hex(LOWER_TRANSPORT_SAMPLE_CONTROL_2.expected));
    expect(decoded).toEqual({
      opcode: LOWER_TRANSPORT_SAMPLE_CONTROL_2.opcode,
      parameters: hex(LOWER_TRANSPORT_SAMPLE_CONTROL_2.parameters),
    });
  });

  // Table 3.15: SEG=1 means a Segmented Control message. No Section 8.3
  // sample publishes one (checked directly - no
  // "LowerTransportSegmentedControlPDU" block exists anywhere in the
  // document), so this uses the one genuine SEG=1 sample the document does
  // publish (Message #24, a Segmented ACCESS message) to prove the SEG
  // check itself is unconditional on CTL - the same first-octet bit decides
  // both decoders, and `decodeUnsegmentedControl` must reject it exactly as
  // `decodeUnsegmentedAccess` does.
  test('decodeUnsegmentedControl returns null for a PDU with SEG set', () => {
    expect(decodeUnsegmentedControl(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED))).toBeNull();
  });

  test('decodeUnsegmentedControl returns null for an empty buffer rather than throwing', () => {
    expect(decodeUnsegmentedControl(Buffer.alloc(0))).toBeNull();
  });

  describe('caller mistakes throw rather than being treated as a verification failure', () => {
    test('encodeUnsegmentedControl rejects an out-of-range opcode', () => {
      expect(() => encodeUnsegmentedControl({ opcode: 0x80, parameters: Buffer.alloc(0) })).toThrow(
        /lower transport field "opcode" must be an integer in \[0, 127\], got 128/,
      );
      expect(() => encodeUnsegmentedControl({ opcode: -1, parameters: Buffer.alloc(0) })).toThrow(
        /lower transport field "opcode"/,
      );
    });

    test('encodeUnsegmentedControl accepts an empty parameters field (0 is the published minimum)', () => {
      expect(() => encodeUnsegmentedControl({ opcode: 0x01, parameters: Buffer.alloc(0) })).not.toThrow();
    });

    test('encodeUnsegmentedControl rejects a parameters field longer than 11 bytes', () => {
      expect(() => encodeUnsegmentedControl({ opcode: 0x01, parameters: Buffer.alloc(12) })).toThrow(
        /lower transport field "parameters" must be 0-11 bytes, got 12/,
      );
      expect(() => encodeUnsegmentedControl({ opcode: 0x01, parameters: Buffer.alloc(11) })).not.toThrow();
    });
  });

  test('decodeUnsegmentedControl returns null for a parameters field longer than 11 bytes', () => {
    const pdu = Buffer.concat([Buffer.from([0x01]), Buffer.alloc(12)]); // SEG=0, Opcode=0x01, 12-byte parameters.
    expect(decodeUnsegmentedControl(pdu)).toBeNull();
  });

  // Table 3.20 marks 0x00 "Reserved" (it is Table 3.21's fixed Segment
  // Acknowledgment opcode instead, a later task's concern - see the module
  // header). This layer does not special-case it: a generic Unsegmented
  // Control message with opcode 0x00 round-trips like any other, exactly as
  // the module header documents.
  test('opcode 0x00 is not rejected - it round-trips like any other opcode here', () => {
    const pdu = encodeUnsegmentedControl({ opcode: 0x00, parameters: hex('aabb') });
    expect(decodeUnsegmentedControl(pdu)).toEqual({ opcode: 0x00, parameters: hex('aabb') });
  });
});
