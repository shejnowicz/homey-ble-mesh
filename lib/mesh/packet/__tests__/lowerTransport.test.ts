import {
  encodeUnsegmentedAccess,
  decodeUnsegmentedAccess,
  encodeUnsegmentedControl,
  decodeUnsegmentedControl,
  segmentAccessMessage,
  decodeSegmentedAccess,
  encodeSegmentAck,
  decodeSegmentAck,
  SegmentAck,
} from '../lowerTransport';
import { acceptSegment, blockAckFrom } from '../reassembly';
import {
  hex,
  LOWER_TRANSPORT_SAMPLE_CONTROL_1,
  LOWER_TRANSPORT_SAMPLE_CONTROL_2,
  LOWER_TRANSPORT_SAMPLE_ACCESS_1,
  LOWER_TRANSPORT_SAMPLE_ACCESS_2,
  LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY,
  LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1,
  LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2,
  LOWER_TRANSPORT_SAMPLE_SEGMENTED,
  LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY,
  LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1,
  LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_2,
  NETWORK_PDU_SAMPLE_1,
  NETWORK_PDU_SAMPLE_2,
  NETWORK_PDU_SAMPLE_3,
  NETWORK_PDU_SAMPLE_ODD_IV,
  UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY,
  UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC,
  UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL,
  UPPER_TRANSPORT_SAMPLE_SZMIC,
  UPPER_TRANSPORT_SAMPLE_DEVICE_KEY,
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

  // 8.3.16 "Message #16": the ONLY AKF=0 (device-key) sample in this file -
  // every other access sample above has AKF=1. Without this sample, a
  // decoder hardcoded to always report `akf: true` (or an encoder that
  // always sets the AKF bit regardless of input) would pass every other
  // test here, since every other published Header has bit 6 set. This gap
  // was found by review and is deliberately closed this way: the mutation
  // the review applied (encode ignores `akf`, decode reports it as always
  // true) is re-run below and confirmed to now fail these two tests. AID=0
  // is a fixed placeholder here, not a derived value (AKF=0 means no
  // application key is involved - same reasoning as
  // `UPPER_TRANSPORT_SAMPLE_DEVICE_KEY`'s own note in vectors.ts).
  test('encodeUnsegmentedAccess matches the published Message #16 sample (AKF=0, device key)', () => {
    const pdu = encodeUnsegmentedAccess({
      akf: LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY.akf,
      aid: LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY.aid,
      upperTransportPdu: hex(LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY.upperTransportPdu),
    });
    expect(pdu.toString('hex')).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY.expected);
  });

  test('decodeUnsegmentedAccess recovers the published Message #16 AKF=0/AID/payload', () => {
    const decoded = decodeUnsegmentedAccess(hex(LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY.expected));
    expect(decoded).toEqual({
      akf: LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY.akf,
      aid: LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY.aid,
      upperTransportPdu: hex(LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY.upperTransportPdu),
    });
    expect(decoded?.akf).toBe(false); // the specific bit a hardcoded-true decoder would get wrong.
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
    expect(decodeUnsegmentedAccess(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu))).toBeNull();
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
    expect(decodeUnsegmentedControl(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu))).toBeNull();
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

  // Finding (review): the encoder's opcode range is pinned by its own
  // error-message test above ("rejects an out-of-range opcode"), but
  // nothing exercised the DECODER's mask above six bits - narrowing it from
  // 7 bits (0x7F) to 6 (0x3F) still passed every test here, since both
  // published opcode samples (0x03, 0x04) fit in 6 bits, and so does 0x00.
  // 0x7F is 2^7-1, the top of the 7-bit range Table 3.19 itself transcribes
  // (not a value obtained by running this module's own code) - paired with
  // the existing 0x00 round trip above (the bottom of that same range).
  test('opcode 0x7F (top of the 7-bit range) round-trips, alongside the existing 0x00 (bottom) above', () => {
    const pdu = encodeUnsegmentedControl({ opcode: 0x7f, parameters: hex('aabb') });
    expect(decodeUnsegmentedControl(pdu)).toEqual({ opcode: 0x7f, parameters: hex('aabb') });
  });
});

describe("decode returns a COPY, not a view onto the caller's buffer", () => {
  // The network layer's own decoder slices a freshly-decrypted buffer, so
  // it never aliases its input - this module is the first to hand back
  // bytes sliced directly out of what the CALLER passed in, which is a real
  // hazard with a reused BLE receive buffer: a later write to either one
  // would otherwise silently reach through to the other.
  test('decodeUnsegmentedAccess: writing to the input buffer after decoding does not change the decoded payload', () => {
    const input = hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.expected);
    const decoded = decodeUnsegmentedAccess(input);
    const expectedPayload = hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.upperTransportPdu);
    input.fill(0xff); // simulate the caller reusing/overwriting its receive buffer.
    expect(decoded?.upperTransportPdu).toEqual(expectedPayload);
  });

  test('decodeUnsegmentedAccess: writing through the decoded payload does not corrupt the input buffer', () => {
    const input = hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.expected);
    const inputCopy = Buffer.from(input);
    const decoded = decodeUnsegmentedAccess(input);
    // Asserted (not optional-chained) before the write: `decoded?.x.fill()`
    // would silently skip the write - and this test would then pass
    // vacuously - if decode ever returned null here, which is exactly the
    // failure mode a review caught live (this test's sibling above failed
    // under a mutation while this one passed silently, for that reason).
    expect(decoded).not.toBeNull();
    decoded!.upperTransportPdu.fill(0xff); // simulate a caller mutating what it got back.
    expect(input).toEqual(inputCopy);
  });

  test('decodeUnsegmentedControl: writing to the input buffer after decoding does not change the decoded parameters', () => {
    const input = hex(LOWER_TRANSPORT_SAMPLE_CONTROL_1.expected);
    const decoded = decodeUnsegmentedControl(input);
    const expectedParameters = hex(LOWER_TRANSPORT_SAMPLE_CONTROL_1.parameters);
    input.fill(0xff);
    expect(decoded?.parameters).toEqual(expectedParameters);
  });

  test('decodeUnsegmentedControl: writing through the decoded parameters does not corrupt the input buffer', () => {
    const input = hex(LOWER_TRANSPORT_SAMPLE_CONTROL_1.expected);
    const inputCopy = Buffer.from(input);
    const decoded = decodeUnsegmentedControl(input);
    // Same reasoning as the access-side test above: assert non-null before
    // writing, or a null decode makes this test pass vacuously.
    expect(decoded).not.toBeNull();
    decoded!.parameters.fill(0xff);
    expect(input).toEqual(inputCopy);
  });
});

// Finding (review): four fixture fields (opcode on NETWORK_PDU_SAMPLE_1/2,
// akf/aid on NETWORK_PDU_SAMPLE_3/ODD_IV) duplicated values already live in
// the LOWER_TRANSPORT_SAMPLE_* fixtures above with nothing reading either
// copy - the same uncatchable-typo pattern this task's brief closed for the
// fixtures it consumes directly, reopened beside them. Closed here by
// cross-checking both copies against each other (and, where a message also
// has an upper-transport `aid` fixture, against that too), so a future edit
// that silently diverges one copy from its sibling fails a test instead of
// sitting unread. Message #6's device-key sample has no `aid` at all (AKF=0
// means none was derived - see vectors.ts) and Message #16's new device-key
// fixture has no NETWORK_PDU_SAMPLE/UPPER_TRANSPORT_SAMPLE counterpart to
// cross-check against, so neither appears below - there is nothing
// duplicated to lock together for either one.
describe('vectors.ts: duplicated fixture fields cross-check each other', () => {
  test('Message #1: NETWORK_PDU_SAMPLE_1 and LOWER_TRANSPORT_SAMPLE_CONTROL_1 agree', () => {
    expect(NETWORK_PDU_SAMPLE_1.opcode).toBe(LOWER_TRANSPORT_SAMPLE_CONTROL_1.opcode);
    expect(NETWORK_PDU_SAMPLE_1.transportPdu).toBe(LOWER_TRANSPORT_SAMPLE_CONTROL_1.expected);
  });

  test('Message #2: NETWORK_PDU_SAMPLE_2 and LOWER_TRANSPORT_SAMPLE_CONTROL_2 agree', () => {
    expect(NETWORK_PDU_SAMPLE_2.opcode).toBe(LOWER_TRANSPORT_SAMPLE_CONTROL_2.opcode);
    expect(NETWORK_PDU_SAMPLE_2.transportPdu).toBe(LOWER_TRANSPORT_SAMPLE_CONTROL_2.expected);
  });

  test('Message #18: NETWORK_PDU_SAMPLE_3, UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY and LOWER_TRANSPORT_SAMPLE_ACCESS_1 agree on AKF/AID', () => {
    expect(NETWORK_PDU_SAMPLE_3.akf).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_1.akf);
    expect(NETWORK_PDU_SAMPLE_3.aid).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_1.aid);
    expect(NETWORK_PDU_SAMPLE_3.transportPdu).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_1.expected);
    expect(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.aid).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_1.aid);
  });

  test('Message #20: NETWORK_PDU_SAMPLE_ODD_IV and LOWER_TRANSPORT_SAMPLE_ACCESS_2 agree on AKF/AID/PDU', () => {
    expect(NETWORK_PDU_SAMPLE_ODD_IV.akf).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_2.akf);
    expect(NETWORK_PDU_SAMPLE_ODD_IV.aid).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_2.aid);
    expect(NETWORK_PDU_SAMPLE_ODD_IV.transportPdu).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_2.expected);
  });

  test('Message #22: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC and LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1 agree on AID/payload', () => {
    expect(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.aid).toBe(LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1.aid);
    expect(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.expected).toBe(
      LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1.upperTransportPdu,
    );
  });

  test('Message #23: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL and LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2 agree on AID/payload', () => {
    expect(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.aid).toBe(
      LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2.aid,
    );
    expect(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.expected).toBe(
      LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2.upperTransportPdu,
    );
  });

  // Message #24 is segmented (not decoded by this task), but its `aid` and
  // first-segment bytes are independently transcribed in two different
  // sections of vectors.ts (the upper-transport sample and
  // LOWER_TRANSPORT_SAMPLE_SEGMENTED) - cross-checked so they cannot
  // silently drift apart even though neither is read by this task's code.
  test('Message #24: UPPER_TRANSPORT_SAMPLE_SZMIC and LOWER_TRANSPORT_SAMPLE_SEGMENTED agree on AID, and segment0 is the first 12 octets of the full UpperTransportPDU', () => {
    expect(UPPER_TRANSPORT_SAMPLE_SZMIC.aid).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED.aid);
    expect(hex(UPPER_TRANSPORT_SAMPLE_SZMIC.expected).subarray(0, 12)).toEqual(
      hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.segment0),
    );
  });
});

// Finding (second review round): converting LOWER_TRANSPORT_SAMPLE_SEGMENTED
// from a bare hex string into an object (so the segmentation task would not
// have to do it later) added ten fields, of which only three - `pdu`,
// `aid`, `segment0` - were read anywhere above. The other seven, including
// `header` (which duplicates the PDU's own leading 4 octets inside the SAME
// object literal), were exactly the uncatchable-typo shape Finding 2 closed
// elsewhere in this file - reopened one object down. Confirmed by the
// reviewer: a one-digit typo in any of seg/akf/aid/szmic/seqZero/segO/segN
// left all 173 tests green.
//
// Closed by making every field load-bearing: `header`/`segment0` are
// asserted against the corresponding slice of the full `pdu`, and the
// remaining six fields are recovered by unpacking `header` bit by bit per
// Section 3.5.2.2, Table 3.18 "Segmented Access message format" - the
// widths below (SEG 1, AKF 1, AID 6, SZMIC 1, SeqZero 13, SegO 5, SegN 5,
// packed MSB-first into 32 bits) are transcribed from that table, not
// copied from `lowerTransport.ts`'s own (unsegmented) header layout, which
// is a different, 1-octet format. The segmentation task will decode this
// exact sample for real; this is what stops it inheriting unverified data.
describe('LOWER_TRANSPORT_SAMPLE_SEGMENTED: every field cross-checks the PDU bytes (Table 3.18)', () => {
  const pdu = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu);
  const header = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.header);
  const headerInt = header.readUInt32BE(0);

  test("header is the PDU's own first 4 octets, and segment0 is the rest", () => {
    expect(header).toHaveLength(4);
    expect(pdu.subarray(0, 4)).toEqual(header);
    expect(pdu.subarray(4)).toEqual(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.segment0));
  });

  // Table 3.18's 7 fields (1+1+6+1+13+5+5 = 32 bits) packed MSB-first, so
  // field N's bit range is found by subtracting cumulative widths from 31.
  test('bit 31 (SEG, width 1) matches the transcribed seg flag', () => {
    expect((headerInt >>> 31) & 0x1).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED.seg ? 1 : 0);
  });

  test('bit 30 (AKF, width 1) matches the transcribed akf flag', () => {
    expect((headerInt >>> 30) & 0x1).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED.akf ? 1 : 0);
  });

  test('bits 29-24 (AID, width 6) match the transcribed aid', () => {
    expect((headerInt >>> 24) & 0x3f).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED.aid);
  });

  test('bit 23 (SZMIC, width 1) matches the transcribed szmic flag', () => {
    expect((headerInt >>> 23) & 0x1).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED.szmic ? 1 : 0);
  });

  test('bits 22-10 (SeqZero, width 13) match the transcribed seqZero', () => {
    expect((headerInt >>> 10) & 0x1fff).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED.seqZero);
  });

  test('bits 9-5 (SegO, width 5) match the transcribed segO', () => {
    expect((headerInt >>> 5) & 0x1f).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED.segO);
  });

  test('bits 4-0 (SegN, width 5) match the transcribed segN', () => {
    expect(headerInt & 0x1f).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED.segN);
  });

  test('the 7 field widths above sum to exactly the header\'s own 32 bits', () => {
    expect(1 + 1 + 6 + 1 + 13 + 5 + 5).toBe(32);
  });
});

describe('Segmented Access message (Section 3.5.2.2, Table 3.18)', () => {
  // Message #24 (Section 8.3.24): the sample the module header above
  // already proved bit-by-bit against LOWER_TRANSPORT_SAMPLE_SEGMENTED -
  // this is that sample decoded "for real" instead of unpacked by hand.
  // AKF=1, SZMIC=1 (the only 64-bit-TransMIC sample in this file), split
  // 12+4 (an UNEVEN split - the second segment is NOT a full 12 octets).
  test('segmentAccessMessage matches the published Message #24 segments, in order', () => {
    const segments = segmentAccessMessage({
      akf: LOWER_TRANSPORT_SAMPLE_SEGMENTED.akf,
      aid: LOWER_TRANSPORT_SAMPLE_SEGMENTED.aid,
      szmic: LOWER_TRANSPORT_SAMPLE_SEGMENTED.szmic,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENTED.seqZero,
      upperTransportPdu: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.expected),
    });
    expect(segments).toEqual([
      hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu),
      hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu1),
    ]);
  });

  test('decodeSegmentedAccess recovers the published Message #24 segment 0 (segO=0, segN=1)', () => {
    const decoded = decodeSegmentedAccess(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu));
    expect(decoded).toEqual({
      akf: LOWER_TRANSPORT_SAMPLE_SEGMENTED.akf,
      aid: LOWER_TRANSPORT_SAMPLE_SEGMENTED.aid,
      szmic: LOWER_TRANSPORT_SAMPLE_SEGMENTED.szmic,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENTED.seqZero,
      segO: LOWER_TRANSPORT_SAMPLE_SEGMENTED.segO,
      segN: LOWER_TRANSPORT_SAMPLE_SEGMENTED.segN,
      segment: hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.segment0),
    });
  });

  test('decodeSegmentedAccess recovers the published Message #24 segment 1 (segO=1, segN=1)', () => {
    const decoded = decodeSegmentedAccess(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu1));
    expect(decoded).toEqual({
      akf: LOWER_TRANSPORT_SAMPLE_SEGMENTED.akf,
      aid: LOWER_TRANSPORT_SAMPLE_SEGMENTED.aid,
      szmic: LOWER_TRANSPORT_SAMPLE_SEGMENTED.szmic,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENTED.seqZero,
      segO: 1,
      segN: LOWER_TRANSPORT_SAMPLE_SEGMENTED.segN,
      segment: hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.segment1),
    });
  });

  // Message #6 (Section 8.3.6): the other dimension Message #24 alone
  // leaves untested - AKF=0 (device key) and SZMIC=0 (32-bit TransMIC),
  // where every other sample above (including LOWER_TRANSPORT_SAMPLE_
  // SEGMENTED) has both bits set to 1. Without this sample, a
  // segmentAccessMessage/decodeSegmentedAccess pair that silently ignored
  // AKF or SZMIC in either direction would still pass every test above -
  // the same blind spot Message #16 already closed for the unsegmented
  // case (see that test's own comment). Also an EVEN split (12+12, both
  // segments a full 12 octets), unlike Message #24's 12+4.
  test('segmentAccessMessage matches the published Message #6 segments, in order (AKF=0, SZMIC=0)', () => {
    const segments = segmentAccessMessage({
      akf: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.akf,
      aid: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.aid,
      szmic: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.szmic,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.seqZero,
      upperTransportPdu: hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.expected),
    });
    expect(segments).toEqual([
      hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.pdu0),
      hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.pdu1),
    ]);
  });

  test('decodeSegmentedAccess recovers the published Message #6 segment 0 (AKF=0, segO=0, segN=1)', () => {
    const decoded = decodeSegmentedAccess(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.pdu0));
    expect(decoded).toEqual({
      akf: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.akf,
      aid: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.aid,
      szmic: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.szmic,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.seqZero,
      segO: 0,
      segN: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.segN,
      segment: hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.segment0),
    });
    expect(decoded?.akf).toBe(false); // the specific bit a hardcoded-true decoder would get wrong.
  });

  test('decodeSegmentedAccess recovers the published Message #6 segment 1 (AKF=0, segO=1, segN=1)', () => {
    const decoded = decodeSegmentedAccess(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.pdu1));
    expect(decoded).toEqual({
      akf: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.akf,
      aid: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.aid,
      szmic: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.szmic,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.seqZero,
      segO: 1,
      segN: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.segN,
      segment: hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.segment1),
    });
  });

  // Table 3.15: SEG=0 means an Unsegmented Access message - a different
  // message type `decodeUnsegmentedAccess` handles, not an error. Reuses
  // Message #18's genuine SEG=0 wire bytes, the same stance
  // `decodeUnsegmentedAccess`'s own "SEG=1" test above takes in reverse.
  test('decodeSegmentedAccess returns null for the published Message #18 sample (SEG=0, unsegmented)', () => {
    expect(decodeSegmentedAccess(hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.expected))).toBeNull();
  });

  test('decodeSegmentedAccess returns null for an empty buffer rather than throwing', () => {
    expect(decodeSegmentedAccess(Buffer.alloc(0))).toBeNull();
  });

  test('decodeSegmentedAccess returns null for a 4-octet buffer (header only, no segment octets)', () => {
    // SEG=1, AKF=0, AID=0, rest all zero - a genuinely segmented-looking
    // header, but with nothing after it: Table 3.18's Segment m field is
    // never 0 octets (minimum 8 bits), so this cannot be a compliant
    // sender's output.
    expect(decodeSegmentedAccess(hex('80000000'))).toBeNull();
  });

  test('decodeSegmentedAccess returns null for a segment longer than 12 bytes', () => {
    const pdu = Buffer.concat([hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.header), Buffer.alloc(13)]);
    expect(decodeSegmentedAccess(pdu)).toBeNull();
  });

  // Review finding: SegO and SegN both come from the same 4 header octets
  // of the SAME segment (Table 3.18), so SegO > SegN is an invariant one
  // segment can violate entirely on its own - not something only reassembly
  // (looking across several segments) could catch. Header hand-built from
  // Table 3.18's own bit widths (SEG=1,AKF=0,AID=0 -> first octet 0x80;
  // SZMIC=0,SeqZero=0,SegO=2,SegN=1 -> (2<<5)|1 = 0x41 in the low octet of
  // the remaining 3 -> 0x80000041), not produced by segmentAccessMessage -
  // no compliant sender would build it (a legitimate 2-segment message's
  // SegO never exceeds 1), but a received PDU could still contain it.
  test('decodeSegmentedAccess returns null when the recovered SegO exceeds SegN (segO=2, segN=1)', () => {
    const pdu = Buffer.concat([hex('80000041'), Buffer.from([0xaa])]);
    expect(decodeSegmentedAccess(pdu)).toBeNull();
  });

  describe('caller mistakes throw rather than being treated as a verification failure', () => {
    test('segmentAccessMessage rejects an out-of-range aid', () => {
      expect(() =>
        segmentAccessMessage({ akf: true, aid: 0x40, szmic: false, seqZero: 0, upperTransportPdu: Buffer.alloc(1) }),
      ).toThrow(/lower transport field "aid" must be an integer in \[0, 63\], got 64/);
    });

    test('segmentAccessMessage rejects an out-of-range seqZero', () => {
      expect(() =>
        segmentAccessMessage({
          akf: true,
          aid: 0,
          szmic: false,
          seqZero: 0x2000,
          upperTransportPdu: Buffer.alloc(1),
        }),
      ).toThrow(/lower transport field "seqZero" must be an integer in \[0, 8191\], got 8192/);
      expect(() =>
        segmentAccessMessage({ akf: true, aid: 0, szmic: false, seqZero: 0x1fff, upperTransportPdu: Buffer.alloc(1) }),
      ).not.toThrow();
    });

    test('segmentAccessMessage rejects an empty upperTransportPdu', () => {
      expect(() =>
        segmentAccessMessage({ akf: true, aid: 0, szmic: false, seqZero: 0, upperTransportPdu: Buffer.alloc(0) }),
      ).toThrow(/lower transport field "upperTransportPdu" must be 1-384 bytes, got 0/);
    });

    // 384 = 32 segments x 12 octets (Section 2.3.3; SegN is 5 bits, 0-31).
    test('segmentAccessMessage rejects an upperTransportPdu longer than 384 bytes', () => {
      expect(() =>
        segmentAccessMessage({ akf: true, aid: 0, szmic: false, seqZero: 0, upperTransportPdu: Buffer.alloc(385) }),
      ).toThrow(/lower transport field "upperTransportPdu" must be 1-384 bytes, got 385/);
      expect(() =>
        segmentAccessMessage({ akf: true, aid: 0, szmic: false, seqZero: 0, upperTransportPdu: Buffer.alloc(384) }),
      ).not.toThrow();
    });
  });

  // Review finding: the only thing pinning SeqZero's width to 13 bits was
  // the error-message string above ("must be an integer in [0, 8191]") -
  // narrowing the mask by one bit (0xfff instead of 0x1fff) still throws a
  // message matching that same regex's shape for 0x2000, so only that exact
  // string notices, and no published sample sets the field's own top bit
  // (0x80d and 0x9ab, the two transcribed SeqZero values in this file, both
  // fit in 12 bits). Closed with a round trip at the field's maximum value,
  // 0x1fff = 2^13-1 (Table 3.18's own 13-bit width), where the expected
  // WIRE BYTES are computed by hand from that same width - not read back
  // from segmentAccessMessage's own output - so a narrowed mask fails this
  // test even if some other bug happened to make the round trip itself
  // still agree with a 12-bit decoder.
  //
  // Header hand-built: first octet SEG=1,AKF=1,AID=0x15 -> 0x80|0x40|0x15 =
  // 0xd5. Remaining 3 octets SZMIC=1,SeqZero=0x1fff,SegO=0,SegN=0 ->
  // 0x800000 | (0x1fff << 10) | 0 | 0 = 0xfffc00 -> ff fc 00. Full header
  // d5fffc00.
  test('seqZero round-trips at its 13-bit maximum (0x1fff), against a hand-computed header', () => {
    const segments = segmentAccessMessage({
      akf: true,
      aid: 0x15,
      szmic: true,
      seqZero: 0x1fff,
      upperTransportPdu: hex('deadbeef'),
    });
    expect(segments).toEqual([hex('d5fffc00deadbeef')]);

    const decoded = decodeSegmentedAccess(hex('d5fffc00deadbeef'));
    expect(decoded?.seqZero).toBe(0x1fff);
  });

  // The two boundary cases the brief asks for, derived from the segment
  // size transcribed above (Table 3.18: 12 octets per non-last segment) -
  // NOT from running this module's own code and recording what it printed.
  describe('segment-count boundary cases (derived from the transcribed 12-octet segment size)', () => {
    test('a payload one byte longer than one segment holds (13 bytes) produces two segments, the second carrying one byte', () => {
      const segments = segmentAccessMessage({
        akf: true,
        aid: 0x01,
        szmic: false,
        seqZero: 0,
        upperTransportPdu: Buffer.alloc(13, 0xaa),
      });
      // 4-octet header + 12-octet segment = 16; 4-octet header + 1-octet
      // segment = 5 - buffer lengths alone, not decoded, so this does not
      // depend on decodeSegmentedAccess being correct to tell the two
      // segments' sizes apart.
      expect(segments.map((segment) => segment.length)).toEqual([16, 5]);

      const first = decodeSegmentedAccess(segments[0] as Buffer);
      const second = decodeSegmentedAccess(segments[1] as Buffer);
      expect(first).toMatchObject({ segO: 0, segN: 1 });
      expect(first?.segment).toHaveLength(12);
      expect(second).toMatchObject({ segO: 1, segN: 1 });
      expect(second?.segment).toHaveLength(1);
    });

    test('a payload that exactly fills one segment (12 bytes) produces one segment, not two with an empty tail', () => {
      const segments = segmentAccessMessage({
        akf: true,
        aid: 0x01,
        szmic: false,
        seqZero: 0,
        upperTransportPdu: Buffer.alloc(12, 0xaa),
      });
      expect(segments).toHaveLength(1); // not 2 - the whole point of this test.
      expect(segments.map((segment) => segment.length)).toEqual([16]); // 4-octet header + 12-octet segment.

      const decoded = decodeSegmentedAccess(segments[0] as Buffer);
      expect(decoded).toMatchObject({ segO: 0, segN: 0 });
      expect(decoded?.segment).toHaveLength(12);
    });
  });

  // Review finding: every sample and boundary case above is a one- or
  // two-segment message, so nothing in the suite distinguished a correct
  // multi-segment indexer from one that silently caps SegO/SegN at 1 (the
  // reviewer demonstrated this live: capping the last-segment index at one
  // left all 74 segmented tests above passing). This is the regime the
  // product actually depends on - the composition data response that
  // motivates segmentation in the first place is far longer than two
  // segments - and the next task's reassembly builds directly on this
  // decoder's multi-segment indexing, so an off-by-one or a hidden cap here
  // would silently truncate every long message reassembly ever sees.
  //
  // Both cases below are derived from the transcribed segment size (12
  // octets, Table 3.18) and the transcribed maximum message size (384
  // octets, Section 2.3.3) - not from running this module's own code and
  // recording what it printed.
  describe('multi-segment indexing beyond two segments (review finding)', () => {
    // 29 = 12 + 12 + 5: three segments, the third an uneven remainder - the
    // smallest payload that cannot be explained by an implementation that
    // only ever produces at most two segments.
    test('a payload spanning three segments (29 bytes) produces three segments with a shared, correct last-segment index', () => {
      const segments = segmentAccessMessage({
        akf: true,
        aid: 0x01,
        szmic: false,
        seqZero: 0,
        upperTransportPdu: Buffer.alloc(29, 0xaa),
      });
      // 4-octet header + 12/12/5-octet segments = 16/16/9.
      expect(segments.map((segment) => segment.length)).toEqual([16, 16, 9]);

      const decoded = segments.map((segment) => decodeSegmentedAccess(segment as Buffer));
      expect(decoded.map((d) => d?.segO)).toEqual([0, 1, 2]);
      expect(decoded.map((d) => d?.segment.length)).toEqual([12, 12, 5]);
      // Table 3.18: SegN is the SAME on every segment of one message - here,
      // the zero-based index of the last (third) segment, 2.
      expect(decoded.map((d) => d?.segN)).toEqual([2, 2, 2]);
    });

    // 384 = 32 x 12 (Section 2.3.3's own stated ceiling; SegN is 5 bits,
    // 0-31, consistent with it). The largest Upper Transport Access PDU the
    // specification allows a SAR to carry at all.
    test('the largest message the specification allows (384 bytes) produces exactly 32 segments, SegN = 31 on all of them', () => {
      const segments = segmentAccessMessage({
        akf: true,
        aid: 0x01,
        szmic: false,
        seqZero: 0,
        upperTransportPdu: Buffer.alloc(384, 0xaa),
      });
      expect(segments).toHaveLength(32);
      expect(segments.every((segment) => segment.length === 16)).toBe(true); // 4 + 12, every one a full segment.

      const decoded = segments.map((segment) => decodeSegmentedAccess(segment as Buffer));
      expect(decoded.map((d) => d?.segO)).toEqual(Array.from({ length: 32 }, (_, i) => i));
      expect(decoded.every((d) => d?.segN === 31)).toBe(true); // ceil(384/12) - 1 = 31, the same on every segment.
    });
  });
});

describe("decode returns a COPY, not a view onto the caller's buffer (Segmented Access)", () => {
  // Same hazard, same reasoning as the identical describe block above for
  // the unsegmented decoders - this is the segmented decoder's own version
  // of those two tests.
  test('decodeSegmentedAccess: writing to the input buffer after decoding does not change the decoded segment', () => {
    const input = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu);
    const decoded = decodeSegmentedAccess(input);
    const expectedSegment = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.segment0);
    input.fill(0xff);
    expect(decoded?.segment).toEqual(expectedSegment);
  });

  test('decodeSegmentedAccess: writing through the decoded segment does not corrupt the input buffer', () => {
    const input = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu);
    const inputCopy = Buffer.from(input);
    const decoded = decodeSegmentedAccess(input);
    expect(decoded).not.toBeNull();
    decoded!.segment.fill(0xff);
    expect(input).toEqual(inputCopy);
  });

  // Review finding: the decoder has the two tests above, but the encoder
  // had none - the same gap the existing unsegmented encoders already have
  // (symmetry, not a regression). `Buffer.concat` always copies into a
  // freshly allocated buffer, so `segmentAccessMessage`'s output never
  // shares memory with its `upperTransportPdu` input; this is the one test
  // pinning that.
  test("segmentAccessMessage: writing to the input buffer after encoding does not change the produced segments", () => {
    const input = Buffer.alloc(13, 0xaa);
    const segments = segmentAccessMessage({ akf: true, aid: 0x01, szmic: false, seqZero: 0, upperTransportPdu: input });
    const expectedSegments = segments.map((segment) => Buffer.from(segment));
    input.fill(0xff); // simulate the caller reusing/overwriting its own buffer after the call returns.
    expect(segments).toEqual(expectedSegments);
  });
});

// Finding (this task's own review discipline, same as the describe block
// above LOWER_TRANSPORT_SAMPLE_SEGMENTED's per-bit tests): every new field
// this task added to vectors.ts must be read by a test somewhere, or it is
// exactly the uncatchable-typo shape that block was closed for. `header1`
// is the one field the describe block below (not the segment/segO/segN
// round trips above) is for - cross-checked against its own PDU and against
// `header` (its sibling) differing only in the SegO bits, per Table 3.18's
// "Every Segmented Access message for the same Upper Transport Access PDU
// shall have the same values for AKF, AID, SZMIC, SeqZero, and SegN fields"
// rule (everything else must therefore match).
describe('LOWER_TRANSPORT_SAMPLE_SEGMENTED: the second segment (header1/segment1/pdu1) cross-checks', () => {
  test("pdu1 is header1's own bytes followed by segment1", () => {
    const pdu1 = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu1);
    expect(pdu1.subarray(0, 4)).toEqual(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.header1));
    expect(pdu1.subarray(4)).toEqual(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.segment1));
  });

  test('header1 differs from header only in the SegO field (bits 9-5): same AKF/AID/SZMIC/SeqZero/SegN', () => {
    const header = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.header).readUInt32BE(0);
    const header1 = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.header1).readUInt32BE(0);
    const SEG_O_MASK = 0x1f << 5;
    expect(header1 & ~SEG_O_MASK).toBe(header & ~SEG_O_MASK);
    expect((header1 >>> 5) & 0x1f).toBe(1); // this segment's own SegO.
    expect((header >>> 5) & 0x1f).toBe(0); // the first segment's SegO, unaffected.
  });

  test('segment0 followed by segment1 reconstitutes the complete published UpperTransportPDU', () => {
    expect(
      Buffer.concat([hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.segment0), hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.segment1)]),
    ).toEqual(hex(UPPER_TRANSPORT_SAMPLE_SZMIC.expected));
  });
});

describe('LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY: every field cross-checks the PDU bytes (Table 3.18)', () => {
  test('pdu0/pdu1 are header0/header1 followed by segment0/segment1', () => {
    const pdu0 = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.pdu0);
    const pdu1 = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.pdu1);
    expect(pdu0.subarray(0, 4)).toEqual(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.header0));
    expect(pdu0.subarray(4)).toEqual(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.segment0));
    expect(pdu1.subarray(0, 4)).toEqual(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.header1));
    expect(pdu1.subarray(4)).toEqual(hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.segment1));
  });

  test('header0 bits match the transcribed fields (AKF=0, AID=0, SZMIC=0, SegO=0)', () => {
    const headerInt = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.header0).readUInt32BE(0);
    expect((headerInt >>> 31) & 0x1).toBe(1); // SEG.
    expect((headerInt >>> 30) & 0x1).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.akf ? 1 : 0);
    expect((headerInt >>> 24) & 0x3f).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.aid);
    expect((headerInt >>> 23) & 0x1).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.szmic ? 1 : 0);
    expect((headerInt >>> 10) & 0x1fff).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.seqZero);
    expect((headerInt >>> 5) & 0x1f).toBe(0); // SegO.
    expect(headerInt & 0x1f).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.segN);
  });

  test('header1 bits match the transcribed fields (SegO=1, everything else identical to header0)', () => {
    const headerInt = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.header1).readUInt32BE(0);
    expect((headerInt >>> 30) & 0x1).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.akf ? 1 : 0);
    expect((headerInt >>> 24) & 0x3f).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.aid);
    expect((headerInt >>> 23) & 0x1).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.szmic ? 1 : 0);
    expect((headerInt >>> 10) & 0x1fff).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.seqZero);
    expect((headerInt >>> 5) & 0x1f).toBe(1); // SegO.
    expect(headerInt & 0x1f).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.segN);
  });

  test('segment0 followed by segment1 reconstitutes the complete published UpperTransportPDU', () => {
    expect(
      Buffer.concat([
        hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.segment0),
        hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.segment1),
      ]),
    ).toEqual(hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.expected));
  });
});

describe('Segment Acknowledgment message (Section 3.5.2.3.1, Table 3.21)', () => {
  // 8.3.7 "Message #7": OBO=1, SeqZero=0x9ab, BlockAck=0x00000002 (bit 1
  // only, of a 2-segment message). This is the fixture the mutation step
  // below relies on: reversing AckedSegments' 32 bits turns 0x00000002
  // into 0x40000000 (bit 1 moves to bit 30), a completely different value -
  // not a value a symmetric fixture (e.g. 0x00000000 or a palindromic
  // bit pattern) could ever catch. See vectors.ts's own note on this value.
  test('encodeSegmentAck matches the published Message #7 Parameters', () => {
    const parameters = encodeSegmentAck({
      obo: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.obo,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.seqZero,
      blockAck: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.blockAck,
    });
    expect(parameters.toString('hex')).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.parameters);
    expect(parameters).toEqual(hex(LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.parameters));
  });

  test('decodeSegmentAck recovers the published Message #7 OBO/SeqZero/BlockAck', () => {
    const decoded = decodeSegmentAck(hex(LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.parameters));
    expect(decoded).toEqual({
      obo: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.obo,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.seqZero,
      blockAck: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.blockAck,
    });
  });

  // 8.3.9 "Message #9": same OBO/SeqZero as Message #7 (same in-flight
  // transfer, one message later), but BlockAck=3 - both segments
  // acknowledged, not just one. Without this sample, an encoder/decoder
  // that only ever produced/recognised "bit 1 only" would still pass the
  // Message #7 tests above.
  test('encodeSegmentAck matches the published Message #9 Parameters', () => {
    const parameters = encodeSegmentAck({
      obo: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_2.obo,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_2.seqZero,
      blockAck: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_2.blockAck,
    });
    expect(parameters.toString('hex')).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_2.parameters);
  });

  test('decodeSegmentAck recovers the published Message #9 OBO/SeqZero/BlockAck', () => {
    const decoded = decodeSegmentAck(hex(LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_2.parameters));
    expect(decoded).toEqual({
      obo: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_2.obo,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_2.seqZero,
      blockAck: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_2.blockAck,
    });
  });

  // End-to-end through the generic envelope this message reuses (SEG=0,
  // Opcode=0x00 - Section 3.5.2.3's own Unsegmented Control message format,
  // Table 3.19): proves encodeSegmentAck/decodeSegmentAck really do compose
  // with encodeUnsegmentedControl/decodeUnsegmentedControl the way this
  // module's own header documents, against the complete published
  // LowerTransportPDU (Header || Parameters), not just the Parameters alone.
  test('the complete Lower Transport PDU round-trips through encodeUnsegmentedControl + encodeSegmentAck (Message #7)', () => {
    const ack = {
      obo: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.obo,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.seqZero,
      blockAck: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.blockAck,
    };
    const pdu = encodeUnsegmentedControl({ opcode: 0x00, parameters: encodeSegmentAck(ack) });
    expect(pdu.toString('hex')).toBe(LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.expected);

    const envelope = decodeUnsegmentedControl(pdu);
    expect(envelope).not.toBeNull();
    expect(envelope?.opcode).toBe(0x00);
    expect(decodeSegmentAck(envelope!.parameters)).toEqual(ack);
  });

  test('decodeSegmentAck returns null for a Parameters field that is not exactly 6 bytes', () => {
    expect(decodeSegmentAck(Buffer.alloc(5))).toBeNull();
    expect(decodeSegmentAck(Buffer.alloc(7))).toBeNull();
    expect(decodeSegmentAck(Buffer.alloc(0))).toBeNull();
  });

  describe('caller mistakes throw rather than being treated as a verification failure', () => {
    test('encodeSegmentAck rejects an out-of-range seqZero', () => {
      expect(() => encodeSegmentAck({ obo: false, seqZero: 0x2000, blockAck: 0 })).toThrow(
        /lower transport field "seqZero" must be an integer in \[0, 8191\], got 8192/,
      );
      expect(() => encodeSegmentAck({ obo: false, seqZero: -1, blockAck: 0 })).toThrow(
        /lower transport field "seqZero"/,
      );
      expect(() => encodeSegmentAck({ obo: false, seqZero: 0x1fff, blockAck: 0 })).not.toThrow();
    });

    test('encodeSegmentAck rejects an out-of-range blockAck', () => {
      expect(() => encodeSegmentAck({ obo: false, seqZero: 0, blockAck: 0x100000000 })).toThrow(
        /lower transport field "blockAck" must be an integer in \[0, 4294967295\], got 4294967296/,
      );
      expect(() => encodeSegmentAck({ obo: false, seqZero: 0, blockAck: -1 })).toThrow(
        /lower transport field "blockAck"/,
      );
      expect(() => encodeSegmentAck({ obo: false, seqZero: 0, blockAck: 0xffffffff })).not.toThrow();
    });
  });

  // Boundary case at both fields' own maxima, hand-computed from Table
  // 3.21's own bit widths (SeqZero 13 bits, AckedSegments 32 bits) - NOT
  // read back from encodeSegmentAck's own output. OBO=1, SeqZero=0x1fff:
  // octet0 = 0x80 | (0x1fff >>> 6 & 0x7f) = 0x80 | 0x7f = 0xff; octet1 =
  // (0x1fff & 0x3f) << 2 = 0x3f << 2 = 0xfc (RFU, bits 1-0, left at 0).
  // AckedSegments = 0xffffffff, all 32 bits set -> ff ff ff ff.
  test('seqZero and blockAck round-trip at their own maxima (0x1fff, 0xffffffff), against hand-computed Parameters bytes', () => {
    const parameters = encodeSegmentAck({ obo: true, seqZero: 0x1fff, blockAck: 0xffffffff });
    expect(parameters).toEqual(hex('fffcffffffff'));

    const decoded = decodeSegmentAck(parameters);
    expect(decoded).toEqual({ obo: true, seqZero: 0x1fff, blockAck: 0xffffffff });
  });

  // Review-discipline boundary: OBO=0 is never published by Section 8.3
  // (both samples above are OBO=1 - see vectors.ts's own note), so without
  // this round trip nothing would notice an encoder/decoder that silently
  // ignored `obo` and always treated it as 1. seqZero/blockAck reuse
  // Message #7's own published values so only `obo` differs from that
  // known-answer test above.
  test('obo=0 round-trips (no Section 8.3 sample publishes one - see vectors.ts)', () => {
    const ack = {
      obo: false,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.seqZero,
      blockAck: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.blockAck,
    };
    const parameters = encodeSegmentAck(ack);
    expect(parameters[0]! & 0x80).toBe(0); // OBO bit clear.
    expect(decodeSegmentAck(parameters)).toEqual(ack);
  });

  // Review finding (pinning, not fixing - the reviewer confirmed the
  // shipped decoder already behaves correctly): Table 3.21 marks RFU
  // (bits 1-0 of Parameters octet 1) "Reserved for Future Use", and
  // Section 1.3.2 "Reserved for Future Use" states the general receive-side
  // rule for every RFU field in this specification, verbatim: "When a field
  // value is a bit field, unassigned bits can be marked as Reserved for
  // Future Use and shall be set to 0. Implementations that receive a
  // message that contains a Reserved for Future Use bit that is set to 1
  // shall process the message as if that bit was set to 0" - i.e. ignore
  // it, don't reject the message. `decodeSegmentAck` already does this (it
  // masks those two bits out of `secondByte` before ever using it), but
  // nothing asserted it - making the decoder reject a non-zero-RFU
  // Parameters field still passed every test before this one was added.
  // Built from Message #7's own published Parameters (a6ac00000002) with
  // its own RFU bits (currently 0, per that sample) forced to 1 (0b11):
  // octet 1 goes from 0xac (1010 1100) to 0xaf (1010 1111).
  test('decodeSegmentAck ignores the reserved bits (RFU set to 1) rather than rejecting the message (Table 3.21; Section 1.3.2)', () => {
    const withReservedBitsSet = Buffer.from(LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.parameters, 'hex');
    withReservedBitsSet[1] = (withReservedBitsSet[1] as number) | 0x03; // force RFU (bits 1-0) to 1.
    expect(withReservedBitsSet.toString('hex')).toBe('a6af00000002'); // 0xac | 0x03 = 0xaf.

    const decoded = decodeSegmentAck(withReservedBitsSet);
    expect(decoded).toEqual({
      obo: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.obo,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.seqZero,
      blockAck: LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1.blockAck,
    });
  });

  // Review finding: nothing pinned that `encodeSegmentAck` allocates a
  // FRESH buffer per call - replacing `Buffer.alloc(...)` with a shared,
  // module-level buffer reused (and overwritten) on every call still
  // passed every test above a call that merely checks each call's OWN
  // return value in isolation. Scoped to this function only, not the
  // file's other encoders (`encodeUnsegmentedAccess`,
  // `encodeUnsegmentedControl`, `segmentAccessMessage`) - the same gap
  // exists there too, but it is pre-existing, already-reviewed code this
  // task did not touch; fixing/covering it belongs with whichever task
  // revisits those functions, not this one.
  test('encodeSegmentAck does not reuse a buffer across calls - an earlier result is unaffected by a later call', () => {
    const first = encodeSegmentAck({ obo: true, seqZero: 0x001, blockAck: 0x00000001 });
    const firstSnapshot = Buffer.from(first);

    const second = encodeSegmentAck({ obo: false, seqZero: 0x1fff, blockAck: 0xffffffff });

    expect(first).toEqual(firstSnapshot); // unchanged by the second call.
    expect(second).not.toEqual(first); // genuinely a different buffer's worth of bytes.
  });
});

// `blockAckFrom` lives in `./reassembly`, not here, to avoid an import
// cycle (see that module's own doc comment on the function) - these tests
// import it from there and feed its output straight into encodeSegmentAck,
// exercising the real boundary between the two modules the brief for this
// task asked for, rather than a hand-built ReassemblyState.
describe('Segment Acknowledgment message: blockAckFrom (./reassembly) feeds encodeSegmentAck directly', () => {
  const SRC_24 = UPPER_TRANSPORT_SAMPLE_SZMIC.src; // 0x1234 - Message #24's own source address.

  // Step 3's first required test: blockAckFrom, after only the first of two
  // segments has arrived, sets EXACTLY the bit Table 3.21 assigns to
  // segment 0 (the least significant bit) - built from a REAL, in-progress
  // reassembly of Message #24's own first segment (acceptSegment), not a
  // hand-built ReassemblyState object.
  test('after only segment 0 of Message #24, blockAckFrom sets exactly bit 0 - and that bit lands on the wire where Table 3.21 puts it', () => {
    const afterSegment0 = acceptSegment(null, SRC_24, hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu));
    if (afterSegment0.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');

    const blockAck = blockAckFrom(afterSegment0.state);
    expect(blockAck).toBe(0b01);

    const parameters = encodeSegmentAck({ obo: false, seqZero: afterSegment0.state.seqZero, blockAck });
    // AckedSegments occupies Parameters' last 4 octets (Table 3.21); within
    // that 32-bit field, bit 0 is segment 0 ("the least significant bit,
    // bit 0, shall represent segment 0"). Checking the actual WIRE byte's
    // low bit - not just blockAck's own JS-integer value again - is the
    // assertion the mutation step below needs to be meaningful.
    expect(parameters.readUInt32BE(2)).toBe(0b01);
    expect(parameters[parameters.length - 1]! & 0x01).toBe(1);
  });

  // Step 3's second required test: a COMPLETE state (every segment
  // received) produces a field with exactly segN+1 bits set - the general
  // property (derived from Table 3.21's one-bit-per-segment rule), checked
  // alongside the concrete value for this specific (2-segment) message, so
  // this would also catch an implementation that stopped one segment short
  // or set a bit past segN.
  test('after a complete reassembly of Message #24, blockAckFrom sets exactly segN+1 bits, and round-trips through encodeSegmentAck/decodeSegmentAck', () => {
    const afterSegment0 = acceptSegment(null, SRC_24, hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu));
    if (afterSegment0.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');
    const complete = acceptSegment(afterSegment0.state, SRC_24, hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu1));
    if (complete.kind !== 'complete') throw new Error('expected complete after both segments');

    const blockAck = blockAckFrom(complete.state);
    const segN = complete.state.segN;
    expect(blockAck).toBe(2 ** (segN + 1) - 1); // every bit from 0 to segN set, derived from the field width rule.
    expect(blockAck).toBe(0b11); // the concrete value for this 2-segment (segN=1) message.

    const ack: SegmentAck = { obo: true, seqZero: complete.state.seqZero, blockAck };
    const parameters = encodeSegmentAck(ack);
    expect(decodeSegmentAck(parameters)).toEqual(ack);
  });

  // Review finding: both tests above acknowledge a CONTIGUOUS run of
  // segments (just segment 0, or every segment 0..segN) - the one shape a
  // bit-position error is least likely to be caught by, since a reversed
  // or off-by-one mapping can still happen to look "mostly right" on a
  // solid run. A GAP (some segment received, the next one missing, then
  // another received) is the realistic case over a lossy radio link, and
  // it is the case where a wrong bit position actually changes which
  // segments a sender would retransmit - scoped here, not deferred to a
  // future retransmission-driving layer, because this test is about THIS
  // module's own integration boundary (does a real, gapped
  // `ReassemblyState` compose correctly through `blockAckFrom` into
  // `encodeSegmentAck`/`decodeSegmentAck`), not about retransmission
  // policy itself - no such layer exists yet in this codebase to own it,
  // and the bit-position hazard this guards against lives squarely at the
  // encode/decode boundary this task built.
  //
  // CONSTRUCTED (same style as reassembly.test.ts's own 3-segment fixture):
  // a 37-octet Upper Transport PDU - ceil(37/12)-1 = 3, so 4 segments
  // (12+12+12+1 octets) - reusing Message #24's own AKF/AID/SZMIC/SeqZero
  // so the header bits are genuinely self-consistent (segmentAccessMessage,
  // already verified elsewhere in this file), with segments 0 and 2
  // accepted and 1 and 3 left missing.
  test('a 4-segment reassembly with a GAP (segments 0 and 2 present, 1 and 3 missing) produces a non-contiguous bitmask that still round-trips correctly', () => {
    const FOUR_SEGMENT_UPPER_TRANSPORT_PDU = Buffer.alloc(37, 0xaa);
    const segments = segmentAccessMessage({
      akf: LOWER_TRANSPORT_SAMPLE_SEGMENTED.akf,
      aid: LOWER_TRANSPORT_SAMPLE_SEGMENTED.aid,
      szmic: LOWER_TRANSPORT_SAMPLE_SEGMENTED.szmic,
      seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENTED.seqZero,
      upperTransportPdu: FOUR_SEGMENT_UPPER_TRANSPORT_PDU,
    });
    expect(segments).toHaveLength(4); // sanity: this really is a 4-segment fixture, not 2 or 3.

    const afterSeg0 = acceptSegment(null, SRC_24, segments[0] as Buffer);
    if (afterSeg0.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');
    const afterSeg2 = acceptSegment(afterSeg0.state, SRC_24, segments[2] as Buffer);
    if (afterSeg2.kind !== 'incomplete') throw new Error('expected incomplete after segments 0 and 2 (1 and 3 still missing)');

    const blockAck = blockAckFrom(afterSeg2.state);
    expect(blockAck).toBe(0b0101); // segment 0 AND segment 2 - NOT a contiguous run, unlike every test above.

    const ack: SegmentAck = { obo: false, seqZero: afterSeg2.state.seqZero, blockAck };
    const parameters = encodeSegmentAck(ack);
    expect(decodeSegmentAck(parameters)).toEqual(ack);
    // Decisive: the wire bytes carry bit 0 AND bit 2, nothing in between.
    expect(parameters.readUInt32BE(2)).toBe(0b0101);
  });
});
