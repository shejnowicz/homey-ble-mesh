import {
  encodeUnsegmentedAccess,
  decodeUnsegmentedAccess,
  encodeUnsegmentedControl,
  decodeUnsegmentedControl,
  segmentAccessMessage,
  decodeSegmentedAccess,
} from '../lowerTransport';
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
