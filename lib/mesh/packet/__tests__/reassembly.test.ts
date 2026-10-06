import { acceptSegment, blockAckFrom, ReassemblyState } from '../reassembly';
import { segmentAccessMessage } from '../lowerTransport';
import {
  hex,
  LOWER_TRANSPORT_SAMPLE_SEGMENTED,
  LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY,
  LOWER_TRANSPORT_SAMPLE_ACCESS_1,
  UPPER_TRANSPORT_SAMPLE_SZMIC,
  UPPER_TRANSPORT_SAMPLE_DEVICE_KEY,
} from './vectors';

// Message #24 (Section 8.3.24, `LOWER_TRANSPORT_SAMPLE_SEGMENTED`): AKF=1,
// AID=0x26, SZMIC=1, SeqZero=0x80d, SegN=1 - segments split 12+4 (UNEVEN).
// This is the PRIMARY sample for anything order-sensitive below: its two
// segments differ in length, so concatenating them in the wrong order
// produces visibly wrong bytes, not just a coincidentally-correct result.
const SRC_24 = UPPER_TRANSPORT_SAMPLE_SZMIC.src; // 0x1234
const SEQ_ZERO_24 = LOWER_TRANSPORT_SAMPLE_SEGMENTED.seqZero; // 0x80d
const SEGMENT_0_OF_24 = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu);
const SEGMENT_1_OF_24 = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu1);
const UPPER_TRANSPORT_PDU_24 = hex(UPPER_TRANSPORT_SAMPLE_SZMIC.expected);

// Message #6 (Section 8.3.6, `LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY`):
// AKF=0, AID=0x00, SZMIC=0, SeqZero=0x9ab, SegN=1 - the device-key sibling,
// needed because a previous task's review found that using only the
// AKF=1/SZMIC=1 sample above leaves those two header bits undefended (a
// reassembler that hardcoded `akf: true`/`szmic: true` on its 'complete'
// result would still pass every test built from Message #24 alone).
const SRC_6 = UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.src; // 0x0003
const SEGMENT_0_OF_6 = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.pdu0);
const SEGMENT_1_OF_6 = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.pdu1);
const UPPER_TRANSPORT_PDU_6 = hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.expected);

// CONSTRUCTED, NOT TRANSCRIBED. No published Section 8.3 sample's Upper
// Transport Access PDU needs more than 2 segments - the longest one in this
// file's vectors, UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.expected, is exactly 24
// octets (SegN = ceil(24/12)-1 = 1, still 2 segments). A previous task's
// review found that capping the reassembler's handling at "at most 2
// segments" passed every test built from the two published samples alone,
// so this fixture exists specifically to close that gap.
//
// Built by appending ONE arbitrary filler octet (0xaa) to that same
// published 24-octet PDU, reaching 25 octets - just enough to force a 3rd
// segment (Table 3.18: SegN = ceil(25/12)-1 = 2, three segments of 12+12+1
// octets). The header fields (AKF/AID/SZMIC/SeqZero) reuse Message #24's
// own published values so this fixture can also double as "a 3-segment
// message arriving for the SAME (src, seqZero) as Message #24" in the
// out-of-range test below. The segment bytes themselves are produced by
// `segmentAccessMessage`, already verified correct (against both published
// samples) in `lowerTransport.test.ts` - only the 25-octet INPUT PDU is
// synthetic here, not the header-packing logic that splits it.
const THREE_SEGMENT_UPPER_TRANSPORT_PDU = Buffer.concat([
  hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.expected),
  Buffer.from([0xaa]),
]);
const threeSegments = segmentAccessMessage({
  akf: LOWER_TRANSPORT_SAMPLE_SEGMENTED.akf,
  aid: LOWER_TRANSPORT_SAMPLE_SEGMENTED.aid,
  szmic: LOWER_TRANSPORT_SAMPLE_SEGMENTED.szmic,
  seqZero: SEQ_ZERO_24,
  upperTransportPdu: THREE_SEGMENT_UPPER_TRANSPORT_PDU,
});

describe('fixture sanity', () => {
  test("Message #24's two segments differ in length (12 vs 4 octets) - required for the out-of-order test below to be meaningful", () => {
    expect(SEGMENT_0_OF_24.length).not.toBe(SEGMENT_1_OF_24.length);
  });

  test('the constructed 3-segment fixture really has 3 segments', () => {
    expect(threeSegments).toHaveLength(3);
  });
});

describe('acceptSegment: completion, both header-bit combinations (Section 3.5.3.2)', () => {
  test('Message #24 (AKF=1, SZMIC=1), in order, reassembles to the published Upper Transport PDU', () => {
    const first = acceptSegment(null, SRC_24, SEGMENT_0_OF_24);
    expect(first).toEqual({
      kind: 'incomplete',
      state: { src: SRC_24, seqZero: SEQ_ZERO_24, segN: 1, segments: [expect.any(Buffer), undefined] },
    });
    if (first.kind !== 'incomplete') throw new Error('unreachable');

    const second = acceptSegment(first.state, SRC_24, SEGMENT_1_OF_24);
    expect(second).toEqual({
      kind: 'complete',
      upperTransportPdu: UPPER_TRANSPORT_PDU_24,
      akf: true,
      aid: 0x26,
      szmic: true,
    });
  });

  test('Message #6 (AKF=0, SZMIC=0), in order, reassembles to the published Upper Transport PDU', () => {
    const first = acceptSegment(null, SRC_6, SEGMENT_0_OF_6);
    if (first.kind !== 'incomplete') throw new Error('expected incomplete after the first of two segments');

    const second = acceptSegment(first.state, SRC_6, SEGMENT_1_OF_6);
    expect(second).toEqual({
      kind: 'complete',
      upperTransportPdu: UPPER_TRANSPORT_PDU_6,
      akf: false,
      aid: 0x00,
      szmic: false,
    });
  });
});

describe('acceptSegment: the same two segments out of order (Message #24 - lengths differ, so order is load-bearing)', () => {
  test('segment 1 before segment 0 still reassembles to the published Upper Transport PDU, in the correct byte order', () => {
    const first = acceptSegment(null, SRC_24, SEGMENT_1_OF_24);
    expect(first).toEqual({
      kind: 'incomplete',
      state: { src: SRC_24, seqZero: SEQ_ZERO_24, segN: 1, segments: [undefined, expect.any(Buffer)] },
    });
    if (first.kind !== 'incomplete') throw new Error('unreachable');

    const second = acceptSegment(first.state, SRC_24, SEGMENT_0_OF_24);
    expect(second).toEqual({
      kind: 'complete',
      upperTransportPdu: UPPER_TRANSPORT_PDU_24,
      akf: true,
      aid: 0x26,
      szmic: true,
    });
  });
});

describe('acceptSegment: a duplicate segment is ignored without corrupting the state', () => {
  test('the same segment 0 received twice is ignored the second time, leaving the original state untouched', () => {
    const first = acceptSegment(null, SRC_24, SEGMENT_0_OF_24);
    if (first.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');

    const second = acceptSegment(first.state, SRC_24, SEGMENT_0_OF_24);
    expect(second.kind).toBe('ignored');
    if (second.kind !== 'ignored') throw new Error('unreachable');
    expect(second.reason).toMatch(/already received|duplicate/);
    // The state handed back is the SAME value that was passed in, not a
    // corrupted or reset one - the segment that was really missing (slot
    // 1) is still missing, and slot 0 is still exactly what it was.
    expect(second.state).toEqual(first.state);

    // The reassembly is still completable afterwards, proving the
    // duplicate truly did nothing rather than, say, silently clearing
    // slot 0 back to undefined.
    const third = acceptSegment(second.state, SRC_24, SEGMENT_1_OF_24);
    expect(third).toEqual({
      kind: 'complete',
      upperTransportPdu: UPPER_TRANSPORT_PDU_24,
      akf: true,
      aid: 0x26,
      szmic: true,
    });
  });
});

describe('acceptSegment: a mismatched seqZero is ignored, in-progress state left intact', () => {
  test('a segment reporting a different seqZero (segO/segN otherwise consistent) is ignored', () => {
    const inProgress = acceptSegment(null, SRC_24, SEGMENT_0_OF_24);
    if (inProgress.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');

    // CONSTRUCTED: a segment 0 of a different (also 2-segment) message,
    // same AKF/AID/SZMIC as Message #24 for cleanliness, but a seqZero
    // that deliberately does not match the one already in progress -
    // built with the already-verified segmentAccessMessage encoder so the
    // header bits are genuinely self-consistent, not hand-tweaked.
    const wrongSeqZero = segmentAccessMessage({
      akf: true,
      aid: 0x26,
      szmic: true,
      seqZero: 0x001,
      upperTransportPdu: Buffer.alloc(13, 0xcc), // 13 octets -> segN=1, same shape as Message #24.
    })[0] as Buffer;

    const result = acceptSegment(inProgress.state, SRC_24, wrongSeqZero);
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') throw new Error('unreachable');
    expect(result.reason).toMatch(/seqZero/);
    expect(result.reason).toMatch(/0x1\b/); // the rejected segment's own seqZero, 0x001.
    expect(result.reason).toMatch(/0x80d\b/); // the established seqZero, unchanged.
    // The in-progress state is EXACTLY what it was before this call - not
    // reset, not advanced, not merged with the rejected segment.
    expect(result.state).toEqual(inProgress.state);
  });
});

describe('acceptSegment: a mismatched segN is ignored', () => {
  test('a segment reporting a smaller segN (same seqZero) is ignored, established state left intact', () => {
    const inProgress = acceptSegment(null, SRC_24, SEGMENT_0_OF_24);
    if (inProgress.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');

    // CONSTRUCTED: same seqZero as the established reassembly (so this
    // test isolates segN, not seqZero, as the rejected field), but a
    // single-segment (segN=0) message instead of the established segN=1 -
    // again built with segmentAccessMessage, not hand-packed bits.
    const wrongSegN = segmentAccessMessage({
      akf: true,
      aid: 0x26,
      szmic: true,
      seqZero: SEQ_ZERO_24,
      upperTransportPdu: Buffer.alloc(5, 0xdd), // 5 octets -> segN=0.
    })[0] as Buffer;

    const result = acceptSegment(inProgress.state, SRC_24, wrongSegN);
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') throw new Error('unreachable');
    expect(result.reason).toMatch(/segN/);
    expect(result.reason).not.toMatch(/beyond/); // this is the "disagrees", not the "index beyond", branch - see the next describe block.
    expect(result.state).toEqual(inProgress.state);
  });
});

describe('acceptSegment: a segment index beyond the established segN is ignored rather than growing the array', () => {
  test('segO=2 of a constructed 3-segment message, received after a 2-segment reassembly (segN=1) is in progress, is ignored', () => {
    const inProgress = acceptSegment(null, SRC_24, SEGMENT_0_OF_24);
    if (inProgress.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');
    expect(inProgress.state.segments).toHaveLength(2);

    // threeSegments[2] is segO=2, segN=2 - internally self-consistent
    // (decodeSegmentedAccess's own segO<=segN invariant holds for it in
    // isolation), same src and seqZero as the in-progress reassembly
    // above (both reuse Message #24's own values), but segO=2 is beyond
    // index 1, the highest valid slot of a segN=1 (2-segment) reassembly.
    const beyond = threeSegments[2] as Buffer;

    const result = acceptSegment(inProgress.state, SRC_24, beyond);
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') throw new Error('unreachable');
    expect(result.reason).toMatch(/beyond/);
    expect(result.reason).toMatch(/\b2\b/); // the rejected segment's own index.
    expect(result.reason).toMatch(/\b1\b/); // the established last-segment index.

    // The decisive assertion: the array was NOT silently grown to length 3
    // by a bare `segments[2] = ...` assignment - it is still exactly the
    // 2-slot array the first segment established, untouched.
    expect(result.state).toEqual(inProgress.state);
    expect(result.state.segments).toHaveLength(2);
  });
});

describe('acceptSegment: three or more segments (constructed - no published sample needs this many)', () => {
  test('all three segments, out of order, reassemble to the constructed Upper Transport PDU', () => {
    const [seg0, seg1, seg2] = threeSegments as [Buffer, Buffer, Buffer];
    const src = SRC_24;

    // Arrival order: 2, 0, 1 - neither sorted nor reversed, so this cannot
    // pass by coincidence the way a simple "reverse the array" bug might
    // slip past a strictly-reversed two-segment test.
    const afterSeg2 = acceptSegment(null, src, seg2);
    if (afterSeg2.kind !== 'incomplete') throw new Error('expected incomplete after 1 of 3 segments');
    expect(afterSeg2.state.segments).toEqual([undefined, undefined, expect.any(Buffer)]);

    const afterSeg0 = acceptSegment(afterSeg2.state, src, seg0);
    if (afterSeg0.kind !== 'incomplete') throw new Error('expected incomplete after 2 of 3 segments');
    expect(afterSeg0.state.segments).toEqual([expect.any(Buffer), undefined, expect.any(Buffer)]);

    const afterSeg1 = acceptSegment(afterSeg0.state, src, seg1);
    expect(afterSeg1).toEqual({
      kind: 'complete',
      upperTransportPdu: THREE_SEGMENT_UPPER_TRANSPORT_PDU,
      akf: LOWER_TRANSPORT_SAMPLE_SEGMENTED.akf,
      aid: LOWER_TRANSPORT_SAMPLE_SEGMENTED.aid,
      szmic: LOWER_TRANSPORT_SAMPLE_SEGMENTED.szmic,
    });
  });
});

describe('acceptSegment: a mismatched source is ignored (bonus coverage - ReassemblyState.src is part of the grouping key too)', () => {
  test('the right seqZero/segO/segN but a different src is ignored, established state left intact', () => {
    const inProgress = acceptSegment(null, SRC_24, SEGMENT_0_OF_24);
    if (inProgress.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');

    // SEGMENT_1_OF_24 is otherwise exactly the segment this reassembly is
    // waiting for - only the `src` argument passed alongside it is wrong,
    // isolating src as the only mismatched field.
    const wrongSrc = 0x9999;
    const result = acceptSegment(inProgress.state, wrongSrc, SEGMENT_1_OF_24);
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') throw new Error('unreachable');
    expect(result.reason).toMatch(/source/);
    expect(result.state).toEqual(inProgress.state);
  });
});

describe('caller mistakes throw rather than being treated as a verification failure', () => {
  test('acceptSegment rejects a pdu that is not a decodable Segmented Access message', () => {
    // A genuine, published UNSEGMENTED Access message (SEG=0) - never a
    // valid input to this function, whose caller must already know it is
    // routing a segmented PDU here.
    expect(() => acceptSegment(null, SRC_24, hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.expected))).toThrow(
      /does not decode as a Segmented Access message/,
    );
  });

  test('acceptSegment rejects an out-of-range src', () => {
    expect(() => acceptSegment(null, 0x10000, SEGMENT_0_OF_24)).toThrow(
      /reassembly field "src" must be an integer in \[0, 65535\], got 65536/,
    );
    expect(() => acceptSegment(null, -1, SEGMENT_0_OF_24)).toThrow(/reassembly field "src"/);
  });
});

describe('blockAckFrom (Section 3.5.2.3.1, Table 3.21 AckedSegments field)', () => {
  test('bit 0 only, after just segment 0 of a 2-segment message', () => {
    const state: ReassemblyState = { src: SRC_24, seqZero: SEQ_ZERO_24, segN: 1, segments: [Buffer.alloc(12), undefined] };
    expect(blockAckFrom(state)).toBe(0b01);
  });

  test('bit 1 only, after just segment 1 of a 2-segment message - LSB is segment 0, not arrival order', () => {
    const state: ReassemblyState = { src: SRC_24, seqZero: SEQ_ZERO_24, segN: 1, segments: [undefined, Buffer.alloc(4)] };
    expect(blockAckFrom(state)).toBe(0b10);
  });

  test('bits 0 and 2 set, bit 1 clear, for a partially-received 3-segment message', () => {
    const state: ReassemblyState = {
      src: SRC_24,
      seqZero: SEQ_ZERO_24,
      segN: 2,
      segments: [Buffer.alloc(12), undefined, Buffer.alloc(1)],
    };
    expect(blockAckFrom(state)).toBe(0b101);
  });

  test('no bit is ever set beyond segN (a 4-segment state with only the last slot filled sets only bit 3, not higher)', () => {
    const state: ReassemblyState = {
      src: SRC_24,
      seqZero: SEQ_ZERO_24,
      segN: 3,
      segments: [undefined, undefined, undefined, Buffer.alloc(1)],
    };
    expect(blockAckFrom(state)).toBe(0b1000);
  });

  test('an empty reassembly (no segments received yet) acknowledges nothing', () => {
    const state: ReassemblyState = { src: SRC_24, seqZero: SEQ_ZERO_24, segN: 1, segments: [undefined, undefined] };
    expect(blockAckFrom(state)).toBe(0);
  });
});
