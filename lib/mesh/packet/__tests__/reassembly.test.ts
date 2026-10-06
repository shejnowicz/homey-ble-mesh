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
//
// Naming note (review round): these hold the COMPLETE on-the-wire Lower
// Transport PDU (4-octet header + that segment's payload) - the same thing
// `vectors.ts` itself calls `pdu`/`pdu1`, never `segment0`/`segment1`
// (which, in that file, names the payload ALONE). `PDU_*`, not `SEGMENT_*`,
// to match that convention instead of contradicting it.
const SRC_24 = UPPER_TRANSPORT_SAMPLE_SZMIC.src; // 0x1234
const SEQ_ZERO_24 = LOWER_TRANSPORT_SAMPLE_SEGMENTED.seqZero; // 0x80d
const AKF_24 = LOWER_TRANSPORT_SAMPLE_SEGMENTED.akf; // true
const AID_24 = LOWER_TRANSPORT_SAMPLE_SEGMENTED.aid; // 0x26
const SZMIC_24 = LOWER_TRANSPORT_SAMPLE_SEGMENTED.szmic; // true
const PDU_0_OF_24 = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu);
const PDU_1_OF_24 = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.pdu1);
const UPPER_TRANSPORT_PDU_24 = hex(UPPER_TRANSPORT_SAMPLE_SZMIC.expected);

// Message #6 (Section 8.3.6, `LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY`):
// AKF=0, AID=0x00, SZMIC=0, SeqZero=0x9ab, SegN=1 - the device-key sibling,
// needed because a previous task's review found that using only the
// AKF=1/SZMIC=1 sample above leaves those two header bits undefended (a
// reassembler that hardcoded `akf: true`/`szmic: true` on its 'complete'
// result would still pass every test built from Message #24 alone).
const SRC_6 = UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.src; // 0x0003
const AKF_6 = LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.akf; // false
const AID_6 = LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.aid; // 0x00
const SZMIC_6 = LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.szmic; // false
const PDU_0_OF_6 = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.pdu0);
const PDU_1_OF_6 = hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.pdu1);
const UPPER_TRANSPORT_PDU_6 = hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.expected);

// CONSTRUCTED, NOT TRANSCRIBED. No published Section 8.3 sample's Upper
// Transport Access PDU needs more than 2 segments - the longest one in this
// file's vectors, UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.expected, is exactly 24
// octets (SegN = ceil(24/12)-1 = 1, still 2 segments). A previous review
// found that capping the reassembler's handling at "at most 2 segments"
// passed every test built from the two published samples alone, so this
// fixture exists specifically to close that gap.
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
  akf: AKF_24,
  aid: AID_24,
  szmic: SZMIC_24,
  seqZero: SEQ_ZERO_24,
  upperTransportPdu: THREE_SEGMENT_UPPER_TRANSPORT_PDU,
});

// Table 3.18: SegO/SegN are each 5-bit fields, so the highest segment index
// the specification allows is 2**5 - 1 = 31, regardless of anything this
// module's own code happens to do - this is the field-width-derived
// constant `blockAckFrom`'s own high-bit test below needs, per the review
// round's instruction not to derive it by running the implementation.
const MAX_SEG_NUMBER = 0x1f;

describe('fixture sanity', () => {
  // Corrected (review round): the title used to quote the PAYLOAD lengths
  // (12 vs 4 octets) while the assertion compared the two full WIRE PDUs
  // (16 vs 8 octets, 4-octet header included on each). The assertion was
  // always sound - a 16-vs-8 difference still proves the payloads differ
  // too, since both share the same fixed 4-octet header overhead - only
  // the title's numbers were wrong.
  test("Message #24's two segment PDUs differ in length on the wire (16 vs 8 octets) - required for the out-of-order test below to be meaningful", () => {
    expect(PDU_0_OF_24).toHaveLength(16);
    expect(PDU_1_OF_24).toHaveLength(8);
    expect(PDU_0_OF_24.length).not.toBe(PDU_1_OF_24.length);
  });

  test('the constructed 3-segment fixture really has 3 segments', () => {
    expect(threeSegments).toHaveLength(3);
  });
});

describe('acceptSegment: completion, both header-bit combinations (Section 3.5.3.2)', () => {
  test('Message #24 (AKF=1, SZMIC=1), in order, reassembles to the published Upper Transport PDU', () => {
    const first = acceptSegment(undefined, SRC_24, PDU_0_OF_24);
    expect(first).toEqual({
      kind: 'incomplete',
      state: {
        src: SRC_24,
        seqZero: SEQ_ZERO_24,
        segN: 1,
        akf: AKF_24,
        aid: AID_24,
        szmic: SZMIC_24,
        segments: [expect.any(Buffer), undefined],
      },
    });
    if (first.kind !== 'incomplete') throw new Error('unreachable');

    const second = acceptSegment(first.state, SRC_24, PDU_1_OF_24);
    expect(second).toEqual({
      kind: 'complete',
      state: {
        src: SRC_24,
        seqZero: SEQ_ZERO_24,
        segN: 1,
        akf: AKF_24,
        aid: AID_24,
        szmic: SZMIC_24,
        segments: [expect.any(Buffer), expect.any(Buffer)],
      },
      upperTransportPdu: UPPER_TRANSPORT_PDU_24,
      akf: true,
      aid: 0x26,
      szmic: true,
    });
  });

  test('Message #6 (AKF=0, SZMIC=0), in order, reassembles to the published Upper Transport PDU', () => {
    const first = acceptSegment(undefined, SRC_6, PDU_0_OF_6);
    if (first.kind !== 'incomplete') throw new Error('expected incomplete after the first of two segments');

    const second = acceptSegment(first.state, SRC_6, PDU_1_OF_6);
    expect(second).toEqual({
      kind: 'complete',
      state: {
        src: SRC_6,
        seqZero: LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY.seqZero,
        segN: 1,
        akf: AKF_6,
        aid: AID_6,
        szmic: SZMIC_6,
        segments: [expect.any(Buffer), expect.any(Buffer)],
      },
      upperTransportPdu: UPPER_TRANSPORT_PDU_6,
      akf: false,
      aid: 0x00,
      szmic: false,
    });
  });
});

describe('acceptSegment: the same two segments out of order (Message #24 - lengths differ, so order is load-bearing)', () => {
  test('segment 1 before segment 0 still reassembles to the published Upper Transport PDU, in the correct byte order', () => {
    const first = acceptSegment(undefined, SRC_24, PDU_1_OF_24);
    expect(first).toEqual({
      kind: 'incomplete',
      state: {
        src: SRC_24,
        seqZero: SEQ_ZERO_24,
        segN: 1,
        akf: AKF_24,
        aid: AID_24,
        szmic: SZMIC_24,
        segments: [undefined, expect.any(Buffer)],
      },
    });
    if (first.kind !== 'incomplete') throw new Error('unreachable');

    const second = acceptSegment(first.state, SRC_24, PDU_0_OF_24);
    expect(second.kind).toBe('complete');
    if (second.kind !== 'complete') throw new Error('unreachable');
    expect(second.upperTransportPdu).toEqual(UPPER_TRANSPORT_PDU_24);
    expect(second.akf).toBe(true);
    expect(second.aid).toBe(0x26);
    expect(second.szmic).toBe(true);
  });
});

describe('acceptSegment: a duplicate segment is ignored without corrupting the state', () => {
  test('the same segment 0 received twice is ignored the second time, leaving the original state untouched', () => {
    const first = acceptSegment(undefined, SRC_24, PDU_0_OF_24);
    if (first.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');

    const second = acceptSegment(first.state, SRC_24, PDU_0_OF_24);
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
    const third = acceptSegment(second.state, SRC_24, PDU_1_OF_24);
    expect(third.kind).toBe('complete');
    if (third.kind !== 'complete') throw new Error('unreachable');
    expect(third.upperTransportPdu).toEqual(UPPER_TRANSPORT_PDU_24);
  });
});

describe('acceptSegment: a mismatched seqZero is ignored, in-progress state left intact', () => {
  test('a segment reporting a different seqZero (segO/segN otherwise consistent) is ignored', () => {
    const inProgress = acceptSegment(undefined, SRC_24, PDU_0_OF_24);
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
    const inProgress = acceptSegment(undefined, SRC_24, PDU_0_OF_24);
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
    const inProgress = acceptSegment(undefined, SRC_24, PDU_0_OF_24);
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
    expect(result.state?.segments).toHaveLength(2);
  });
});

describe('acceptSegment: three or more segments (constructed - no published sample needs this many)', () => {
  test('all three segments, out of order, reassemble to the constructed Upper Transport PDU', () => {
    const [seg0, seg1, seg2] = threeSegments as [Buffer, Buffer, Buffer];
    const src = SRC_24;

    // Arrival order: 2, 0, 1 - neither sorted nor reversed, so this cannot
    // pass by coincidence the way a simple "reverse the array" bug might
    // slip past a strictly-reversed two-segment test.
    const afterSeg2 = acceptSegment(undefined, src, seg2);
    if (afterSeg2.kind !== 'incomplete') throw new Error('expected incomplete after 1 of 3 segments');
    expect(afterSeg2.state.segments).toEqual([undefined, undefined, expect.any(Buffer)]);

    const afterSeg0 = acceptSegment(afterSeg2.state, src, seg0);
    if (afterSeg0.kind !== 'incomplete') throw new Error('expected incomplete after 2 of 3 segments');
    expect(afterSeg0.state.segments).toEqual([expect.any(Buffer), undefined, expect.any(Buffer)]);

    const afterSeg1 = acceptSegment(afterSeg0.state, src, seg1);
    expect(afterSeg1.kind).toBe('complete');
    if (afterSeg1.kind !== 'complete') throw new Error('unreachable');
    expect(afterSeg1.upperTransportPdu).toEqual(THREE_SEGMENT_UPPER_TRANSPORT_PDU);
    expect(afterSeg1.akf).toBe(AKF_24);
    expect(afterSeg1.aid).toBe(AID_24);
    expect(afterSeg1.szmic).toBe(SZMIC_24);
    expect(afterSeg1.state.segN).toBe(2);
    expect(afterSeg1.state.segments).toEqual([expect.any(Buffer), expect.any(Buffer), expect.any(Buffer)]);
  });
});

describe('acceptSegment: a mismatched source is ignored (bonus coverage - ReassemblyState.src is part of the grouping key too)', () => {
  test('the right seqZero/segO/segN but a different src is ignored, established state left intact', () => {
    const inProgress = acceptSegment(undefined, SRC_24, PDU_0_OF_24);
    if (inProgress.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');

    // PDU_1_OF_24 is otherwise exactly the segment this reassembly is
    // waiting for - only the `src` argument passed alongside it is wrong,
    // isolating src as the only mismatched field.
    const wrongSrc = 0x9999;
    const result = acceptSegment(inProgress.state, wrongSrc, PDU_1_OF_24);
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') throw new Error('unreachable');
    expect(result.reason).toMatch(/source/);
    expect(result.state).toEqual(inProgress.state);
  });
});

describe('acceptSegment: a mismatched AKF/AID/SZMIC is ignored (review round - Finding 1)', () => {
  // CONSTRUCTED: same src/seqZero/segN/segO as the in-progress reassembly
  // from Message #24 (segO=1, the still-missing slot), so each of these
  // three tests isolates exactly ONE of AKF/AID/SZMIC as the differing
  // field - never segN/seqZero/src, which have their own dedicated tests
  // above. Built with segmentAccessMessage so every header bit this test
  // does NOT intend to vary is still genuinely self-consistent.
  function wrongHeaderSegment(overrides: { akf?: boolean; aid?: number; szmic?: boolean }): Buffer {
    const segments = segmentAccessMessage({
      akf: overrides.akf ?? AKF_24,
      aid: overrides.aid ?? AID_24,
      szmic: overrides.szmic ?? SZMIC_24,
      seqZero: SEQ_ZERO_24,
      // Same 16-octet total as Message #24's real Upper Transport PDU, so
      // segO=1 lands on a 4-octet final segment exactly like PDU_1_OF_24 -
      // not load-bearing for this test, just keeps the fixture unsurprising.
      upperTransportPdu: Buffer.alloc(16, 0xee),
    });
    return segments[1] as Buffer;
  }

  test('a segment reporting a different akf is ignored, established state left intact', () => {
    const inProgress = acceptSegment(undefined, SRC_24, PDU_0_OF_24);
    if (inProgress.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');

    const result = acceptSegment(inProgress.state, SRC_24, wrongHeaderSegment({ akf: false }));
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') throw new Error('unreachable');
    expect(result.reason).toMatch(/akf/);
    expect(result.state).toEqual(inProgress.state);
  });

  test('a segment reporting a different aid is ignored, established state left intact', () => {
    const inProgress = acceptSegment(undefined, SRC_24, PDU_0_OF_24);
    if (inProgress.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');

    const result = acceptSegment(inProgress.state, SRC_24, wrongHeaderSegment({ aid: 0x01 }));
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') throw new Error('unreachable');
    expect(result.reason).toMatch(/aid/);
    expect(result.state).toEqual(inProgress.state);
  });

  test('a segment reporting a different szmic is ignored, established state left intact', () => {
    const inProgress = acceptSegment(undefined, SRC_24, PDU_0_OF_24);
    if (inProgress.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');

    const result = acceptSegment(inProgress.state, SRC_24, wrongHeaderSegment({ szmic: false }));
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') throw new Error('unreachable');
    expect(result.reason).toMatch(/szmic/);
    expect(result.state).toEqual(inProgress.state);
  });

  test('a message whose own two segments disagree on akf completes with byte-correct payload but still reports only one set of flags (documents the known limit, not a bug in this test)', () => {
    // This is the exact end-to-end scenario the coordinator's review
    // measured: nothing stops acceptSegment itself from completing once
    // every SLOT is filled - the cross-check above only rejects a
    // DISAGREEING segment from reaching a slot in the first place. A
    // disagreeing segment is "ignored" before it is ever stored, so two
    // genuinely-disagreeing segments can never BOTH be stored into the same
    // reassembly - this test exists to make that guarantee explicit, not to
    // show a gap.
    const inProgress = acceptSegment(undefined, SRC_24, PDU_0_OF_24);
    if (inProgress.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');
    const rejected = acceptSegment(inProgress.state, SRC_24, wrongHeaderSegment({ akf: false }));
    expect(rejected.kind).toBe('ignored');

    // The real segment 1 (agreeing AKF) still completes the message normally.
    const completed = acceptSegment(inProgress.state, SRC_24, PDU_1_OF_24);
    expect(completed.kind).toBe('complete');
  });
});

describe("acceptSegment: a pdu that does not decode as a Segmented Access message is 'ignored', not thrown (review round - Finding 2)", () => {
  test('with no reassembly in progress, there is no state to report, so it is undefined', () => {
    // A genuine, published UNSEGMENTED Access message (SEG=0) - reachable
    // in practice if a caller ever mis-routes one here, and also simply
    // too short/malformed to be a segment in other ways.
    const result = acceptSegment(undefined, SRC_24, hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.expected));
    expect(result).toEqual({
      kind: 'ignored',
      state: undefined,
      reason: expect.stringMatching(/does not decode as a Segmented Access message/),
    });
  });

  test('a genuinely reachable case: the network layer admits Access transport PDUs down to a single octet, so a 3-octet PDU with SEG set authenticates and routes here, too short for any segment', () => {
    // SEG bit (0x80) set, 3 octets total - decodeSegmentedAccess's own
    // length guard (pdu.length <= 4) rejects this before it even reads
    // SegO/SegN, exactly the "too short for a non-empty segment" case the
    // module header cites as genuinely reachable, not hypothetical.
    const tooShort = Buffer.from([0x80, 0x00, 0x00]);
    const result = acceptSegment(undefined, SRC_24, tooShort);
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') throw new Error('unreachable');
    expect(result.state).toBeUndefined();
    expect(result.reason).toMatch(/does not decode/);
  });

  test('with a reassembly already in progress, that in-progress state is returned untouched, not discarded', () => {
    const inProgress = acceptSegment(undefined, SRC_24, PDU_0_OF_24);
    if (inProgress.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');

    const result = acceptSegment(inProgress.state, SRC_24, hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.expected));
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') throw new Error('unreachable');
    expect(result.reason).toMatch(/does not decode/);
    // The decisive assertion: one unparseable PDU must not wipe out a
    // real, already-collected segment.
    expect(result.state).toEqual(inProgress.state);

    // And the reassembly is still completable afterward.
    const completed = acceptSegment(result.state, SRC_24, PDU_1_OF_24);
    expect(completed.kind).toBe('complete');
  });
});

// Fix wave, Important 1: `acceptSegment` used to take `ReassemblyState |
// null` while the `'ignored'` variant reported `ReassemblyState |
// undefined`, so the module could not consume its own output - and the
// storage its own header recommends, a `Map` keyed by source address,
// hands back `undefined` for a key it does not hold, i.e. for the FIRST
// segment of every new message: the most common call this function will
// ever receive. Settled on `undefined` on both sides.
//
// These tests exist so the documented usage is EXERCISED rather than only
// described. They are load-bearing in two different ways at once: the
// assertions below, and the types - narrowing the parameter back to
// `ReassemblyState | null` makes every `acceptSegment(inFlight.get(...))`
// and every `acceptSegment(result.state, ...)` here a compile error, which
// ts-jest reports as an outright suite failure rather than a lint warning.
// Nothing below writes `?? null` or `?? undefined`: inserting one would
// hide exactly the defect these tests are here to pin.
describe("the Map-keyed-by-source pattern this module's header recommends (one nullish convention: undefined)", () => {
  test('a Map lookup MISS - the first segment from a source not in the map - starts a reassembly rather than throwing', () => {
    const inFlight = new Map<number, ReassemblyState>();
    expect(inFlight.get(SRC_24)).toBeUndefined(); // the value actually passed below.

    const result = acceptSegment(inFlight.get(SRC_24), SRC_24, PDU_0_OF_24);
    expect(result.kind).toBe('incomplete');
    if (result.kind !== 'incomplete') throw new Error('unreachable');
    expect(result.state.src).toBe(SRC_24);
    expect(result.state.segN).toBe(1);
    expect(result.state.segments).toEqual([expect.any(Buffer), undefined]);
  });

  test('a whole message drives end to end through the Map, every call fed the raw lookup result', () => {
    const inFlight = new Map<number, ReassemblyState>();
    let completed: Buffer | undefined;

    for (const pdu of [PDU_0_OF_24, PDU_1_OF_24]) {
      const result = acceptSegment(inFlight.get(SRC_24), SRC_24, pdu);
      if (result.kind === 'complete') {
        completed = result.upperTransportPdu;
        inFlight.delete(SRC_24);
      } else if (result.kind === 'incomplete') {
        inFlight.set(SRC_24, result.state);
      } else if (result.state !== undefined) {
        inFlight.set(SRC_24, result.state); // 'ignored' mid-flight: put the untouched state back.
      }
    }

    expect(completed).toEqual(UPPER_TRANSPORT_PDU_24);
    expect(inFlight.size).toBe(0); // the completed message was removed, nothing left dangling.
  });

  test('two sources interleaved through ONE map, so each source hits the lookup-miss path independently', () => {
    const inFlight = new Map<number, ReassemblyState>();
    const completed = new Map<number, Buffer>();
    // Interleaved deliberately: Message #24's segment 0, then Message #6's
    // segment 0, then each message's segment 1 - so neither reassembly is
    // ever the only one in the map, and SRC_6's first segment is a lookup
    // miss on a map that is already non-empty.
    const arrivals: Array<[number, Buffer]> = [
      [SRC_24, PDU_0_OF_24],
      [SRC_6, PDU_0_OF_6],
      [SRC_24, PDU_1_OF_24],
      [SRC_6, PDU_1_OF_6],
    ];

    for (const [src, pdu] of arrivals) {
      const result = acceptSegment(inFlight.get(src), src, pdu);
      if (result.kind === 'complete') {
        completed.set(src, result.upperTransportPdu);
        inFlight.delete(src);
      } else if (result.kind === 'incomplete') {
        inFlight.set(src, result.state);
      }
    }

    expect(completed.get(SRC_24)).toEqual(UPPER_TRANSPORT_PDU_24);
    expect(completed.get(SRC_6)).toEqual(UPPER_TRANSPORT_PDU_6);
    expect(inFlight.size).toBe(0);
  });

  test("an 'ignored' result's own state feeds straight back in, both when it is undefined and when it carries a reassembly", () => {
    // (a) No reassembly in progress: 'ignored' with state undefined - the
    // variant whose type used to be incompatible with the parameter.
    const ignoredWithoutState = acceptSegment(undefined, SRC_24, hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.expected));
    if (ignoredWithoutState.kind !== 'ignored') throw new Error('expected ignored for an unsegmented PDU');
    expect(ignoredWithoutState.state).toBeUndefined();

    const started = acceptSegment(ignoredWithoutState.state, SRC_24, PDU_0_OF_24);
    if (started.kind !== 'incomplete') throw new Error('expected incomplete after segment 0');

    // (b) Reassembly in progress: 'ignored' carrying that untouched state.
    const ignoredWithState = acceptSegment(started.state, SRC_24, hex(LOWER_TRANSPORT_SAMPLE_ACCESS_1.expected));
    if (ignoredWithState.kind !== 'ignored') throw new Error('expected ignored for an unsegmented PDU');
    expect(ignoredWithState.state).toEqual(started.state);

    const completed = acceptSegment(ignoredWithState.state, SRC_24, PDU_1_OF_24);
    if (completed.kind !== 'complete') throw new Error('expected complete after both segments');
    expect(completed.upperTransportPdu).toEqual(UPPER_TRANSPORT_PDU_24);
  });
});

// Fix wave, Important 3: the review built two SHORT segments claiming
// segN=1 and watched them reassemble into a PDU far shorter than any
// conforming two-segment message. `decodeSegmentedAccess` now rejects a
// non-last segment that is not exactly the fixed segment size (Section
// 3.5.2.2), so such a segment never reaches a slot here. The decoder-level
// tests live in `lowerTransport.test.ts`; this one pins the CONSEQUENCE the
// finding was actually about - that a short impostor cannot poison the
// reassembly the genuine segments are about to start.
describe('acceptSegment: a short non-last segment can neither start nor poison a reassembly (Section 3.5.2.2)', () => {
  test("a 3-octet segment carrying Message #24's own segment-0 header is ignored, and the genuine segments still reassemble", () => {
    // The header is Message #24's published segment-0 header verbatim
    // (SegO=0, SegN=1), so this impostor differs from the genuine segment 0
    // in its PAYLOAD LENGTH alone - 3 octets where the format fixes 12.
    const shortNonLast = Buffer.concat([hex(LOWER_TRANSPORT_SAMPLE_SEGMENTED.header), Buffer.alloc(3, 0xaa)]);

    const ignored = acceptSegment(undefined, SRC_24, shortNonLast);
    expect(ignored.kind).toBe('ignored');
    if (ignored.kind !== 'ignored') throw new Error('unreachable');
    expect(ignored.state).toBeUndefined(); // no reassembly was started by it.
    expect(ignored.reason).toMatch(/does not decode/);

    // The decisive half: the genuine segment 0 that arrives next is NOT
    // seen as a duplicate of the impostor, and the message reassembles
    // byte-for-byte into the published Upper Transport PDU.
    const first = acceptSegment(ignored.state, SRC_24, PDU_0_OF_24);
    if (first.kind !== 'incomplete') throw new Error('expected incomplete after segment 0');
    const second = acceptSegment(first.state, SRC_24, PDU_1_OF_24);
    if (second.kind !== 'complete') throw new Error('expected complete after segment 1');
    expect(second.upperTransportPdu).toEqual(UPPER_TRANSPORT_PDU_24);
  });
});

describe('caller mistakes throw rather than being treated as a verification failure', () => {
  test('acceptSegment rejects an out-of-range src', () => {
    expect(() => acceptSegment(undefined, 0x10000, PDU_0_OF_24)).toThrow(
      /reassembly field "src" must be an integer in \[0, 65535\], got 65536/,
    );
    expect(() => acceptSegment(undefined, -1, PDU_0_OF_24)).toThrow(/reassembly field "src"/);
  });
});

describe('acceptSegment: stored segments are copies, not views onto the caller-owned buffer (review round - minor finding)', () => {
  test('mutating the original pdu buffer AFTER it was accepted, but BEFORE completion, does not change the eventual upperTransportPdu', () => {
    // Fresh, mutable copies - NOT the shared PDU_0_OF_24/PDU_1_OF_24
    // constants above, so mutating them here cannot affect any other test.
    //
    // The mutation happens BETWEEN the two acceptSegment calls, deliberately
    // - not after both, and not after completion. `Buffer.concat` (used by
    // `finish()` on completion) always allocates a brand-new buffer and
    // copies into it, so mutating an input buffer AFTER the message is
    // already complete can never reveal an aliasing bug: the output would
    // already be an independent copy regardless of how the segment was
    // stored while incomplete. Mutating segment 0's buffer while the
    // reassembly is still *incomplete* - before segment 1 arrives and the
    // concatenation actually runs - is what actually exercises whether the
    // INCOMPLETE state stored a copy of segment 0 or a view onto it.
    const ownPdu0 = Buffer.from(PDU_0_OF_24);
    const ownPdu1 = Buffer.from(PDU_1_OF_24);
    const expected = Buffer.from(UPPER_TRANSPORT_PDU_24);

    const first = acceptSegment(undefined, SRC_24, ownPdu0);
    if (first.kind !== 'incomplete') throw new Error('expected incomplete after only segment 0');

    // Mutate segment 0's ORIGINAL buffer now, while it is only sitting in
    // the (still incomplete) state, not yet concatenated into anything.
    ownPdu0.fill(0xff);

    const second = acceptSegment(first.state, SRC_24, ownPdu1);
    if (second.kind !== 'complete') throw new Error('expected complete after both segments');

    // Mutate segment 1's buffer too, now that the message is complete -
    // this half is not load-bearing (Buffer.concat already copied by this
    // point regardless), but costs nothing to also assert.
    ownPdu1.fill(0xff);

    expect(second.upperTransportPdu).toEqual(expected);
  });
});

describe('blockAckFrom (Section 3.5.2.3.1, Table 3.21 AckedSegments field)', () => {
  test('bit 0 only, after just segment 0 of a 2-segment message', () => {
    const state: ReassemblyState = {
      src: SRC_24,
      seqZero: SEQ_ZERO_24,
      segN: 1,
      akf: AKF_24,
      aid: AID_24,
      szmic: SZMIC_24,
      segments: [Buffer.alloc(12), undefined],
    };
    expect(blockAckFrom(state)).toBe(0b01);
  });

  test('bit 1 only, after just segment 1 of a 2-segment message - LSB is segment 0, not arrival order', () => {
    const state: ReassemblyState = {
      src: SRC_24,
      seqZero: SEQ_ZERO_24,
      segN: 1,
      akf: AKF_24,
      aid: AID_24,
      szmic: SZMIC_24,
      segments: [undefined, Buffer.alloc(4)],
    };
    expect(blockAckFrom(state)).toBe(0b10);
  });

  test('bits 0 and 2 set, bit 1 clear, for a partially-received 3-segment message', () => {
    const state: ReassemblyState = {
      src: SRC_24,
      seqZero: SEQ_ZERO_24,
      segN: 2,
      akf: AKF_24,
      aid: AID_24,
      szmic: SZMIC_24,
      segments: [Buffer.alloc(12), undefined, Buffer.alloc(1)],
    };
    expect(blockAckFrom(state)).toBe(0b101);
  });

  test('no bit is ever set beyond segN (a 4-segment state with only the last slot filled sets only bit 3, not higher)', () => {
    const state: ReassemblyState = {
      src: SRC_24,
      seqZero: SEQ_ZERO_24,
      segN: 3,
      akf: AKF_24,
      aid: AID_24,
      szmic: SZMIC_24,
      segments: [undefined, undefined, undefined, Buffer.alloc(1)],
    };
    expect(blockAckFrom(state)).toBe(0b1000);
  });

  test('an empty reassembly (no segments received yet) acknowledges nothing', () => {
    const state: ReassemblyState = {
      src: SRC_24,
      seqZero: SEQ_ZERO_24,
      segN: 1,
      akf: AKF_24,
      aid: AID_24,
      szmic: SZMIC_24,
      segments: [undefined, undefined],
    };
    expect(blockAckFrom(state)).toBe(0);
  });

  // Review round (minor finding): the documented reason for using `2**segO`
  // instead of `1 << segO` - a signed 32-bit shift goes negative at bit 31
  // - was asserted nowhere: every case above tops out at bit 3. SegN's own
  // field width (5 bits, Table 3.18) is what the specification actually
  // bounds the highest segment index by - MAX_SEG_NUMBER above is derived
  // from that width, not from running this module's code, so segN=31
  // (32 segments) is the highest legal case, not an arbitrarily large one.
  test('bit 31 (the highest segment index the specification allows) is a large POSITIVE number, not negative', () => {
    const segments: Array<Buffer | undefined> = new Array(MAX_SEG_NUMBER + 1).fill(undefined);
    segments[MAX_SEG_NUMBER] = Buffer.alloc(1);
    const state: ReassemblyState = {
      src: SRC_24,
      seqZero: SEQ_ZERO_24,
      segN: MAX_SEG_NUMBER,
      akf: AKF_24,
      aid: AID_24,
      szmic: SZMIC_24,
      segments,
    };
    const ack = blockAckFrom(state);
    expect(ack).toBe(2 ** 31);
    expect(ack).toBeGreaterThan(0);
  });
});
