import { decodeSegmentedAccess } from './lowerTransport';
import { assertRange, MAX_ADDRESS } from './ranges';

/**
 * Reassembly (Mesh Protocol v1.1, Section 3.5.3.2 "Reassembly"): collecting
 * the Segmented Access messages of one Upper Transport Access PDU back into
 * that complete PDU. Section 3.5.3 states the grouping key directly - "The
 * SeqZero field is included in the segmented message ... to identify the
 * Upper Transport PDU" - and Table 3.18 (Section 3.5.2.2) adds the
 * completion test: "Every Segmented Access message for the same Upper
 * Transport Access PDU shall have the same values for ... SeqZero ... and
 * SegN fields", so a message is complete once a segment has arrived for
 * every index from 0 to the established SegN, inclusive.
 *
 * This module consumes `decodeSegmentedAccess` (`./lowerTransport`) for
 * every field it needs per segment: SeqZero and SegN as the grouping key
 * and completion test, SegO as the slot, and AKF/AID/SZMIC to hand back
 * unchanged on completion. That decoder already rejects a segment whose own
 * SegO exceeds its own SegN (Table 3.18's own invariant), so by the time a
 * decoded segment reaches the logic below, SegO<=SegN already holds for
 * THAT segment in isolation - what this module still has to guard against
 * is a segment that is internally consistent but does not belong to the
 * reassembly already in progress (wrong source, wrong SeqZero, or a SegN
 * that disagrees with the one the first segment established).
 *
 * STATELESS BY DESIGN. This module keeps nothing of its own: no map keyed
 * by source address, no timer, no clock, no `Date.now()`. `ReassemblyState`
 * is a plain, immutable value - the CALLER owns it, stores it however it
 * likes (e.g. a `Map` keyed by source address), and hands it back on the
 * next segment for the same in-flight message. Section 3.5.3.4 "Reassembly
 * behavior" defines a SAR Discard timer (abandon a reassembly that has
 * stalled) and a SAR Acknowledgment timer (when to send a Segment
 * Acknowledgment message); both need a clock, which is exactly why they are
 * NOT this module's job - that belongs to the adapter layer, not the mesh
 * core (see `lib/__tests__/import-boundary.test.ts`: this module performs
 * no I/O and must stay that way).
 *
 * WHAT IS DELIBERATELY NOT VALIDATED HERE: AKF/AID/SZMIC are NOT part of
 * `ReassemblyState` and are NOT cross-checked between segments of the same
 * message, even though Table 3.18 requires every segment to repeat the same
 * values. On `'complete'`, this module reports whatever the segment that
 * happened to complete the message carries for those three fields, trusting
 * the specification's own invariant rather than re-deriving it - the same
 * trust boundary `upperTransport.ts`'s own `szmic` parameter documents for
 * ASZMIC, one layer up.
 *
 * `blockAckFrom` lives in this file, not next to the rest of the (future)
 * Segment Acknowledgment message code in `lowerTransport.ts`, purely to
 * avoid an import cycle: it reads `ReassemblyState`, so putting it there
 * would make `lowerTransport.ts` import this module while this module
 * already imports `lowerTransport.ts` for `decodeSegmentedAccess`.
 */

export interface ReassemblyState {
  /**
   * The originating node's source address (Network PDU SRC field, Table
   * 3.10) - NOT a field of the Segmented Access message itself, so it is
   * taken from the caller on every call rather than decoded from `pdu`.
   * SeqZero alone (13 bits, Table 3.18) is not unique across the whole
   * network - two different source nodes can use the same value for
   * unrelated messages at the same time - so `src` is the other half of
   * the grouping key alongside `seqZero`.
   */
  readonly src: number;
  /** Table 3.18's SeqZero field, common to every segment of this message - the grouping key alongside `src`. */
  readonly seqZero: number;
  /** The last-segment index (SegN) the first-seen segment of this message established; `segments` always holds exactly `segN + 1` slots. */
  readonly segN: number;
  /** One slot per segment index, 0 to `segN` inclusive; `undefined` where that segment has not arrived yet. */
  readonly segments: ReadonlyArray<Buffer | undefined>;
}

export type ReassemblyResult =
  | { kind: 'incomplete'; state: ReassemblyState }
  | { kind: 'complete'; upperTransportPdu: Buffer; akf: boolean; aid: number; szmic: boolean }
  | { kind: 'ignored'; state: ReassemblyState; reason: string };

function allSegmentsReceived(segments: ReadonlyArray<Buffer | undefined>): boolean {
  return segments.every((segment) => segment !== undefined);
}

/**
 * Concatenates `segments` in INDEX order (slot 0, then 1, ... then segN) -
 * the order the complete Upper Transport Access PDU was originally split in
 * (Table 3.18: "Segment m is octet 12*m to 12*m+11"), which is NOT
 * necessarily the order the segments arrived in over the air. Only called
 * once `allSegmentsReceived` has confirmed every slot is filled; the cast
 * below is therefore safe even though `noUncheckedIndexedAccess` cannot see
 * that from the array's own element type.
 */
function concatSegmentsInOrder(segments: ReadonlyArray<Buffer | undefined>): Buffer {
  return Buffer.concat(segments.map((segment) => segment as Buffer));
}

function finish(state: ReassemblyState, akf: boolean, aid: number, szmic: boolean): ReassemblyResult {
  if (allSegmentsReceived(state.segments)) {
    return { kind: 'complete', upperTransportPdu: concatSegmentsInOrder(state.segments), akf, aid, szmic };
  }
  return { kind: 'incomplete', state };
}

/**
 * Feeds one received Segmented Access message (`pdu`, the on-the-wire
 * Lower Transport PDU - 4-octet header plus that segment's payload, Table
 * 3.18) into a reassembly, starting a new one when `state` is `null`.
 * `src` is the sending node's address (Network PDU SRC field), supplied
 * separately because the Segmented Access message format itself carries no
 * address.
 *
 * `pdu` must already be known to be a Segmented Access message - the same
 * "caller already knows from CTL/SEG which decoder to call" convention
 * `lowerTransport.ts`'s own module header documents. If `decodeSegmentedAccess`
 * cannot decode it (SEG clear, too short, or an internally inconsistent
 * SegO/SegN pair), this is a caller mistake, not a protocol condition this
 * function reports through `ReassemblyResult` - it throws instead, exactly
 * as `assertRange` below does for an out-of-range `src`.
 *
 * Checks run in this order once `state` is non-null, each one independent
 * of the others so every "ignored" case has its own, specific `reason`:
 *
 * 1. `src` must match `state.src` - otherwise this segment belongs to a
 *    different sender entirely.
 * 2. `seqZero` must match `state.seqZero` - otherwise it belongs to a
 *    different Upper Transport PDU from the SAME sender.
 * 3. `segN` must match `state.segN`. This single check also doubles as the
 *    array-bounds guard: because `decodeSegmentedAccess` already guarantees
 *    `segO <= segN` for THIS segment, a `segN` that matches `state.segN`
 *    can never carry a `segO` beyond `state.segments.length - 1` either -
 *    so when `segN` disagrees by being LARGER than established, `segO` can
 *    be at or past the current array's length, and rejecting here is what
 *    stops a plain array index assignment from silently growing that array
 *    instead of being ignored.
 * 4. The slot `state.segments[segO]` must still be empty - otherwise this
 *    is a duplicate (Table 3.24's "Repeated Segment" processing result).
 *
 * Only once all four hold is the segment stored, in a FRESH array (the
 * passed-in `state`/`state.segments` are never mutated).
 */
export function acceptSegment(state: ReassemblyState | null, src: number, pdu: Buffer): ReassemblyResult {
  assertRange('reassembly field "src"', src, MAX_ADDRESS);

  const decoded = decodeSegmentedAccess(pdu);
  if (decoded === null) {
    throw new Error(
      'reassembly: pdu does not decode as a Segmented Access message (SEG clear, too short, or SegO>SegN) - ' +
        'the caller must only route already-identified segmented PDUs here',
    );
  }
  const { akf, aid, szmic, seqZero, segO, segN, segment } = decoded;

  if (state === null) {
    const segments: Array<Buffer | undefined> = new Array(segN + 1).fill(undefined);
    segments[segO] = segment;
    return finish({ src, seqZero, segN, segments }, akf, aid, szmic);
  }

  if (src !== state.src) {
    return {
      kind: 'ignored',
      state,
      reason: `segment source 0x${src.toString(16)} does not match the in-progress reassembly's source 0x${state.src.toString(16)}`,
    };
  }
  if (seqZero !== state.seqZero) {
    return {
      kind: 'ignored',
      state,
      reason: `segment seqZero 0x${seqZero.toString(16)} does not match the in-progress reassembly's seqZero 0x${state.seqZero.toString(16)}`,
    };
  }
  if (segN !== state.segN) {
    const reason =
      segO >= state.segments.length
        ? `segment index ${segO} is beyond the established last-segment index ${state.segN}`
        : `segment segN ${segN} does not match the established last-segment index ${state.segN}`;
    return { kind: 'ignored', state, reason };
  }
  if (state.segments[segO] !== undefined) {
    return { kind: 'ignored', state, reason: `segment ${segO} was already received (duplicate)` };
  }

  const segments = state.segments.slice();
  segments[segO] = segment;
  return finish({ src: state.src, seqZero: state.seqZero, segN: state.segN, segments }, akf, aid, szmic);
}

/**
 * Builds the 32-bit AckedSegments field of a (future) Segment Acknowledgment
 * message (Section 3.5.2.3.1, Table 3.21) from the segments received so
 * far: "The least significant bit, bit 0, shall represent segment 0; and
 * the most significant bit, bit 31, shall represent segment 31. If bit n is
 * set to 1, then segment n is being acknowledged." Built with `2 ** segO`
 * additions rather than `1 << segO`, because `<<` operates on 32-bit SIGNED
 * integers in JavaScript - `1 << 31` is negative - while `state.segments`
 * never holds more than 32 slots (SegN is a 5-bit field, Table 3.18) and
 * the resulting sum never exceeds `2**32 - 1`, comfortably inside a JS
 * number's exact-integer range. `state.segments.length` is always `segN+1`,
 * so bits for indices beyond the established SegN are never touched -
 * satisfying Table 3.21's own "Any bits for segments larger than the SegN
 * field value ... shall be set to 0" without a separate mask.
 */
export function blockAckFrom(state: ReassemblyState): number {
  let ack = 0;
  for (let segO = 0; segO < state.segments.length; segO++) {
    if (state.segments[segO] !== undefined) {
      ack += 2 ** segO;
    }
  }
  return ack;
}
