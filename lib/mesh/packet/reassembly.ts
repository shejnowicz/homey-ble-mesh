import { decodeSegmentedAccess } from './lowerTransport';
import { assertRange, MAX_ADDRESS } from './ranges';

/**
 * Reassembly (Mesh Protocol v1.1, Section 3.5.3.2 "Reassembly"): collecting
 * the Segmented Access messages of one Upper Transport Access PDU back into
 * that complete PDU. Section 3.5.3 states the grouping key directly - "The
 * SeqZero field is included in the segmented message ... to identify the
 * Upper Transport PDU" - and Table 3.18 (Section 3.5.2.2) adds both the
 * completion test and a consistency rule: "Every Segmented Access message
 * for the same Upper Transport Access PDU shall have the same values for
 * AKF, AID, SZMIC, SeqZero, and SegN fields." A message is complete once a
 * segment has arrived for every index from 0 to the established SegN,
 * inclusive; this module ALSO enforces the "same values" half of that
 * sentence for AKF/AID/SZMIC (SeqZero/SegN were already enforced) - see the
 * review-round note below.
 *
 * This module consumes `decodeSegmentedAccess` (`./lowerTransport`) for
 * every field it needs per segment: SeqZero and SegN as the grouping key
 * and completion test, SegO as the slot, and AKF/AID/SZMIC, now cross-
 * checked against the values the first segment established and carried
 * forward in `ReassemblyState` itself. That decoder already rejects a
 * segment whose own SegO exceeds its own SegN, and a NON-LAST segment
 * (SegO != SegN) whose payload is not exactly the fixed segment size
 * (both Table 3.18's own invariants, both decidable from one segment's
 * four header octets plus its own payload length), so by the time a
 * decoded segment reaches the logic below, SegO<=SegN and the segment-size
 * rule already hold for THAT segment in isolation - what this
 * module still has to guard against is a segment that is internally
 * consistent but does not belong to the reassembly already in progress
 * (wrong source, wrong SeqZero, a SegN that disagrees with the one the
 * first segment established, or - new this round - an AKF/AID/SZMIC that
 * disagrees with it).
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
 * ONE NULLISH CONVENTION - `undefined` - ACROSS THE WHOLE MODULE. "No
 * reassembly in progress" is spelled `undefined` everywhere it can occur:
 * as `acceptSegment`'s `state` argument, and as the `'ignored'` result
 * variant's own `state`. `undefined` rather than `null` for one concrete
 * reason - the storage this header recommends just above is a `Map` keyed
 * by source address, and `Map.prototype.get` returns `undefined` for a key
 * it does not hold, which is exactly the first segment of every new
 * message: the single most frequent call this function ever receives. So
 * the recommended usage is literally
 *
 *     const inFlight = new Map<number, ReassemblyState>();
 *     const result = acceptSegment(inFlight.get(src), src, pdu);
 *
 * with no `?? null` adapter wedged in between, and this module's own output
 * feeds straight back into its own input: every result variant's `state`
 * has precisely the type `acceptSegment`'s first parameter accepts. An
 * earlier version of this module ACCEPTED `ReassemblyState | null` while
 * REPORTING `ReassemblyState | undefined`, which made both of those a type
 * error and, if forced through anyway, a raw `TypeError` while reading a
 * property of `undefined` on that commonest call of all - inverting this
 * module's own "a caller's programming error throws, ordinary foreign
 * traffic returns a result" line for a reason that had nothing to do with
 * either. `__tests__/reassembly.test.ts` now EXERCISES the `Map` pattern
 * above rather than this header merely describing it.
 *
 * `ReassemblyState` IS NOT JSON-ROUND-TRIPPABLE, AND MUST NOT CONTAIN
 * ARRAY HOLES. It must be handed back to `acceptSegment`/`blockAckFrom`
 * exactly as this module returned it. Two concrete hazards for whatever
 * adapter persists it:
 *
 * - `JSON.stringify` turns an `undefined` array ELEMENT into `null` (an
 *   array's `undefined` elements, unlike an object's `undefined`
 *   properties, are NOT dropped - they become `null`); `JSON.parse` reads
 *   that back as `null`, not `undefined`. Every check in this module that
 *   asks "is this slot still empty" does so with `!== undefined`, so a
 *   round-tripped state's genuinely-empty slots would read as "already
 *   filled" - the real missing segment can then never be accepted (the
 *   duplicate check rejects it forever) while `blockAckFrom` reports it as
 *   received. `JSON.stringify` also turns each FILLED slot's `Buffer` into
 *   a plain `{type:'Buffer', data:[...]}` object, which `Buffer.concat`
 *   cannot consume on completion either.
 * - A `segments` array built with real HOLES (e.g. `new Array(n)` without
 *   filling every index, as opposed to an index genuinely holding
 *   `undefined`) is silently mishandled by `Array.prototype.every`/`.map`,
 *   which skip holes entirely rather than treating them as present-but-
 *   empty: a state with only its LAST slot assigned and the rest left as
 *   true holes reads as "every segment received" (vacuously - the holes
 *   are never visited) and then `Buffer.concat` throws a raw `TypeError`
 *   when it reaches one of those holes by index, instead of this module
 *   returning a meaningful result. Always build `segments` via
 *   `new Array(n).fill(undefined)` or an equivalent that leaves no holes,
 *   exactly as this module's own code does.
 *
 * `blockAckFrom` lives in this file, not next to the rest of the
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
  /**
   * Application Key Flag the first-seen segment of this message carried
   * (Table 3.18); every later segment must repeat it (see the module
   * header's "same values" rule) or be ignored.
   */
  readonly akf: boolean;
  /** Application key identifier the first-seen segment carried (Table 3.18); every later segment must repeat it. */
  readonly aid: number;
  /** TransMIC-size flag the first-seen segment carried (Table 3.18); every later segment must repeat it. */
  readonly szmic: boolean;
  /** One slot per segment index, 0 to `segN` inclusive; `undefined` where that segment has not arrived yet. */
  readonly segments: ReadonlyArray<Buffer | undefined>;
}

export type ReassemblyResult =
  | { kind: 'incomplete'; state: ReassemblyState }
  | { kind: 'complete'; state: ReassemblyState; upperTransportPdu: Buffer; akf: boolean; aid: number; szmic: boolean }
  /**
   * `state` is `undefined` - never `null` - when there was no reassembly in
   * progress to report back, matching the type `acceptSegment` accepts for
   * its own `state` argument exactly (see the module header's "one nullish
   * convention" note), so an `'ignored'` result can be fed straight back in.
   */
  | { kind: 'ignored'; state: ReassemblyState | undefined; reason: string };

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

/**
 * `state`'s own AKF/AID/SZMIC are what gets reported - NOT whatever the
 * segment that happened to complete the message carried - because by this
 * point every stored segment's header fields have already been checked
 * against them (the cross-validation in `acceptSegment` below), so
 * `state`'s values are the canonical, agreed-upon ones, not merely "the
 * most recent".
 */
function finish(state: ReassemblyState): ReassemblyResult {
  if (allSegmentsReceived(state.segments)) {
    return {
      kind: 'complete',
      state,
      upperTransportPdu: concatSegmentsInOrder(state.segments),
      akf: state.akf,
      aid: state.aid,
      szmic: state.szmic,
    };
  }
  return { kind: 'incomplete', state };
}

/**
 * Feeds one received Segmented Access message (`pdu`, the on-the-wire
 * Lower Transport PDU - 4-octet header plus that segment's payload, Table
 * 3.18) into a reassembly, starting a new one when `state` is `undefined`
 * (the module header's "one nullish convention" note: `undefined`, never
 * `null`, so both `inFlight.get(src)` on a `Map` the caller keeps and this
 * function's own `'ignored'` result can be passed straight back in).
 * `src` is the sending node's address (Network PDU SRC field), supplied
 * separately because the Segmented Access message format itself carries no
 * address.
 *
 * WHEN `pdu` DOES NOT DECODE AS A SEGMENTED ACCESS MESSAGE (SEG clear, too
 * short for a non-empty segment, a NON-LAST segment that is not exactly the
 * fixed segment size, or an internally inconsistent SegO/SegN pair), THIS
 * IS ORDINARY FOREIGN TRAFFIC, NOT A CALLER MISTAKE - it is
 * `'ignored'`, exactly like every other condition this function reports
 * through `ReassemblyResult`, never thrown. `decodeSegmentedAccess`'s own
 * documentation already makes this point about its `null` return value -
 * "none of these are malformed input, they are not decodable by this
 * function" - and it carries through here: the network layer accepts
 * Access-message transport PDUs down to a single octet (see
 * `network.ts`), so a 3-octet PDU with the SEG bit set authenticates,
 * routes to this module by the lower transport format table (Table 3.15),
 * and is simply too short to be a real segment - a caller cannot filter
 * this out upstream without decoding the segment itself first, which would
 * defeat the purpose of this function. (An earlier version of this module
 * threw here; the coordinator's review round found that both wrong on
 * principle - it inverts the "caller error vs. foreign traffic" line every
 * other decoder in this codebase draws - and unreachable as a true caller
 * mistake besides.) If a reassembly is already in progress when this
 * happens, that in-progress `state` is returned completely untouched - one
 * unparseable PDU must not discard real, already-collected segments. If no
 * reassembly was in progress, there is no `ReassemblyState` to hand back,
 * hence `ReassemblyResult`'s `'ignored'` variant allows `state` to be
 * `undefined` - the same `undefined` this parameter itself accepts, so the
 * result needs no translation before being passed back in.
 *
 * The only thing this function still throws for is an out-of-range `src` -
 * that one stays a thrown `Error` (via `assertRange`) because it is a
 * value the CALLER computes/supplies itself (not decoded from `pdu`), so a
 * bad one really is this function's caller's own mistake, the same
 * distinction `upperTransport.ts` draws for its own `src`/`dst`
 * parameters.
 *
 * Checks run in this order once `state` is defined, each one independent
 * of the others so every `'ignored'` case has its own, specific `reason`:
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
 * 4. `akf`, `aid` and `szmic` must each match `state`'s own (Table 3.18's
 *    "same values" rule). This is a plain consistency check, nothing more:
 *    the coordinator's review measured the consequence of skipping it end
 *    to end (a wrong-flags-but-right-bytes reassembly either fails
 *    authentication outright or redirects key selection into a key the
 *    real MIC was never computed under, so nothing downstream ever
 *    verifies) and classified this as a correctness defect, not a security
 *    one - no secret-dependent branching, no timing concern, just three
 *    `!==` comparisons.
 * 5. The slot `state.segments[segO]` must still be empty - otherwise this
 *    is a duplicate (Table 3.24's "Repeated Segment" processing result).
 *
 * Only once all five hold is the segment stored, in a FRESH array (the
 * passed-in `state`/`state.segments` are never mutated).
 */
export function acceptSegment(state: ReassemblyState | undefined, src: number, pdu: Buffer): ReassemblyResult {
  assertRange('reassembly field "src"', src, MAX_ADDRESS);

  const decoded = decodeSegmentedAccess(pdu);
  if (decoded === null) {
    return {
      kind: 'ignored',
      state,
      reason:
        'pdu does not decode as a Segmented Access message (SEG clear, too short for a non-empty segment, a non-last segment that is not exactly the fixed segment size, or SegO>SegN)',
    };
  }
  const { akf, aid, szmic, seqZero, segO, segN, segment } = decoded;

  if (state === undefined) {
    const segments: Array<Buffer | undefined> = new Array(segN + 1).fill(undefined);
    segments[segO] = segment;
    return finish({ src, seqZero, segN, akf, aid, szmic, segments });
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
  if (akf !== state.akf) {
    return {
      kind: 'ignored',
      state,
      reason: `segment akf ${akf} does not match the established akf ${state.akf}`,
    };
  }
  if (aid !== state.aid) {
    return {
      kind: 'ignored',
      state,
      reason: `segment aid 0x${aid.toString(16)} does not match the established aid 0x${state.aid.toString(16)}`,
    };
  }
  if (szmic !== state.szmic) {
    return {
      kind: 'ignored',
      state,
      reason: `segment szmic ${szmic} does not match the established szmic ${state.szmic}`,
    };
  }
  if (state.segments[segO] !== undefined) {
    return { kind: 'ignored', state, reason: `segment ${segO} was already received (duplicate)` };
  }

  const segments = state.segments.slice();
  segments[segO] = segment;
  return finish({ src: state.src, seqZero: state.seqZero, segN: state.segN, akf: state.akf, aid: state.aid, szmic: state.szmic, segments });
}

/**
 * Builds the 32-bit AckedSegments field of a Segment Acknowledgment
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
