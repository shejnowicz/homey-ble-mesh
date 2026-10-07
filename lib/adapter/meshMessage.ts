import { encodeNetworkPdu, decodeNetworkPdu } from '../mesh/packet/network';
import {
  encodeUnsegmentedAccess,
  decodeUnsegmentedAccess,
  segmentAccessMessage,
  decodeSegmentedAccess,
} from '../mesh/packet/lowerTransport';
import { encryptUpperTransport, decryptUpperTransport, type UpperTransportKeyKind } from '../mesh/packet/upperTransport';
import { acceptSegment, type ReassemblyState } from '../mesh/packet/reassembly';
import { decodeAccessMessage, type AccessMessage } from '../mesh/packet/access';

// Table 3.18 "Segmented Access message format": SeqZero is 13 bits — the
// same bound `lowerTransport.ts` already enforces internally as
// `MAX_SEQ_ZERO` (not exported; repeated here per this project's own
// established per-module convention of each module keeping its own copy of
// a bound it needs rather than importing one — see store.ts's/
// connection.ts's own comments making the same choice).
const MAX_SEQ_ZERO_MASK = 0x1fff;

/**
 * Composes one Access-layer message across the network, lower transport and
 * upper transport layers for ONE peer — and the inverse, feeding received
 * Network PDUs through the same three layers back to a decoded Access
 * message, reassembling when the message arrived segmented. Nothing here is
 * new cryptography or new wire format: every field below is built from
 * `lib/mesh/packet/{network,lowerTransport,upperTransport,reassembly,
 * access}.ts`, which are already written, specification-anchored and
 * individually tested. What did not exist before task 6 is the GLUE that
 * drives all four together for a single logical message — composition data
 * is the first message in this whole project that does not fit in one
 * Network PDU (see `composition.ts`'s own module header: "a real node's
 * model list routinely exceeds one Access message"), so reading it is also
 * the first time anything in this codebase bridges `reassembly.ts`'s
 * per-segment output back into `upperTransport.ts`'s decryption.
 *
 * This is lib/adapter, not lib/mesh: it performs no I/O itself (every
 * function here is a pure transformation of bytes already in hand, same as
 * every module it is built from), but it is glue code specific to how this
 * project drives the stack, not part of the published standard's own layer
 * boundaries — so it lives next to connection.ts/queue.ts/store.ts rather
 * than under lib/mesh (which the import-boundary test does not police this
 * directory for, but the project's own layering keeps pure protocol/
 * provenance code in lib/mesh and project-specific composition here
 * regardless).
 *
 * SEQUENCE NUMBERS AND SeqAuth. Table 3.18 "Segmented Access message
 * format": each segment of one message is sent with its OWN Network PDU
 * SEQ, assigned consecutively from the first segment's SEQ — the value this
 * project calls SeqAuth's low 24 bits, and the same value `seqZero` (13
 * bits of it) is carried on the wire for. `encodeMeshMessage` below relies
 * on this by calling `allocateSeq()` EXACTLY ONCE PER NETWORK PDU IT SENDS,
 * never computing `firstSeq + k` by hand and skipping intermediate calls —
 * `lib/adapter/store.ts#allocateSequenceBlock`'s own contract is "hands out
 * the next sequence number" (strictly one higher than the last, with no
 * gaps), which is what makes consecutive calls produce consecutive wire
 * values at all; skipping calls would leave the store's own counter behind
 * what was actually transmitted, and the NEXT real allocation — for a
 * completely different message — would then reissue a number already seen
 * on the air (exactly the replay hazard `store.ts`'s own module header
 * exists to prevent). A caller supplies `allocateSeq` (typically
 * `store.allocateSequenceBlock`), never a raw number, so this module can
 * never be tempted to compute one instead of asking for it.
 *
 * RECEIVING A SEGMENTED REPLY NEEDS THE FIRST SEGMENT'S OWN SEQ, NOT JUST
 * SeqZero. `nonce.ts#UpperTransportNonceInput.seq` is documented as "the 24
 * lowest bits of SeqAuth when segmented" — the FULL 24-bit value, not
 * `seqZero`'s 13 bits (which, read back in isolation, are ambiguous by
 * multiples of 8192). `reassembly.ts#ReassemblyState` does not carry this
 * (it only needs `seqZero` for its own grouping key), so
 * `MeshReceiveState` below tracks it separately: the Network PDU seq of
 * whichever segment had SegO=0, captured the moment that segment arrives.
 * This project's own GATT bearer delivers notifications strictly in the
 * order they were sent (a single Write-Without-Response/Notify stream over
 * one connection, never a multi-hop relay with its own reordering) — this
 * module therefore does not attempt to handle SegO=0 arriving anywhere but
 * first; a reassembly whose first-seen segment is not SegO=0 is reported as
 * `'ignored'` rather than guessed at (see `acceptIncomingPdu` below).
 *
 * KEY KIND. Config messages (Composition Data Get/Status, AppKey Add/
 * Status, Model App Bind/Status, Node Reset/Status) are ALWAYS secured with
 * the DEVICE KEY, never an application key — Section 4.3.1 "Model
 * behaviour": "A model shall... use a device key... for the Config model".
 * `drivers/light/pairing.ts`, this module's only caller so far, therefore
 * only ever passes `keyKind: 'device'`; `keyKind: 'application'` is wired
 * through end to end anyway (not hardcoded to 'device') because the SAME
 * composition this module performs is exactly what a later task's device
 * layer needs for application-key-secured lighting commands — leaving that
 * branch unexercised until that task is honestly disclosed below and in the
 * report, not hidden.
 *
 * TTL. `DEFAULT_CONFIG_TTL = 0` ("message shall not be relayed", Table
 * 3.67) — both parties in every exchange this module drives are the SAME
 * two nodes physically linked by the one GATT connection in use (us and the
 * node we are pairing/configuring), so there is nothing for a relay to do
 * and no reason to ask for one.
 *
 * NULLISH CONVENTION: `null` for "no Service Data of interest" is
 * connection.ts's own convention (`findServiceData`); this module instead
 * follows `reassembly.ts`'s OWN convention for its own state, since it is
 * built directly on top of `ReassemblyState` — `undefined` for "no
 * reassembly (or SeqAuth tracking) in progress yet", both as
 * `acceptIncomingPdu`'s own `state` parameter and as every result variant's
 * `state` field, so a caller's own `Map<number, MeshReceiveState>` (keyed by
 * source address, exactly as `reassembly.ts`'s own header recommends) reads
 * and writes through this function with no translation in between.
 */

/** Table 3.67: TTL=0 means "this message shall not be relayed" — see the
 *  module header's TTL note for why that is always the right value here. */
export const DEFAULT_CONFIG_TTL = 0;

export interface MeshMessageKey {
  /** 128-bit application key or device key. */
  readonly key: Buffer;
  readonly keyKind: UpperTransportKeyKind;
  /** Application key identifier (Table 3.17/3.18), required and meaningful
   *  only when `keyKind` is `'application'`. */
  readonly aid?: number;
}

export interface EncodeMeshMessageInput extends MeshMessageKey {
  /** The complete Access message (Opcode || Parameters, already built by
   *  `packet/access.ts`/a model/`config/client.ts`) to deliver. */
  readonly accessPayload: Buffer;
  /** 16-bit source address (this node's own unicast address). */
  readonly src: number;
  /** 16-bit destination address (the peer's unicast address). */
  readonly dst: number;
  readonly netKey: Buffer;
  readonly ivIndex: number;
  readonly ttl?: number; // default DEFAULT_CONFIG_TTL
  /** Hands out the next sequence number — see the module header's SEQUENCE
   *  NUMBERS note for why this must be called exactly once per Network PDU
   *  this function sends, never computed by hand. */
  readonly allocateSeq: () => number;
}

/**
 * Builds one or more complete, ready-to-write Network PDUs for
 * `accessPayload`, segmenting at the lower transport layer when the
 * encrypted payload does not fit an Unsegmented Access message (Table
 * 3.17's 5-15 octet bound) — see the module header. Always uses the
 * 32-bit TransMIC (`szmic: false`): every message this project's config
 * exchange sends is comfortably under the 376-380 octet ceiling the 64-bit
 * variant exists for (Section 3.6.2.1), so there is no reason to ask for
 * the longer one.
 */
export function encodeMeshMessage(input: EncodeMeshMessageInput): Buffer[] {
  const ttl = input.ttl ?? DEFAULT_CONFIG_TTL;
  const akf = input.keyKind === 'application';
  const aid = akf ? (input.aid ?? 0) : 0;

  // SeqAuth's low 24 bits = the FIRST segment's own Network PDU seq — see
  // the module header. Allocated before encrypting, since the nonce needs
  // it regardless of whether the result ends up segmented.
  const firstSeq = input.allocateSeq();

  const upperTransportPdu = encryptUpperTransport({
    accessPayload: input.accessPayload,
    key: input.key,
    keyKind: input.keyKind,
    seq: firstSeq,
    src: input.src,
    dst: input.dst,
    ivIndex: input.ivIndex,
    szmic: false,
  });

  const buildNetworkPdu = (seq: number, transportPdu: Buffer): Buffer =>
    encodeNetworkPdu({
      networkKey: input.netKey,
      ivIndex: input.ivIndex,
      ctl: false,
      ttl,
      seq,
      src: input.src,
      dst: input.dst,
      transportPdu,
    });

  // Table 3.17 "Unsegmented Access message format": the Upper Transport
  // Access PDU it carries is 40-120 bits, i.e. 5-15 octets
  // (`lowerTransport.ts`'s own, unexported
  // MIN/MAX_UNSEGMENTED_UPPER_TRANSPORT_ACCESS_PDU_LENGTH — repeated here
  // per this project's established per-module convention rather than
  // exported and imported, same as `store.ts`'s own address-bound comment).
  const MIN_UNSEGMENTED = 5;
  const MAX_UNSEGMENTED = 15;
  if (upperTransportPdu.length >= MIN_UNSEGMENTED && upperTransportPdu.length <= MAX_UNSEGMENTED) {
    const transportPdu = encodeUnsegmentedAccess({ akf, aid, upperTransportPdu });
    return [buildNetworkPdu(firstSeq, transportPdu)];
  }

  const segments = segmentAccessMessage({
    akf,
    aid,
    szmic: false,
    seqZero: firstSeq & MAX_SEQ_ZERO_MASK,
    upperTransportPdu,
  });
  const pdus: Buffer[] = [];
  segments.forEach((segmentPdu, segO) => {
    // Segment 0 reuses firstSeq itself (already allocated above); every
    // later segment allocates its own next number, which — per the module
    // header's SEQUENCE NUMBERS note — is guaranteed to equal firstSeq+segO
    // precisely because nothing else allocates in between.
    const seq = segO === 0 ? firstSeq : input.allocateSeq();
    if (seq !== firstSeq + segO) {
      throw new Error(
        `meshMessage.encodeMeshMessage: allocateSeq() returned ${seq} for segment ${segO}, expected ${firstSeq + segO} (SeqAuth contiguity broken — something else allocated a sequence number between these calls)`,
      );
    }
    pdus.push(buildNetworkPdu(seq, segmentPdu));
  });
  return pdus;
}

/** One in-flight reassembly's extra bookkeeping this module needs beyond
 *  `reassembly.ts`'s own `ReassemblyState` — see the module header's
 *  RECEIVING A SEGMENTED REPLY note. */
export interface MeshReceiveState {
  readonly reassembly: ReassemblyState;
  /** The Network PDU seq of this reassembly's SegO=0 segment. */
  readonly firstSeq: number;
}

export interface MeshReceiveContext extends MeshMessageKey {
  readonly netKey: Buffer;
  readonly ivIndex: number;
  /** Only a Network PDU from this source address is ever accepted — a
   *  pairing/config session only ever talks to the one node it is
   *  currently connected to. */
  readonly expectedSrc: number;
}

export type MeshReceiveResult =
  | { readonly kind: 'ignored'; readonly state: MeshReceiveState | undefined; readonly reason: string }
  | { readonly kind: 'incomplete'; readonly state: MeshReceiveState }
  | { readonly kind: 'complete'; readonly state: undefined; readonly message: AccessMessage };

/**
 * Decrypts and decodes one reassembled (or unsegmented) Upper Transport
 * Access PDU with `context.key`/`keyKind` — note `context.aid` is NOT
 * passed to `decryptUpperTransport` below: AID is a LOWER transport field
 * (already stripped off by `decodeUnsegmentedAccess`/`decodeSegmentedAccess`/
 * `acceptSegment` before this function ever runs) that identifies WHICH
 * application key a message claims to use, not an input the upper
 * transport layer itself takes — `upperTransport.ts#UpperTransportInput`
 * has no such field. This project has exactly one application key (the
 * design's "We generate one network key and one application key"), so
 * there is nothing for a caller to disambiguate yet; `MeshMessageKey.aid`
 * exists on this module's own interface only so a future multi-AppKey
 * caller has somewhere to put the value it would need to check BEFORE
 * calling this — not because this function uses it.
 */
function decryptAndDecode(
  context: MeshReceiveContext,
  seq: number,
  src: number,
  dst: number,
  upperTransportPdu: Buffer,
): AccessMessage | null {
  const accessPayload = decryptUpperTransport({
    key: context.key,
    keyKind: context.keyKind,
    seq,
    src,
    dst,
    ivIndex: context.ivIndex,
    szmic: false,
    upperTransportPdu,
  });
  if (accessPayload === null) return null;
  return decodeAccessMessage(accessPayload);
}

/**
 * Feeds one received Network PDU into a reassembly in progress (or starts a
 * new one), mirroring `reassembly.ts#acceptSegment`'s own shape and nullish
 * convention exactly — see the module header. `state` is `undefined` when
 * nothing is in progress for this peer yet (the first call for a fresh
 * exchange, or right after a previous `'complete'`/terminal `'ignored'`
 * result).
 */
export function acceptIncomingPdu(state: MeshReceiveState | undefined, context: MeshReceiveContext, pdu: Buffer): MeshReceiveResult {
  const decodedNet = decodeNetworkPdu({ networkKey: context.netKey, ivIndex: context.ivIndex, pdu });
  if (decodedNet === null) {
    return { kind: 'ignored', state, reason: 'network PDU did not authenticate under our NetKey/IV Index (foreign traffic)' };
  }
  if (decodedNet.ctl) {
    return { kind: 'ignored', state, reason: 'Transport Control message (CTL=1) — not an Access message this module decodes' };
  }
  if (decodedNet.src !== context.expectedSrc) {
    return {
      kind: 'ignored',
      state,
      reason: `unexpected source 0x${decodedNet.src.toString(16)}, expected 0x${context.expectedSrc.toString(16)}`,
    };
  }

  const unsegmented = decodeUnsegmentedAccess(decodedNet.transportPdu);
  if (unsegmented !== null) {
    const message = decryptAndDecode(context, decodedNet.seq, decodedNet.src, decodedNet.dst, unsegmented.upperTransportPdu);
    if (message === null) {
      return { kind: 'ignored', state, reason: 'Upper Transport MIC did not authenticate (wrong key, or foreign traffic)' };
    }
    return { kind: 'complete', state: undefined, message };
  }

  const segmented = decodeSegmentedAccess(decodedNet.transportPdu);
  if (segmented === null) {
    return {
      kind: 'ignored',
      state,
      reason: 'transport PDU is neither a valid Unsegmented nor Segmented Access message',
    };
  }
  if (state === undefined && segmented.segO !== 0) {
    // See the module header's RECEIVING A SEGMENTED REPLY note: this
    // project's own GATT bearer delivers notifications in order, so a
    // fresh reassembly's first-seen segment is always SegO=0 in practice.
    // A segment arriving before it (not reachable through this project's
    // own transport, but foreign/garbled traffic could still produce one)
    // cannot be assigned a SeqAuth, so it is ignored rather than guessed.
    return {
      kind: 'ignored',
      state: undefined,
      reason: `first-seen segment for a new reassembly has SegO=${segmented.segO}, not 0 — cannot determine SeqAuth`,
    };
  }
  const firstSeq = segmented.segO === 0 ? decodedNet.seq : (state as MeshReceiveState).firstSeq;

  const accepted = acceptSegment(state?.reassembly, decodedNet.src, decodedNet.transportPdu);
  if (accepted.kind === 'ignored') {
    return {
      kind: 'ignored',
      state: accepted.state === undefined ? undefined : { reassembly: accepted.state, firstSeq },
      reason: accepted.reason,
    };
  }
  if (accepted.kind === 'incomplete') {
    return { kind: 'incomplete', state: { reassembly: accepted.state, firstSeq } };
  }

  const message = decryptAndDecode(context, firstSeq, decodedNet.src, decodedNet.dst, accepted.upperTransportPdu);
  if (message === null) {
    return { kind: 'ignored', state: undefined, reason: 'Upper Transport MIC did not authenticate (wrong key, or foreign traffic)' };
  }
  return { kind: 'complete', state: undefined, message };
}
