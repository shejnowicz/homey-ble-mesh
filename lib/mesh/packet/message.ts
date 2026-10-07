import { encodeNetworkPdu, decodeNetworkPdu } from './network';
import {
  encodeUnsegmentedAccess,
  decodeUnsegmentedAccess,
  segmentAccessMessage,
  decodeSegmentedAccess,
} from './lowerTransport';
import { encryptUpperTransport, decryptUpperTransport, type UpperTransportKeyKind } from './upperTransport';
import { acceptSegment, type ReassemblyState } from './reassembly';
import { decodeAccessMessage, type AccessMessage } from './access';

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
 * THIS IS lib/mesh, NOT lib/adapter (moved here on review — originally
 * placed under lib/adapter on the reasoning that it is "project-specific
 * glue, not part of the published standard's own layer boundaries"; that
 * reasoning was wrong. This module performs no I/O, imports only sibling
 * packet-layer modules, and composing the network/lower-transport/upper-
 * transport/reassembly/access layers into "one logical message, on or off
 * the wire" IS the standard's own layering, not a project convention
 * layered on top of it — `lib/mesh/config/client.ts` already does exactly
 * this kind of composition (Access-layer messages built from
 * `packet/access.ts`) one layer down. Living under `lib/adapter` left it
 * OUTSIDE `lib/__tests__/import-boundary.test.ts`'s policing, and meant a
 * future `lib/mesh`-side consumer would have had to import "backwards",
 * from the pure core into the Homey-facing adapter tree. Both are fixed by
 * this move.
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
 * the DEVICE KEY, never an application key. CITATION CORRECTED in the final
 * fix wave: this comment used to cite `Section 4.3.1 "Model behaviour"` and
 * quote "A model shall... use a device key... for the Config model". Both
 * were wrong — Section 4.3.1 is "Supplemental parameter requirements", and
 * that sentence appears nowhere in Mesh Protocol v1.1 (searched: neither
 * "A model shall" nor "for the Config model" occurs in the document). The
 * real statements are one per side of the exchange, each in that model's
 * own Description subsection: Section 4.4.1.1 "Description" (under 4.4.1
 * "Configuration Server model") — "The access layer security on the
 * Configuration Server model shall use the device key." — and Section
 * 4.4.2.1 "Description" (under 4.4.2 "Configuration Client model"), which
 * is the role THIS app plays — "The access layer security on the
 * Configuration Client model shall use the device key of the node
 * supporting the Configuration Server model."
 * `drivers/light/pairing.ts`, this module's first caller, therefore
 * only ever passes `keyKind: 'device'`; `keyKind: 'application'` is wired
 * through end to end anyway (not hardcoded to 'device') because the SAME
 * composition this module performs is exactly what a later task's device
 * layer needs for application-key-secured lighting commands — leaving that
 * branch unexercised until that task is honestly disclosed below and in the
 * report, not hidden.
 *
 * TTL, AND THE DEFECT THAT HID BEHIND ITS OLD CITATION. This module used to
 * carry one TTL constant, `DEFAULT_CONFIG_TTL = 0`, justified by a quoted
 * "message shall not be relayed" attributed to Table 3.67. BOTH HALVES WERE
 * WRONG. Table 3.67 is "CTL and TTL field format" — the two-field layout of
 * one octet of the Network nonce (Section 3.9.5.1 "Network nonce") — and it
 * says nothing about relaying at all; its TTL row's whole content is "See
 * Section 3.4.4.4". And the quoted sentence appears nowhere in Mesh
 * Protocol v1.1 (searched: "message shall not be relayed" has zero
 * occurrences). The real source is Table 3.12 "TTL field values" (Section
 * 3.4.4.4 "TTL"), whose first row reads, verbatim:
 *
 *     0 | Network PDU has not been relayed and will not be relayed.
 *
 * which is exactly why 0 was the right value for the exchange this module
 * was FIRST written for, and exactly why it was the wrong one everywhere
 * else: the device layer later reused this same encoder for lighting
 * commands that must cross the mesh, and silently inherited a default that
 * guarantees no node will ever forward them. A command for any bulb other
 * than the one currently holding the GATT connection simply never arrived.
 * A fabricated citation and the defect it was defending turned out to be
 * the same mistake.
 *
 * SO THERE ARE NOW TWO CONSTANTS, and callers choose:
 *   - `POINT_TO_POINT_TTL = 0` for the pairing and configuration session,
 *     which genuinely is point-to-point — both parties are the SAME two
 *     nodes physically linked by the one GATT connection in use (us and the
 *     node we are pairing/configuring), so there is nothing for a relay to
 *     do. Table 3.12's own note on that row says the same thing from the
 *     receiver's side: "The use of the TTL value of zero allows a node to
 *     transmit a Network PDU that it knows will not be relayed, and
 *     therefore the receiving node can determine that the sending node is a
 *     single radio link away."
 *   - `RELAYED_TTL = 0x7F` for everything that has to reach a node we are
 *     not connected to — the design's own "The bulbs relay for each other
 *     without our help."
 *
 * WHERE 0x7F COMES FROM, stated carefully because the obvious answer does
 * not exist. Mesh Protocol v1.1 defines a Default TTL STATE (Section 4.2.8
 * "Default TTL": "The Default TTL state determines the TTL value used when
 * sending messages.") and gives its permitted values in Table 4.23 "Default
 * TTL values" — "0x00, 0x02–0x7F | The Default TTL state" and "0x01,
 * 0x80–0xFF | Prohibited" — but it publishes NO numeric default for it.
 * That is a checked negative, not an assumption: the document states its
 * own convention for such a thing (Section 4.2 "State definitions": "If a
 * default value is defined for a state, it represents the value of the
 * state of the node immediately after the node is provisioned"), uses the
 * phrase "The default value of the X state is ..." for dozens of other
 * states, and uses it for the Default TTL state nowhere. So there is no
 * published number to transcribe FOR THE DEFAULT, and the value here is
 * instead transcribed from the only row of Table 3.12 that describes a
 * freshly-originated, fully relayable message:
 *
 *     127 | Network PDU has not been relayed and can be relayed.
 *
 * 127 is 0x7F: the largest value the field can hold (Section 3.4.4.4: "The
 * TTL field is a 7-bit field."), inside Table 4.23's permitted range, and
 * the maximum reach the specification offers — which for three bulbs in one
 * building is simply "as far as it ever needs to go". Being generous here
 * costs nothing: TTL bounds how far a message may travel, and this network
 * has no distant parts to protect from it.
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

/** Table 3.12 "TTL field values", row 0, verbatim: "Network PDU has not
 *  been relayed and will not be relayed." The right value ONLY for an
 *  exchange whose two parties are the two ends of one GATT link — see the
 *  module header's TTL note. */
export const POINT_TO_POINT_TTL = 0;

/** Table 3.12 "TTL field values", row 127, verbatim: "Network PDU has not
 *  been relayed and can be relayed." Everything that has to reach a node
 *  this app is not itself connected to — see the module header's TTL note
 *  for why this is transcribed from Table 3.12 rather than from a published
 *  Default TTL default, which Mesh Protocol v1.1 does not have. */
export const RELAYED_TTL = 0x7f;


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
  /**
   * REQUIRED, with no default — see the module header's TTL note. This used
   * to be optional and fall back to 0, and that fallback is exactly how
   * every lighting command and every node reset went out unrelayable: a
   * second caller adopted the encoder without ever naming a TTL, and
   * nothing made it choose. `POINT_TO_POINT_TTL` and `RELAYED_TTL` are the
   * two answers; there is no third, and no silent one.
   */
  readonly ttl: number;
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
  const ttl = input.ttl;
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
