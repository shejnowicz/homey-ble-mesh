/**
 * The settings-backed network store (docs/superpowers/specs/2026-10-06-ble-mesh-
 * provisioner-design.md, "Persistence, sequence numbers and removal"): the one
 * place holding the mesh network's keys, our own and the next free unicast
 * address, and the roster of provisioned nodes — plus the message
 * sequence-number allocator, which exists purely so a sudden power loss can
 * never make the app reissue a sequence number a node could already have
 * seen (a node rejects a reused number as a replay).
 *
 * This is lib/adapter, not lib/mesh: it is the one piece of this design that
 * performs I/O (through the injected `SettingsPort` below), so it may never
 * be imported from lib/mesh — see lib/__tests__/import-boundary.test.ts. It
 * takes a settings port rather than `homey` itself so it is fully testable
 * without a hub (see lib/adapter/__tests__/store.test.ts, which only ever
 * constructs a fake one).
 *
 * STATE SHAPE. `netKey`/`appKey`/`ourUnicastAddress` and their indexes start
 * out `null`: this module generates no randomness and knows nothing about
 * when a network is first created (see the plan's "What already exists" —
 * randomness and the wall clock are deliberately kept out of lib/mesh and
 * lib/adapter and enter only in app.ts). A fresh install therefore has a
 * perfectly well-defined state — `EMPTY_NETWORK_STATE` below — in which
 * those fields are `null` and the first address offered by
 * `allocateUnicastAddress()` is `MIN_UNICAST_ADDRESS`. Every nullable field
 * in `NetworkState` follows the SAME convention this module receives from
 * its own `SettingsPort` (`get` returns `null` for an absent key, never
 * `undefined` — matching Homey's real settings manager): absent is `null`
 * everywhere in this module, on the way in and on the way out, so nothing
 * downstream has to recognise two different spellings of "nothing here."
 *
 * PERSISTENCE SHAPE. Homey settings values are whatever survives a JSON
 * round-trip. Keys are `Buffer`s in every other module of this project, so
 * this is the one place that turns them into hex strings for storage and
 * back into fresh `Buffer`s on the way out — never the caller's own buffer,
 * and never a stored reference reused across reads, which is what keeps
 * this module honest about "never retain a view into a buffer it does not
 * own": every `Buffer` this module returns was allocated by this module,
 * from the string it just read, on this call.
 *
 * TWO SETTINGS KEYS, DELIBERATELY. The network state (keys, addresses,
 * nodes) and the sequence-number block ceiling are persisted under
 * different keys (`network`/`sequence`) so that handing out sequence
 * numbers — the hot path, happening on every outgoing message in later
 * tasks — never has to re-serialise the (potentially large, growing) node
 * roster just to persist one integer.
 */

import type { CompositionData } from '../mesh/config/composition';
import type { ModelProbeVerdict, NodeProbeResult, ProbedModel, TemperatureRange } from '../models/capabilities';
import { MAX_SEQ } from '../mesh/packet/ranges';

/**
 * The minimal slice of Homey's own settings manager (`this.homey.settings` in
 * a real app — `ManagerSettings#get`/`#set` are synchronous in the Homey Apps
 * SDK, which is why none of this module is async) this store needs, injected
 * so it is testable without a hub. `get` returns `null` for a key that was
 * never set, matching Homey's own settings manager — never `undefined`.
 */
export interface SettingsPort {
  get(key: string): unknown;
  set(key: string, value: unknown): void;
}

/** Per-node record this store keeps: its address, its device key, and the
 *  composition summary read from it during pairing. `composition` reuses
 *  `lib/mesh/config/composition.ts`'s own `CompositionData` shape rather than
 *  inventing a parallel one — see the plan's "Type consistency" note: this
 *  store is the only module allowed to invent names, and only for things
 *  (like this type's own fields, or the sequence block) that have no
 *  existing name in `lib/mesh` to keep. */
export interface NodeEntry {
  readonly address: number;
  readonly deviceKey: Buffer;
  readonly composition: CompositionData;
  /**
   * What the node was MEASURED to do at pairing time
   * (`drivers/light/modelProbe.ts`), stored ALONGSIDE the composition
   * rather than instead of it - the declaration still says which models
   * exist to probe, and keeping both means a later version of this app can
   * re-derive capabilities differently without re-pairing anything.
   *
   * OPTIONAL, AND THAT IS THE MIGRATION. Every node paired before the probe
   * existed has no entry here, and must keep working exactly as it did:
   * `undefined` means "never measured", which
   * `capabilities.ts#mapCompositionToCapabilities` treats as "believe the
   * declaration" - the pre-probe behaviour, byte for byte. There is no
   * version bump and no rewrite pass for the same reason: an absent field
   * that already means the right thing is a migration that cannot fail
   * halfway.
   */
  readonly probe?: NodeProbeResult;
}

/** Everything the design's "Persistence, sequence numbers and removal"
 *  section lists as living in app settings, except the sequence-number
 *  block ceiling (see the module header's "TWO SETTINGS KEYS" note). */
export interface NetworkState {
  readonly netKey: Buffer | null;
  readonly netKeyIndex: number | null;
  readonly appKey: Buffer | null;
  readonly appKeyIndex: number | null;
  /**
   * NOTHING IN THIS APP EVER CHANGES THIS AFTER PAIRING WRITES IT, and that
   * is a design clause deliberately not implemented rather than an
   * oversight — stated here as well as at the one place that could have
   * implemented it, because this is where a reader would otherwise assume
   * it was being kept up to date. The design says "The IV index is followed
   * from the secure network beacons the nodes emit; we never start an IV
   * update ourselves." The second half holds by construction. The first
   * half does not: a Secure Network beacon arrives as a Proxy PDU of
   * MessageType 0x01 and nothing decodes one. See
   * `lib/adapter/connection.ts`'s own "IV INDEX" note for why that is safe
   * for a network we own outright, and for the single condition that would
   * make it unsafe.
   */
  readonly ivIndex: number;
  readonly ourUnicastAddress: number | null;
  readonly nextUnicastAddress: number;
  readonly nodes: ReadonlyArray<NodeEntry>;
}

// Table 3.5 "16-bit address allocations": a Unicast Address is 0x0001-0x7fff;
// 0x0000 is Unassigned and 0x8000-0xffff is Virtual/Group — the same bound
// already transcribed and cited in `lib/mesh/provisioning/machine.ts` and
// `lib/mesh/config/client.ts`. Repeated here, not imported: both of those
// modules keep their own copy rather than sharing one, and this module
// follows that same established convention.
const MIN_UNICAST_ADDRESS = 0x0001;
const MAX_UNICAST_ADDRESS = 0x7fff;

// Section 4.3.1.1 "Global key indexes are 12 bits long" — the same bound
// already transcribed in `lib/mesh/provisioning/machine.ts` and
// `lib/mesh/config/client.ts` as `MAX_KEY_INDEX`; repeated here per the same
// per-module convention as the unicast address bounds above.
const MAX_KEY_INDEX = 0x0fff;

// AES-128 key material is 16 octets throughout this specification: Table
// 5.47 for the Network Key and Table 4.119 for the AppKey (both already
// transcribed as `NET_KEY_LENGTH`/`APP_KEY_LENGTH` in
// `lib/mesh/provisioning/machine.ts`/`lib/mesh/config/client.ts`), and the
// device key is the untruncated output of `k1` (Section 3.9.6.1), an
// AES-CMAC whose output is one AES block — 16 octets — same as the keys
// above. One shared length for all three, since all three are 16-octet
// AES-128 keys.
const KEY_LENGTH = 16;

/** The network's starting IV Index. The design follows this from the mesh's
 *  own secure network beacons once a network exists and never starts an IV
 *  update itself; 0 is simply where a brand new network — one this app has
 *  not yet created — starts, so it is the empty state's default rather than
 *  a value this module ever chooses on its own. */
const INITIAL_IV_INDEX = 0;

/**
 * Builds a fresh, independent empty state object. Used everywhere this
 * module needs to HAND OUT an empty state (`getState`'s absent/corrupt
 * fallbacks): returning the shared `EMPTY_NETWORK_STATE` singleton itself
 * would let a caller that mutates what it got back (e.g. pushing onto
 * `.nodes`, which `readonly` only stops at compile time, not at runtime)
 * poison every future call for the lifetime of the process. `EMPTY_NETWORK_STATE`
 * remains exported, frozen, as a convenient literal for callers/tests to
 * compare against or spread from — it is just never itself returned by any
 * method below.
 */
function freshEmptyState(): NetworkState {
  return {
    netKey: null,
    netKeyIndex: null,
    appKey: null,
    appKeyIndex: null,
    ivIndex: INITIAL_IV_INDEX,
    ourUnicastAddress: null,
    nextUnicastAddress: MIN_UNICAST_ADDRESS,
    nodes: [],
  };
}

export const EMPTY_NETWORK_STATE: NetworkState = Object.freeze(freshEmptyState());

const SETTINGS_KEY_NETWORK = 'network';
const SETTINGS_KEY_SEQUENCE = 'sequence';

/**
 * Sequence numbers are allocated in blocks rather than persisted one at a
 * time (design: "The app takes a block, counts within it in memory, and
 * persists the next block before the current one runs out"). This size is
 * an engineering choice, not a specification value: large enough that a
 * settings write happens only once every `SEQ_BLOCK_SIZE` messages rather
 * than on every one, small enough that an ordinary restart — which this
 * module cannot tell apart from a crash, and does not try to — wastes only
 * a small, bounded slice of the 24-bit sequence space (`MAX_SEQ`,
 * Table 3.10/Table 3.66) rather than a meaningful fraction of it.
 */
export const SEQ_BLOCK_SIZE = 1000;

function assertRange(name: string, value: number, min: number, max: number): void {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`network state field "${name}" must be an integer in [${min}, ${max}], got ${value}`);
  }
}

function assertKeyLength(name: string, value: Buffer): void {
  if (value.length !== KEY_LENGTH) {
    throw new Error(`network state field "${name}" must be ${KEY_LENGTH} bytes, got ${value.length}`);
  }
}

/** Plain-JSON shape `NetworkState` round-trips through on the way to
 *  `SettingsPort#set` — hex strings for key material, nothing else. */
interface PersistedNode {
  address: number;
  deviceKey: string;
  composition: CompositionData;
  /** Absent for a node paired before the probe existed - see `NodeEntry.probe`. */
  probe?: PersistedProbe;
}

/** `NodeProbeResult`'s own JSON shape. Plain data already (no Buffers), so this is a structural copy rather than a conversion - but it is still re-validated on the way back in, like every other field here, because a hand-edited settings value never went through `encodeNetworkState`. */
interface PersistedProbe {
  models: Partial<Record<ProbedModel, ModelProbeVerdict>>;
  temperatureRange: TemperatureRange | null;
}

interface PersistedNetworkState {
  netKey: string | null;
  netKeyIndex: number | null;
  appKey: string | null;
  appKeyIndex: number | null;
  ivIndex: number;
  ourUnicastAddress: number | null;
  nextUnicastAddress: number;
  nodes: PersistedNode[];
}

interface PersistedSequenceState {
  /** Exclusive ceiling: every sequence number below this has possibly
   *  already been issued (by this run or an earlier one), so a reload must
   *  never hand out anything less than this value. */
  reservedUpTo: number;
}

/** Every verdict `ModelProbeVerdict` allows, as a runtime set - a stored
 *  value that is a string but not one of these is corrupt, and must fail
 *  the same way a wrong JS type does (the type system has nothing to say
 *  about a value that came out of Homey's settings). */
const PROBE_VERDICTS: ReadonlySet<string> = new Set(['supported', 'unsupported', 'unknown']);

/** Every `ProbedModel` key, likewise. An UNRECOGNISED key is dropped rather
 *  than rejected on the way IN (a settings value written by a newer version
 *  of this app, read back by an older one, must not brick the store) but a
 *  recognised key with a nonsense verdict IS rejected, because that is
 *  corruption rather than a version difference. */
const PROBED_MODELS: ReadonlyArray<ProbedModel> = [
  'genericOnOff',
  'lightLightness',
  'lightCtl',
  'lightCtlTemperature',
  'lightHsl',
];

function encodeProbe(field: string, probe: NodeProbeResult): PersistedProbe {
  const models: Partial<Record<ProbedModel, ModelProbeVerdict>> = {};
  for (const model of PROBED_MODELS) {
    const verdict = probe.models[model];
    if (verdict === undefined) continue;
    if (!PROBE_VERDICTS.has(verdict)) {
      throw new Error(`network state field "${field}.models.${model}" is not a valid probe verdict, got ${String(verdict)}`);
    }
    models[model] = verdict;
  }
  const range = probe.temperatureRange;
  if (range !== null) {
    assertRange(`${field}.temperatureRange.minKelvin`, range.minKelvin, 0, 0xffff);
    assertRange(`${field}.temperatureRange.maxKelvin`, range.maxKelvin, 0, 0xffff);
  }
  return { models, temperatureRange: range === null ? null : { minKelvin: range.minKelvin, maxKelvin: range.maxKelvin } };
}

/** The inverse. Throws on anything that is not our own shape, like every
 *  other decoder here - `readStateForWrite`'s caller turns that into "the
 *  empty state" or "refuse to write", never a crash. */
function decodeProbe(field: string, value: unknown): NodeProbeResult {
  if (typeof value !== 'object' || value === null) {
    throw new Error(`stored network state field "${field}" is not an object`);
  }
  const raw = value as Record<string, unknown>;
  if (typeof raw.models !== 'object' || raw.models === null) {
    throw new Error(`stored network state field "${field}.models" is not an object`);
  }
  const rawModels = raw.models as Record<string, unknown>;
  const models: Partial<Record<ProbedModel, ModelProbeVerdict>> = {};
  for (const model of PROBED_MODELS) {
    const verdict = rawModels[model];
    if (verdict === undefined || verdict === null) continue;
    if (typeof verdict !== 'string' || !PROBE_VERDICTS.has(verdict)) {
      throw new Error(`stored network state field "${field}.models.${model}" is not a valid probe verdict`);
    }
    models[model] = verdict as ModelProbeVerdict;
  }

  let temperatureRange: TemperatureRange | null = null;
  if (raw.temperatureRange !== null && raw.temperatureRange !== undefined) {
    const rawRange = raw.temperatureRange as Record<string, unknown>;
    if (typeof rawRange.minKelvin !== 'number' || typeof rawRange.maxKelvin !== 'number') {
      throw new Error(`stored network state field "${field}.temperatureRange" is not a {minKelvin, maxKelvin} pair`);
    }
    assertRange(`${field}.temperatureRange.minKelvin`, rawRange.minKelvin, 0, 0xffff);
    assertRange(`${field}.temperatureRange.maxKelvin`, rawRange.maxKelvin, 0, 0xffff);
    temperatureRange = { minKelvin: rawRange.minKelvin, maxKelvin: rawRange.maxKelvin };
  }
  return { models, temperatureRange };
}

/**
 * Validates and copies a caller-supplied state into its wire shape. Never
 * mutates `state` or retains any of its buffers — every field below is
 * either a primitive, a freshly-copied string, or (for `nodes`) a freshly
 * built array of freshly-copied objects.
 */
function encodeNetworkState(state: NetworkState): PersistedNetworkState {
  if (state.netKey !== null) assertKeyLength('netKey', state.netKey);
  if (state.netKeyIndex !== null) assertRange('netKeyIndex', state.netKeyIndex, 0, MAX_KEY_INDEX);
  if (state.appKey !== null) assertKeyLength('appKey', state.appKey);
  if (state.appKeyIndex !== null) assertRange('appKeyIndex', state.appKeyIndex, 0, MAX_KEY_INDEX);
  assertRange('ivIndex', state.ivIndex, 0, 0xffffffff);
  if (state.ourUnicastAddress !== null) {
    assertRange('ourUnicastAddress', state.ourUnicastAddress, MIN_UNICAST_ADDRESS, MAX_UNICAST_ADDRESS);
  }
  assertRange('nextUnicastAddress', state.nextUnicastAddress, MIN_UNICAST_ADDRESS, MAX_UNICAST_ADDRESS + 1);

  const nodes: PersistedNode[] = state.nodes.map((node, i) => {
    assertRange(`nodes[${i}].address`, node.address, MIN_UNICAST_ADDRESS, MAX_UNICAST_ADDRESS);
    assertKeyLength(`nodes[${i}].deviceKey`, node.deviceKey);
    const encoded: PersistedNode = {
      address: node.address,
      deviceKey: Buffer.from(node.deviceKey).toString('hex'),
      composition: JSON.parse(JSON.stringify(node.composition)) as CompositionData,
    };
    // Written only when there IS one: a node never probed stays absent
    // rather than acquiring an empty object, so "never measured" and
    // "measured nothing" stay distinguishable in the stored value.
    if (node.probe !== undefined) {
      encoded.probe = encodeProbe(`nodes[${i}].probe`, node.probe);
    }
    return encoded;
  });

  return {
    netKey: state.netKey === null ? null : Buffer.from(state.netKey).toString('hex'),
    netKeyIndex: state.netKeyIndex,
    appKey: state.appKey === null ? null : Buffer.from(state.appKey).toString('hex'),
    appKeyIndex: state.appKeyIndex,
    ivIndex: state.ivIndex,
    ourUnicastAddress: state.ourUnicastAddress,
    nextUnicastAddress: state.nextUnicastAddress,
    nodes,
  };
}

function hexToKeyBuffer(hex: string, field: string): Buffer {
  if (hex.length !== KEY_LENGTH * 2 || !/^[0-9a-f]+$/i.test(hex)) {
    throw new Error(`stored network state field "${field}" is not a valid ${KEY_LENGTH}-byte hex string`);
  }
  return Buffer.from(hex, 'hex');
}

/**
 * The inverse of `encodeNetworkState`. Throws on anything that does not look
 * like our own wire shape, INCLUDING an out-of-range value that is the right
 * JS type (e.g. a `nextUnicastAddress` of `0`, a `number` but the Unassigned
 * address, never a legal unicast one) — the same fields `encodeNetworkState`
 * range-checks, checked again here because a hand-edited or otherwise
 * corrupted settings value does not go through `encodeNetworkState` on its
 * way in. `NetworkStore#readStateForWrite` below is this function's only
 * caller and turns that throw into "missing/unreadable data yields the
 * empty state" (via `getState`) or "refuse to write" (via
 * `allocateUnicastAddress`), rather than letting a corrupt settings value
 * crash app startup or be silently accepted.
 */
function decodeNetworkState(value: unknown): NetworkState {
  if (typeof value !== 'object' || value === null) {
    throw new Error('stored network state is not an object');
  }
  const v = value as Record<string, unknown>;
  if (!Array.isArray(v.nodes)) {
    throw new Error('stored network state field "nodes" is not an array');
  }

  const nodes: NodeEntry[] = (v.nodes as unknown[]).map((raw, i) => {
    if (typeof raw !== 'object' || raw === null) {
      throw new Error(`stored network state field "nodes[${i}]" is not an object`);
    }
    const node = raw as Record<string, unknown>;
    if (typeof node.address !== 'number') {
      throw new Error(`stored network state field "nodes[${i}].address" is not a number`);
    }
    assertRange(`nodes[${i}].address`, node.address, MIN_UNICAST_ADDRESS, MAX_UNICAST_ADDRESS);
    if (typeof node.deviceKey !== 'string') {
      throw new Error(`stored network state field "nodes[${i}].deviceKey" is not a string`);
    }
    const entry: NodeEntry = {
      address: node.address,
      deviceKey: hexToKeyBuffer(node.deviceKey, `nodes[${i}].deviceKey`),
      composition: JSON.parse(JSON.stringify(node.composition)) as CompositionData,
    };
    // Absent (a node paired before the probe existed) stays absent - see
    // `NodeEntry.probe`'s own note on why that IS the migration.
    if (node.probe === undefined || node.probe === null) return entry;
    return { ...entry, probe: decodeProbe(`nodes[${i}].probe`, node.probe) };
  });

  const netKey = v.netKey === null || v.netKey === undefined ? null : hexToKeyBuffer(v.netKey as string, 'netKey');
  const appKey = v.appKey === null || v.appKey === undefined ? null : hexToKeyBuffer(v.appKey as string, 'appKey');
  const netKeyIndex = (v.netKeyIndex as number | null | undefined) ?? null;
  const appKeyIndex = (v.appKeyIndex as number | null | undefined) ?? null;
  const ourUnicastAddress = (v.ourUnicastAddress as number | null | undefined) ?? null;

  if (netKeyIndex !== null) assertRange('netKeyIndex', netKeyIndex, 0, MAX_KEY_INDEX);
  if (appKeyIndex !== null) assertRange('appKeyIndex', appKeyIndex, 0, MAX_KEY_INDEX);
  if (ourUnicastAddress !== null) {
    assertRange('ourUnicastAddress', ourUnicastAddress, MIN_UNICAST_ADDRESS, MAX_UNICAST_ADDRESS);
  }

  // Range-checked, not just type-checked (mirrors encodeNetworkState): a
  // stored value that is a `number` but out of range -- e.g. a
  // nextUnicastAddress of 0, the Unassigned address and never a legal
  // unicast one -- is exactly as unsafe to hand to a caller as one of the
  // wrong JS type, and must fail the same way (caught by the caller below,
  // never silently accepted).
  if (typeof v.ivIndex !== 'number') {
    throw new Error('stored network state field "ivIndex" is not a number');
  }
  assertRange('ivIndex', v.ivIndex, 0, 0xffffffff);
  if (typeof v.nextUnicastAddress !== 'number') {
    throw new Error('stored network state field "nextUnicastAddress" is not a number');
  }
  assertRange('nextUnicastAddress', v.nextUnicastAddress, MIN_UNICAST_ADDRESS, MAX_UNICAST_ADDRESS + 1);

  return {
    netKey,
    netKeyIndex,
    appKey,
    appKeyIndex,
    ivIndex: v.ivIndex,
    ourUnicastAddress,
    nextUnicastAddress: v.nextUnicastAddress,
    nodes,
  };
}

/**
 * The settings-backed `NetworkStore`. Construct one per app instance (or per
 * test) against a `SettingsPort`; every method reads and writes through it
 * immediately; nothing is buffered beyond the single call it was made in,
 * except the sequence-number counter, which is documented where it lives.
 */
export class NetworkStore {
  private readonly settings: SettingsPort;

  /** In-memory sequence-number cursor: the next number this run will hand
   *  out. Always `<= reservedUpTo`; never itself persisted (see
   *  `allocateSequenceBlock` for why persisting the CEILING ahead of it,
   *  not this counter, is what makes the allocator power-loss safe). */
  private nextSeq: number;

  /** The persisted ceiling: every number below this has possibly already
   *  been handed out (by this run or an earlier one) and must never be
   *  reissued. Loaded once at construction — see the class doc comment. */
  private reservedUpTo: number;

  constructor(settings: SettingsPort) {
    this.settings = settings;
    const persisted = this.loadSequenceState();
    // Resuming exactly at the persisted ceiling is deliberate and is what
    // makes this safe whether this construction follows a clean restart or
    // a crash: the ceiling is the only number this module can prove was
    // never handed out, because it was persisted BEFORE anything past it
    // was issued (see allocateSequenceBlock). Anything smaller might
    // already have been issued by the run that just ended.
    this.nextSeq = persisted.reservedUpTo;
    this.reservedUpTo = persisted.reservedUpTo;
  }

  private loadSequenceState(): PersistedSequenceState {
    const raw = this.settings.get(SETTINGS_KEY_SEQUENCE);
    if (raw === null || raw === undefined) {
      return { reservedUpTo: 0 };
    }
    if (
      typeof raw !== 'object' ||
      raw === null ||
      typeof (raw as Record<string, unknown>).reservedUpTo !== 'number'
    ) {
      // Unreadable sequence state is exactly as dangerous as a missing key
      // would be if we silently trusted it, so it gets the same safe
      // fallback as a missing key — never a value we did not ourselves
      // persist in this shape.
      return { reservedUpTo: 0 };
    }
    return { reservedUpTo: (raw as PersistedSequenceState).reservedUpTo };
  }

  /**
   * The single read path both `getState` and `allocateUnicastAddress` build
   * on. Distinguishes "nothing stored yet" from "something is stored but
   * will not decode" — a distinction `getState` itself deliberately throws
   * away (both read as the empty state, so a caller that only wants to READ
   * never has to think about it), but which `allocateUnicastAddress` below
   * cannot: it also WRITES, and overwriting a merely-unreadable value
   * destroys the only remaining chance of recovering it (see that method's
   * own comment). Returns a freshly built empty state (`freshEmptyState`),
   * never the shared `EMPTY_NETWORK_STATE` singleton, for either case.
   */
  private readStateForWrite(): { state: NetworkState; corrupt: boolean } {
    const raw = this.settings.get(SETTINGS_KEY_NETWORK);
    if (raw === null || raw === undefined) {
      return { state: freshEmptyState(), corrupt: false };
    }
    try {
      return { state: decodeNetworkState(raw), corrupt: false };
    } catch {
      return { state: freshEmptyState(), corrupt: true };
    }
  }

  /**
   * Returns the current network state — a defined, empty `NetworkState`
   * when nothing has been stored yet, or when what IS stored does not parse
   * as this module's own shape. Never throws, and never returns the same
   * object instance across two calls (not even for the empty case — see
   * `freshEmptyState`), so mutating what one call returned can never affect
   * what a later call returns.
   */
  getState(): NetworkState {
    return this.readStateForWrite().state;
  }

  /**
   * Replaces the whole network state. Validates every field (key lengths,
   * index widths, address ranges) before writing anything, so a bad call
   * never partially persists. Does not mutate `state` and does not retain
   * any of its buffers — see `encodeNetworkState`.
   */
  setState(state: NetworkState): void {
    const persisted = encodeNetworkState(state);
    this.settings.set(SETTINGS_KEY_NETWORK, persisted);
  }

  /**
   * Hands out the next unicast address and advances the store's "next free"
   * pointer past it, persisting that advance before returning — so the same
   * address is never offered twice, even across a reload. Throws once the
   * unicast range (Table 3.5, `MAX_UNICAST_ADDRESS`) is exhausted, which
   * three bulbs are nowhere near doing but a store must still say something
   * about rather than silently handing out an invalid address.
   *
   * REFUSES TO RUN when the stored network state is present but will not
   * decode. `getState()` papers over that case as the empty state so a
   * plain read never has to think about it — but this method does not just
   * read, it writes the rest of that (empty) state straight back via
   * `setState`, which would PERMANENTLY overwrite whatever was actually
   * there. Per the design, losing the network/application keys and the
   * node roster means physically factory-resetting every bulb; silently
   * turning "unreadable" into "gone" would be the single most expensive
   * failure this app can have, so this method would rather throw and leave
   * the corrupt value exactly as it found it.
   *
   * CALLER HAZARD, worth a loud comment because nothing enforces it: this
   * method does its own whole-state read-modify-write (read via
   * `readStateForWrite`, write via `setState`). A caller that ALSO reads
   * `getState()` before calling this and writes its own `setState()` after
   * — e.g. "provision a node, then call this, then save the node entry" —
   * will stomp this method's advance with its own stale copy of
   * `nextUnicastAddress`, and the SAME address will be handed out again on
   * the next call. Call this first and fold its result into your own
   * single `setState`, or re-read state after calling it, never before.
   *
   * ALSO NOTE for whoever wires pairing (Task 6): this hands out exactly
   * ONE address. A node with N elements occupies N consecutive unicast
   * addresses (its primary element's address, then +1 per further
   * element) — but composition data, which is what reveals N, is only read
   * AFTER provisioning assigns the node's address. This method does not
   * and cannot know N; the caller must advance `nextUnicastAddress` past
   * the extra elements itself once it has read the composition.
   */
  allocateUnicastAddress(): number {
    const { state, corrupt } = this.readStateForWrite();
    if (corrupt) {
      throw new Error(
        'cannot allocate a unicast address: the stored network state is present but unreadable; refusing to overwrite it (it may still be recoverable)',
      );
    }
    const address = state.nextUnicastAddress;
    if (address > MAX_UNICAST_ADDRESS) {
      throw new Error(
        `no unicast addresses remain: nextUnicastAddress ${address} exceeds the unicast range (Table 3.5, max 0x${MAX_UNICAST_ADDRESS.toString(16)})`,
      );
    }
    this.setState({ ...state, nextUnicastAddress: address + 1 });
    return address;
  }

  /**
   * Hands out the next sequence number. Internally this draws from a block
   * reserved ahead of time; when the in-memory counter reaches the
   * persisted ceiling, this method persists a NEW, further-out ceiling
   * BEFORE handing out the number that would have exceeded the old one —
   * never after. That ordering is the whole safety property: at every
   * instant, `settings` holds a ceiling that is provably >= every number
   * this method has ever returned, because nothing past the old ceiling is
   * ever returned until the new one is already durable. A power loss at any
   * point therefore leaves the next construction's `reservedUpTo` (and so
   * its first-issued number) strictly greater than every number this
   * method returned before the loss — see store.test.ts's power-loss
   * property test, and the mutation in step 7 of the task brief, which
   * swaps this ordering to prove the test actually depends on it.
   */
  allocateSequenceBlock(): number {
    if (this.nextSeq >= this.reservedUpTo) {
      const newCeiling = this.reservedUpTo + SEQ_BLOCK_SIZE;
      if (newCeiling > MAX_SEQ + 1) {
        throw new Error(
          `sequence-number space exhausted: cannot reserve up to ${newCeiling}, the 24-bit space ends at ${MAX_SEQ + 1}`,
        );
      }
      this.settings.set(SETTINGS_KEY_SEQUENCE, { reservedUpTo: newCeiling } satisfies PersistedSequenceState);
      this.reservedUpTo = newCeiling;
    }
    const seq = this.nextSeq;
    this.nextSeq += 1;
    return seq;
  }
}
