import { randomBytes as nodeRandomBytes } from 'node:crypto';
import {
  acceptProxyPdu,
  encodeProxyPdus,
  PROXY_MESSAGE_TYPE_NETWORK_PDU,
  PROXY_MESSAGE_TYPE_PROVISIONING_PDU,
  PROXY_SAR_TIMEOUT_MS,
  type ProxyReassemblyState,
} from '../../lib/mesh/packet/proxyPdu';
import { withTimeout } from '../../lib/adapter/timeout';
import {
  MAX_PROXY_PDU_LENGTH,
  MESH_PROVISIONING_DATA_IN_UUID,
  MESH_PROVISIONING_DATA_OUT_UUID,
  MESH_PROVISIONING_SERVICE_UUID,
  MESH_PROXY_DATA_IN_UUID,
  MESH_PROXY_DATA_OUT_UUID,
  MESH_PROXY_SERVICE_UUID,
  findServiceData,
  type BluetoothPort,
  type CharacteristicHandle,
  type ClockPort,
  type ConnectionHandle,
  type DiscoveredCharacteristic,
  type ServiceDataEntry,
  type TimerHandle,
} from '../../lib/adapter/connection';
import { NetworkStore } from '../../lib/adapter/store';
import {
  encodeMeshMessage,
  acceptIncomingPdu,
  POINT_TO_POINT_TTL,
  type MeshReceiveState,
  type MeshReceiveContext,
} from '../../lib/mesh/packet/message';
import {
  beginProvisioning,
  step as provisioningStep,
  type BeginProvisioningInput,
  type EphemeralKeyPair,
  type ProvisioningState,
} from '../../lib/mesh/provisioning/machine';
import { generateKeyPair } from '../../lib/mesh/crypto/ecdh';
import {
  encodeConfigCompositionDataGet,
  encodeConfigAppKeyAdd,
  encodeConfigModelAppBind,
  encodeConfigNodeReset,
  decodeConfigStatus,
} from '../../lib/mesh/config/client';
import { encodeAccessMessage, type AccessMessage } from '../../lib/mesh/packet/access';
import { k4 } from '../../lib/mesh/crypto/derive';
import type { CompositionData } from '../../lib/mesh/config/composition';
import {
  mapCompositionToCapabilities,
  LIGHTING_SERVER_MODEL_IDS,
  type HomeyCapability,
  type NodeProbeResult,
} from '../../lib/models/capabilities';
import { probeModels, type ProbeTransport } from './modelProbe';
import { DEFAULT_TEMPERATURE_RANGE } from './temperatureRange';

/**
 * Pairing (docs/superpowers/specs/2026-10-06-ble-mesh-provisioner-design.md,
 * "The Homey layer" > "Pairing"): "The driver's pairing screen scans for
 * nodes advertising the provisioning service, which means nodes with no
 * owner, and lists them with signal strength. On selection the app
 * provisions the node, allocates its unicast address, adds the application
 * key, reads the composition data and binds the key to the node's models.
 * Only then is the Homey device created."
 *
 * This is the task where everything built so far has to work together:
 * the provisioning state machine (`lib/mesh/provisioning/machine.ts`), the
 * Configuration Client messages and composition parser
 * (`lib/mesh/config/*.ts`), the network/transport/access layers
 * (`lib/mesh/packet/*.ts`, composed by `lib/mesh/packet/message.ts`), the
 * settings-backed store and its unicast-address allocator
 * (`lib/adapter/store.ts`), and capability mapping
 * (`lib/models/capabilities.ts`). This module is PURE orchestration of all
 * of them — it takes a `BluetoothPort` and a `NetworkStore` rather than
 * `homey` itself, the same narrow-port pattern every other lib/adapter
 * module uses, so the whole flow is testable without a hub (see
 * `__tests__/pairing.test.ts`, which drives it with
 * `lib/adapter/__tests__/fakeBluetooth.ts` and a real `NetworkStore` over a
 * fake settings port). `drivers/light/driver.ts` is the thin `Homey.Driver`
 * wrapper around `pairNode`/`scanForUnprovisionedNodes` below — the only
 * file in this directory that imports `homey`.
 *
 * TWO GATT SESSIONS, NOT ONE, deliberately. A node has no network
 * membership until Provisioning Data is accepted, so it cannot possibly run
 * the Mesh Proxy Service beforehand — the provisioning exchange runs over
 * the Mesh Provisioning Service's own characteristics
 * (`MESH_PROVISIONING_DATA_IN/OUT_UUID`), and only once `machine.ts` reaches
 * `'provisioned'` does this module disconnect and reconnect to the SAME
 * peripheral over the Mesh Proxy Service's characteristics
 * (`MESH_PROXY_DATA_IN/OUT_UUID`) to run the configuration exchange.
 * KNOWN SIMPLIFICATION, to verify on hardware: this assumes the node is
 * reachable again immediately, with no re-scan or settling delay between
 * disconnect and reconnect. If a real bulb needs a settling delay, this is
 * the first place to look, the same way `machine.ts`'s own CMAC-only
 * limitation is documented as the first thing to suspect for a refused
 * provisioning.
 *
 * BOTH SESSIONS CARRY THE PROXY PDU ENVELOPE. This module used to write
 * bare Provisioning PDUs and bare Network PDUs straight onto the Data In
 * characteristics, disclosed as a simplification "to verify on hardware".
 * That disclosure was wrong on its own terms — there was nothing to verify:
 * Section 5.2.2 "PB-GATT" says it outright, "The Mesh Provisioning Data In
 * and Mesh Provisioning Data Out characteristic formats use the Proxy PDU
 * format defined in Section 6.3.1.", and Section 7.2.3.1 "Mesh Proxy Data
 * In characteristic" says the same for the other pair, "The characteristic
 * value has the same format as the Proxy PDU." `openSession` below now
 * wraps and segments every write and reassembles every notification through
 * `lib/mesh/packet/proxyPdu.ts`, with the MessageType each service's own
 * behaviour clause prescribes (Provisioning PDU for the provisioning pair,
 * Network PDU for the proxy pair — Table 6.3). This matters most for
 * provisioning: a Provisioning Public Key PDU is 65 octets, far past one
 * ATT write on a minimal link, so without segmentation the single most
 * important message of the whole exchange could never arrive at all.
 *
 * RANDOMNESS ENTERS HERE. `machine.ts` deliberately takes its ephemeral ECDH
 * key pair and RandomProvisioner as caller-supplied inputs rather than
 * generating them itself (see that module's own PURITY note), precisely so
 * a real source could be supplied at the edge. This module is that edge:
 * `createNodeCryptoRandomSource` below is the first thing in this whole
 * project that calls `node:crypto` for anything other than a known-answer
 * cryptographic primitive — real entropy for a real provisioning attempt.
 * `ProvisioningRandomSource` is injected (the same narrow-port pattern as
 * `BluetoothPort`/`ClockPort`/`SettingsPort`), so `__tests__/pairing.test.ts`
 * can supply a FAKE one that returns the Mesh Protocol specification's own
 * published Section 8.7/8.17.1 sample values instead — which is also what
 * makes the whole exchange replayable deterministically in a test: feeding
 * the SAME ephemeral key pair and RandomProvisioner the sample used, and
 * replaying the sample's own published Provisionee-side PDUs as the fake
 * node's replies, reproduces the sample's own published device key byte for
 * byte (see the test file's own header). The network key and application
 * key this project generates on first run (`ensureNetworkInitialized`
 * below) are the SECOND thing that needs real randomness, and go through
 * the exact same injected source for the exact same reason.
 *
 * NODE ENTRIES ARE WRITTEN ONLY ON COMPLETE SUCCESS (`finishPairing`, the
 * ONE place this module writes to `store.nodes`). The allocated node
 * address, by contrast, is NEVER reclaimed on failure — once
 * `store.allocateUnicastAddress()` hands one out, this module simply
 * abandons it if anything later fails, the same way a real provisioner
 * cannot safely reuse an address a partially-provisioned node might
 * already have recorded. This is deliberate, not an oversight: see
 * `store.ts`'s own module header for why handing out the same address
 * twice is the one failure this design treats as worse than wasting a
 * unicast address.
 *
 * A FAILURE AFTER PROVISIONING SUCCEEDS MUST NOT ORPHAN THE NODE (review
 * finding, HIGH). The design: a failed provisioning "leaves the node
 * untouched and can be retried." That is true up to the moment `machine.ts`
 * reaches `'provisioned'` — but a review proved that past that point, a
 * LATER failure (a refused AppKey Add, an unparseable composition reply, a
 * stalled wait) with no further action left the node PERMANENTLY
 * unreachable by this app: it had already left the Mesh Provisioning
 * Service for the Mesh Proxy Service (so a later scan for unprovisioned
 * nodes can never find it again), while no store entry existed yet to hold
 * the device key it would take to reach it any other way — recoverable only
 * by a physical factory reset. `runConfigExchange`'s own `failWithReset`
 * closes this: every failure path once provisioning has succeeded sends a
 * Config Node Reset over the still-open session FIRST (the encoder/decoder
 * for this already existed, already tested, and had no caller before this
 * fix), and names whether that reset itself succeeded in the returned
 * message — never silently swallowed. The one case this cannot cover is a
 * configuration session that could never be opened at all (no session, no
 * way to send anything); `pairNode` says so plainly in that message instead
 * of pretending the node is still reachable.
 *
 * THE INHERITED ADDRESS-ADVANCE HAZARD (plan 1, carried into this task's
 * brief). `store.allocateUnicastAddress()` hands out exactly ONE address,
 * but a node occupies as many CONSECUTIVE unicast addresses as it has
 * elements — and composition data, which reveals the element count, is only
 * read AFTER provisioning assigns the node's own (single) address.
 * `reserveElementAddresses` advances `nextUnicastAddress` past the extra
 * elements — called by `pairNode` as soon as the element count is known,
 * WIN OR LOSE (review finding, MEDIUM: the same root cause as the orphaning
 * finding above — a multi-element node that provisions and then fails
 * configuration still occupies several consecutive addresses, regardless of
 * whether this app ever finishes configuring it), from a FRESH
 * `store.getState()` read taken immediately before that single `setState`
 * call, never from a state snapshot read before `allocateUnicastAddress()`
 * ran, per that method's own loud CALLER HAZARD comment (reading-before-
 * allocating and writing after would silently rewind the pointer and
 * reissue an address already handed out — see `ensureNetworkInitialized`
 * below for the other call site with the exact same discipline).
 *
 * COMPOSITION DATA THAT DOES NOT PARSE (plan 4's open question, this task's
 * brief). `parseCompositionData` returns a single `null` for four distinct
 * rejections — too short, truncated mid-element, zero elements, trailing
 * bytes indistinguishable from a truncated next element (`composition.ts`'s
 * own module header enumerates all four). This module cannot tell the user
 * WHICH of the four occurred, because the parser does not tell IT — so
 * `finishPairing` reports a single, honest, generic failure
 * ("the node's composition data could not be parsed") rather than
 * inventing a reason the parser never gave it. See this task's report for
 * the proposed fix (a discriminated rejection reason returned instead of a
 * bare `null`) — not implemented here, since `composition.ts` is outside
 * this task's file list and the brief says to propose, not invent.
 */

// ===========================================================================
// Randomness — see the module header's RANDOMNESS ENTERS HERE note.
// ===========================================================================

export interface ProvisioningRandomSource {
  /** Cryptographically random bytes of the given length — used for the
   *  network key, the application key, and RandomProvisioner (Section
   *  5.4.2.4.1). */
  randomBytes(length: number): Buffer;
  /** A fresh ephemeral P-256 key pair for one provisioning attempt (Section
   *  5.4.2.3) — never reused across attempts. */
  generateEphemeralKeyPair(): EphemeralKeyPair;
}

/** The real source: `node:crypto`'s CSPRNG for both. */
export function createNodeCryptoRandomSource(): ProvisioningRandomSource {
  return {
    randomBytes: (length: number): Buffer => nodeRandomBytes(length),
    generateEphemeralKeyPair: (): EphemeralKeyPair => generateKeyPair(),
  };
}

// ===========================================================================
// The clock — review finding (HIGH): nothing in this module bounded a wait
// for a reply, so a silent node (or a stream of packets this module ignores)
// left a pairing attempt pending forever, with the wizard stuck on
// "Pairing…" and no way back. This project already built exactly the
// machinery for "the node never answered" — `ClockPort` and
// `lib/adapter/queue.ts`'s own bounded per-attempt timeout — and pairing
// bypassed both.
//
// EVERY GATT OPERATION IS BOUNDED, NOT ONLY THE REPLY WAIT (review finding,
// re-review: the first version of this fix bounded `session.next()` only,
// and disclosed — WRONGLY — that nothing in the fake port could make
// `connect`/`discover`/`subscribe`/`write`/`disconnect` hang. The fake
// port's own `writeBehavior: 'hold'` mode, documented in
// `fakeBluetooth.ts` as modelling a congested transmit queue, does exactly
// that to `write()` — and pairing calls `write()` on every single PDU it
// sends, so a held write hangs real pairing attempts, not merely a test
// double. The conclusion was wrong even though the underlying fact — "the
// fake can misbehave in ways worth naming" — was the one thing worth
// checking before writing the disclaimer). `openSession` below now wraps
// ALL FIVE `BluetoothPort` operations — `connect`, `discover`, `subscribe`,
// `write` and `disconnect` — through the same `withTimeout` helper the
// reply wait already used, keyed to a `stage` identifying which GATT
// session ('provisioning' or 'configuration exchange') is stalling. No new
// machinery: the clock was already injected, `withTimeout` already existed.
// ===========================================================================

/** Not a specification value — an engineering choice. Generous because
 *  pairing is a one-shot, human-paced action (not an automatic retry loop
 *  like `queue.ts`'s), but still bounded: a node that will never answer must
 *  eventually fail the attempt rather than hang it forever. */
export const DEFAULT_PAIRING_STEP_TIMEOUT_MS = 30_000;

/** The real clock: wraps the global timer functions, same shape as
 *  `lib/adapter/connection.ts#ClockPort` (which every fake in this project
 *  already implements against — see `lib/adapter/__tests__/fakeClock.ts`). */
export function createRealClock(): ClockPort {
  return {
    now: (): number => Date.now(),
    setTimeout: (callback: () => void, delayMs: number): TimerHandle => setTimeout(callback, delayMs),
    clearTimeout: (handle: TimerHandle): void => clearTimeout(handle as ReturnType<typeof setTimeout>),
  };
}

// ===========================================================================
// Homey BLE UUID parsing — review finding (MEDIUM): this used to be three
// lines of real logic (`parseInt(uuid, 16)`) sitting in `driver.ts`, outside
// the typecheck/jest gate (that file imports `homey`). Moved here, under the
// gate, with a test per shape — the naive version had three real bugs: a
// full canonical 128-bit form (32 hex chars) parses as one enormous number
// that never matches any of this project's 16-bit constants; a DASHED
// canonical form silently truncates at the first dash, which only happens
// to recover the right 16-bit value when that value is the EXACT short-UUID
// embedding (and gives a wrong, unguarded answer for any other 128-bit
// UUID a real scan can legitimately include); and a non-hex string produces
// `NaN`, not a thrown error, so a lookup failure then surfaces as "does not
// expose both required characteristics" — pointing at the wrong place
// entirely. This module only ever needs to recognise Bluetooth SIG 16-bit
// short UUIDs (the Mesh Provisioning/Proxy services and their four
// characteristics), in the two shapes Homey's own BLE API plausibly hands
// back: a bare 4-hex-digit short form, or a full 128-bit UUID string (dashed
// or not) that embeds one via the Bluetooth Base UUID. Anything else throws
// a clear error rather than silently producing a wrong number.
// ===========================================================================

// Bluetooth Core Specification, Vol 3, Part B, Section 2.5.1 "UUID": 16-/32-
// bit "short" Bluetooth SIG UUIDs are the first 32 bits of a 128-bit UUID
// built from this fixed base, lowercase hex, no dashes (bytes 4-15):
// 0000xxxx-0000-1000-8000-00805F9B34FB.
const BLE_BASE_UUID_SUFFIX = '00001000800000805f9b34fb';

/**
 * Parses a Bluetooth UUID string into this project's own 16-bit numeric
 * convention (`lib/adapter/connection.ts`'s `MESH_PROXY_SERVICE_UUID`-style
 * constants). Accepts a bare 4-hex-digit short form ("1827") or a 128-bit
 * form (32 hex digits, with or without the canonical dashes) that embeds a
 * 16-bit short UUID via the Bluetooth Base UUID — throws for anything else
 * (non-hex input, the wrong length, or a well-formed 128-bit UUID that does
 * NOT embed a 16-bit short UUID) rather than silently returning a wrong or
 * `NaN` value.
 */
export function parseBleUuid(uuid: string): number {
  const normalized = uuid.toLowerCase().replace(/-/g, '');
  if (normalized.length === 0 || !/^[0-9a-f]+$/.test(normalized)) {
    throw new Error(`parseBleUuid: "${uuid}" is not a hexadecimal UUID string`);
  }
  if (normalized.length === 4) {
    return parseInt(normalized, 16);
  }
  if (normalized.length === 32) {
    const shortPart = normalized.slice(0, 8);
    const rest = normalized.slice(8);
    if (rest === BLE_BASE_UUID_SUFFIX && shortPart.startsWith('0000')) {
      return parseInt(shortPart.slice(4), 16);
    }
    throw new Error(
      `parseBleUuid: "${uuid}" is a 128-bit UUID that does not embed a 16-bit Bluetooth SIG short UUID via the Bluetooth Base UUID (this project only expects the Mesh Provisioning/Proxy services and their characteristics)`,
    );
  }
  throw new Error(`parseBleUuid: "${uuid}" is not a recognised UUID shape (expected 4 hex digits, or 32 with dashes optional)`);
}

/** Inverse of `parseBleUuid` for this project's own 16-bit constants only —
 *  used to build the service filter `HomeyBluetoothPort.scan()` passes to
 *  `ManagerBLE.discover()`. */
export function bleUuidString(uuid: number): string {
  if (!Number.isInteger(uuid) || uuid < 0 || uuid > 0xffff) {
    throw new Error(`bleUuidString: ${uuid} is not a 16-bit UUID`);
  }
  return uuid.toString(16).padStart(4, '0');
}

/**
 * Non-throwing wrapper over `parseBleUuid` — a REAL peripheral's discovery
 * routinely includes entirely unrelated services/characteristics (Device
 * Information, Battery, GAP/GATT housekeeping, vendor-specific 128-bit
 * UUIDs) alongside this project's own four, so a throw here must mean "not
 * one of ours, skip it", never "crash the whole scan()/discover() call".
 *
 * MOVED HERE FROM `driver.ts` (review finding, smaller item: the filtering
 * loop that used this wrapper lived entirely in the one file this project's
 * gate cannot see — `driver.ts` imports `homey`, so neither
 * `npm run typecheck` nor `npx jest --ci` ever exercised it — meaning
 * nothing proved this wrapper's SKIP behaviour, as opposed to a THROWING
 * form that would brick every real scan/discover call the moment an
 * unrelated service showed up, was load-bearing. The reviewer demonstrated
 * the entire gate passing with the throwing form substituted in. Now this
 * wrapper, and the two filtering loops that use it below, are under the
 * gate; `driver.ts` keeps nothing but the direct Homey API calls and a
 * reshape of their results into these functions' input shape.
 */
export function tryParseBleUuid(uuid: string): number | null {
  try {
    return parseBleUuid(uuid);
  } catch {
    return null;
  }
}

/**
 * Filters a scan's raw, Homey-shaped service-data entries down to the ones
 * this project recognises, translating each surviving UUID to this
 * project's numeric convention — the actual logic inside
 * `HomeyBluetoothPort.scan()`, as opposed to the Homey API call itself.
 * Order-preserving.
 */
export function filterKnownServiceData(
  entries: ReadonlyArray<{ readonly uuid: string; readonly data: Buffer }>,
): ServiceDataEntry[] {
  const result: ServiceDataEntry[] = [];
  for (const entry of entries) {
    const serviceUuid = tryParseBleUuid(entry.uuid);
    if (serviceUuid !== null) result.push({ serviceUuid, data: entry.data });
  }
  return result;
}

/**
 * Filters a connection's raw, Homey-shaped discovered services/
 * characteristics down to the ones this project recognises, translating
 * each surviving UUID pair to this project's numeric convention — the
 * actual logic inside `HomeyBluetoothPort.discover()`, as opposed to the
 * Homey API call itself. Order-preserving (service order, then
 * characteristic order within each service).
 */
export function filterKnownCharacteristics(
  services: ReadonlyArray<{
    readonly uuid: string;
    readonly characteristics: ReadonlyArray<{ readonly uuid: string; readonly handle: CharacteristicHandle }>;
  }>,
): DiscoveredCharacteristic[] {
  const result: DiscoveredCharacteristic[] = [];
  for (const service of services) {
    const serviceUuid = tryParseBleUuid(service.uuid);
    if (serviceUuid === null) continue;
    for (const characteristic of service.characteristics) {
      const characteristicUuid = tryParseBleUuid(characteristic.uuid);
      if (characteristicUuid === null) continue;
      result.push({ serviceUuid, characteristicUuid, handle: characteristic.handle });
    }
  }
  return result;
}

// ===========================================================================
// Scanning for unprovisioned nodes.
// ===========================================================================

export interface UnprovisionedNodeCandidate {
  readonly peripheralId: string;
  readonly rssi: number;
}

/** Not a specification value — an engineering choice, the same way
 *  connection.ts's own SCAN_DURATION_MS is (see that module's comment on
 *  its own constants for the same reasoning). */
export const PAIRING_SCAN_DURATION_MS = 4000;

/**
 * Scans for nodes advertising the Mesh Provisioning Service — "nodes with
 * no owner" (design) — and lists them with signal strength, strongest
 * first. A node that also happens to advertise OTHER services is still
 * listed; this function only cares whether `MESH_PROVISIONING_SERVICE_UUID`
 * is present among `ScanResult.serviceData`, the same `findServiceData`
 * lookup `connection.ts` uses for its own, different service.
 */
export async function scanForUnprovisionedNodes(
  bluetooth: BluetoothPort,
  durationMs: number = PAIRING_SCAN_DURATION_MS,
): Promise<UnprovisionedNodeCandidate[]> {
  const results = await bluetooth.scan(durationMs);
  return results
    .filter((result) => findServiceData(result, MESH_PROVISIONING_SERVICE_UUID) !== null)
    .map((result) => ({ peripheralId: result.peripheralId, rssi: result.rssi }))
    .sort((a, b) => b.rssi - a.rssi);
}

// ===========================================================================
// One GATT session — connect, discover, subscribe once; write/read notifications after.
// ===========================================================================

/** A notification "channel": buffers pushes that arrive before anything is
 *  waiting for one, and resolves immediately when something already queued
 *  exists — so a caller's `next()` never has to be racing the exact
 *  microtask a notification happens to arrive on. The one piece of
 *  machinery that makes the rest of this module's async code order-safe
 *  regardless of precisely when a reply shows up relative to the write
 *  that provoked it. */
class NotificationChannel {
  private readonly queue: Buffer[] = [];
  private waiting: { readonly resolve: (data: Buffer) => void; readonly reject: (err: Error) => void } | null = null;
  /** Set once by `fail` and never cleared — see that method. */
  private failure: Error | null = null;

  push(data: Buffer): void {
    if (this.failure !== null) return; // the channel is over; nothing more arrives on it
    if (this.waiting !== null) {
      const { resolve } = this.waiting;
      this.waiting = null;
      resolve(data);
      return;
    }
    this.queue.push(data);
  }

  /**
   * Ends this channel permanently, rejecting whoever is waiting now and
   * everyone who asks later (final re-review, finding 2). The one caller is
   * `openSession`'s Section 6.3.2.2 handling: once this session has
   * disconnected the link because the specification said to, there is no
   * link left for a reply to arrive over, and anything still queued belongs
   * to a conversation that is already over — so "once failed, always
   * failed" is the only honest state, and a waiter learning the real reason
   * beats it learning the stage timeout ten seconds later.
   *
   * Idempotent: the first failure is the one that is reported, since it is
   * the one that caused everything after it.
   */
  fail(err: Error): void {
    if (this.failure !== null) return;
    this.failure = err;
    const waiting = this.waiting;
    this.waiting = null;
    if (waiting !== null) waiting.reject(err);
  }

  /**
   * A wait that may END WITHOUT A REPLY, resolving `null`, and that leaves
   * this channel clean when it does.
   *
   * The ordinary `next()` below is bounded from OUTSIDE, by `openSession`'s
   * `withTimeout` - which rejects the caller while leaving `this.waiting`
   * set, so the very next `next()` throws "called again while a previous
   * call is still pending". That is harmless for every existing caller,
   * because a stage timeout ends the whole pairing attempt anyway. The
   * capability probe (`modelProbe.ts`) is the first caller for which a
   * timeout is an EXPECTED, recoverable outcome - it is the probe's
   * negative result - and which must keep using the session afterward. So
   * this method owns both the waiter and the timer, and clears both on
   * either path, rather than being bounded from outside.
   */
  nextWithin(clock: ClockPort, timeoutMs: number): Promise<Buffer | null> {
    if (this.failure !== null) return Promise.reject(this.failure);
    const queued = this.queue.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    if (this.waiting !== null) {
      throw new Error('NotificationChannel.nextWithin: called again while a previous call is still pending');
    }
    return new Promise<Buffer | null>((resolve, reject) => {
      const settle = (): void => {
        clock.clearTimeout(timer);
        // Only clear the slot if it is still OURS: `fail()` may already
        // have taken it, and stealing a later caller's slot would lose
        // that caller's wait forever.
        if (this.waiting === waiter) this.waiting = null;
      };
      const waiter = {
        resolve: (data: Buffer): void => {
          settle();
          resolve(data);
        },
        reject: (err: Error): void => {
          settle();
          reject(err);
        },
      };
      const timer = clock.setTimeout(() => {
        settle();
        resolve(null);
      }, timeoutMs);
      this.waiting = waiter;
    });
  }

  next(): Promise<Buffer> {
    if (this.failure !== null) return Promise.reject(this.failure);
    const queued = this.queue.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    if (this.waiting !== null) {
      // Review finding: calling `next()` again while a previous call is
      // still pending would silently overwrite `this.waiting`, losing the
      // first caller's wait forever (it would never resolve, since `push`
      // only ever resolves the CURRENT `this.waiting`). Every call site in
      // this module awaits exactly one `next()` at a time in a strict loop,
      // so this is never reachable through this module's own use — thrown
      // loudly, as a programming error, rather than silently losing data.
      throw new Error('NotificationChannel.next: called again while a previous call is still pending');
    }
    return new Promise<Buffer>((resolve, reject) => {
      this.waiting = { resolve, reject };
    });
  }
}

interface GattSession {
  write(data: Buffer): Promise<void>;
  next(): Promise<Buffer>;
  /** Waits at most `timeoutMs` for the next notification, resolving `null`
   *  if none arrives - see `NotificationChannel#nextWithin` for why this is
   *  not just `next()` with a shorter bound. */
  nextWithin(timeoutMs: number): Promise<Buffer | null>;
  disconnect(): Promise<void>;
}

/**
 * Opens one GATT session and bounds ALL FIVE `BluetoothPort` operations it
 * performs — `connect`, `discover`, `subscribe`, and (via the returned
 * `GattSession`) `write`/`next`(wait-for-reply)/`disconnect` — through
 * `withTimeout`, keyed by `stage` (e.g. 'provisioning', 'configuration
 * exchange') so a stalled attempt names which phase and which operation is
 * stuck. `next()`'s own `what` is composed as `${stage} stalled` rather
 * than the generic form the other four use, so existing callers/tests that
 * check for the literal substrings "provisioning stalled"/"configuration
 * exchange stalled" keep seeing exactly that wording — see the module
 * header's "The clock" note for why every one of these needed bounding,
 * not only the reply wait.
 */
async function openSession(
  bluetooth: BluetoothPort,
  peripheralId: string,
  serviceUuid: number,
  dataInUuid: number,
  dataOutUuid: number,
  messageType: number,
  clock: ClockPort,
  timeoutMs: number,
  stage: string,
): Promise<GattSession> {
  const bounded = <T>(promise: Promise<T>, what: string): Promise<T> => withTimeout(promise, clock, timeoutMs, what);

  const connection: ConnectionHandle = await bounded(
    bluetooth.connect(peripheralId, () => {
      // An unexpected mid-session disconnect simply stops this channel from
      // ever receiving anything further; whatever this module is currently
      // awaiting (`next()`) then never resolves, and the pairing attempt is
      // left to the caller's own judgement (there is no retry/backoff here —
      // pairing is a one-shot, user-initiated action the design says can
      // simply be retried, not a persistent connection with its own recovery
      // policy the way `ProxyConnectionManager` is).
    }),
    `${stage}: connecting`,
  );
  const characteristics = await bounded(bluetooth.discover(connection), `${stage}: discovering services`);
  const dataIn = characteristics.find((c) => c.serviceUuid === serviceUuid && c.characteristicUuid === dataInUuid);
  const dataOut = characteristics.find((c) => c.serviceUuid === serviceUuid && c.characteristicUuid === dataOutUuid);
  if (!dataIn || !dataOut) {
    throw new Error(
      `peripheral "${peripheralId}" does not expose both required characteristics for service 0x${serviceUuid.toString(16)} (0x${dataInUuid.toString(16)}/0x${dataOutUuid.toString(16)})`,
    );
  }
  const channel = new NotificationChannel();
  // THE PROXY PDU ENVELOPE, on both characteristic pairs — see the module
  // header's own note. `reassembly` is this session's single in-flight
  // reassembly (`proxyPdu.ts`'s `undefined` convention); it lives for the
  // life of the connection and dies with it, because `openSession` is
  // called once per connection and nothing here outlives that.
  let reassembly: ProxyReassemblyState | undefined;

  // ---------------------------------------------------------------------
  // SECTION 6.3.2.2 IS THIS SESSION'S RULE TOO, and it is enforced here
  // rather than left to the stage timeout (final re-review, finding 2 —
  // MEDIUM). The comment that used to stand in this spot argued the
  // opposite and had its arithmetic backwards: "20 seconds is longer than
  // any `timeoutMs` this project passes, so the stage timeout always fires
  // first". DEFAULT_PAIRING_STEP_TIMEOUT_MS is 30_000 and
  // PROXY_SAR_TIMEOUT_MS is 20_000, and `driver.ts` passes no override, so
  // the project's timeout is the LONGER one — the stage timeout fires ten
  // seconds LATE, and the disconnect the specification requires never
  // happened at all.
  //
  // That this session is bound by the Proxy PDU CLIENT rules is not an
  // inference. Section 5.2.2 "PB-GATT": "When PB-GATT is used, the
  // Provisioner shall use the PB-GATT Client role and the unprovisioned
  // device shall use the PB-GATT Server role." and "The PB-GATT Server
  // shall use the Provisioning Server role (see Section 6.2.2) and the
  // PB-GATT Client shall use the Provisioning Client role (see Section
  // 6.2.2)."; Section 6.2.2 "Provisioning PB-GATT bearer roles": "The
  // Provisioning Client is a node that supports the Proxy PDU Client and
  // supports transporting Provisioning PDUs using the Proxy protocol." We
  // are the Provisioner on the provisioning pair and the Proxy Client on
  // the proxy pair, so both of this session's channels are Proxy PDU
  // Client channels.
  //
  // WHAT IS ENFORCED, both from Section 6.3.2.2: "Upon receiving a message
  // with an unexpected value of the SAR field, the Proxy PDU Client shall
  // disconnect." and "The timeout for the SAR transfer is 20 seconds. When
  // the timeout expires, the Proxy PDU Client shall disconnect." The first
  // `acceptProxyPdu` already detects on arrival; the second it cannot,
  // because a transfer that simply STOPS arriving produces no arrival to
  // check — hence a timer, armed exactly as `lib/adapter/connection.ts`
  // arms its own, from the current segment rather than the first (the
  // on-arrival check in `acceptProxyPdu` measures the real deadline from
  // `startedAtMs` regardless, so this timer only has to guarantee a
  // stalled transfer is eventually noticed; it never shortens the window).
  //
  // 'ignored' (an unsupported MessageType, Section 6.3.2) still ends with
  // nothing pushed and nothing dropped — that one the specification really
  // does say to ignore, and any reassembly in progress survives it.
  // ---------------------------------------------------------------------
  let sarTimer: TimerHandle | null = null;
  const clearSarTimer = (): void => {
    if (sarTimer !== null) {
      clock.clearTimeout(sarTimer);
      sarTimer = null;
    }
  };
  const disconnectOnProxyProtocolViolation = (reason: string): void => {
    clearSarTimer();
    reassembly = undefined;
    // Whoever is waiting learns the real reason now, instead of the stage
    // timeout's generic one later — and every later `next()` on this dead
    // session learns it too (see `NotificationChannel.fail`).
    channel.fail(new Error(`${stage}: ${reason}`));
    bluetooth.disconnect(connection).catch(() => {
      // The link is being abandoned either way; a close that itself fails
      // changes nothing this session can act on, and there is no caller
      // left to tell.
    });
  };
  const armSarTimer = (): void => {
    clearSarTimer();
    sarTimer = clock.setTimeout(() => {
      sarTimer = null;
      if (reassembly === undefined) return;
      disconnectOnProxyProtocolViolation(
        'SAR transfer timed out (Section 6.3.2.2: the timeout for the SAR transfer is 20 seconds)',
      );
    }, PROXY_SAR_TIMEOUT_MS);
  };

  await bounded(
    bluetooth.subscribe(dataOut.handle, (pdu) => {
      const result = acceptProxyPdu(reassembly, pdu, clock.now());
      switch (result.kind) {
        case 'ignored':
          reassembly = result.state;
          return;
        case 'incomplete':
          reassembly = result.state;
          armSarTimer();
          return;
        case 'disconnect':
          disconnectOnProxyProtocolViolation(result.reason);
          return;
        case 'complete':
          reassembly = undefined;
          clearSarTimer();
          if (result.messageType === messageType) channel.push(result.message);
          return;
      }
    }),
    `${stage}: subscribing to notifications`,
  );
  return {
    write: async (data: Buffer): Promise<void> => {
      // Section 6.3.2.1 "Segmentation": the segments of one message are
      // written in order, and nothing else goes out in between. This
      // session is strictly request/response (`runProvisioningExchange`
      // and `sendConfigRequest` both await each write), so there is no
      // concurrent writer to interleave with.
      for (const pdu of encodeProxyPdus(messageType, data, MAX_PROXY_PDU_LENGTH)) {
        await bounded(bluetooth.write(dataIn.handle, pdu), `${stage}: writing to the node`);
      }
    },
    next: (): Promise<Buffer> => bounded(channel.next(), `${stage} stalled`),
    nextWithin: (timeoutMs: number): Promise<Buffer | null> => channel.nextWithin(clock, timeoutMs),
    disconnect: (): Promise<void> => {
      // Nothing of this session's own may outlive it: an un-cleared SAR
      // timer would keep a real event loop alive, and would fire against a
      // connection the caller has already closed.
      clearSarTimer();
      return bounded(bluetooth.disconnect(connection), `${stage}: disconnecting`);
    },
  };
}

/** Connects for the PROVISIONING phase (Mesh Provisioning Service). Every
 *  GATT operation this session performs is bounded by `timeoutMs` — see
 *  `openSession`'s own doc comment. */
export function connectForProvisioning(
  bluetooth: BluetoothPort,
  peripheralId: string,
  clock: ClockPort,
  timeoutMs: number,
): Promise<GattSession> {
  return openSession(
    bluetooth,
    peripheralId,
    MESH_PROVISIONING_SERVICE_UUID,
    MESH_PROVISIONING_DATA_IN_UUID,
    MESH_PROVISIONING_DATA_OUT_UUID,
    // Table 6.3: this pair carries Provisioning PDUs and nothing else —
    // Section 7.1.3.1.1 "Characteristic behavior": "The Mesh Provisioning
    // Data In characteristic shall support Proxy PDU messages containing
    // Provisioning PDUs and shall not support other Proxy PDU type
    // messages."
    PROXY_MESSAGE_TYPE_PROVISIONING_PDU,
    clock,
    timeoutMs,
    'provisioning',
  );
}

/** Connects for the CONFIGURATION phase (Mesh Proxy Service) — see the
 *  module header's "TWO GATT SESSIONS" note for why this is a fresh
 *  connection, not the same one. Every GATT operation this session
 *  performs is bounded by `timeoutMs` — see `openSession`'s own doc
 *  comment. */
export function connectForConfiguration(
  bluetooth: BluetoothPort,
  peripheralId: string,
  clock: ClockPort,
  timeoutMs: number,
): Promise<GattSession> {
  return openSession(
    bluetooth,
    peripheralId,
    MESH_PROXY_SERVICE_UUID,
    MESH_PROXY_DATA_IN_UUID,
    MESH_PROXY_DATA_OUT_UUID,
    // Table 6.3: the configuration exchange rides ordinary Network PDUs.
    PROXY_MESSAGE_TYPE_NETWORK_PDU,
    clock,
    timeoutMs,
    'configuration exchange',
  );
}

// ===========================================================================
// The provisioning exchange.
// ===========================================================================

/**
 * Drives `machine.ts`'s `beginProvisioning`/`step` to a terminal phase over
 * `session`, writing every PDU the machine produces and feeding back every
 * notification the channel delivers, in order, until the state reaches
 * `'provisioned'`, `'unsupported'` or `'failed'`. `session` is already
 * bounded end-to-end (`openSession`/`connectForProvisioning` — see the
 * module header's "The clock" note), so every `write`/`next` below already
 * throws, naming the stall, rather than hanging forever against a silent
 * node; this function adds no bounding of its own.
 */
export async function runProvisioningExchange(session: GattSession, input: BeginProvisioningInput): Promise<ProvisioningState> {
  let { state, send } = beginProvisioning(input);
  for (const pdu of send) await session.write(pdu);

  while (state.phase !== 'provisioned' && state.phase !== 'unsupported' && state.phase !== 'failed') {
    const incoming = await session.next();
    ({ state, send } = provisioningStep(state, incoming));
    for (const pdu of send) await session.write(pdu);
  }
  return state;
}

// ===========================================================================
// The configuration exchange.
// ===========================================================================

interface ConfigExchangeInput {
  readonly session: GattSession;
  /** Only `now()`/`setTimeout`/`clearTimeout` are used, and only by the
   *  capability probe at the end of the exchange — see `runConfigExchange`'s
   *  own THE PROBE note. */
  readonly clock: ClockPort;
  /** Overrides `modelProbe.ts`'s own per-probe timeout, for tests. */
  readonly probeTimeoutMs?: number;
  /** Overrides `modelProbe.ts`'s own total probe budget, for tests. */
  readonly probeBudgetMs?: number;
  readonly netKey: Buffer;
  readonly netKeyIndex: number;
  readonly appKey: Buffer;
  readonly appKeyIndex: number;
  readonly ivIndex: number;
  readonly ourAddress: number;
  readonly nodeAddress: number;
  readonly deviceKey: Buffer;
  readonly allocateSeq: () => number;
}

/**
 * `composition` is carried on BOTH variants, not only `'ok'` — review
 * finding (MEDIUM): the extra-element address reservation (see
 * `reserveElementAddresses` below) must happen whenever the element count
 * becomes known, regardless of whether configuration goes on to succeed.
 * `null` on `'failed'` means the failure happened before Composition Data
 * Status was even read (nothing to reserve for); a non-null composition on
 * `'failed'` means it parsed fine but something LATER (AppKey Add, a Model
 * App Bind) was refused or stalled.
 */
export type ConfigExchangeResult =
  | { readonly kind: 'ok'; readonly composition: CompositionData; readonly probe: NodeProbeResult }
  | { readonly kind: 'failed'; readonly message: string; readonly composition: CompositionData | null };

/** Sends one device-key-secured Config message and waits for the (possibly
 *  segmented) reply, decoded all the way to an `AccessMessage`.
 *  `input.session` is already bounded end-to-end (see the module header's
 *  "The clock" note) — this function adds no bounding of its own. */
async function sendConfigRequest(input: ConfigExchangeInput, accessPayload: Buffer): Promise<AccessMessage> {
  const pdus = encodeMeshMessage({
    accessPayload,
    key: input.deviceKey,
    keyKind: 'device',
    src: input.ourAddress,
    dst: input.nodeAddress,
    netKey: input.netKey,
    ivIndex: input.ivIndex,
    // The one exchange in this app that genuinely IS point-to-point: this
    // session holds its own GATT connection to the very node it is
    // configuring, so there is nothing for a relay to do. See `message.ts`'s
    // own TTL note for why this is now spelled out rather than defaulted.
    ttl: POINT_TO_POINT_TTL,
    allocateSeq: input.allocateSeq,
  });
  for (const pdu of pdus) await input.session.write(pdu);

  const receiveContext: MeshReceiveContext = {
    key: input.deviceKey,
    keyKind: 'device',
    netKey: input.netKey,
    ivIndex: input.ivIndex,
    expectedSrc: input.nodeAddress,
  };
  let state: MeshReceiveState | undefined;
  for (;;) {
    const incoming = await input.session.next();
    const result = acceptIncomingPdu(state, receiveContext, incoming);
    if (result.kind === 'complete') return result.message;
    state = result.state;
  }
}

/** Reconstructs the raw Access-message PDU bytes `decodeConfigStatus`
 *  expects, from the already-split `AccessMessage`
 *  `acceptIncomingPdu`/`sendConfigRequest` already decoded it to — cheaper
 *  than giving `client.ts` a second entry point for pre-split fields, and
 *  this module's only caller of `decodeConfigStatus`. */
function toConfigStatus(message: AccessMessage): ReturnType<typeof decodeConfigStatus> {
  return decodeConfigStatus(encodeAccessMessage(message));
}

/**
 * Sends a Config Node Reset over the SAME still-open session and waits for
 * Node Reset Status — review finding (HIGH): without this, any failure
 * AFTER provisioning succeeds orphaned the node permanently (it has already
 * left the Mesh Provisioning Service for the Mesh Proxy Service, so a later
 * scan for unprovisioned nodes can never find it again; no store entry was
 * ever written, so this app holds no device key to reach it with later
 * either). The design: a failed provisioning "leaves the node untouched and
 * can be retried" — once a node is actually provisioned, "untouched" is no
 * longer achievable, but "reset back to the unowned state" is the
 * equivalent a configuration-phase failure can still deliver, using the
 * encoder/decoder pair (`encodeConfigNodeReset`/`decodeConfigStatus`'s
 * `'nodeReset'` variant) that already existed and were already tested but
 * had no caller before this fix. Never throws — a failure to reset is
 * reported back to the caller, never swallowed.
 */
async function attemptNodeReset(input: ConfigExchangeInput): Promise<{ readonly ok: true } | { readonly ok: false; readonly error: string }> {
  try {
    const message = await sendConfigRequest(input, encodeConfigNodeReset());
    const status = toConfigStatus(message);
    if (status === null || status.type !== 'nodeReset') {
      return { ok: false, error: 'node did not answer Config Node Reset with a Node Reset Status message' };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: errorMessage(err) };
  }
}

/** Builds a `'failed'` result, attempting a node reset first (see
 *  `attemptNodeReset`) and naming the outcome of THAT attempt in the
 *  message too — never silently losing whether the node is still orphaned
 *  or has been returned to the unowned state. */
async function failWithReset(input: ConfigExchangeInput, composition: CompositionData | null, message: string): Promise<ConfigExchangeResult> {
  const reset = await attemptNodeReset(input);
  const suffix = reset.ok
    ? ' — the node has been reset and can be paired again'
    : ` — attempted to reset the node so it can be paired again, but that also failed (${reset.error}); it may need a manual factory reset`;
  return { kind: 'failed', message: `${message}${suffix}`, composition };
}

/**
 * The capability probe's own transport (`modelProbe.ts#ProbeTransport`) over
 * this still-open configuration session.
 *
 * APPLICATION KEY, NOT THE DEVICE KEY every other message in this exchange
 * uses: Config messages are device-key-secured (Section 4.3.1), but the
 * LIGHTING models answer on the application key - the very key the Model
 * App Binds immediately above have just bound to them. Probing with the
 * device key would get silence from every model and the probe would
 * conclude, wrongly and confidently, that the node implements none of them.
 *
 * `accept` is handed the re-encoded ACCESS message (Opcode || Parameters),
 * which is the shape every `lib/models/lighting.ts` decoder takes - the
 * same reshape `meshLight.ts#tryDecodeModel` performs for the same reason.
 *
 * KEEPS WAITING WITHIN ITS OWN WINDOW for something `accept` likes, rather
 * than resolving on the first PDU to arrive. A previous probe's LATE answer
 * is the case that matters: resolving on it would turn one model's silence
 * into the next model's false `'supported'`, which is precisely the
 * conclusion this whole mechanism exists to get right.
 */
function createProbeTransport(input: ConfigExchangeInput): ProbeTransport {
  const receiveContext: MeshReceiveContext = {
    key: input.appKey,
    keyKind: 'application',
    netKey: input.netKey,
    ivIndex: input.ivIndex,
    expectedSrc: input.nodeAddress,
  };
  return {
    async request(accessPayload: Buffer, accept: (pdu: Buffer) => boolean, timeoutMs: number): Promise<Buffer | null> {
      const pdus = encodeMeshMessage({
        accessPayload,
        key: input.appKey,
        keyKind: 'application',
        aid: k4(input.appKey),
        src: input.ourAddress,
        dst: input.nodeAddress,
        netKey: input.netKey,
        ivIndex: input.ivIndex,
        // Point-to-point for the same reason `sendConfigRequest` is: this
        // session holds its own GATT connection to the very node being
        // probed, so there is nothing for a relay to do.
        ttl: POINT_TO_POINT_TTL,
        allocateSeq: input.allocateSeq,
      });
      for (const pdu of pdus) await input.session.write(pdu);

      const deadline = input.clock.now() + timeoutMs;
      let state: MeshReceiveState | undefined;
      for (;;) {
        const remaining = deadline - input.clock.now();
        if (remaining <= 0) return null;
        const incoming = await input.session.nextWithin(remaining);
        if (incoming === null) return null;
        const result = acceptIncomingPdu(state, receiveContext, incoming);
        if (result.kind !== 'complete') {
          state = result.state;
          continue;
        }
        state = undefined;
        const reencoded = encodeAccessMessage(result.message);
        if (accept(reencoded)) return reencoded;
        // Decoded cleanly, but it is not what this request asked for (a
        // stale answer, or an unsolicited report) - keep waiting inside the
        // same window rather than reporting it as this request's reply.
      }
    },
  };
}

/** Nothing measured - what a node gets when the probe could not run at all. */
const EMPTY_PROBE_RESULT: NodeProbeResult = { models: {}, temperatureRange: null };

/**
 * Runs the capability probe, and CANNOT FAIL PAIRING. The probe is an
 * optimisation of a pairing that has already succeeded - composition read,
 * application key added, every model bound - so an exception from it (an
 * encoder refusing a Prohibited value a node reported for itself, say) must
 * cost the user their measurement, never their bulb. `probeModels` already
 * turns a lost link and an unanswered message into ordinary verdicts; this
 * wrapper is for everything else.
 */
async function runProbe(input: ConfigExchangeInput, composition: CompositionData): Promise<NodeProbeResult> {
  try {
    return await probeModels(
      {
        transport: createProbeTransport(input),
        clock: input.clock,
        probeTimeoutMs: input.probeTimeoutMs,
        probeBudgetMs: input.probeBudgetMs,
      },
      composition,
    );
  } catch {
    return EMPTY_PROBE_RESULT;
  }
}

/**
 * Reads composition data, adds the application key, and binds it to every
 * one of the node's SIG models this design maps to a Homey capability
 * (`LIGHTING_SERVER_MODEL_IDS`) — the design's "adds the application key,
 * reads the composition data and binds the key to the node's models", in
 * that dependency order (binding needs to know WHICH models exist, which
 * composition data is what reveals). Every failure path — including an
 * unexpected exception (e.g. a stalled wait timing out mid-exchange) —
 * attempts a node reset before returning; see `failWithReset`.
 */
export async function runConfigExchange(input: ConfigExchangeInput): Promise<ConfigExchangeResult> {
  let knownComposition: CompositionData | null = null;
  try {
    const compositionReply = toConfigStatus(await sendConfigRequest(input, encodeConfigCompositionDataGet(0)));
    if (compositionReply === null || compositionReply.type !== 'compositionData') {
      return await failWithReset(input, null, 'node did not answer Config Composition Data Get with a Composition Data Status message');
    }
    if (compositionReply.composition === null) {
      // See the module header's COMPOSITION DATA THAT DOES NOT PARSE note —
      // genuinely cannot say more than this without guessing.
      return await failWithReset(
        input,
        null,
        "the node's composition data could not be parsed (malformed or truncated Composition Data Page 0)",
      );
    }
    knownComposition = compositionReply.composition;
    const composition = knownComposition;

    const appKeyReply = toConfigStatus(
      await sendConfigRequest(
        input,
        encodeConfigAppKeyAdd({ netKeyIndex: input.netKeyIndex, appKeyIndex: input.appKeyIndex, appKey: input.appKey }),
      ),
    );
    if (appKeyReply === null || appKeyReply.type !== 'appKey') {
      return await failWithReset(input, composition, 'node did not answer Config AppKey Add with an AppKey Status message');
    }
    if (appKeyReply.status !== 0x00) {
      return await failWithReset(
        input,
        composition,
        `Config AppKey Add was refused: ${appKeyReply.statusName ?? `status 0x${appKeyReply.status.toString(16)}`}`,
      );
    }

    for (const [elementIndex, element] of composition.elements.entries()) {
      for (const modelId of LIGHTING_SERVER_MODEL_IDS) {
        if (!element.sigModels.includes(modelId)) continue;
        const elementAddress = input.nodeAddress + elementIndex;
        const bindReply = toConfigStatus(
          await sendConfigRequest(
            input,
            encodeConfigModelAppBind({ elementAddress, appKeyIndex: input.appKeyIndex, modelIdentifier: modelId }),
          ),
        );
        if (bindReply === null || bindReply.type !== 'modelApp') {
          return await failWithReset(
            input,
            composition,
            `node did not answer Config Model App Bind (element ${elementIndex}, model 0x${modelId.toString(16)}) with a Model App Status message`,
          );
        }
        if (bindReply.status !== 0x00) {
          return await failWithReset(
            input,
            composition,
            `Config Model App Bind was refused for element ${elementIndex}, model 0x${modelId.toString(16)}: ${bindReply.statusName ?? `status 0x${bindReply.status.toString(16)}`}`,
          );
        }
      }
    }

    // THE PROBE, last and deliberately so: it needs the application key
    // bound to the node's models (every Model App Bind above) before any
    // lighting model will answer it at all. See `modelProbe.ts`'s own
    // module header for what it measures and why silence counts as a
    // negative in this one place.
    const probe = await runProbe(input, composition);
    return { kind: 'ok', composition, probe };
  } catch (err) {
    return failWithReset(input, knownComposition, `configuration exchange failed unexpectedly: ${errorMessage(err)}`);
  }
}

// ===========================================================================
// First-run network initialisation — see the module header's INHERITED
// ADDRESS-ADVANCE HAZARD note for the discipline this follows.
// ===========================================================================

const FIRST_NET_KEY_INDEX = 0;
const FIRST_APP_KEY_INDEX = 0;
const KEY_LENGTH = 16; // AES-128, matching store.ts's own KEY_LENGTH.

/** Generates the network's one network key and one application key on
 *  first run (design: "We generate one network key and one application key
 *  on first run"), and allocates our own unicast address — a no-op once
 *  `netKey` is already set. */
function ensureNetworkInitialized(store: NetworkStore, random: ProvisioningRandomSource): void {
  if (store.getState().netKey !== null) return;

  const netKey = random.randomBytes(KEY_LENGTH);
  const appKey = random.randomBytes(KEY_LENGTH);
  // store's own internal read-modify-write; safe on its own (store.ts's
  // own CALLER HAZARD comment is about what callers do AROUND this call,
  // not about this call itself).
  const ourAddress = store.allocateUnicastAddress();
  // Re-read AFTER allocating, never reuse a snapshot taken before it — see
  // the module header's INHERITED ADDRESS-ADVANCE HAZARD note.
  const fresh = store.getState();
  store.setState({
    ...fresh,
    netKey,
    netKeyIndex: FIRST_NET_KEY_INDEX,
    appKey,
    appKeyIndex: FIRST_APP_KEY_INDEX,
    ourUnicastAddress: ourAddress,
  });
}

// ===========================================================================
// pairNode — the one entry point driver.ts calls.
// ===========================================================================

export interface PairingDeps {
  readonly bluetooth: BluetoothPort;
  readonly store: NetworkStore;
  readonly random: ProvisioningRandomSource;
  /** See the module header's "The clock" note — every bounded wait for a
   *  reply in one pairing attempt is driven by this. */
  readonly clock: ClockPort;
  /** Overrides `DEFAULT_PAIRING_STEP_TIMEOUT_MS` for this attempt. */
  readonly stepTimeoutMs?: number;
  /** Overrides `modelProbe.ts#DEFAULT_PROBE_TIMEOUT_MS` for this attempt - injected so tests drive the probe's own timing without waiting on it. */
  readonly probeTimeoutMs?: number;
  /** Overrides `modelProbe.ts#DEFAULT_PROBE_BUDGET_MS` for this attempt. */
  readonly probeBudgetMs?: number;
}

export interface PairedDeviceDescriptor {
  readonly name: string;
  /** Homey device data — `id` is the node's own unicast address, stable
   *  for the node's lifetime in this network (task 7's device.ts looks
   *  nodes up by it). */
  readonly data: { readonly id: string };
  readonly capabilities: ReadonlyArray<HomeyCapability>;
  /** Opaque to Homey; carries the peripheral id this node was last seen
   *  advertising under, for task 7's connection use. */
  readonly store: { readonly peripheralId: string };
  /** Initial per-device settings (`driver.compose.json`'s own `settings`
   *  block) - the colour-temperature range, seeded from what the node
   *  reported about itself at pairing time, or from the documented
   *  fallback when it reported nothing. The user can correct it afterward;
   *  see `temperatureRange.ts`. */
  readonly settings: { readonly temperature_min_kelvin: number; readonly temperature_max_kelvin: number };
}

export type PairingOutcome =
  | { readonly kind: 'paired'; readonly device: PairedDeviceDescriptor }
  | { readonly kind: 'unsupported'; readonly reason: string }
  | { readonly kind: 'failed'; readonly message: string };

async function disconnectQuietly(session: GattSession): Promise<void> {
  try {
    await session.disconnect();
  } catch {
    // A failed (or, review finding, HUNG) disconnect of a session we are
    // already done with is not worth failing the whole pairing attempt
    // over — the peripheral either already dropped the link itself, or
    // `session.disconnect()`'s own bound (every GATT operation `openSession`
    // returns is bounded by the clock — see the module header's "The
    // clock" note) eventually turns a hang into a rejection this catch
    // swallows the same way it swallows an ordinary failure.
  }
}

/**
 * Provisions `peripheralId`, allocates its unicast address, adds the
 * application key, reads its composition data and binds the key to its
 * models — the design's own sentence, in that order. Returns a result the
 * caller can show in the pairing wizard directly; never throws for an
 * ordinary pairing failure (connection/protocol/parse problems are all
 * reported through `PairingOutcome`, not an exception) — see the module
 * header's NODE ENTRIES ARE WRITTEN ONLY ON COMPLETE SUCCESS note for what
 * happens to the store on every non-`'paired'` outcome.
 */
export async function pairNode(deps: PairingDeps, peripheralId: string): Promise<PairingOutcome> {
  const timeoutMs = deps.stepTimeoutMs ?? DEFAULT_PAIRING_STEP_TIMEOUT_MS;
  let provisioningSession: GattSession;
  try {
    provisioningSession = await connectForProvisioning(deps.bluetooth, peripheralId, deps.clock, timeoutMs);
  } catch (err) {
    return { kind: 'failed', message: `could not connect to "${peripheralId}" for provisioning: ${errorMessage(err)}` };
  }

  try {
    ensureNetworkInitialized(deps.store, deps.random);
    const nodeAddress = deps.store.allocateUnicastAddress();

    // Re-read AFTER allocating (same discipline as ensureNetworkInitialized
    // above) — these fields are guaranteed non-null now.
    const fresh = deps.store.getState();
    const netKey = fresh.netKey as Buffer;
    const netKeyIndex = fresh.netKeyIndex as number;
    const appKey = fresh.appKey as Buffer;
    const appKeyIndex = fresh.appKeyIndex as number;
    const ivIndex = fresh.ivIndex;
    const ourAddress = fresh.ourUnicastAddress as number;

    const provisioningInput: BeginProvisioningInput = {
      attentionDuration: 0,
      ephemeralKeyPair: deps.random.generateEphemeralKeyPair(),
      randomProvisioner: deps.random.randomBytes(16),
      provisioningData: { netKey, netKeyIndex, flags: 0, ivIndex, unicastAddress: nodeAddress },
    };

    const finalState = await runProvisioningExchange(provisioningSession, provisioningInput);
    await disconnectQuietly(provisioningSession);

    if (finalState.phase === 'unsupported') {
      return { kind: 'unsupported', reason: finalState.reason };
    }
    if (finalState.phase === 'failed') {
      return { kind: 'failed', message: `provisioning failed: ${finalState.errorName} — ${finalState.reason}` };
    }
    if (finalState.phase !== 'provisioned') {
      // Unreachable in practice — runProvisioningExchange's own loop only
      // returns once the phase is one of the three terminal ones, so by
      // here it is always 'provisioned' — but its return type is the FULL
      // ProvisioningState union, which TypeScript cannot narrow past the
      // two checks above on its own (they name-check two of five
      // non-provisioned variants, not all five). This guard is what lets
      // `finalState.deviceKey` below typecheck AND gives a safe, honestly-
      // worded fallback instead of a silent `undefined` if that invariant
      // is ever broken by a future change to runProvisioningExchange.
      return { kind: 'failed', message: `pairing ended in an unexpected internal phase "${finalState.phase}"` };
    }
    const deviceKey = finalState.deviceKey;

    let configSession: GattSession;
    try {
      configSession = await connectForConfiguration(deps.bluetooth, peripheralId, deps.clock, timeoutMs);
    } catch (err) {
      // No session, no way to send a reset — the node is provisioned but
      // unreachable right now. Said plainly, not hidden behind a generic
      // message: see the report's disclosed residual risk for this path.
      return {
        kind: 'failed',
        message: `provisioned "${peripheralId}", but could not reconnect for configuration: ${errorMessage(err)} — the node is provisioned but could not be reset, and may need a manual factory reset`,
      };
    }

    try {
      const exchangeResult = await runConfigExchange({
        session: configSession,
        clock: deps.clock,
        probeTimeoutMs: deps.probeTimeoutMs,
        probeBudgetMs: deps.probeBudgetMs,
        netKey,
        netKeyIndex,
        appKey,
        appKeyIndex,
        ivIndex,
        ourAddress,
        nodeAddress,
        deviceKey,
        allocateSeq: () => deps.store.allocateSequenceBlock(),
      });
      await disconnectQuietly(configSession);

      // Review finding (MEDIUM): reserve the extra-element addresses as
      // soon as the element count is known, regardless of whether
      // configuration goes on to succeed — a node that provisions with N
      // elements occupies N consecutive addresses the moment it is
      // provisioned, independent of whether AppKey Add/Model App Bind ever
      // complete. Done here, not inside `finishPairing`, which no longer
      // touches `nextUnicastAddress` at all (see that function's own
      // comment).
      if (exchangeResult.composition !== null) {
        reserveElementAddresses(deps.store, exchangeResult.composition);
      }

      if (exchangeResult.kind === 'failed') {
        return { kind: 'failed', message: exchangeResult.message };
      }
      return finishPairing(deps.store, peripheralId, nodeAddress, deviceKey, exchangeResult.composition, exchangeResult.probe);
    } catch (err) {
      // Defensive only: runConfigExchange catches its own exceptions
      // internally now (attempting a reset first — see failWithReset) and
      // should never actually throw; kept so an unforeseen bug here still
      // produces an honest failure instead of an unhandled rejection.
      await disconnectQuietly(configSession);
      return { kind: 'failed', message: `configuring "${peripheralId}" failed: ${errorMessage(err)}` };
    }
  } catch (err) {
    await disconnectQuietly(provisioningSession);
    return { kind: 'failed', message: `pairing "${peripheralId}" failed: ${errorMessage(err)}` };
  }
}

/**
 * Advances the store's next-free unicast address past a multi-element
 * node's EXTRA elements (the node's own primary address was already
 * allocated via `store.allocateUnicastAddress()` before provisioning — see
 * the module header's INHERITED ADDRESS-ADVANCE HAZARD note). Called as
 * soon as the element count is known, win or lose — see `pairNode`'s own
 * comment at its one call site for why this must not wait for success.
 * A no-op for a single-element node (nothing extra to reserve). Follows the
 * same "re-read immediately before the one `setState`" discipline as
 * `ensureNetworkInitialized`.
 */
function reserveElementAddresses(store: NetworkStore, composition: CompositionData): void {
  if (composition.elements.length <= 1) return;
  const fresh = store.getState();
  store.setState({ ...fresh, nextUnicastAddress: fresh.nextUnicastAddress + (composition.elements.length - 1) });
}

/** The ONE place this module writes a node entry. Does NOT touch
 *  `nextUnicastAddress` (see `reserveElementAddresses` above, which the
 *  caller runs separately and unconditionally once composition is known). */
function finishPairing(
  store: NetworkStore,
  peripheralId: string,
  nodeAddress: number,
  deviceKey: Buffer,
  composition: CompositionData,
  probe: NodeProbeResult,
): PairingOutcome {
  const fresh = store.getState();
  // The probe is stored ALONGSIDE the composition, not instead of it: the
  // declaration is still what says which models exist to probe at all, and
  // a later version of this app may measure differently. Both are kept.
  store.setState({
    ...fresh,
    nodes: [...fresh.nodes, { address: nodeAddress, deviceKey, composition, probe }],
  });

  // MEASUREMENT FIRST, DECLARATION WHERE THERE IS NONE - see
  // `capabilities.ts#mapCompositionToCapabilities`. This is the one line
  // that makes the probe matter: a node that declares a model and was
  // measured not to run it does not get that model's capability.
  const assignments = mapCompositionToCapabilities(composition, probe);
  const capabilities: HomeyCapability[] = [];
  for (const assignment of assignments) {
    if (!capabilities.includes(assignment.capability)) capabilities.push(assignment.capability);
  }

  // The per-device range settings start from what the node reported, and
  // from the documented fallback when it reported nothing - see
  // `temperatureRange.ts`'s own module header for the full precedence
  // order and for what goes wrong on a silent bulb with a different range.
  const range = probe.temperatureRange ?? DEFAULT_TEMPERATURE_RANGE;

  return {
    kind: 'paired',
    device: {
      name: `Mesh light ${nodeAddress}`,
      data: { id: String(nodeAddress) },
      capabilities,
      store: { peripheralId },
      settings: { temperature_min_kelvin: range.minKelvin, temperature_max_kelvin: range.maxKelvin },
    },
  };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
