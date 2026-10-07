/**
 * The proxy connection manager (docs/superpowers/specs/2026-10-06-ble-mesh-
 * provisioner-design.md, "The Homey layer" > "Connection manager"): "One
 * connection serves the whole mesh, not one per bulb. It scans for nodes
 * advertising the proxy service, checks that the advertised network
 * identity derives from *our* network key so a neighbour's installation can
 * never be mistaken for ours, connects to the strongest, subscribes to
 * notifications and writes commands. On disconnect it rescans, picks the
 * next node and reconnects with increasing backoff."
 *
 * This is lib/adapter, not lib/mesh: it is the one piece of this design
 * that drives a Bluetooth radio, so it may never be imported from lib/mesh
 * (see lib/__tests__/import-boundary.test.ts). It takes a `BluetoothPort`
 * and a `ClockPort` rather than `homey` itself, the same shape `store.ts`
 * established for its own `SettingsPort`: narrow ports in, so this whole
 * module is testable without a radio and without a real clock (see
 * lib/adapter/__tests__/connection.test.ts, which only ever constructs the
 * fakes in lib/adapter/__tests__/fakeBluetooth.ts and fakeClock.ts).
 *
 * THE ADVERTISED NETWORK IDENTITY. Table 7.7 "Service Data for Mesh Proxy
 * Service" gives every proxy advertisement the same envelope regardless of
 * what it is advertising: a 1-octet Identification Type followed by
 * variable-length Identification Parameters whose format Table 7.8
 * ("Identification Type values") hands off per type — 0x00 Network ID
 * type, 0x01 Node Identity type, 0x02 Private Network Identity type, 0x03
 * Private Node Identity type, 0x04-0xFF reserved. Only the first of those,
 * Network ID (Section 7.2.2.2.2 "Advertising with Network ID", Table 7.11
 * "Service Data for Mesh Proxy Service with Network ID"), is a fixed value
 * derived from the network key alone, with nothing random or rotating in
 * it — Section 3.9.6.3.2 "Network ID": "The Network ID is derived from the
 * network key such that each network key generates one Network ID. This
 * identifier becomes public information." and the formula right after it:
 * `Network ID=k3(NetKey)`. That is the one check this module can make with
 * nothing but the bytes already sitting in an advertisement and the network
 * key already sitting in the store — no connection, no decryption, no
 * rotating state to track. The OTHER three identification types exist
 * precisely to let a node be found WITHOUT handing out this public value
 * (Node Identity; the Private variants additionally encrypt it) and are not
 * something this module can check at all without a live connection. This
 * module therefore only ever matches type 0x00; every other type, or a
 * payload of the wrong length for that type, is simply never ours — see
 * `isOurNetworkId` below.
 *
 * THE KNOWN-ANSWER TEST. Section 8.6.1 "Service data using Network ID"
 * (under "8.6 Mesh Proxy Service sample data") publishes a complete sample:
 * a NetKey, the Network ID k3 derives from it, AND the full byte-for-byte
 * advertising data this module has to recognise — see
 * NETWORK_ID_ADVERTISING_SAMPLE in __tests__/fakeBluetooth.ts and the
 * known-answer test built from it in connection.test.ts. k3 itself is
 * already implemented and separately known-answer-tested (a DIFFERENT
 * sample, Section 8.1.5) in lib/mesh/crypto/derive.ts/__tests__ — this
 * module imports that implementation rather than re-deriving it, exactly as
 * the plan's "Type consistency" note intends.
 *
 * THE PROXY PDU ENVELOPE (added in the final fix wave; this module used to
 * write BARE Network PDUs and parse notifications as if they were bare,
 * which no node can understand). Section 3.3.2 "GATT bearer": "The GATT
 * bearer uses the Proxy protocol (see Section 6) to transmit and receive
 * Proxy PDUs between two devices over a GATT connection." Section 7.2.3.1
 * "Mesh Proxy Data In characteristic": "The characteristic value has the
 * same format as the Proxy PDU." The envelope itself — the one-octet
 * SAR/MessageType header, its segmentation rules, its reassembly rules and
 * its 20-second SAR timeout — is transcribed and tested in
 * `lib/mesh/packet/proxyPdu.ts`; this module does the I/O around it: it
 * segments every outgoing Network PDU (`write` below), reassembles every
 * incoming notification (`handleNotification`), delivers only completed
 * Network PDU messages to its listeners, and DISCONNECTS when the
 * specification says to (Section 6.3.2.2 "Reassembly": "Upon receiving a
 * message with an unexpected value of the SAR field, the Proxy PDU Client
 * shall disconnect."). `MAX_PROXY_PDU_LENGTH` below is the one engineering
 * input that work needs.
 *
 * IV INDEX: A DESIGN CLAUSE DELIBERATELY NOT IMPLEMENTED, stated here
 * rather than left looking implemented. The design says "The IV index is
 * followed from the secure network beacons the nodes emit; we never start
 * an IV update ourselves." The second half is true by construction — this
 * app has no code that could start an IV Update procedure (Section 3.11.5
 * "IV Update procedure"). The FIRST half is not implemented: a Secure
 * Network beacon (Section 3.10.3 "Secure Network beacon": "The Secure
 * Network beacon is used by nodes to identify the subnet and its security
 * state.") arrives as a Proxy PDU with MessageType 0x01 (Table 6.3), and
 * nothing here, or anywhere else in this app, decodes one — `proxyPdu.ts`
 * classifies that type as unsupported and this module drops it. The stored
 * `ivIndex` is therefore whatever pairing wrote and never moves.
 * WHY THAT IS SAFE HERE, and the conditions under which it stops being
 * safe: the IV Index is a network-wide value (Section 3.9.4 "IV Index":
 * "The IV Index is a 32-bit value that is a shared network resource") that
 * changes only through the IV Update procedure, which only a node already
 * in the network can start. We own this network outright: three bulbs we
 * provisioned ourselves, none of which is a Provisioner, and nothing in
 * this app ever initiates an update. So the value this app wrote at
 * pairing time is the value the network keeps. It stops being safe the
 * moment a FOURTH party joins this network — another provisioner, a
 * gateway, a node that itself starts an update — at which point every
 * message this app sends would authenticate under the wrong IV Index and
 * simply be dropped by every node, silently and permanently, until the app
 * is re-paired. That is the failure to look for first if the whole mesh
 * goes deaf at once after someone else touched it.
 *
 * GATT SHAPE. Section 7.2.3 "Mesh Proxy Service characteristics", Table
 * 7.15: "Mesh Proxy Data In", Write Without Response, and "Mesh Proxy Data
 * Out", Notify — no acknowledgement at the GATT layer either way, which is
 * exactly why "drop a write silently" is one of the fake port's required
 * behaviours (WHAT YOU NEED TO KNOW section of the task brief) rather than
 * a corner this module invented: Write Without Response genuinely gives no
 * confirmation that the peripheral did anything with what was written.
 * Verifying that a write actually took effect is the traffic queue's job
 * (a later task), not this module's. The service and characteristic UUIDs
 * (MESH_PROXY_SERVICE_UUID/MESH_PROXY_DATA_IN_UUID/MESH_PROXY_DATA_OUT_UUID
 * below) are transcribed from the Bluetooth SIG "Assigned Numbers" document
 * (version date 2026-10-05, 1,324,070 bytes, fetched 2026-10-07 from
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/
 * Assigned_Numbers/out/en/Assigned_Numbers.pdf), Section 3.4.1 "Services by
 * Name" and Section 3.8.1 "Characteristics by Name" respectively.
 *
 * WHAT THIS MODULE DOES NOT TEST ITSELF AGAINST. There is no published
 * sample of a connection migrating between proxy nodes, of a backoff
 * schedule, or of a device going unavailable — the task brief says so
 * plainly. Selection, migration, backoff and availability below are this
 * project's OWN design, pinned by behavioural tests against the fakes, not
 * by anything the specification publishes. See connection.test.ts.
 *
 * NULLISH CONVENTION: `null` throughout, matching store.ts — the manager's
 * reported `peripheralId` is `null` whenever `status` is not `'connected'`,
 * never `undefined`. `ScanResult.serviceData` (below) follows the same
 * "absent is empty, never a bare null/undefined" rule a `ReadonlyArray`
 * already gives for free — a peripheral advertising no service data at all
 * is simply an empty array, not a third spelling of "nothing here".
 *
 * SCAN RESULT SHAPE, GENERALISED (task 6 / pairing). This module used to
 * give every `ScanResult` one `proxyServiceData: Buffer | null` field,
 * hardcoded to the single service THIS module happens to care about. Task
 * 6's pairing flow scans for a DIFFERENT service entirely (the Mesh
 * Provisioning Service, `MESH_PROVISIONING_SERVICE_UUID` below) through the
 * exact same `BluetoothPort.scan()`/`FakeBluetoothPort`, so one hardcoded
 * field cannot serve both callers without one of them reading a field named
 * after the OTHER'S service. `serviceData` below is the general shape
 * instead — every Service Data entry a scan result advertised, keyed by
 * service UUID, mirroring Homey's own real
 * `BleAdvertisement.serviceData: {uuid, data}[]` (`@types/homey`'s
 * `BleAdvertisement.d.ts`) rather than inventing a parallel shape this
 * project would have to translate from scratch. `findServiceData` below is
 * the one lookup helper both this module's own `isOurNetworkId` and
 * `drivers/light/pairing.ts` use, rather than two call sites each
 * re-deriving the same `.find(...)`.
 */

import { k3 } from '../mesh/crypto/derive';
import {
  acceptProxyPdu,
  encodeProxyPdus,
  PROXY_MESSAGE_TYPE_NETWORK_PDU,
  PROXY_SAR_TIMEOUT_MS,
  type ProxyReassemblyState,
} from '../mesh/packet/proxyPdu';
import { withTimeout } from './timeout';

// Assigned Numbers, Section 3.4.1 "Services by Name": Mesh Proxy Service.
export const MESH_PROXY_SERVICE_UUID = 0x1828;
// Assigned Numbers, Section 3.8.1 "Characteristics by Name".
export const MESH_PROXY_DATA_IN_UUID = 0x2add;
export const MESH_PROXY_DATA_OUT_UUID = 0x2ade;

// Assigned Numbers, Section 3.4.1 "Services by Name": Mesh Provisioning
// Service — the service an UNPROVISIONED node (no owner) advertises, unlike
// Mesh Proxy Service above, which only a PROVISIONED node advertises.
// Transcribed from the SAME fetch the three proxy constants above already
// cite (version date 2026-10-05, 1,324,070 bytes) — re-fetched 2026-10-07
// and re-extracted with `pdftotext -layout` for this task: "Mesh
// Provisioning Service" appears on the identical page (67 of 446) as "Mesh
// Proxy Service", one row above it in the same table.
export const MESH_PROVISIONING_SERVICE_UUID = 0x1827;
// Assigned Numbers, Section 3.8.1 "Characteristics by Name" — same
// re-fetch/re-extraction as above; both appear on page 83 of 446, directly
// above the two Mesh Proxy characteristics this module already cites.
export const MESH_PROVISIONING_DATA_IN_UUID = 0x2adb;
export const MESH_PROVISIONING_DATA_OUT_UUID = 0x2adc;

// Table 7.8 "Identification Type values": 0x00 is the Network ID type: the
// only one this module can check without a live connection (see the module
// header). Table 7.11's Network ID field is 8 octets.
const NETWORK_ID_TYPE = 0x00;
const NETWORK_ID_LENGTH = 8;

// AES-128 key material is 16 octets (Table 5.47, the Network Key) — the same
// bound already transcribed under this name in lib/adapter/store.ts and
// several lib/mesh modules; repeated here per this project's established
// per-module convention (each module keeps its own copy rather than
// importing a shared constant — see store.ts's own comment on the same
// choice) rather than imported.
const NET_KEY_LENGTH = 16;

/** One Service Data advertising entry — the Service Data VALUE a peripheral
 *  advertised for ONE service UUID (Table 7.7's envelope, Identification
 *  Type followed by its parameters, for the Mesh Proxy/Provisioning
 *  Services — opaque bytes for any other service this module never
 *  interprets), with the UUID itself and the surrounding AD structure bytes
 *  (AD Length, AD Type) already stripped. */
export interface ServiceDataEntry {
  readonly serviceUuid: number;
  readonly data: Buffer;
}

/**
 * One BLE advertisement observed during a scan window. `serviceData` is
 * every Service Data entry this peripheral advertised, keyed by service
 * UUID — the shape a real platform BLE scan API hands back (Homey's own
 * `BleAdvertisement.serviceData` is exactly `{uuid, data}[]`, see the module
 * header's SCAN RESULT SHAPE note), general enough for every caller of
 * `scan()` to look up the ONE service UUID it cares about
 * (`findServiceData` below) without this interface hardcoding which
 * service that is. An advertisement carrying no service data at all is
 * simply an empty array — see the module header's NULLISH CONVENTION note.
 */
export interface ScanResult {
  readonly peripheralId: string;
  /** Received Signal Strength Indicator, in dBm. Less negative is stronger
   *  (e.g. -40 is a stronger signal than -70). */
  readonly rssi: number;
  readonly serviceData: ReadonlyArray<ServiceDataEntry>;
}

/** Looks up ONE service's Service Data value in a scan result, or `null` if
 *  the advertisement carried none for that service UUID — the one place
 *  this lookup is written, shared by this module's own `isOurNetworkId` and
 *  by `drivers/light/pairing.ts` (which looks up
 *  `MESH_PROVISIONING_SERVICE_UUID` instead of this module's
 *  `MESH_PROXY_SERVICE_UUID`). */
export function findServiceData(result: ScanResult, serviceUuid: number): Buffer | null {
  const entry = result.serviceData.find((candidate) => candidate.serviceUuid === serviceUuid);
  return entry === undefined ? null : entry.data;
}

/** Opaque handle to an open GATT connection, returned by `connect` and
 *  consumed by `discover`/`disconnect`. This module never inspects it. */
export type ConnectionHandle = unknown;

/** Opaque handle to one discovered characteristic, returned by `discover`
 *  and consumed by `read`/`write`/`subscribe`. This module never inspects
 *  it, only passes back exactly what `discover` gave it. */
export type CharacteristicHandle = unknown;

export interface DiscoveredCharacteristic {
  readonly serviceUuid: number;
  readonly characteristicUuid: number;
  readonly handle: CharacteristicHandle;
}

export interface Subscription {
  unsubscribe(): void;
}

/**
 * The narrow Bluetooth port this module consumes instead of `homey`
 * directly (see the module header). Modelled on what a real platform BLE
 * API offers — scan, connect, discover, read, write, subscribe, disconnect
 * — rather than on the Mesh Proxy Service's own PDU format, which is a
 * later task's concern (the traffic queue, and the pairing flow, both of
 * which reuse this exact port and its fake — see
 * lib/adapter/__tests__/fakeBluetooth.ts).
 */
export interface BluetoothPort {
  /** One scan window; resolves with every advertisement seen during it
   *  (an empty array is a completely ordinary result, not an error). */
  scan(durationMs: number): Promise<ScanResult[]>;
  /**
   * Opens a GATT connection to the given peripheral. `onDisconnect` is
   * called AT MOST ONCE, whenever the link drops for any reason OTHER than
   * this module's own `disconnect` call below (the far end losing power, a
   * radio error, a timeout) — never for a clean `disconnect()` this module
   * initiated itself, which is how it tells "the node went away" apart from
   * "we chose to let go of it."
   */
  connect(peripheralId: string, onDisconnect: () => void): Promise<ConnectionHandle>;
  /** GATT service/characteristic discovery against an open connection. */
  discover(connection: ConnectionHandle): Promise<DiscoveredCharacteristic[]>;
  read(characteristic: CharacteristicHandle): Promise<Buffer>;
  /** Write Without Response at the GATT layer (Table 7.15) — resolving
   *  means the radio accepted the write, NOT that the node acted on it;
   *  see the module header. */
  write(characteristic: CharacteristicHandle, data: Buffer): Promise<void>;
  subscribe(characteristic: CharacteristicHandle, onNotify: (data: Buffer) => void): Promise<Subscription>;
  /** A clean, caller-initiated close. Must NOT invoke the `onDisconnect`
   *  callback that was passed to `connect` for this same connection. */
  disconnect(connection: ConnectionHandle): Promise<void>;
}

/** Opaque handle to a pending timer, returned by `setTimeout` and consumed
 *  by `clearTimeout`. This module never inspects it. */
export type TimerHandle = unknown;

/**
 * The narrow clock port backoff is driven through, so it is testable by
 * advancing virtual time rather than by actually waiting (task brief,
 * "WHAT YOU NEED TO KNOW": "The clock must be a port too"). A real
 * implementation wraps `Date.now`/`setTimeout`/`clearTimeout`; the fake in
 * lib/adapter/__tests__/fakeClock.ts advances virtual time deliberately
 * instead.
 */
export interface ClockPort {
  now(): number;
  setTimeout(callback: () => void, delayMs: number): TimerHandle;
  clearTimeout(handle: TimerHandle): void;
}

/** What `ProxyConnectionManager.getState` reports. `peripheralId` is
 *  non-null if and only if `status` is `'connected'` — never `undefined`
 *  for the disconnected case, matching this module's nullish convention. */
export interface ProxyConnectionState {
  readonly status: 'connected' | 'unavailable';
  readonly peripheralId: string | null;
}

export interface ProxyConnectionOptions {
  /** The maximum size of one outgoing Proxy PDU, header included. Defaults
   *  to `MAX_PROXY_PDU_LENGTH`; see that constant for why it is an
   *  engineering choice rather than a transcribed value, and why it is
   *  injectable at all (a test that wants to observe segmentation, or to
   *  avoid it, says so explicitly instead of depending on the default). */
  readonly maxProxyPduLength?: number;
  /** How long ONE `BluetoothPort.write` may take before this module stops
   *  waiting on it. Defaults to `PROXY_WRITE_TIMEOUT_MS`; injectable for
   *  the same reason `maxProxyPduLength` is — a test that wants to observe
   *  the bound says which bound rather than depending on the default. */
  readonly proxyWriteTimeoutMs?: number;
  /** Where this module reports a specification-mandated disconnect (see
   *  `LogPort`). Omitted, those disconnects are silent — which is what the
   *  final re-review's finding 4 was about, so `app.ts` passes one. */
  readonly log?: LogPort;
}

/**
 * The narrow log port this module reports through, the same shape and for
 * the same reason as `BluetoothPort`/`ClockPort`: `Homey.App`'s own `log` is
 * `(...args: unknown[]) => void` on a class this module must never import,
 * and a one-line function is all that needs crossing the boundary. `app.ts`
 * supplies `this.log`; a test supplies an array push; the default is a
 * no-op, so nothing is forced to care.
 *
 * ONLY SPECIFICATION-MANDATED DISCONNECTS GO THROUGH IT, deliberately. This
 * module's ordinary business — scanning, connecting, migrating, backing off
 * — is normal and frequent, and a log line per scan window would bury the
 * one event that actually means something is wrong with a node.
 */
export type LogPort = (message: string) => void;

// --- Backoff schedule -------------------------------------------------
//
// Not a specification value — engineering choices, the same way store.ts's
// SEQ_BLOCK_SIZE is. The design only fixes the SHAPE ("increasing backoff",
// "backoff resets after a successful connection"), not these numbers.
//
// failureStreak 0 (immediately after start(), and immediately after a
// disconnect from what had been a successful connection, since a success
// resets the streak to 0 — see `onAttemptSettled`) gets NO delay: "On
// disconnect it rescans" reads as prompt, not throttled. Only REPEATED
// failures escalate, doubling from BACKOFF_BASE_MS and capped at
// BACKOFF_MAX_MS so a node that is simply gone for a while does not make
// this module scan slower and slower forever.
const BACKOFF_BASE_MS = 1000;
const BACKOFF_MAX_MS = 30_000;
// Capped well before the doubling could produce an unreasonably large
// number (2**7 * 1000 = 128_000, already past BACKOFF_MAX_MS) — purely
// defensive, so a mesh that stays unavailable for a very long time never
// grows this counter or the number `Math.min` compares against without
// bound.
const MAX_FAILURE_STREAK = 8;

function backoffDelayMs(failureStreak: number): number {
  if (failureStreak <= 0) return 0;
  const scaled = BACKOFF_BASE_MS * 2 ** (failureStreak - 1);
  return Math.min(scaled, BACKOFF_MAX_MS);
}

// How long one scan window lasts. Not a specification value either; see the
// backoff constants' comment above for why this module carries its own
// engineering choices rather than the specification's. Exported so a test
// can assert the port actually receives this value (review finding: the
// fake previously accepted and discarded `durationMs` entirely, so this
// constant was never observed by anything).
export const SCAN_DURATION_MS = 4000;

/**
 * The maximum size of ONE Proxy PDU this app writes, header included —
 * Section 6.3 "Proxy PDU": "The size of the Proxy PDU is determined by the
 * user of the Proxy protocol. For example, the GATT bearer defines the size
 * of the Proxy PDU based on the ATT_MTU."
 *
 * NOT A SPECIFICATION VALUE — an engineering choice, the same way
 * SCAN_DURATION_MS and the backoff constants above are, and the one in this
 * module with the clearest route to being WRONG on hardware, so it is
 * written down in full. What the specification does publish, and what it
 * does not:
 *   - Section 7.2.2.2.7 "ATT_MTU": "The server should support an ATT_MTU
 *     size equal to or larger than 33 octets to be able to pass the content
 *     of a full Proxy PDU (see Section 6.5)." That is a SHOULD on the
 *     server, not a guarantee to the client, and an ATT_MTU of 33 leaves
 *     exactly 30 octets of attribute value — one Proxy PDU header octet
 *     plus the 29-octet maximum Network PDU that Table 3.10's own field
 *     widths add up to (9 octets of header + a 16-octet maximum
 *     TransportPDU + a 4-octet NetMIC).
 *   - Section 5.2.2 "PB-GATT" states the consequence of a smaller one
 *     plainly: "If the negotiated ATT_MTU is smaller than a required Proxy
 *     PDU size, the transmission of the Mesh Provisioning Data In and Mesh
 *     Provisioning Out characteristics always needs to be fragmented and
 *     reassembled. Each PDU shall be fully reassembled before processing."
 *   - Nothing in Mesh Protocol v1.1 fixes a minimum, because that belongs
 *     to the Bluetooth Core Specification, which this project has not
 *     fetched and therefore does not cite.
 * Homey's own BLE API exposes no negotiated ATT_MTU at all (checked across
 * `@types/homey`'s BleCharacteristic/BlePeripheral declarations: no MTU
 * member of any kind), so this app cannot ask. 20 is therefore chosen as a
 * deliberately pessimistic floor: small enough that it should fit any link
 * a BLE stack will give us, at the cost of segmenting messages that a
 * larger ATT_MTU would have carried whole. Segmenting unnecessarily is
 * correct, just chattier; segmenting too little is a silently truncated or
 * rejected write. ONE OF THE THINGS TO WATCH ON THE FIRST BULB: if traffic
 * works but is slower than expected, this is the number to raise.
 */
export const MAX_PROXY_PDU_LENGTH = 20;

/**
 * How long ONE `BluetoothPort.write` may take before this module stops
 * waiting on it and fails the write that was using it.
 *
 * WHY THIS EXISTS AT ALL (final re-review, finding 1 — HIGH). Nothing here
 * used to bound a GATT write, and `write()` below holds a flag across the
 * whole segment loop. A single `bluetooth.write` promise that never settles
 * — which is exactly what a peripheral going out of range mid-write
 * produces on a stack that does not error the pending operation — therefore
 * left that flag set forever: the loop's `finally` never ran, and from then
 * on EVERY message this app sent was refused, on every bulb, until the
 * Homey app restarted. `drivers/light/pairing.ts` had already learned this
 * lesson once (commit f6dd4ae, "bound every GATT operation, not only the
 * reply wait"); the proxy path had not. The helper both now use is
 * `./timeout.ts#withTimeout`.
 *
 * NOT A SPECIFICATION VALUE — an engineering choice, like SCAN_DURATION_MS
 * and the backoff constants above, and chosen against ONE constraint that
 * is not arbitrary: it must be short enough that a hung write is abandoned
 * before the traffic queue's own per-attempt deadline comes round, or the
 * retry would arrive while the previous attempt still held the flag and be
 * refused for the same reason the bound exists to remove. That deadline is
 * `lib/adapter/queue.ts`'s `DEFAULT_TIMEOUT_MS` (8 000 ms). Every message
 * this app sends is exactly two Proxy PDUs (see `write()` below), so the
 * worst case one attempt can spend inside `write()` is 2 x 2 000 = 4 000 ms
 * — half that budget, with the whole margin left for the attempt's own
 * status wait. The relationship is pinned by a test rather than left to two
 * separately-chosen numbers staying in agreement.
 *
 * It must also be long enough that an ordinarily slow write is not killed:
 * a GATT Write Without Response (Table 7.15) is queued and sent within one
 * or two connection intervals, so 2 000 ms is roughly two orders of
 * magnitude of headroom. UNVERIFIED ON HARDWARE, like everything else about
 * Homey's BLE write semantics (see drivers/light/driver.ts's own header):
 * if writes start failing with this module's own timeout message on a link
 * that is otherwise healthy, this is the number to raise — and
 * `DEFAULT_TIMEOUT_MS` the one to raise with it.
 */
export const PROXY_WRITE_TIMEOUT_MS = 2000;

interface ActiveConnection {
  readonly connection: ConnectionHandle;
  readonly dataInHandle: CharacteristicHandle;
  readonly subscription: Subscription;
}

/**
 * Holds one proxy connection for the whole mesh and migrates it to another
 * node when the current one disappears. See the module header for the
 * design this implements and pins.
 *
 * LIFECYCLE: construct, then call `start()` once. `stop()` cancels any
 * pending timer, tears down an active connection (without treating that as
 * a "disconnect" worth backing off from — this is a deliberate, caller-
 * initiated stop, not a lost node), and makes the manager inert: nothing it
 * was already in the middle of doing takes effect afterwards (see the
 * `epoch` field below).
 *
 * REENTRANCY: everything this class does happens serially — one scan, one
 * connect attempt, in flight at a time — except for one case a real
 * Bluetooth stack can still produce: a port that keeps a reference to an
 * old connection could fire `onDisconnect` for a connection this module has
 * already superseded (started a new attempt from, or torn down via `stop`).
 * `epoch` is bumped every time this module starts a new attempt or stops
 * entirely, and every callback the port can invoke later closes over the
 * epoch it was issued under; any callback whose epoch no longer matches
 * `this.epoch` is a stale one and is ignored. This is defensive rather than
 * exercised by name in connection.test.ts, which drives the fake port the
 * same way a real one would (one event at a time) rather than deliberately
 * replaying a stale callback.
 */
export class ProxyConnectionManager {
  private readonly bluetooth: BluetoothPort;
  private readonly clock: ClockPort;
  /** k3(netKey) — see the module header. Computed once at construction;
   *  this module never re-derives it per scan. */
  private readonly ourNetworkId: Buffer;

  private state: ProxyConnectionState = { status: 'unavailable', peripheralId: null };
  private active: ActiveConnection | null = null;
  private timer: TimerHandle | null = null;
  private failureStreak = 0;
  /** Bumped by `scheduleNext` (a new attempt generation) and by `stop`
   *  (nothing more should ever take effect); see the class doc comment. */
  private epoch = 0;
  private readonly notificationListeners = new Set<(data: Buffer) => void>();
  /** The maximum size of one outgoing Proxy PDU, header included — see
   *  MAX_PROXY_PDU_LENGTH. */
  private readonly maxProxyPduLength: number;
  /** How long one `BluetoothPort.write` may take — see
   *  PROXY_WRITE_TIMEOUT_MS. */
  private readonly proxyWriteTimeoutMs: number;
  private readonly log: LogPort;
  /** The reassembly in progress on the Mesh Proxy Data Out characteristic,
   *  if any (`proxyPdu.ts`'s own `undefined` convention). Reset whenever a
   *  connection is established or torn down — a reassembly cannot survive
   *  the link it was arriving over. */
  private reassembly: ProxyReassemblyState | undefined;
  /** Section 6.3.2.2's 20-second SAR transfer timeout. Armed when a
   *  reassembly starts, cleared when it ends; a transfer that simply STOPS
   *  arriving is invisible to `acceptProxyPdu`'s own on-arrival check, so
   *  without this timer the specification's "when the timeout expires, the
   *  Proxy PDU Client shall disconnect" would never fire at all. */
  private sarTimer: TimerHandle | null = null;
  /** True while a MULTI-PDU write is in flight — see `write` below. */
  private segmentedWriteInFlight = false;
  /** The reason for the most recent specification-mandated disconnect
   *  (Section 6.3.2.2), or `null` if none has happened. Diagnostic only;
   *  exposed so a test can assert WHY the link was dropped rather than
   *  merely that it was — and reported through `log` as it happens, which
   *  is what the final re-review's finding 4 added. */
  private lastProxyProtocolDisconnect: string | null = null;
  /**
   * How many specification-mandated disconnects have happened in a row
   * without a message completing in between — the backoff
   * `disconnectOnProxyProtocolViolation` paces itself with, and the reason
   * it does not simply reuse `failureStreak` (final re-review, finding 4).
   *
   * `failureStreak` counts failures to ESTABLISH a connection and is reset
   * by a successful one. A protocol violation happens AFTER a connection
   * succeeds, so it would always be computing its delay from a streak of 0
   * — which is 0 ms, i.e. no backoff at all — and a node whose proxy
   * behaviour this module rejects would be rescanned, reconnected and
   * rejected again forever at scan speed. A violation is also not a
   * transient the way a failed connect is: it will repeat on every
   * reconnection to the same node.
   *
   * Reset by a COMPLETED incoming message rather than by a successful
   * connection, because connecting is the part that keeps working in this
   * failure mode; a message completing is the link actually behaving. So an
   * isolated odd PDU on a healthy link decays to no penalty, while a node
   * that violates every time escalates to BACKOFF_MAX_MS.
   */
  private proxyProtocolViolationStreak = 0;

  constructor(bluetooth: BluetoothPort, clock: ClockPort, netKey: Buffer, options: ProxyConnectionOptions = {}) {
    if (netKey.length !== NET_KEY_LENGTH) {
      throw new Error(`ProxyConnectionManager: netKey must be ${NET_KEY_LENGTH} bytes, got ${netKey.length}`);
    }
    const maxProxyPduLength = options.maxProxyPduLength ?? MAX_PROXY_PDU_LENGTH;
    if (!Number.isInteger(maxProxyPduLength) || maxProxyPduLength < 2) {
      throw new Error(
        `ProxyConnectionManager: maxProxyPduLength must be an integer >= 2, got ${maxProxyPduLength}`,
      );
    }
    this.maxProxyPduLength = maxProxyPduLength;
    const proxyWriteTimeoutMs = options.proxyWriteTimeoutMs ?? PROXY_WRITE_TIMEOUT_MS;
    if (!Number.isInteger(proxyWriteTimeoutMs) || proxyWriteTimeoutMs < 1) {
      throw new Error(
        `ProxyConnectionManager: proxyWriteTimeoutMs must be an integer >= 1, got ${proxyWriteTimeoutMs}`,
      );
    }
    this.proxyWriteTimeoutMs = proxyWriteTimeoutMs;
    this.log = options.log ?? ((): void => {});
    this.bluetooth = bluetooth;
    this.clock = clock;
    // Copy before deriving: this module never retains a view into a buffer
    // it does not own, and the caller's netKey buffer is exactly such a
    // view — only the derived ourNetworkId (this module's own, freshly
    // allocated by k3/aesCmac) is kept.
    this.ourNetworkId = k3(Buffer.from(netKey));
  }

  /** Kicks off the first scan attempt. Call once. */
  start(): void {
    this.scheduleNext(0);
  }

  /** Cancels any pending timer and tears down an active connection, if any,
   *  without treating it as a lost node (no backoff bump, no rescan
   *  scheduled). Safe to call whether or not a connection is active. */
  stop(): void {
    this.epoch += 1;
    // A reassembly cannot survive the link it was arriving over.
    this.reassembly = undefined;
    this.clearSarTimer();
    this.releaseSegmentedWrite();
    if (this.timer !== null) {
      this.clock.clearTimeout(this.timer);
      this.timer = null;
    }
    if (this.active !== null) {
      const { connection, subscription } = this.active;
      this.active = null;
      subscription.unsubscribe();
      void this.bluetooth.disconnect(connection);
    }
    this.state = { status: 'unavailable', peripheralId: null };
  }

  /** The state object itself is a frozen-shape literal of primitives only
   *  (a status string and a nullable string) — handing out the same
   *  reference is safe, unlike store.ts's NetworkState, which carries
   *  mutable arrays/buffers a caller could otherwise corrupt. */
  getState(): ProxyConnectionState {
    return this.state;
  }

  /**
   * Writes one complete NETWORK PDU to the active connection's Mesh Proxy
   * Data In characteristic, wrapped in the Proxy PDU envelope and segmented
   * across as many writes as `maxProxyPduLength` requires (Section 6.3.2.1
   * "Segmentation", implemented in `proxyPdu.ts#encodeProxyPdus`). Callers
   * hand over the bare Network PDU and never see the envelope — the queue
   * above this module stays protocol-blind, as its own header requires.
   * Rejects, naming why, when nothing is connected — there is no queue here
   * to hold the write for later (that is the traffic queue's job).
   *
   * WHY A SECOND, OVERLAPPING SEGMENTED WRITE IS REFUSED RATHER THAN
   * INTERLEAVED. Segments of one message must be "sent in order" (Section
   * 6.3.2.1) and nothing else may arrive between them: a node that receives
   * a first segment of message B in the middle of message A sees an
   * unexpected SAR value and, per Section 6.3.2.2, disconnects. Callers
   * here do not await each other — `TrafficQueue.attempt` deliberately
   * fires `write()` without awaiting it, so a retry can begin while a
   * previous, still-pending write holds the radio. Serialising instead of
   * refusing would make the retry WAIT on a write that may never settle,
   * silently converting a bounded retry into a hang; refusing hands the
   * caller a rejection, which the queue already treats as "a reason to
   * wait" and paces on its own timer.
   *
   * THE SEGMENTED PATH IS THE ONLY PATH, which is what makes the flag's
   * correctness matter (final re-review, finding 1 — this comment used to
   * claim the opposite: "Single-PDU writes — every command this app sends
   * when the link's ATT_MTU is generous — never set the flag, so this path
   * costs nothing in the ordinary case". There is no generous case: the
   * ATT_MTU is never consulted anywhere in this app, because Homey exposes
   * none, and `maxProxyPduLength` is fixed at `MAX_PROXY_PDU_LENGTH` = 20
   * for the reasons that constant gives). At 20, one Proxy PDU carries 19
   * octets of Data. Every Network PDU this app builds is longer than that:
   * Table 3.10's fixed fields are 9 octets (IVI+NID, CTL+TTL, SEQ, SRC,
   * DST) and a CTL=0 Network PDU adds a 4-octet NetMIC, so the floor is 13
   * octets plus the Lower Transport PDU, and the smallest this app sends —
   * an Unsegmented Access message carrying a 2-octet opcode Get, Table 3.17
   * — is 9 + 7 + 4 = 20 octets. The largest, a Light CTL/HSL Set, is 27.
   * So every message is 2 Proxy PDUs, every message takes this path, and
   * the single-PDU branch below is reachable only from a test that injects
   * a larger `maxProxyPduLength`.
   *
   * WHICH IS WHY EVERY WRITE IS BOUNDED. `withTimeout` wraps each
   * individual `bluetooth.write` (both branches — a hung single-PDU write
   * latches nothing, but it would still hang its caller forever), so the
   * `finally` below ALWAYS runs and the flag is always released. See
   * `PROXY_WRITE_TIMEOUT_MS` for the bound and why it is what it is. The
   * flag is additionally cleared wherever the active connection is dropped
   * (`stop`, `handleDisconnect`, `disconnectOnProxyProtocolViolation`),
   * because a write pending against a link that no longer exists may never
   * settle at all and no timeout can hurry it.
   *
   * WHAT A TIMED-OUT SEGMENT LEAVES BEHIND, said plainly: the node is
   * holding half a SAR transfer. Per Section 6.3.2.2 it discards that and
   * disconnects us 20 seconds later, and this module then rescans and
   * reconnects as it does for any other dropped link — so the mesh recovers
   * on its own, within one SAR window, instead of staying broken until the
   * app restarts. This module does not pre-emptively drop the link itself;
   * that would be a second policy for the same recovery the node already
   * performs.
   */
  async write(data: Buffer): Promise<void> {
    if (this.active === null) {
      throw new Error('ProxyConnectionManager.write: no active proxy connection');
    }
    const pdus = encodeProxyPdus(PROXY_MESSAGE_TYPE_NETWORK_PDU, data, this.maxProxyPduLength);
    const handle = this.active.dataInHandle;
    if (pdus.length === 1) {
      await this.boundedWrite(handle, pdus[0] as Buffer, 1, 1);
      return;
    }
    if (this.segmentedWriteInFlight) {
      throw new Error(
        'ProxyConnectionManager.write: a segmented Proxy PDU write is already in flight; interleaving segments would make the node disconnect (Section 6.3.2.2)',
      );
    }
    this.segmentedWriteInFlight = true;
    try {
      for (const [index, pdu] of pdus.entries()) {
        await this.boundedWrite(handle, pdu, index + 1, pdus.length);
      }
    } finally {
      this.segmentedWriteInFlight = false;
    }
  }

  /** One GATT write, bounded by `proxyWriteTimeoutMs` — see
   *  `PROXY_WRITE_TIMEOUT_MS` and `write`'s own comment. The failure names
   *  WHICH segment stalled, because "segment 1 of 2" and "segment 2 of 2"
   *  are different problems on hardware: the first means the write never
   *  reached the radio, the second that the node stopped accepting
   *  mid-message. */
  private boundedWrite(handle: CharacteristicHandle, pdu: Buffer, index: number, total: number): Promise<void> {
    return withTimeout(
      this.bluetooth.write(handle, pdu),
      this.clock,
      this.proxyWriteTimeoutMs,
      `ProxyConnectionManager.write: Proxy PDU ${index} of ${total} to the Mesh Proxy Data In characteristic`,
    );
  }

  /** The reason for the most recent disconnect this module performed
   *  because the specification required it (Section 6.3.2.2), or `null` if
   *  that has never happened. Diagnostic only — nothing in the app's own
   *  behaviour depends on it. */
  getLastProxyProtocolDisconnect(): string | null {
    return this.lastProxyProtocolDisconnect;
  }

  /** Registers a listener for every notification delivered on the Mesh
   *  Proxy Data Out characteristic of whichever connection is active at the
   *  time it arrives. Returns an unsubscribe function. Each listener gets
   *  its own fresh copy of the bytes, so one listener mutating what it
   *  received can never affect another, or what a later notification
   *  delivers. */
  onNotification(listener: (data: Buffer) => void): () => void {
    this.notificationListeners.add(listener);
    return () => {
      this.notificationListeners.delete(listener);
    };
  }

  /**
   * One notification on the Mesh Proxy Data Out characteristic — ONE Proxy
   * PDU ("Each notification contains a single Proxy PDU." — Section 3.3.2
   * "GATT bearer"), stripped of its envelope and reassembled before any
   * listener sees it. Listeners only ever receive COMPLETE Network PDU
   * messages: a mesh beacon or a proxy configuration message, both legal on
   * this characteristic (Section 7.2.3.2.1 "Characteristic behavior"), is
   * dropped here because nothing in this app consumes one — see the module
   * header's IV INDEX note for the one design clause that rests on that.
   */
  private handleNotification(data: Buffer): void {
    const result = acceptProxyPdu(this.reassembly, data, this.clock.now());
    switch (result.kind) {
      case 'ignored':
        this.reassembly = result.state;
        return;
      case 'incomplete':
        this.reassembly = result.state;
        this.armSarTimer();
        return;
      case 'disconnect':
        this.disconnectOnProxyProtocolViolation(result.reason);
        return;
      case 'complete':
        this.reassembly = undefined;
        this.clearSarTimer();
        // The link demonstrably works — see `proxyProtocolViolationStreak`.
        // Reset before the MessageType check below: a complete mesh beacon
        // we drop is still proof the proxy's own SAR behaviour is sound.
        this.proxyProtocolViolationStreak = 0;
        if (result.messageType !== PROXY_MESSAGE_TYPE_NETWORK_PDU) return;
        for (const listener of this.notificationListeners) {
          listener(Buffer.from(result.message));
        }
    }
  }

  /** (Re)arms the SAR transfer timeout for the reassembly now in progress.
   *  Always restarted from the CURRENT segment rather than left running
   *  from the first: `acceptProxyPdu` measures the real deadline from
   *  `startedAtMs` and will reject a late segment on arrival regardless, so
   *  this timer only has to guarantee that a transfer which stops arriving
   *  is eventually noticed — it never shortens the real window. */
  private armSarTimer(): void {
    this.clearSarTimer();
    this.sarTimer = this.clock.setTimeout(() => {
      this.sarTimer = null;
      if (this.reassembly === undefined) return;
      this.disconnectOnProxyProtocolViolation(
        'SAR transfer timed out (Section 6.3.2.2: the timeout for the SAR transfer is 20 seconds)',
      );
    }, PROXY_SAR_TIMEOUT_MS);
  }

  private clearSarTimer(): void {
    if (this.sarTimer !== null) {
      this.clock.clearTimeout(this.sarTimer);
      this.sarTimer = null;
    }
  }

  /**
   * Releases the segmented-write latch because the connection it was
   * guarding has gone (final re-review, finding 1). Called from every place
   * `this.active` is dropped — `stop`, `handleDisconnect` and
   * `disconnectOnProxyProtocolViolation` — and deliberately NOT only from
   * `write`'s own `finally`, which is reached only if that write actually
   * settles. A write still pending against a dead link may never settle at
   * all (a real stack can simply drop it, and the project's own fake models
   * exactly that), and `PROXY_WRITE_TIMEOUT_MS` cannot help a link that is
   * already gone: by the time it fires there is nothing left to abandon,
   * and until then the next connection would be refused every write.
   *
   * A still-running segment loop from the OLD link may later set this flag
   * back to false in its own `finally`, which is harmless — false is the
   * value this method just wrote. What that loop cannot do is interleave on
   * the NEW link: it holds the old connection's `CharacteristicHandle`,
   * which the port no longer accepts, so its remaining writes fail rather
   * than reaching the new node.
   */
  private releaseSegmentedWrite(): void {
    this.segmentedWriteInFlight = false;
  }

  /**
   * Section 6.3.2.2 "Reassembly" — the Proxy PDU Client "shall disconnect".
   * Tears the active connection down exactly as a lost link would (same
   * state, same rescan at the same backoff, so a protocol violation is
   * recoverable rather than terminal) and records the reason for
   * diagnostics. `scheduleNext` bumps the epoch, which is what stops the
   * connection being torn down here from ever reporting anything later.
   */
  private disconnectOnProxyProtocolViolation(reason: string): void {
    this.lastProxyProtocolDisconnect = reason;
    this.reassembly = undefined;
    this.clearSarTimer();
    this.releaseSegmentedWrite();
    this.proxyProtocolViolationStreak = Math.min(this.proxyProtocolViolationStreak + 1, MAX_FAILURE_STREAK);
    const active = this.active;
    if (active === null) {
      // Not reachable through this module's own call paths (a notification
      // can only arrive on a subscription an active connection owns), but
      // if it ever were, a violation with nothing to drop is still worth
      // saying out loud rather than recording where nothing reads it.
      this.log(`mesh proxy protocol violation with no active connection: ${reason}`);
      return;
    }
    const peripheralId = this.state.peripheralId;
    this.active = null;
    active.subscription.unsubscribe();
    void this.bluetooth.disconnect(active.connection);
    this.state = { status: 'unavailable', peripheralId: null };
    const delayMs = backoffDelayMs(this.proxyProtocolViolationStreak);
    this.log(
      `mesh proxy protocol violation on ${peripheralId ?? 'the active node'} (${this.proxyProtocolViolationStreak} in a row): ${reason} — dropped the link, rescanning in ${delayMs}ms`,
    );
    this.scheduleNext(delayMs);
  }

  private scheduleNext(delayMs: number): void {
    const myEpoch = (this.epoch += 1);
    this.timer = this.clock.setTimeout(() => {
      this.timer = null;
      void this.runAttempt(myEpoch);
    }, delayMs);
  }

  /** One full scan-select-connect-discover-subscribe cycle. `myEpoch` is
   *  the generation this attempt was scheduled under; checked after every
   *  await so a `stop()` or a newer attempt superseding this one (see the
   *  class doc comment) stops this one from taking any further action,
   *  including reporting a state or scheduling a next attempt. */
  private async runAttempt(myEpoch: number): Promise<void> {
    let results: ScanResult[];
    try {
      results = await this.bluetooth.scan(SCAN_DURATION_MS);
    } catch {
      results = [];
    }
    if (myEpoch !== this.epoch) return;

    const candidate = this.selectStrongestOurs(results);
    if (candidate === null) {
      this.onAttemptSettled(myEpoch, false);
      return;
    }

    let connection: ConnectionHandle;
    try {
      connection = await this.bluetooth.connect(candidate.peripheralId, () => {
        if (myEpoch !== this.epoch) return;
        this.handleDisconnect();
      });
    } catch {
      this.onAttemptSettled(myEpoch, false);
      return;
    }
    if (myEpoch !== this.epoch) {
      void this.bluetooth.disconnect(connection);
      return;
    }

    try {
      const characteristics = await this.bluetooth.discover(connection);
      if (myEpoch !== this.epoch) {
        void this.bluetooth.disconnect(connection);
        return;
      }

      const dataIn = characteristics.find(
        (c) => c.serviceUuid === MESH_PROXY_SERVICE_UUID && c.characteristicUuid === MESH_PROXY_DATA_IN_UUID,
      );
      const dataOut = characteristics.find(
        (c) => c.serviceUuid === MESH_PROXY_SERVICE_UUID && c.characteristicUuid === MESH_PROXY_DATA_OUT_UUID,
      );
      if (!dataIn || !dataOut) {
        throw new Error(
          `node ${candidate.peripheralId} does not expose both Mesh Proxy Data In (0x${MESH_PROXY_DATA_IN_UUID.toString(16)}) and Data Out (0x${MESH_PROXY_DATA_OUT_UUID.toString(16)}) characteristics`,
        );
      }

      const subscription = await this.bluetooth.subscribe(dataOut.handle, (data) => this.handleNotification(data));
      if (myEpoch !== this.epoch) {
        subscription.unsubscribe();
        void this.bluetooth.disconnect(connection);
        return;
      }

      // A fresh link starts with a clean reassembly, never whatever a
      // previous one left half-arrived.
      this.reassembly = undefined;
      this.clearSarTimer();
      this.active = { connection, dataInHandle: dataIn.handle, subscription };
      this.state = { status: 'connected', peripheralId: candidate.peripheralId };
      this.onAttemptSettled(myEpoch, true);
    } catch {
      void this.bluetooth.disconnect(connection);
      this.onAttemptSettled(myEpoch, false);
    }
  }

  private onAttemptSettled(myEpoch: number, success: boolean): void {
    if (myEpoch !== this.epoch) return;
    if (success) {
      this.failureStreak = 0;
      return;
    }
    this.state = { status: 'unavailable', peripheralId: null };
    this.failureStreak = Math.min(this.failureStreak + 1, MAX_FAILURE_STREAK);
    this.scheduleNext(backoffDelayMs(this.failureStreak));
  }

  private handleDisconnect(): void {
    this.active = null;
    // Same reason as `stop()`: a half-arrived message belongs to a link
    // that no longer exists, and feeding its segments to the next
    // connection's first notification would produce exactly the
    // "unexpected SAR" state Section 6.3.2.2 disconnects over.
    this.reassembly = undefined;
    this.clearSarTimer();
    this.releaseSegmentedWrite();
    this.state = { status: 'unavailable', peripheralId: null };
    // failureStreak is 0 here: the connection that just dropped was itself
    // a SUCCESSFUL attempt, which reset it in onAttemptSettled. This is the
    // whole mechanism behind "backoff resets after a successful
    // connection" — nothing special-cases disconnect; it simply schedules
    // the next attempt at whatever the current streak already is.
    this.scheduleNext(backoffDelayMs(this.failureStreak));
  }

  /** Picks the strongest scan result whose advertised identity derives from
   *  OUR network key, or `null` if none does (an empty scan, a scan full of
   *  only foreign-network or non-mesh advertisements, or both). */
  private selectStrongestOurs(results: ScanResult[]): ScanResult | null {
    let best: ScanResult | null = null;
    for (const result of results) {
      if (!this.isOurNetworkId(findServiceData(result, MESH_PROXY_SERVICE_UUID))) continue;
      if (best === null || result.rssi > best.rssi) {
        best = result;
      }
    }
    return best;
  }

  /** Table 7.7/7.8/7.11 — see the module header. `null` and anything not
   *  shaped exactly like a Network ID advertisement (wrong type, wrong
   *  length) is never ours; a length/type check before the byte comparison
   *  also means a Node Identity or Private-variant advertisement (Table
   *  7.8's other types, which are not fixed values derived from the network
   *  key the way Network ID is) is rejected on shape alone, never compared
   *  as if it meant something it does not. */
  private isOurNetworkId(serviceData: Buffer | null): boolean {
    if (serviceData === null) return false;
    if (serviceData.length !== 1 + NETWORK_ID_LENGTH) return false;
    if (serviceData[0] !== NETWORK_ID_TYPE) return false;
    return serviceData.subarray(1).equals(this.ourNetworkId);
  }
}
