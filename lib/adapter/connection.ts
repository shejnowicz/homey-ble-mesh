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
 * NULLISH CONVENTION: `null` throughout, matching store.ts — a scan result
 * with no Mesh Proxy Service data is `proxyServiceData: null`, the manager's
 * reported `peripheralId` is `null` whenever `status` is not `'connected'`,
 * never `undefined` for either.
 */

import { k3 } from '../mesh/crypto/derive';

// Assigned Numbers, Section 3.4.1 "Services by Name": Mesh Proxy Service.
export const MESH_PROXY_SERVICE_UUID = 0x1828;
// Assigned Numbers, Section 3.8.1 "Characteristics by Name".
export const MESH_PROXY_DATA_IN_UUID = 0x2add;
export const MESH_PROXY_DATA_OUT_UUID = 0x2ade;

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

/**
 * One BLE advertisement observed during a scan window. `proxyServiceData`
 * is exactly the Service Data VALUE this peripheral advertised for the Mesh
 * Proxy Service UUID (0x1828) — Table 7.7's envelope, Identification Type
 * followed by its parameters — with the UUID itself and the surrounding AD
 * structure bytes (AD Length, AD Type) already stripped, which is the shape
 * a real platform BLE scan API hands back (it keys service data by UUID
 * already); `null` when this advertisement carried no Mesh Proxy Service
 * data at all, which is most advertisements from devices that are not mesh
 * nodes and is exactly as "not ours" as any other identification this
 * module cannot recognise.
 */
export interface ScanResult {
  readonly peripheralId: string;
  /** Received Signal Strength Indicator, in dBm. Less negative is stronger
   *  (e.g. -40 is a stronger signal than -70). */
  readonly rssi: number;
  readonly proxyServiceData: Buffer | null;
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

  constructor(bluetooth: BluetoothPort, clock: ClockPort, netKey: Buffer) {
    if (netKey.length !== NET_KEY_LENGTH) {
      throw new Error(`ProxyConnectionManager: netKey must be ${NET_KEY_LENGTH} bytes, got ${netKey.length}`);
    }
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

  /** Writes to the active connection's Mesh Proxy Data In characteristic.
   *  Rejects, naming why, when nothing is connected — there is no queue
   *  here to hold the write for later (that is Task 5). */
  async write(data: Buffer): Promise<void> {
    if (this.active === null) {
      throw new Error('ProxyConnectionManager.write: no active proxy connection');
    }
    await this.bluetooth.write(this.active.dataInHandle, Buffer.from(data));
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

  private handleNotification(data: Buffer): void {
    for (const listener of this.notificationListeners) {
      listener(Buffer.from(data));
    }
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
      if (!this.isOurNetworkId(result.proxyServiceData)) continue;
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
