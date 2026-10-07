/**
 * A fake `BluetoothPort` (see ../connection.ts) — a first-class test
 * fixture, not an incidental test detail: the task brief for connection.ts
 * says plainly that two later tasks (the traffic queue and the pairing
 * flow) reuse this exact fake, so it lives in its own file, is configured
 * through data rather than hardcoded scenarios, and is built so a later
 * task can add a new failure mode without rewriting what is here.
 *
 * It can, per peripheral: advertise at a configurable, changeable signal
 * strength; advertise an identity derived from a DIFFERENT network key (or
 * an arbitrary/malformed Service Data payload, or none at all); fail a
 * connection attempt, a discovery, or a subscribe; expose only one of the
 * two Mesh Proxy characteristics (simulating a node that advertises the
 * service but does not actually implement it fully); drop a write
 * silently (modelling Write Without Response's total lack of
 * acknowledgement, Table 7.15 — see connection.ts's module header); hold a
 * write open until a test chooses to settle it (modelling a congested
 * transmit queue — see `setWriteBehavior`/`releaseWrite` below, added for
 * Task 5's traffic queue after an earlier, task-local stub for the same
 * need was judged better placed here, for Task 6 to reuse too); and
 * simulate both an inbound Data Out notification and an unexpected
 * disconnect. "Never answers at all" is simply a peripheral that is
 * registered but never advertising (or no peripheral registered at all) —
 * `scan()` returning an empty array is an entirely ordinary result, not a
 * special case this fixture has to fake up.
 *
 * SCAN TIMING. By default (no `clock` passed to the constructor) `scan()`
 * resolves immediately regardless of the `durationMs` it was asked for —
 * the behaviour every connection.test.ts test already relies on. Passing a
 * `ClockPort` (added for Task 5, after a review found a defect that had
 * been hidden by exactly this instant-scan shortcut) makes `scan()`
 * genuinely consume `durationMs` of virtual time, via that same clock,
 * before resolving — for a test that needs a reconnect to cost real time
 * rather than none, which is the only way to tell "retries paced correctly
 * against a slow reconnect" apart from "retries that happened to work
 * because nothing ever took any time at all".
 *
 * SCAN TIMING IS PARTIAL (review finding, not fixed here): only `scan()`
 * consumes clock time in this mode — `connect`/`discover`/`subscribe`
 * still resolve on the next microtask regardless, exactly as in the
 * default, fully-instant mode. A real reconnect costs "at least one full
 * scan window PLUS connect/discover/subscribe" (connection.ts's own
 * module header, and `queue.ts`'s account of the defect this was built to
 * reproduce) — this fixture can only demonstrate the SCAN half of that
 * sum. `DEFAULT_TIMEOUT_MS` being double `SCAN_DURATION_MS` is still the
 * right constant (it needs to clear the scan plus whatever
 * connect/discover/subscribe cost in reality, and doubling leaves
 * headroom for that unmodelled remainder too) — it is this FIXTURE that
 * proves less than a comment claiming "a reconnect costs scan plus
 * connect" would suggest, not the constant that is wrong. A future task
 * needing to exercise that fuller cost would need connect/discover/
 * subscribe to accept their own simulated delay the same way `scan` now
 * does.
 */

import { k3 } from '../../mesh/crypto/derive';
import {
  MESH_PROXY_DATA_IN_UUID,
  MESH_PROXY_DATA_OUT_UUID,
  MESH_PROXY_SERVICE_UUID,
  type BluetoothPort,
  type CharacteristicHandle,
  type ClockPort,
  type ConnectionHandle,
  type DiscoveredCharacteristic,
  type ScanResult,
  type Subscription,
} from '../connection';

export type AttemptBehavior = 'succeed' | 'fail';

/** `write()`'s own behaviour for a node: 'succeed' resolves normally
 *  (recording the write, unless `dropWrites` also applies), 'fail' rejects
 *  immediately (naming the peripheral), and 'hold' neither — it returns a
 *  promise that stays pending until a test explicitly settles it with
 *  `releaseWrite`, modelling a congested transmit queue (the GATT layer
 *  genuinely accepting a write but not yet having gotten it onto the air)
 *  rather than an instant accept-or-reject. */
export type WriteBehavior = AttemptBehavior | 'hold';

export interface FakeNodeConfig {
  readonly id: string;
  readonly rssi: number;
  /** The network key this node's advertised Network ID is derived from
   *  (via k3, same as connection.ts's own `ourNetworkId`). Exactly one of
   *  `networkKey`/`serviceDataOverride` must be given. */
  readonly networkKey?: Buffer;
  /** Advertise this exact Service Data value instead of deriving one from
   *  `networkKey` — for a malformed payload or a non-Network-ID
   *  identification type (Table 7.8). `null` means "advertises the Mesh
   *  Proxy Service with no Service Data at all", distinct from
   *  `advertising: false` ("does not advertise the service at all": see
   *  `setAdvertising`). Exactly one of `networkKey`/`serviceDataOverride`
   *  must be given. */
  readonly serviceDataOverride?: Buffer | null;
  readonly advertising?: boolean; // default true
  readonly connectBehavior?: AttemptBehavior; // default 'succeed'
  readonly discoverBehavior?: AttemptBehavior; // default 'succeed'
  readonly subscribeBehavior?: AttemptBehavior; // default 'succeed'
  readonly dropWrites?: boolean; // default false
  readonly writeBehavior?: WriteBehavior; // default 'succeed'; see setWriteBehavior
  /** Omit one Mesh Proxy characteristic from `discover()`'s result,
   *  modelling a node that advertises the service but does not fully
   *  implement it. `null` (default): expose both. */
  readonly missingCharacteristic?: 'dataIn' | 'dataOut' | null;
}

interface FakeNode {
  id: string;
  rssi: number;
  serviceData: Buffer | null;
  advertising: boolean;
  connectBehavior: AttemptBehavior;
  discoverBehavior: AttemptBehavior;
  subscribeBehavior: AttemptBehavior;
  dropWrites: boolean;
  writeBehavior: WriteBehavior;
  missingCharacteristic: 'dataIn' | 'dataOut' | null;
}

/**
 * KNOWN GAP, written down for the next task rather than fixed here (review
 * finding, task 5's second round): `releaseWrite` never prunes a settled
 * entry out of the per-peripheral array it reads from. Two consequences
 * worth knowing before extending this: indices keep accumulating across a
 * whole test (the Nth call to `write()` in 'hold' mode is always held at
 * index N-1 within that peripheral, never index 0 again, even after
 * earlier ones were released), and releasing the SAME index twice is
 * silently a no-op (resolving/rejecting an already-settled promise does
 * nothing) rather than an error. This is the OPPOSITE stance this file
 * already takes for "nothing to act on" elsewhere (`releaseWrite` itself
 * throws when the index was never held at all; `simulateDisconnect`/
 * `simulateNotification` throw on their own "nothing to act on" cases) --
 * a double-release should arguably throw too, for the same reason, but
 * does not.
 */
interface HeldWrite {
  readonly resolve: () => void;
  readonly reject: (err: Error) => void;
}

interface OpenConnection {
  readonly onDisconnect: () => void;
}

interface FakeConnectionHandle {
  readonly peripheralId: string;
}

interface FakeCharacteristicHandle {
  readonly peripheralId: string;
  readonly serviceUuid: number;
  readonly characteristicUuid: number;
}

function deriveServiceData(networkKey: Buffer): Buffer {
  // Table 7.11: Identification Type (0x00 = Network ID type, Table 7.8)
  // followed by the 8-octet Network ID (k3(NetKey), Section 3.9.6.3.2).
  return Buffer.concat([Buffer.from([0x00]), k3(networkKey)]);
}

function notifyKey(peripheralId: string, characteristicUuid: number): string {
  return `${peripheralId}:${characteristicUuid.toString(16)}`;
}

export class FakeBluetoothPort implements BluetoothPort {
  private readonly nodes = new Map<string, FakeNode>();
  private readonly openConnections = new Map<string, OpenConnection>();
  private readonly notifyCallbacks = new Map<string, (data: Buffer) => void>();
  private readonly readValues = new Map<string, Buffer>();
  private readonly heldWrites = new Map<string, HeldWrite[]>();

  /** `clock`, if given, is what `scan()` actually waits on for its
   *  `durationMs` — see the module header's "SCAN TIMING" note. Omit it
   *  (the default) to keep every existing test's instant-scan assumption
   *  unchanged. */
  constructor(private readonly clock?: ClockPort) {}

  /** Every peripheralId passed to `connect()`, in call order, including
   *  attempts that went on to fail — so a test can assert not just WHICH
   *  node ended up connected but which ones were ever tried, and in what
   *  order (e.g. "the foreign node was never even attempted"). */
  readonly connectCalls: string[] = [];
  /** Every write that was NOT silently dropped (see `dropWrites`), in
   *  order, with a defensive copy of the bytes (never the caller's own
   *  buffer — see connection.ts's own rule about not retaining a view into
   *  a buffer this module does not own, applied here too). Records WHICH
   *  characteristic the write targeted, not just which peripheral and what
   *  bytes — review finding: without this, swapping the Data In handle for
   *  the Data Out handle in connection.ts passes every test here, because
   *  nothing previously distinguished "wrote to the right peripheral" from
   *  "wrote to the right CHARACTERISTIC on that peripheral." */
  readonly writesReceived: Array<{ peripheralId: string; characteristicUuid: number; data: Buffer }> = [];
  /** Every `durationMs` a caller passed to `scan()`, in order — review
   *  finding: this fixture previously accepted and ignored that argument
   *  entirely, so connection.ts's SCAN_DURATION_MS constant was never
   *  actually observed by anything. */
  readonly scanDurationsRequested: number[] = [];
  private scanCalls = 0;

  scanCallCount(): number {
    return this.scanCalls;
  }

  // --- Test configuration -------------------------------------------

  addNode(config: FakeNodeConfig): void {
    const hasKey = config.networkKey !== undefined;
    const hasOverride = config.serviceDataOverride !== undefined;
    if (hasKey === hasOverride) {
      throw new Error(
        `FakeBluetoothPort.addNode: "${config.id}" must set exactly one of networkKey/serviceDataOverride`,
      );
    }
    const serviceData = hasOverride ? (config.serviceDataOverride as Buffer | null) : deriveServiceData(config.networkKey as Buffer);
    this.nodes.set(config.id, {
      id: config.id,
      rssi: config.rssi,
      serviceData,
      advertising: config.advertising ?? true,
      connectBehavior: config.connectBehavior ?? 'succeed',
      discoverBehavior: config.discoverBehavior ?? 'succeed',
      subscribeBehavior: config.subscribeBehavior ?? 'succeed',
      dropWrites: config.dropWrites ?? false,
      writeBehavior: config.writeBehavior ?? 'succeed',
      missingCharacteristic: config.missingCharacteristic ?? null,
    });
  }

  removeNode(id: string): void {
    this.nodes.delete(id);
  }

  private node(id: string): FakeNode {
    const node = this.nodes.get(id);
    if (!node) {
      throw new Error(`FakeBluetoothPort: unknown peripheral "${id}"`);
    }
    return node;
  }

  setAdvertising(id: string, advertising: boolean): void {
    this.node(id).advertising = advertising;
  }

  setRssi(id: string, rssi: number): void {
    this.node(id).rssi = rssi;
  }

  setConnectBehavior(id: string, behavior: AttemptBehavior): void {
    this.node(id).connectBehavior = behavior;
  }

  setDiscoverBehavior(id: string, behavior: AttemptBehavior): void {
    this.node(id).discoverBehavior = behavior;
  }

  setSubscribeBehavior(id: string, behavior: AttemptBehavior): void {
    this.node(id).subscribeBehavior = behavior;
  }

  setDropWrites(id: string, drop: boolean): void {
    this.node(id).dropWrites = drop;
  }

  setWriteBehavior(id: string, behavior: WriteBehavior): void {
    this.node(id).writeBehavior = behavior;
  }

  /** Settles the `index`-th currently-held write for `id` (in the order
   *  `write()` was called, 0-based) with `outcome` — `{ ok: true }`
   *  resolves it, `{ ok: false, err }` rejects it with `err`. Throws if
   *  there is no such held write — a misconfigured test, not a thing to
   *  paper over (same stance `simulateDisconnect`/`simulateNotification`
   *  already take for their own "nothing to act on" cases). */
  releaseWrite(id: string, index: number, outcome: { ok: true } | { ok: false; err: Error }): void {
    const held = this.heldWrites.get(id);
    const entry = held?.[index];
    if (!entry) {
      throw new Error(`FakeBluetoothPort.releaseWrite: no held write #${index} for "${id}"`);
    }
    if (outcome.ok) {
      entry.resolve();
    } else {
      entry.reject(outcome.err);
    }
  }

  setReadValue(id: string, characteristicUuid: number, value: Buffer): void {
    this.node(id); // validate existence
    this.readValues.set(notifyKey(id, characteristicUuid), Buffer.from(value));
  }

  /** Simulates the open connection to `id` dropping unexpectedly (the far
   *  end losing power, a radio error — anything other than this module's
   *  own `disconnect()`): invokes the `onDisconnect` callback `connect()`
   *  was given for it, exactly once. Throws if `id` is not currently
   *  connected — a misconfigured test, not a thing to paper over.
   *
   *  KNOWN GAP (review finding): does NOT settle any write currently held
   *  open for `id` (see `write()`'s own 'hold' branch) — a real GATT stack
   *  would error an in-flight write when the link drops; this fake instead
   *  leaves it pending forever. A test combining a held write with a
   *  disconnect needs to `releaseWrite` it explicitly first. */
  simulateDisconnect(id: string): void {
    const open = this.openConnections.get(id);
    if (!open) {
      throw new Error(`FakeBluetoothPort.simulateDisconnect: "${id}" is not currently connected`);
    }
    this.openConnections.delete(id);
    this.clearNotifyCallbacksFor(id);
    open.onDisconnect();
  }

  /** Convenience for the common case the design itself describes ("cutting
   *  power to the node"): stops advertising AND, if connected, simulates
   *  the disconnect — both at once, since a powered-off node does both in
   *  reality. */
  simulateNodePoweredOff(id: string): void {
    this.setAdvertising(id, false);
    if (this.openConnections.has(id)) {
      this.simulateDisconnect(id);
    }
  }

  /** Simulates an inbound notification on `id`'s Mesh Proxy Data Out
   *  characteristic. Throws if nothing is currently subscribed to it — a
   *  misconfigured test, not a silently-dropped notification (that is
   *  what `dropWrites` models for the opposite direction; nothing in this
   *  fixture silently drops a configured notification). */
  simulateNotification(id: string, data: Buffer): void {
    const key = notifyKey(id, MESH_PROXY_DATA_OUT_UUID);
    const callback = this.notifyCallbacks.get(key);
    if (!callback) {
      throw new Error(`FakeBluetoothPort.simulateNotification: "${id}" has no active Data Out subscription`);
    }
    callback(Buffer.from(data));
  }

  private clearNotifyCallbacksFor(peripheralId: string): void {
    const prefix = `${peripheralId}:`;
    for (const key of [...this.notifyCallbacks.keys()]) {
      if (key.startsWith(prefix)) this.notifyCallbacks.delete(key);
    }
  }

  // --- BluetoothPort ---------------------------------------------------

  async scan(durationMs: number): Promise<ScanResult[]> {
    this.scanCalls += 1;
    this.scanDurationsRequested.push(durationMs);
    if (this.clock !== undefined && durationMs > 0) {
      // See the module header's "SCAN TIMING" note: genuinely consumes
      // `durationMs` of virtual time via the SAME clock the caller drives,
      // rather than resolving instantly.
      await new Promise<void>((resolve) => {
        this.clock!.setTimeout(resolve, durationMs);
      });
    }
    const results: ScanResult[] = [];
    for (const node of this.nodes.values()) {
      if (!node.advertising) continue;
      results.push({
        peripheralId: node.id,
        rssi: node.rssi,
        proxyServiceData: node.serviceData === null ? null : Buffer.from(node.serviceData),
      });
    }
    return results;
  }

  async connect(peripheralId: string, onDisconnect: () => void): Promise<ConnectionHandle> {
    this.connectCalls.push(peripheralId);
    const node = this.node(peripheralId);
    if (this.openConnections.has(peripheralId)) {
      throw new Error(`FakeBluetoothPort.connect: "${peripheralId}" is already connected`);
    }
    if (node.connectBehavior === 'fail') {
      throw new Error(`FakeBluetoothPort.connect: configured to fail for "${peripheralId}"`);
    }
    this.openConnections.set(peripheralId, { onDisconnect });
    const handle: FakeConnectionHandle = { peripheralId };
    return handle;
  }

  async discover(connection: ConnectionHandle): Promise<DiscoveredCharacteristic[]> {
    const { peripheralId } = connection as FakeConnectionHandle;
    const node = this.node(peripheralId);
    if (!this.openConnections.has(peripheralId)) {
      throw new Error(`FakeBluetoothPort.discover: "${peripheralId}" is not connected`);
    }
    if (node.discoverBehavior === 'fail') {
      throw new Error(`FakeBluetoothPort.discover: configured to fail for "${peripheralId}"`);
    }
    const characteristics: DiscoveredCharacteristic[] = [];
    if (node.missingCharacteristic !== 'dataIn') {
      characteristics.push(this.characteristic(peripheralId, MESH_PROXY_DATA_IN_UUID));
    }
    if (node.missingCharacteristic !== 'dataOut') {
      characteristics.push(this.characteristic(peripheralId, MESH_PROXY_DATA_OUT_UUID));
    }
    return characteristics;
  }

  private characteristic(peripheralId: string, characteristicUuid: number): DiscoveredCharacteristic {
    const handle: FakeCharacteristicHandle = { peripheralId, serviceUuid: MESH_PROXY_SERVICE_UUID, characteristicUuid };
    return { serviceUuid: MESH_PROXY_SERVICE_UUID, characteristicUuid, handle };
  }

  private requireConnectedCharacteristic(characteristic: CharacteristicHandle): FakeCharacteristicHandle {
    const handle = characteristic as FakeCharacteristicHandle;
    this.node(handle.peripheralId);
    if (!this.openConnections.has(handle.peripheralId)) {
      throw new Error(`FakeBluetoothPort: "${handle.peripheralId}" is not connected`);
    }
    return handle;
  }

  async read(characteristic: CharacteristicHandle): Promise<Buffer> {
    const handle = this.requireConnectedCharacteristic(characteristic);
    const value = this.readValues.get(notifyKey(handle.peripheralId, handle.characteristicUuid));
    return Buffer.from(value ?? Buffer.alloc(0));
  }

  /**
   * ASYMMETRY, written down for whoever next extends this (review finding,
   * task 5's second round): `dropWrites` returns BEFORE recording anything
   * in `writesReceived`, while `writeBehavior: 'fail'` records FIRST and
   * THEN throws. Defensible as written -- `dropWrites` models a write that
   * never reached the GATT layer at all (nothing to record), while 'fail'
   * models one that WAS handed to the stack and only then rejected (the
   * radio tried and failed, so the attempt genuinely happened) -- but the
   * two were never stated side by side before now, and a future failure
   * mode should pick one of these two shapes deliberately rather than by
   * accident.
   */
  async write(characteristic: CharacteristicHandle, data: Buffer): Promise<void> {
    const handle = this.requireConnectedCharacteristic(characteristic);
    const node = this.node(handle.peripheralId);
    if (node.dropWrites) return; // Write Without Response: silently discarded, no error either way
    this.writesReceived.push({
      peripheralId: handle.peripheralId,
      characteristicUuid: handle.characteristicUuid,
      data: Buffer.from(data),
    });
    if (node.writeBehavior === 'fail') {
      throw new Error(`FakeBluetoothPort.write: configured to fail for "${handle.peripheralId}"`);
    }
    if (node.writeBehavior === 'hold') {
      // KNOWN GAP (review finding): a held write is NOT settled by
      // `simulateDisconnect`/`simulateNodePoweredOff` below. A real GATT
      // stack would error an in-flight write when the link drops; this
      // fixture instead leaves it pending forever, so a test that holds a
      // write and then disconnects gets a promise that never settles
      // rather than one that rejects. The reviewer flagged this as the
      // most likely of this fixture's asymmetries to bite a future task
      // (the pairing flow inherits this file) -- not fixed here because
      // task 5 never needed a disconnect-while-held scenario, but the next
      // task that does will need `simulateDisconnect` to also reject every
      // currently-held write for that peripheral.
      return new Promise<void>((resolve, reject) => {
        const held = this.heldWrites.get(handle.peripheralId) ?? [];
        held.push({ resolve, reject });
        this.heldWrites.set(handle.peripheralId, held);
      });
    }
  }

  async subscribe(characteristic: CharacteristicHandle, onNotify: (data: Buffer) => void): Promise<Subscription> {
    const handle = this.requireConnectedCharacteristic(characteristic);
    const node = this.node(handle.peripheralId);
    if (node.subscribeBehavior === 'fail') {
      throw new Error(`FakeBluetoothPort.subscribe: configured to fail for "${handle.peripheralId}"`);
    }
    const key = notifyKey(handle.peripheralId, handle.characteristicUuid);
    this.notifyCallbacks.set(key, onNotify);
    return {
      unsubscribe: (): void => {
        if (this.notifyCallbacks.get(key) === onNotify) {
          this.notifyCallbacks.delete(key);
        }
      },
    };
  }

  async disconnect(connection: ConnectionHandle): Promise<void> {
    const { peripheralId } = connection as FakeConnectionHandle;
    // A clean, caller-initiated close: deliberately does NOT invoke
    // onDisconnect (see BluetoothPort's own contract in connection.ts).
    this.openConnections.delete(peripheralId);
    this.clearNotifyCallbacksFor(peripheralId);
  }
}
