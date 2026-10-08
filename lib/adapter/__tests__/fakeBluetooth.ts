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
 *
 * TWO GATT PROFILES, ADDED FOR TASK 6 (pairing). A node's `serviceUuid`
 * (which service `scan()` advertises Service Data for) and `gattProfile`
 * (which characteristic pair `discover()` returns) now default to the Mesh
 * PROXY Service/characteristics — every existing connection.ts/queue.ts
 * test that never sets either field keeps behaving exactly as before this
 * task. A node can instead be configured as `gattProfile: 'provisioning'`
 * (and `serviceUuid: MESH_PROVISIONING_SERVICE_UUID`) to model an
 * UNPROVISIONED node, which `discover()` then answers with the Mesh
 * Provisioning Service's Data In/Out characteristics instead of the Mesh
 * Proxy Service's. `reconfigureAsProvisioned` flips a node from the former
 * to the latter in one call, modelling what a real bulb does the moment
 * provisioning completes — it stops being findable as an unowned node and
 * starts advertising our own network's identity instead. This generalises
 * the SAME hardcoded-to-proxy assumption `ScanResult.proxyServiceData` had
 * (connection.ts's own module header) one layer lower, in the fixture that
 * produces it — see that module's SCAN RESULT SHAPE note for why one
 * hardcoded field could not serve both connection.ts and pairing.ts.
 *
 * FOUR ASYMMETRIES ARE DOCUMENTED BELOW AND DELIBERATELY LEFT UNRESOLVED BY
 * THIS TASK (see each one's own comment: `write()`'s dropWrites-vs-fail
 * recording order, `releaseWrite`'s lack of pruning/double-release guard,
 * `simulateDisconnect` not settling a held write, and SCAN TIMING IS
 * PARTIAL above). Task 6's pairing flow talks to `BluetoothPort` directly —
 * it never goes through `ProxyConnectionManager` or `TrafficQueue`, which
 * is the entire reason its scan targets a different service in the first
 * place — so it has no backoff to race, no queued retries to hold a write
 * open for, and no reconnect timing to get right. None of its required
 * test scenarios exercise any of the four, so none are touched here; they
 * remain exactly as documented for whichever task next needs one.
 *
 * THIS FAKE SPEAKS THE PROXY PDU PROTOCOL (final fix wave). A real bulb
 * never sees a bare Network PDU or a bare Provisioning PDU: both
 * characteristic pairs carry the Proxy PDU envelope (Mesh Protocol v1.1
 * Section 7.2.3.1 "Mesh Proxy Data In characteristic": "The characteristic
 * value has the same format as the Proxy PDU."; Section 5.2.2 "PB-GATT":
 * "The Mesh Provisioning Data In and Mesh Provisioning Data Out
 * characteristic formats use the Proxy PDU format defined in Section
 * 6.3.1."). Before this round this fixture accepted and recorded whatever
 * bytes it was handed, which is precisely why an app that sent no envelope
 * at all passed 889 tests. It now behaves like the Proxy PDU Server it is
 * pretending to be:
 *   - `write()` feeds every PDU through `proxyPdu.ts#acceptProxyPdu`, per
 *     (peripheral, characteristic), and only records a COMPLETE message in
 *     `writesReceived` — so every existing assertion on that array keeps
 *     meaning "one entry per logical message", segmented or not, and an
 *     `AutoResponder` is still called once per logical message;
 *     `rawWritesReceived` keeps the untouched GATT writes for a test that
 *     wants to see the envelope bytes themselves.
 *   - `simulateNotification()` and an `AutoResponder`'s replies are
 *     SEGMENTED on the way out, exactly as a node's would be, so the
 *     manager's own reassembly path is exercised by the whole suite rather
 *     than only by its own unit tests.
 *   - a write the specification says a Proxy PDU Server "shall disconnect"
 *     over (Section 6.3.2.2 "Reassembly") THROWS here instead, naming the
 *     violation. That is deliberately LOUDER than a real node: a fixture
 *     that silently dropped the link would surface as a test timeout three
 *     layers from the cause, and the one mutation this guard exists to
 *     catch — removing the envelope again — is exactly the one that must
 *     never pass quietly. An unsupported/RFU message type throws for the
 *     same reason: this app only ever writes two of Table 6.3's types.
 */

import { k3 } from '../../mesh/crypto/derive';
import {
  acceptProxyPdu,
  encodeProxyPdus,
  PROXY_MESSAGE_TYPE_NETWORK_PDU,
  PROXY_MESSAGE_TYPE_PROVISIONING_PDU,
  type ProxyReassemblyState,
} from '../../mesh/packet/proxyPdu';
import {
  MAX_PROXY_PDU_LENGTH,
  MESH_PROVISIONING_DATA_IN_UUID,
  MESH_PROVISIONING_DATA_OUT_UUID,
  MESH_PROVISIONING_SERVICE_UUID,
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

/** Which GATT profile a `FakeNode` currently exposes — see the module
 *  header's "TWO GATT PROFILES" note. */
export type GattProfile = 'proxy' | 'provisioning';

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
   *  `networkKey`/`serviceDataOverride` must be given. Only meaningful
   *  together with `serviceUuid: MESH_PROXY_SERVICE_UUID` (the default) —
   *  an unprovisioned node has no network key to derive an identity from at
   *  all, so a `gattProfile: 'provisioning'` node should use
   *  `serviceDataOverride` instead (see that field's own doc comment). */
  readonly networkKey?: Buffer;
  /** Advertise this exact Service Data value instead of deriving one from
   *  `networkKey` — for a malformed payload, a non-Network-ID
   *  identification type (Table 7.8), or an unprovisioned node's Mesh
   *  Provisioning Service data (which this fixture never derives, having no
   *  notion of a Device UUID to build one from — any non-empty buffer
   *  models it well enough, since `pairing.ts` never inspects its content,
   *  only its PRESENCE under `MESH_PROVISIONING_SERVICE_UUID`). `null` means
   *  "advertises `serviceUuid` with no Service Data value at all", distinct
   *  from `advertising: false` ("does not advertise at all": see
   *  `setAdvertising`). Exactly one of `networkKey`/`serviceDataOverride`
   *  must be given. */
  readonly serviceDataOverride?: Buffer | null;
  /** Which service UUID `scan()` attaches this node's Service Data to —
   *  default `MESH_PROXY_SERVICE_UUID`, matching every test written before
   *  task 6. Set to `MESH_PROVISIONING_SERVICE_UUID` to model an
   *  unprovisioned node (see the module header's "TWO GATT PROFILES"
   *  note). */
  readonly serviceUuid?: number;
  /** Which characteristic pair `discover()` returns for this node — default
   *  `'proxy'` (Mesh Proxy Data In/Out), matching every test written before
   *  task 6. `'provisioning'` returns the Mesh Provisioning Service's Data
   *  In/Out characteristics instead. */
  readonly gattProfile?: GattProfile;
  readonly advertising?: boolean; // default true
  readonly connectBehavior?: AttemptBehavior; // default 'succeed'
  readonly discoverBehavior?: AttemptBehavior; // default 'succeed'
  readonly subscribeBehavior?: AttemptBehavior; // default 'succeed'
  readonly dropWrites?: boolean; // default false
  readonly writeBehavior?: WriteBehavior; // default 'succeed'; see setWriteBehavior
  /** Omit one data characteristic (of whichever pair `gattProfile`
   *  selects) from `discover()`'s result, modelling a node that advertises
   *  the service but does not fully implement it. `null` (default): expose
   *  both. */
  readonly missingCharacteristic?: 'dataIn' | 'dataOut' | null;
}

interface FakeNode {
  id: string;
  rssi: number;
  serviceUuid: number;
  serviceData: Buffer | null;
  gattProfile: GattProfile;
  advertising: boolean;
  connectBehavior: AttemptBehavior;
  discoverBehavior: AttemptBehavior;
  subscribeBehavior: AttemptBehavior;
  dropWrites: boolean;
  writeBehavior: WriteBehavior;
  missingCharacteristic: 'dataIn' | 'dataOut' | null;
  autoResponder: AutoResponder | null;
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

/**
 * ADDED FOR TASK 6 (pairing): a node's canned reply to one `write()` on its
 * Data In characteristic, if any — `undefined`/no return means no reply for
 * THIS write (modelling, e.g., one segment of a multi-segment request,
 * which a real node never acknowledges individually). Delivered
 * SYNCHRONOUSLY, inside `write()` itself, before its own returned promise
 * resolves — this models a real node answering a request with a
 * notification shortly afterwards without this fixture needing a second,
 * separately-timed call the way `simulateNotification` requires; a test
 * that instead wants to control exactly when a reply lands (to pin a race)
 * should keep using `simulateNotification` directly, which this does not
 * replace. Takes the written bytes and the characteristic written to,
 * mirroring the shape `writesReceived` already records, so a responder can
 * build a real, stateful fake peer (see `drivers/light/__tests__/
 * pairing.test.ts`, which drives the real provisioning state machine and
 * real config exchange this way, keyed on how many writes it has seen
 * rather than on their contents, which the published sample fixtures this
 * project already trusts for `machine.ts` make exact).
 */
export type AutoResponder = (data: Buffer, characteristicUuid: number) => Buffer[] | undefined;

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
  /** One in-flight Proxy PDU reassembly per (peripheral, characteristic) —
   *  see the module header's "THIS FAKE SPEAKS THE PROXY PDU PROTOCOL"
   *  note. Cleared whenever the link to that peripheral goes away. */
  private readonly writeReassembly = new Map<string, ProxyReassemblyState>();

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
  readonly writesReceived: Array<{ peripheralId: string; characteristicUuid: number; data: Buffer; messageType: number }> = [];
  /** Every GATT write exactly as it arrived — envelope octet included, one
   *  entry per `write()` call rather than per logical message. The place to
   *  look when a test is about the envelope itself (its SAR values, its
   *  segment sizes) rather than about the message inside it. */
  readonly rawWritesReceived: Array<{ peripheralId: string; characteristicUuid: number; data: Buffer }> = [];
  /** Every `durationMs` a caller passed to `scan()`, in order — review
   *  finding: this fixture previously accepted and ignored that argument
   *  entirely, so connection.ts's SCAN_DURATION_MS constant was never
   *  actually observed by anything. */
  readonly scanDurationsRequested: number[] = [];
  private scanCalls = 0;
  private subscriptionsOpened = 0;
  private subscriptionsReleased = 0;

  scanCallCount(): number {
    return this.scanCalls;
  }

  /**
   * How many `Subscription`s this port has handed out whose `unsubscribe()`
   * has never been called — the instrument for "what a caller subscribes, it
   * releases", added for the hardware round of 2026-10-08 (three bulbs lost
   * to notifications delivered once per leaked subscription; see
   * `drivers/light/pairing.ts#openSession`).
   *
   * DELIBERATELY INDEPENDENT OF `disconnect()`. Dropping the link clears
   * this fixture's notification callbacks, because a real link's
   * notifications stop when it does — but that is the LINK letting go, not
   * the caller, and counting it as a release would hide exactly the defect
   * this counts: a `Subscription` the caller never released. So this number
   * moves only when `unsubscribe()` is actually called.
   */
  liveSubscriptionCount(): number {
    return this.subscriptionsOpened - this.subscriptionsReleased;
  }

  /** How many subscriptions were handed out in total — so a test asserting
   *  `liveSubscriptionCount() === 0` can first prove there was something to
   *  release, rather than passing because nothing ever subscribed. */
  subscriptionCount(): number {
    return this.subscriptionsOpened;
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
      serviceUuid: config.serviceUuid ?? MESH_PROXY_SERVICE_UUID,
      serviceData,
      gattProfile: config.gattProfile ?? 'proxy',
      advertising: config.advertising ?? true,
      connectBehavior: config.connectBehavior ?? 'succeed',
      discoverBehavior: config.discoverBehavior ?? 'succeed',
      subscribeBehavior: config.subscribeBehavior ?? 'succeed',
      dropWrites: config.dropWrites ?? false,
      writeBehavior: config.writeBehavior ?? 'succeed',
      missingCharacteristic: config.missingCharacteristic ?? null,
      autoResponder: null,
    });
  }

  /** Sets (or, with `null`, clears) `id`'s auto-responder — see
   *  `AutoResponder`'s own doc comment. Replacing a node's responder with a
   *  new one is the normal way a test models the node's own behaviour
   *  CHANGING mid-session (e.g. switching from answering provisioning
   *  requests to answering configuration requests, once provisioning
   *  completes) — each responder instance tracks its own state (such as a
   *  write counter) in its own closure, so replacing it always starts that
   *  state fresh. */
  setAutoResponder(id: string, responder: AutoResponder | null): void {
    this.node(id).autoResponder = responder;
  }

  /** Models a node completing provisioning: it stops being findable as an
   *  unowned node and starts advertising OUR network's identity instead —
   *  both halves at once, the way a real bulb's own transition from the
   *  Mesh Provisioning Service to the Mesh Proxy Service is one event, not
   *  two independently-timed ones. A test calls this between the
   *  provisioning phase and the configuration phase of a pairing flow,
   *  exactly where the real GATT bearer switches over (see
   *  `drivers/light/pairing.ts`'s own module header for why pairing
   *  reconnects rather than reusing one link across both phases). */
  reconfigureAsProvisioned(id: string, networkKey: Buffer): void {
    const node = this.node(id);
    node.serviceUuid = MESH_PROXY_SERVICE_UUID;
    node.serviceData = deriveServiceData(networkKey);
    node.gattProfile = 'proxy';
  }

  /** The inverse of `reconfigureAsProvisioned` — models a node returning to
   *  the unowned state (Config Node Reset accepted, or a factory reset):
   *  it stops advertising our network's identity and starts advertising the
   *  Mesh Provisioning Service again, with `serviceData` the caller
   *  supplies (an arbitrary non-empty buffer is enough — nothing in this
   *  project inspects an unprovisioned node's Service Data content, only
   *  its presence under `MESH_PROVISIONING_SERVICE_UUID`; see
   *  `drivers/light/pairing.ts#scanForUnprovisionedNodes`). Added for the
   *  review finding that a configuration-phase failure must not orphan the
   *  node: a test can call this (from a Config Node Reset auto-responder)
   *  and then assert the SAME peripheral is scannable as unprovisioned
   *  again. */
  reconfigureAsUnprovisioned(id: string, serviceData: Buffer): void {
    const node = this.node(id);
    node.serviceUuid = MESH_PROVISIONING_SERVICE_UUID;
    node.serviceData = Buffer.from(serviceData);
    node.gattProfile = 'provisioning';
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

  /** Simulates an inbound notification on `id`'s Data Out characteristic —
   *  the Mesh Proxy one by default, or the Mesh Provisioning one when the
   *  node is currently `gattProfile: 'provisioning'` (see the module
   *  header's "TWO GATT PROFILES" note), matching whichever pair
   *  `discover()` would return for it right now. Throws if nothing is
   *  currently subscribed to it — a misconfigured test, not a
   *  silently-dropped notification (that is what `dropWrites` models for
   *  the opposite direction; nothing in this fixture silently drops a
   *  configured notification). */
  simulateNotification(id: string, data: Buffer): void {
    const node = this.node(id);
    const dataOutUuid = node.gattProfile === 'provisioning' ? MESH_PROVISIONING_DATA_OUT_UUID : MESH_PROXY_DATA_OUT_UUID;
    const messageType = node.gattProfile === 'provisioning' ? PROXY_MESSAGE_TYPE_PROVISIONING_PDU : PROXY_MESSAGE_TYPE_NETWORK_PDU;
    const key = notifyKey(id, dataOutUuid);
    const callback = this.notifyCallbacks.get(key);
    if (!callback) {
      throw new Error(`FakeBluetoothPort.simulateNotification: "${id}" has no active Data Out subscription`);
    }
    // A node wraps and segments what it notifies, exactly as this fixture's
    // caller's own transport does — "Each notification contains a single
    // Proxy PDU." (Section 3.3.2 "GATT bearer"), so one logical message can
    // be several callbacks.
    for (const pdu of encodeProxyPdus(messageType, data, MAX_PROXY_PDU_LENGTH)) callback(pdu);
  }

  /** Delivers ONE raw Proxy PDU with no wrapping or segmentation at all —
   *  for a test that needs to put a specific envelope (a malformed one, a
   *  stray continuation segment, an unsupported message type) on the wire.
   *  `simulateNotification` above is the ordinary route. */
  simulateRawNotification(id: string, pdu: Buffer): void {
    const node = this.node(id);
    const dataOutUuid = node.gattProfile === 'provisioning' ? MESH_PROVISIONING_DATA_OUT_UUID : MESH_PROXY_DATA_OUT_UUID;
    const callback = this.notifyCallbacks.get(notifyKey(id, dataOutUuid));
    if (!callback) {
      throw new Error(`FakeBluetoothPort.simulateRawNotification: "${id}" has no active Data Out subscription`);
    }
    callback(Buffer.from(pdu));
  }

  private clearNotifyCallbacksFor(peripheralId: string): void {
    const prefix = `${peripheralId}:`;
    for (const key of [...this.notifyCallbacks.keys()]) {
      if (key.startsWith(prefix)) this.notifyCallbacks.delete(key);
    }
    // A half-arrived Proxy PDU belongs to the link it was arriving over —
    // see connection.ts's own identical reset on every disconnect.
    for (const key of [...this.writeReassembly.keys()]) {
      if (key.startsWith(prefix)) this.writeReassembly.delete(key);
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
        serviceData: node.serviceData === null ? [] : [{ serviceUuid: node.serviceUuid, data: Buffer.from(node.serviceData) }],
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
    const serviceUuid = node.gattProfile === 'provisioning' ? MESH_PROVISIONING_SERVICE_UUID : MESH_PROXY_SERVICE_UUID;
    const dataInUuid = node.gattProfile === 'provisioning' ? MESH_PROVISIONING_DATA_IN_UUID : MESH_PROXY_DATA_IN_UUID;
    const dataOutUuid = node.gattProfile === 'provisioning' ? MESH_PROVISIONING_DATA_OUT_UUID : MESH_PROXY_DATA_OUT_UUID;
    const characteristics: DiscoveredCharacteristic[] = [];
    if (node.missingCharacteristic !== 'dataIn') {
      characteristics.push(this.characteristic(peripheralId, serviceUuid, dataInUuid));
    }
    if (node.missingCharacteristic !== 'dataOut') {
      characteristics.push(this.characteristic(peripheralId, serviceUuid, dataOutUuid));
    }
    return characteristics;
  }

  private characteristic(peripheralId: string, serviceUuid: number, characteristicUuid: number): DiscoveredCharacteristic {
    const handle: FakeCharacteristicHandle = { peripheralId, serviceUuid, characteristicUuid };
    return { serviceUuid, characteristicUuid, handle };
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
    this.rawWritesReceived.push({
      peripheralId: handle.peripheralId,
      characteristicUuid: handle.characteristicUuid,
      data: Buffer.from(data),
    });
    const message = this.acceptWrittenProxyPdu(handle, data);
    if (message !== null) {
      this.writesReceived.push({
        peripheralId: handle.peripheralId,
        characteristicUuid: handle.characteristicUuid,
        data: message.message,
        messageType: message.messageType,
      });
    }
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
    if (node.autoResponder) {
      // Captured from `handle` BEFORE calling the responder, not read from
      // `node.gattProfile` afterwards: a responder is allowed to flip the
      // node's profile as a side effect of answering (exactly what models a
      // node completing provisioning — see `AutoResponder`'s own doc
      // comment and `reconfigureAsProvisioned`). Reading `node.gattProfile`
      // AFTER that call would then route THIS reply to the NEW profile's
      // Data Out — the wrong one, since this write (and so this reply)
      // belongs to whichever service `handle` itself was discovered under.
      const dataOutUuid = handle.serviceUuid === MESH_PROVISIONING_SERVICE_UUID ? MESH_PROVISIONING_DATA_OUT_UUID : MESH_PROXY_DATA_OUT_UUID;
      const messageType =
        handle.serviceUuid === MESH_PROVISIONING_SERVICE_UUID ? PROXY_MESSAGE_TYPE_PROVISIONING_PDU : PROXY_MESSAGE_TYPE_NETWORK_PDU;
      // The responder is handed the REASSEMBLED message, so it sees one
      // call per logical message exactly as it did before this fixture
      // learned the envelope — and is never called at all for a segment
      // that merely continues one (`message === null`), which is the same
      // "no reply for THIS write" case `AutoResponder` already documents.
      if (message === null) return;
      const replies = node.autoResponder(Buffer.from(message.message), handle.characteristicUuid);
      if (replies && replies.length > 0) {
        const callback = this.notifyCallbacks.get(notifyKey(handle.peripheralId, dataOutUuid));
        if (callback) {
          for (const reply of replies) {
            for (const pdu of encodeProxyPdus(messageType, reply, MAX_PROXY_PDU_LENGTH)) callback(pdu);
          }
        }
      }
    }
  }

  /**
   * The Proxy PDU Server half of this fixture — see the module header.
   * Returns the complete message once its last segment has arrived, `null`
   * while a message is still arriving, and THROWS for anything the
   * specification says a server shall disconnect over, or for a message
   * type this app never writes.
   */
  private acceptWrittenProxyPdu(
    handle: FakeCharacteristicHandle,
    pdu: Buffer,
  ): { readonly messageType: number; readonly message: Buffer } | null {
    const key = notifyKey(handle.peripheralId, handle.characteristicUuid);
    const result = acceptProxyPdu(this.writeReassembly.get(key), pdu, this.clock?.now() ?? 0);
    switch (result.kind) {
      case 'complete':
        this.writeReassembly.delete(key);
        return { messageType: result.messageType, message: result.message };
      case 'incomplete':
        this.writeReassembly.set(key, result.state);
        return null;
      case 'ignored':
        throw new Error(
          `FakeBluetoothPort.write: "${handle.peripheralId}" was written something it cannot interpret as a Proxy PDU it supports — ${result.reason}. A real node would ignore this silently; this fixture fails loudly (see its module header).`,
        );
      case 'disconnect':
        this.writeReassembly.delete(key);
        throw new Error(
          `FakeBluetoothPort.write: "${handle.peripheralId}" received a Proxy PDU the specification says it shall disconnect over — ${result.reason} (Section 6.3.2.2). A real node would drop the link; this fixture fails loudly (see its module header).`,
        );
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
    this.subscriptionsOpened += 1;
    // Per SUBSCRIPTION, not per callback: a second `unsubscribe()` on the
    // same object is a no-op in any sane implementation, and must not count
    // as a second release (see `liveSubscriptionCount`).
    let releasedThis = false;
    return {
      unsubscribe: (): void => {
        if (!releasedThis) {
          releasedThis = true;
          this.subscriptionsReleased += 1;
        }
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
