import {
  pairNode,
  scanForUnprovisionedNodes,
  connectForProvisioning,
  parseBleUuid,
  bleUuidString,
  tryParseBleUuid,
  filterKnownServiceData,
  filterKnownCharacteristics,
  DEFAULT_PAIRING_STEP_TIMEOUT_MS,
  type PairingDeps,
  type ProvisioningRandomSource,
} from '../pairing';
import { NetworkStore, type SettingsPort } from '../../../lib/adapter/store';
import { FakeBluetoothPort, type AutoResponder } from '../../../lib/adapter/__tests__/fakeBluetooth';
import { createFakeClock, type FakeClock } from '../../../lib/adapter/__tests__/fakeClock';
import {
  MESH_PROVISIONING_SERVICE_UUID,
  MESH_PROVISIONING_DATA_IN_UUID,
  MESH_PROVISIONING_DATA_OUT_UUID,
  MESH_PROXY_SERVICE_UUID,
  type BluetoothPort,
  type ScanResult,
  type DiscoveredCharacteristic,
  type Subscription,
} from '../../../lib/adapter/connection';
import { encodeMeshMessage, acceptIncomingPdu, type MeshReceiveState, type MeshReceiveContext } from '../../../lib/mesh/packet/message';
import { encodeProvisioningPdu, type ProvisioningCapabilities } from '../../../lib/mesh/provisioning/pdu';
import type { EphemeralKeyPair } from '../../../lib/mesh/provisioning/machine';
import { decodeNetworkPdu } from '../../../lib/mesh/packet/network';
import { decodeUnsegmentedAccess } from '../../../lib/mesh/packet/lowerTransport';
import { decryptUpperTransport } from '../../../lib/mesh/packet/upperTransport';
import { decodeAccessMessage } from '../../../lib/mesh/packet/access';
import {
  hex,
  PDU_TYPE_SAMPLE_CAPABILITIES,
  PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE,
  PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE,
  PDU_TYPE_SAMPLE_RANDOM_PROVISIONER,
  PDU_TYPE_SAMPLE_RANDOM_DEVICE,
  PDU_TYPE_SAMPLE_COMPLETE,
  PROVISIONING_CRYPTO_SAMPLE,
} from '../../../lib/mesh/provisioning/__tests__/vectors';
import { PROVISIONING_SAMPLE } from '../../../lib/mesh/crypto/__tests__/vectors';
import { COMPOSITION_DATA_PAGE0_SAMPLE } from '../../../lib/mesh/config/__tests__/vectors';

/**
 * Drives the WHOLE pairing sequence — provisioning (the real
 * `lib/mesh/provisioning/machine.ts` state machine), address allocation
 * (the real `lib/adapter/store.ts`), the configuration exchange (the real
 * `lib/mesh/config/client.ts` + `lib/adapter/meshMessage.ts`'s network/
 * transport composition) and capability mapping (the real
 * `lib/models/capabilities.ts`) — against the shared fake Bluetooth port,
 * per the task brief's "Drive the whole sequence with the fake Bluetooth
 * port and the real core."
 *
 * DETERMINISM, AND WHY THE EXCHANGE IS STILL "THE REAL CORE". `pairNode`'s
 * injected `ProvisioningRandomSource` is fed the Mesh Protocol
 * specification's own published Section 8.7/8.17.1 sample's PROVISIONER-side
 * inputs (ephemeral key pair, RandomProvisioner) — the same fixture
 * `lib/mesh/provisioning/__tests__/machine.test.ts` already trusts. This
 * fake node then replies with that SAME sample's published DEVICE-side PDUs,
 * in order. Nothing is replayed blindly: `machine.ts` still runs its own
 * real ECDH, its own real Confirmation/Random checks, and its own real
 * AES-CCM encryption of the Provisioning Data block (built from THIS test's
 * own network key and the store's own allocated address, never the
 * sample's) — fixing the RANDOM INPUTS is what makes the result
 * deterministic (a known device key, `PROVISIONING_CRYPTO_SAMPLE.deviceKey`),
 * not a shortcut around running the exchange. The configuration exchange
 * that follows is built the same way in reverse: the fake node's Composition
 * Data Status / AppKey Status / Model App Status replies are constructed
 * with `lib/adapter/meshMessage.ts`'s own `encodeMeshMessage` — the exact
 * function `pairing.ts` itself uses — so this test is a real node-key/
 * network-key-encrypted, real-segmentation round trip through the network,
 * lower transport, upper transport and access layers, not a canned buffer
 * compared against itself.
 *
 * COUNTING WRITES, NOT DECODING THEM. The fake node's auto-responders key
 * their replies on HOW MANY writes they have seen (see
 * `installProvisioningResponder`/`installConfigResponder` below), not on
 * decoding what was written — the provisioning exchange's wire order is
 * fixed by the specification (machine.ts's own DIRECTION AND ORDER note),
 * and this task's config exchange always sends Composition Data Get, then
 * AppKey Add (segmented into exactly two Network PDUs — see
 * `meshMessage.ts`'s own header), then one Config Model App Bind per
 * matching SIG model (exactly one, Generic OnOff Server, for this file's
 * fixture composition). `writesReceived` is asserted separately in the
 * dedicated "wrote the expected requests" test below, which DOES decode
 * every write back to its opcode — closing the gap a pure write-counting
 * responder would otherwise leave (a driver that sent the wrong request
 * would still "pass" a test that never inspects what it sent).
 */

// ===========================================================================
// Fixtures: known-answer provisioning inputs/outputs, and synthetic (never
// published, chosen to differ from each other and from every KAT value —
// the project's own "fixture value" lesson) network/application keys.
// ===========================================================================

const KAT_EPHEMERAL_KEY_PAIR: EphemeralKeyPair = {
  publicKey: Buffer.concat([
    hex(PROVISIONING_SAMPLE.provisionerPublicKeyX),
    hex(PROVISIONING_SAMPLE.provisionerPublicKeyY),
  ]),
  privateKey: hex(PROVISIONING_SAMPLE.provisionerPrivateKey),
};
const KAT_RANDOM_PROVISIONER = hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.fields.random);
const KAT_DEVICE_KEY = hex(PROVISIONING_CRYPTO_SAMPLE.deviceKey);

// Synthetic — not published anywhere, and deliberately unlike each other
// (see this plan's own lesson on palindromic/shared fixture values: a
// network key equal to the application key, or either reading the same
// forwards and backwards, would hide a field confused with the other).
const TEST_NET_KEY = Buffer.from('3f8a19c20e5b74d1a6f0238b9cd4e157', 'hex');
const TEST_APP_KEY = Buffer.from('7c0e4b98213fa5d6889021cc45baf310', 'hex');

/** An arbitrary, non-empty Service Data value for an unprovisioned node's
 *  Mesh Provisioning Service advertisement — this project's own fixture
 *  never derives one the way it derives a Proxy node's Network ID (there is
 *  no key yet to derive it from), and `pairing.ts` never inspects its
 *  content, only its PRESENCE (see `scanForUnprovisionedNodes`). */
const UNPROVISIONED_SERVICE_DATA = Buffer.from('00112233445566778899aabbccddeeff0', 'hex');

class FakeSettingsPort implements SettingsPort {
  private readonly data = new Map<string, string>();

  get(key: string): unknown {
    const raw = this.data.get(key);
    return raw === undefined ? null : JSON.parse(raw);
  }

  set(key: string, value: unknown): void {
    this.data.set(key, JSON.stringify(value));
  }
}

/** Hands out queued random values in order, throwing (a misconfigured
 *  test, not a thing to paper over — same stance the shared fixture's own
 *  "nothing to act on" methods take) if asked for more than were queued, or
 *  for a length that does not match what was queued next — so a change to
 *  `pairing.ts`'s own call count/order is caught here immediately rather
 *  than silently handing back the wrong value. */
class FixedRandomSource implements ProvisioningRandomSource {
  private readonly queue: Buffer[];
  constructor(
    queue: readonly Buffer[],
    private readonly keyPair: EphemeralKeyPair,
  ) {
    this.queue = [...queue];
  }

  randomBytes(length: number): Buffer {
    const next = this.queue.shift();
    if (next === undefined) {
      throw new Error('FixedRandomSource: randomBytes queue exhausted');
    }
    if (next.length !== length) {
      throw new Error(`FixedRandomSource: expected a ${length}-byte request, next queued value is ${next.length} bytes`);
    }
    return next;
  }

  generateEphemeralKeyPair(): EphemeralKeyPair {
    return this.keyPair;
  }
}

/**
 * Polls `predicate` once per real macrotask turn until it is true (or gives
 * up after `maxIterations`, failing loudly rather than hanging) — used only
 * to know WHEN it is safe to call `FakeClock#advance` against an un-awaited
 * `pairNode(...)` promise that is expected to genuinely stall on the fake
 * clock. This is NOT the same hazard this plan's own lesson warns about (a
 * fake too fast to lose a race): every OTHER wait in this whole test file
 * resolves instantly via the synchronous auto-responder, so advancing the
 * clock before its own timer is armed would needlessly risk firing an
 * EARLIER step's own (momentarily pending, about to be cleared) timeout
 * instead of the one this test means to trigger. Polling on OBSERVABLE
 * STATE (`predicate`) rather than a fixed number of microtask flushes is
 * what makes this safe regardless of exactly how many ticks the chain
 * ahead of it takes.
 */
async function waitUntil(predicate: () => boolean, maxIterations = 1000): Promise<void> {
  for (let i = 0; i < maxIterations && !predicate(); i++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  if (!predicate()) {
    throw new Error('waitUntil: condition never became true');
  }
}

function setUp(randomQueue: readonly Buffer[] = [TEST_NET_KEY, TEST_APP_KEY, KAT_RANDOM_PROVISIONER, KAT_RANDOM_PROVISIONER]): {
  bluetooth: FakeBluetoothPort;
  store: NetworkStore;
  random: FixedRandomSource;
  clock: FakeClock;
  deps: PairingDeps;
} {
  const bluetooth = new FakeBluetoothPort();
  const store = new NetworkStore(new FakeSettingsPort());
  const random = new FixedRandomSource(randomQueue, KAT_EPHEMERAL_KEY_PAIR);
  const clock = createFakeClock();
  return { bluetooth, store, random, clock, deps: { bluetooth, store, random, clock } };
}

function addUnprovisionedNode(bluetooth: FakeBluetoothPort, id: string, rssi: number): void {
  bluetooth.addNode({
    id,
    rssi,
    serviceUuid: MESH_PROVISIONING_SERVICE_UUID,
    serviceDataOverride: UNPROVISIONED_SERVICE_DATA,
    gattProfile: 'provisioning',
  });
}

// ===========================================================================
// The fake node's own behaviour, phase by phase.
// ===========================================================================

interface ProvisioningResponderOptions {
  /** Default: the genuine published Capabilities PDU. Overridden to test
   *  the OOB-unsupported and malformed-reply paths. */
  readonly capabilitiesReply?: Buffer;
  readonly publicKeyDeviceReply?: Buffer;
  /** Called once, exactly when the Complete reply is handed back (write
   *  #6) — the success path's hook for "the node now switches to its
   *  provisioned (Proxy) GATT profile", mirroring a real bulb's own
   *  behaviour at that exact point (see `pairing.ts`'s own module header,
   *  "TWO GATT SESSIONS"). */
  readonly onComplete?: () => void;
}

function installProvisioningResponder(bluetooth: FakeBluetoothPort, peripheralId: string, options: ProvisioningResponderOptions = {}): void {
  const repliesByWriteCount: Record<number, Buffer[]> = {
    1: [options.capabilitiesReply ?? hex(PDU_TYPE_SAMPLE_CAPABILITIES.message)],
    3: [options.publicKeyDeviceReply ?? hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message)],
    4: [hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message)],
    5: [hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message)],
    6: [hex(PDU_TYPE_SAMPLE_COMPLETE.message)],
  };
  let count = 0;
  const responder: AutoResponder = () => {
    count += 1;
    const reply = repliesByWriteCount[count];
    if (count === 6) options.onComplete?.();
    return reply;
  };
  bluetooth.setAutoResponder(peripheralId, responder);
}

interface ConfigResponderOptions {
  /** Opcode||Parameters for the Config Composition Data Status reply.
   *  Default: the published Composition Data Page 0 sample (one element,
   *  Generic OnOff Server among its SIG models). Overridden to test the
   *  malformed-composition path. */
  readonly compositionAccessPayload?: Buffer;
  /** Table 4.308 status code for the Config AppKey Status reply. Default
   *  0x00 (Success); overridden to test the node-refuses-AppKey-Add path. */
  readonly appKeyStatus?: number;
  /** Table 4.308 status code for the Config Model App Status reply.
   *  Default 0x00 (Success); overridden to test the
   *  node-refuses-Model-App-Bind path. */
  readonly modelAppStatus?: number;
  /** When true, a Config Node Reset request gets NO reply at all (modelling
   *  a node that is unreachable for the reset too) — default false
   *  (replies with Node Reset Status and returns to the unowned state). */
  readonly failReset?: boolean;
  /** When true, a Config Node Reset request is answered with the WRONG
   *  status message type (an AppKey Status) instead of silence or a
   *  correct Node Reset Status — a node that is reachable but misbehaves,
   *  as opposed to one that is merely unreachable (`failReset`). Exercises
   *  `attemptNodeReset`'s `status.type !== 'nodeReset'` branch, which
   *  silence alone cannot reach (that path throws/times out before ever
   *  decoding a reply to check its type). */
  readonly nodeResetWrongReply?: boolean;
}

function installConfigResponder(
  bluetooth: FakeBluetoothPort,
  peripheralId: string,
  ourAddress: number,
  nodeAddress: number,
  options: ConfigResponderOptions = {},
): void {
  let nodeSeq = 0;
  const allocateNodeSeq = (): number => nodeSeq++;
  const sendAsNode = (accessPayload: Buffer): Buffer[] =>
    encodeMeshMessage({
      accessPayload,
      key: KAT_DEVICE_KEY,
      keyKind: 'device',
      src: nodeAddress,
      dst: ourAddress,
      netKey: TEST_NET_KEY,
      ivIndex: 0,
      allocateSeq: allocateNodeSeq,
    });

  const compositionAccessPayload =
    options.compositionAccessPayload ?? Buffer.concat([Buffer.from([0x02, 0x00]), hex(COMPOSITION_DATA_PAGE0_SAMPLE.message)]);

  // OPCODE-DRIVEN, NOT POSITION-COUNTED (fixed after a review-round bug):
  // an earlier version of this responder keyed its replies on "the Nth
  // write", which breaks the moment a failure short-circuits the exchange
  // — e.g. a refused AppKey Add means the NEXT write is a Config Node
  // Reset, not the Model App Bind position-counting assumed. Decoding every
  // write with the real `acceptIncomingPdu` (the same reassembly machinery
  // `pairing.ts` itself uses) and dispatching on the resulting OPCODE is
  // correct regardless of which step failed or how many writes preceded it
  // — and for free, correctly reassembles AppKey Add's two segments before
  // ever looking at its opcode.
  let driverRequestState: MeshReceiveState | undefined;
  const driverRequestContext: MeshReceiveContext = {
    key: KAT_DEVICE_KEY,
    keyKind: 'device',
    netKey: TEST_NET_KEY,
    ivIndex: 0,
    expectedSrc: ourAddress,
  };

  const responder: AutoResponder = (data) => {
    const result = acceptIncomingPdu(driverRequestState, driverRequestContext, data);
    if (result.kind !== 'complete') {
      driverRequestState = result.state;
      return undefined; // mid-segmented-request (AppKey Add's first segment) — no reply yet
    }
    driverRequestState = undefined;

    if (result.message.opcode === 0x8008) {
      // Config Composition Data Get -> Config Composition Data Status.
      return sendAsNode(compositionAccessPayload);
    }
    if (result.message.opcode === 0x00) {
      // Config AppKey Add -> Config AppKey Status. NetKeyIndex=AppKeyIndex=0
      // (packed bytes are all-zero regardless of packing scheme when both
      // indexes are zero).
      const status = options.appKeyStatus ?? 0x00;
      return sendAsNode(Buffer.from([0x80, 0x03, status, 0x00, 0x00, 0x00]));
    }
    if (result.message.opcode === 0x803d) {
      // Config Model App Bind (Generic OnOff Server, element 0) -> Config
      // Model App Status.
      const status = options.modelAppStatus ?? 0x00;
      const elementAddressLe = Buffer.alloc(2);
      elementAddressLe.writeUInt16LE(nodeAddress, 0);
      const modelIdLe = Buffer.alloc(2);
      modelIdLe.writeUInt16LE(0x1000, 0);
      return sendAsNode(Buffer.concat([Buffer.from([0x80, 0x3e, status]), elementAddressLe, Buffer.from([0x00, 0x00]), modelIdLe]));
    }
    if (result.message.opcode === 0x8049) {
      // Config Node Reset — review finding (HIGH): pairing.ts now sends one
      // on every configuration-phase failure, over this same still-open
      // session, so a test exercising one of those failures must answer it
      // (or `sendConfigRequest`'s own wait for Node Reset Status hangs) and
      // model the node's real response: it returns to the unowned state
      // and is scannable again.
      if (options.failReset) return undefined; // modelling a node unreachable for the reset too
      if (options.nodeResetWrongReply) {
        // Reachable, but answers with the WRONG status type (an AppKey
        // Status) — never silently treated as a successful reset.
        return sendAsNode(Buffer.from([0x80, 0x03, 0x00, 0x00, 0x00, 0x00]));
      }
      bluetooth.reconfigureAsUnprovisioned(peripheralId, UNPROVISIONED_SERVICE_DATA);
      return sendAsNode(Buffer.from([0x80, 0x4a])); // Config Node Reset Status — no parameters.
    }
    return undefined;
  };
  bluetooth.setAutoResponder(peripheralId, responder);
}

/** Wires BOTH phases together exactly as a real pairing run would
 *  experience them: provisioning first, then (once Complete is handed
 *  back) the node flips to its provisioned GATT profile and the config
 *  responder takes over. `ourAddress`/`nodeAddress` must be known ahead of
 *  time by the caller (this project's store allocates deterministically —
 *  address 1 for ourselves on first use, then one per node in pairing
 *  order), since the config responder's replies are addressed using them. */
function installSuccessfulNodeBehaviour(
  bluetooth: FakeBluetoothPort,
  peripheralId: string,
  ourAddress: number,
  nodeAddress: number,
  configOptions: ConfigResponderOptions = {},
): void {
  installProvisioningResponder(bluetooth, peripheralId, {
    onComplete: () => {
      bluetooth.reconfigureAsProvisioned(peripheralId, TEST_NET_KEY);
      installConfigResponder(bluetooth, peripheralId, ourAddress, nodeAddress, configOptions);
    },
  });
}

// ===========================================================================
// scanForUnprovisionedNodes
// ===========================================================================

describe('scanForUnprovisionedNodes', () => {
  test('lists only nodes advertising the Mesh Provisioning Service, strongest first', async () => {
    const { bluetooth } = setUp();
    addUnprovisionedNode(bluetooth, 'weak', -70);
    addUnprovisionedNode(bluetooth, 'strong', -40);
    bluetooth.addNode({ id: 'already-ours', rssi: -10, networkKey: TEST_NET_KEY }); // a PROXY node — already provisioned, not ours to pair

    const candidates = await scanForUnprovisionedNodes(bluetooth);

    expect(candidates).toEqual([
      { peripheralId: 'strong', rssi: -40 },
      { peripheralId: 'weak', rssi: -70 },
    ]);
  });
});

// ===========================================================================
// A successful pairing.
// ===========================================================================

describe('a successful pairing', () => {
  test('produces a device whose capabilities match the composition the node reported, and a store entry with its address/device key/composition', async () => {
    const { bluetooth, store, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'bulb-1', -55);
    // Deterministic per this project's own allocator (MIN_UNICAST_ADDRESS):
    // our own address is 1 (first-run), the first node paired is 2.
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-1', 1, 2);

    const outcome = await pairNode(deps, 'bulb-1');

    // THE LEAK CHECK (review finding, smaller item): every bounded GATT
    // operation across BOTH GATT sessions (connect/discover/subscribe/
    // write/next/disconnect, twice over) must have cleared its own timer
    // on success — `withTimeout` already does (`clock.clearTimeout(timer)`
    // on both the fulfil and reject branches), but nothing previously
    // asserted it, the same instrument `lib/adapter/__tests__/queue.test.ts`
    // already uses for its own analogous check ("a settled command actually
    // cancels its own timer"). A single skipped `clearTimeout` anywhere in
    // this whole successful run would leave this above 0.
    expect(clock.pendingCount()).toBe(0);

    expect(outcome.kind).toBe('paired');
    if (outcome.kind !== 'paired') return; // narrows for the type checker; the expect above already fails the test otherwise
    expect(outcome.device.data.id).toBe('2');
    expect(outcome.device.store.peripheralId).toBe('bulb-1');
    // Generic OnOff Server (0x1000) is the only one of the four lighting
    // SIG models COMPOSITION_DATA_PAGE0_SAMPLE's single element declares
    // (its other SIG models, 0x0000/0x8000/0x0001/0x1003, are not in
    // lib/models/capabilities.ts's table at all).
    expect(outcome.device.capabilities).toEqual(['onoff']);

    const state = store.getState();
    expect(state.netKey).toEqual(TEST_NET_KEY);
    expect(state.appKey).toEqual(TEST_APP_KEY);
    expect(state.ourUnicastAddress).toBe(1);
    expect(state.nodes).toHaveLength(1);
    expect(state.nodes[0]?.address).toBe(2);
    expect(state.nodes[0]?.deviceKey).toEqual(KAT_DEVICE_KEY);
    expect(state.nodes[0]?.composition.elements).toHaveLength(1);
    expect(state.nodes[0]?.composition.elements[0]?.sigModels).toEqual(COMPOSITION_DATA_PAGE0_SAMPLE.fields.elements[0]?.sigModels);
  });

  test('the unicast address allocated is the one the store offered, and the store\'s next free address moves past it — proved across TWO consecutive pairings', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'bulb-1', -55);
    addUnprovisionedNode(bluetooth, 'bulb-2', -60);
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-1', 1, 2);

    const first = await pairNode(deps, 'bulb-1');
    expect(first.kind).toBe('paired');
    // store.getState() is read AFTER bulb-1's pairing: offered address is
    // exactly what the store's own next-free pointer had just been, and
    // that pointer has moved past it (1 element, so by exactly 1).
    expect(store.getState().nextUnicastAddress).toBe(3);

    installSuccessfulNodeBehaviour(bluetooth, 'bulb-2', 1, 3);
    const second = await pairNode(deps, 'bulb-2');
    expect(second.kind).toBe('paired');
    if (second.kind !== 'paired') return;
    // THE DISCRIMINATING ASSERTION: bulb-2 gets address 3, never address 2
    // again — an allocator that handed out the same address twice (this
    // task's own brief's mutation target) would make this fail while the
    // test above (which only pairs one node) would not notice at all.
    expect(second.device.data.id).toBe('3');
    expect(store.getState().nodes.map((n) => n.address)).toEqual([2, 3]);
    expect(store.getState().nextUnicastAddress).toBe(4);
  });

  test('a multi-element node advances the next free address past its extra elements (the inherited hazard, plan 1/task 6 brief)', async () => {
    // A synthetic, hand-built 2-element Composition Data Page 0 (no
    // published sample has more than one element) — header fields are all
    // zero (this test is not about composition.ts's own byte-order
    // decoding, already covered elsewhere; only the ELEMENT COUNT matters
    // here). Element 0 declares Generic OnOff Server (0x1000, little-endian
    // `00 10`); element 1 declares no models at all — it only needs to
    // EXIST, to prove the store's next-free pointer is advanced past it.
    const twoElementComposition = Buffer.from([
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header (cid/pid/vid/crpl/features, all zero)
      0x00, 0x00, 0x01, 0x00, 0x00, 0x10, // element 0: loc=0, numS=1, numV=0, sigModels=[0x1000]
      0x00, 0x00, 0x00, 0x00, // element 1: loc=0, numS=0, numV=0
    ]);
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'bulb-1', -55);
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-1', 1, 2, {
      compositionAccessPayload: Buffer.concat([Buffer.from([0x02, 0x00]), twoElementComposition]),
    });

    const outcome = await pairNode(deps, 'bulb-1');

    expect(outcome.kind).toBe('paired');
    expect(store.getState().nodes[0]?.composition.elements).toHaveLength(2);
    // THE DISCRIMINATING ASSERTION: allocateUnicastAddress() itself only
    // ever advances the pointer by 1 (to 3); a node with 2 elements must
    // additionally skip the second element's own address, landing on 4 —
    // reverting pairing.ts's own extra-element advance (back to "+0
    // always") would leave this at 3, passing the single-element tests
    // above but failing only this one.
    expect(store.getState().nextUnicastAddress).toBe(4);
  });

  test('wrote the expected Config requests, in order, addressed to the node — decoded back from the raw bytes the driver actually sent', async () => {
    const { bluetooth, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'bulb-1', -55);
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-1', 1, 2);

    await pairNode(deps, 'bulb-1');

    // 6 provisioning writes, then 1 (Composition Get) + 2 (AppKey Add,
    // segmented) + 1 (Model App Bind) = 4 config writes = 10 total.
    expect(bluetooth.writesReceived).toHaveLength(10);
    const configWrites = bluetooth.writesReceived.slice(6);
    expect(configWrites.every((w) => w.peripheralId === 'bulb-1')).toBe(true);
    // The first config write's Network PDU decrypts to exactly Config
    // Composition Data Get (opcode 0x8008, page 0) under OUR netKey and
    // device key, addressed FROM us TO the node — i.e. the driver really
    // did send the request this test's responder assumed, not merely
    // "something" that happened to make the responder's canned replies
    // line up.
    const firstConfigWrite = configWrites[0]?.data as Buffer;
    const net = decodeNetworkPdu({ networkKey: TEST_NET_KEY, ivIndex: 0, pdu: firstConfigWrite });
    if (net === null) throw new Error('test fixture error: the first config write did not decode as a Network PDU under TEST_NET_KEY');
    expect(net.src).toBe(1);
    expect(net.dst).toBe(2);
    const lower = decodeUnsegmentedAccess(net.transportPdu);
    if (lower === null) throw new Error('test fixture error: the first config write was not an Unsegmented Access message');
    const accessPayload = decryptUpperTransport({
      key: KAT_DEVICE_KEY,
      keyKind: 'device',
      seq: net.seq,
      src: net.src,
      dst: net.dst,
      ivIndex: 0,
      szmic: false,
      upperTransportPdu: lower.upperTransportPdu,
    });
    if (accessPayload === null) throw new Error('test fixture error: the first config write did not authenticate under KAT_DEVICE_KEY');
    const message = decodeAccessMessage(accessPayload);
    expect(message).toEqual({ opcode: 0x8008, parameters: Buffer.from([0x00]) });
  });
});

// ===========================================================================
// A node whose Capabilities demand an out-of-band method we do not
// implement.
// ===========================================================================

describe('a node demanding an unsupported out-of-band method', () => {
  test('is reported as unsupported with a distinct message, not a generic failure — and leaves no device, no store entry', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'oob-only', -50);
    const oobOnlyCapabilities: ProvisioningCapabilities = {
      ...PDU_TYPE_SAMPLE_CAPABILITIES.fields,
      type: 'capabilities',
      oobType: 0x02, // Table 5.23 bit 1: "Only OOB authenticated provisioning supported".
    };
    installProvisioningResponder(bluetooth, 'oob-only', { capabilitiesReply: encodeProvisioningPdu(oobOnlyCapabilities) });

    const outcome = await pairNode(deps, 'oob-only');

    expect(outcome.kind).toBe('unsupported');
    if (outcome.kind !== 'unsupported') return;
    expect(outcome.reason).toContain('OOB-authenticated provisioning');
    expect(store.getState().nodes).toHaveLength(0);
  });
});

// ===========================================================================
// A node that fails provisioning.
// ===========================================================================

describe('a node that fails provisioning', () => {
  test('leaves no device and no store entry, and surfaces a message naming what failed', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'misbehaving', -50);
    // A Random PDU where a Public Key (Device) PDU is expected — Table
    // 5.41's "Unexpected PDU" (0x03), machine.ts's own per-phase type
    // check.
    installProvisioningResponder(bluetooth, 'misbehaving', {
      publicKeyDeviceReply: hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.message),
    });

    const outcome = await pairNode(deps, 'misbehaving');

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('Unexpected PDU');
    expect(outcome.message).toContain('provisioning failed');
    expect(store.getState().nodes).toHaveLength(0);
  });
});

// ===========================================================================
// A silent node — review finding (HIGH): nothing in this module bounded a
// wait for a reply, so this used to hang the returned promise forever. "Test
// it with a responder that returns nothing" (the review's own words).
// ===========================================================================

describe('a silent node', () => {
  test('one that never answers Provisioning Invite fails with a message naming the stall, instead of hanging forever', async () => {
    const { bluetooth, store, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'silent', -50);
    bluetooth.setAutoResponder('silent', () => undefined); // never replies to anything

    const outcomePromise = pairNode(deps, 'silent');
    // Invite is the very first write; its own withTimeout is armed as soon
    // as that write lands.
    await waitUntil(() => bluetooth.writesReceived.length >= 1 && clock.pendingCount() >= 1);
    await clock.advance(DEFAULT_PAIRING_STEP_TIMEOUT_MS);
    const outcome = await outcomePromise;

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('provisioning stalled');
    expect(outcome.message).toContain(`${DEFAULT_PAIRING_STEP_TIMEOUT_MS}ms`);
    expect(store.getState().nodes).toHaveLength(0);
  });

  test('one that answers provisioning but goes silent during configuration fails the same way, naming the stall', async () => {
    const { bluetooth, store, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'silent-config', -50);
    installProvisioningResponder(bluetooth, 'silent-config', {
      onComplete: () => {
        bluetooth.reconfigureAsProvisioned('silent-config', TEST_NET_KEY);
        bluetooth.setAutoResponder('silent-config', () => undefined); // silent from here on
      },
    });

    const outcomePromise = pairNode(deps, 'silent-config');
    let settled = false;
    void outcomePromise.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    // The node stays silent for the REST of the attempt — both the
    // original Composition Data Get wait AND the failWithReset-triggered
    // Node Reset wait that follows it stall — so this advances the clock
    // in a loop, once per pending timer, until the promise actually
    // settles, rather than assuming exactly one stall occurs.
    for (let i = 0; i < 5 && !settled; i++) {
      await waitUntil(() => clock.pendingCount() >= 1 || settled);
      if (settled) break;
      await clock.advance(DEFAULT_PAIRING_STEP_TIMEOUT_MS);
    }
    const outcome = await outcomePromise;

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('configuration exchange stalled');
    expect(store.getState().nodes).toHaveLength(0);
  });
});

// ===========================================================================
// The pairing step timeout — review finding (smaller item): the tests above
// assert a stall message against `DEFAULT_PAIRING_STEP_TIMEOUT_MS` ITSELF,
// so they cannot tell thirty seconds from one millisecond (whatever the
// constant equals, the message echoes it, and the assertion always passes);
// and `PairingDeps.stepTimeoutMs`'s override was never exercised at all —
// dead in every test. These two tests pin the DEFAULT's actual value as a
// literal (the same convention `lib/adapter/__tests__/queue.test.ts` uses
// for its own `DEFAULT_MAX_ATTEMPTS`), and prove the OVERRIDE, not the
// default, is what actually gates the deadline.
// ===========================================================================

describe('the pairing step timeout', () => {
  test('DEFAULT_PAIRING_STEP_TIMEOUT_MS is thirty seconds', () => {
    expect(DEFAULT_PAIRING_STEP_TIMEOUT_MS).toBe(30_000);
  });

  test('stepTimeoutMs overrides the default — the actual deadline used, not merely a value echoed in the failure message', async () => {
    const { bluetooth, clock, deps } = setUp();
    const customTimeoutMs = 500; // deliberately far from DEFAULT_PAIRING_STEP_TIMEOUT_MS
    addUnprovisionedNode(bluetooth, 'silent-custom-timeout', -50);
    bluetooth.setAutoResponder('silent-custom-timeout', () => undefined); // never replies to anything

    const outcomePromise = pairNode({ ...deps, stepTimeoutMs: customTimeoutMs }, 'silent-custom-timeout');
    let settled = false;
    void outcomePromise.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await waitUntil(() => bluetooth.writesReceived.length >= 1 && clock.pendingCount() >= 1);

    // THE DISCRIMINATING ASSERTION, part 1: advancing by one less than the
    // OVERRIDE must not settle the attempt yet — a mutation that used the
    // override as, say, a multiplier instead of a replacement could still
    // pass part 2 below while failing this one.
    await clock.advance(customTimeoutMs - 1);
    expect(settled).toBe(false);

    // THE DISCRIMINATING ASSERTION, part 2: the remaining 1ms crosses the
    // OVERRIDE's own deadline. If the override were ignored (the real
    // deadline silently staying at DEFAULT_PAIRING_STEP_TIMEOUT_MS, thirty
    // seconds away), this would never settle, and the bounded `waitUntil`
    // below — not jest's own test timeout — is what reports that cleanly.
    await clock.advance(1);
    await waitUntil(() => settled, 50);
    const outcome = await outcomePromise;

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain(`${customTimeoutMs}ms`);
    expect(outcome.message).not.toContain(`${DEFAULT_PAIRING_STEP_TIMEOUT_MS}ms`);
  });
});

// ===========================================================================
// Composition data that does not parse.
// ===========================================================================

describe('composition data that does not parse', () => {
  test('produces a clear failure rather than a half-created device', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'bad-composition', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'bad-composition', 1, 2, {
      // Opcode (02) || Page (00) || Data far too short for even the fixed
      // 10-octet header (composition.ts's own MIN rejection).
      compositionAccessPayload: Buffer.from([0x02, 0x00, 0xaa, 0xbb]),
    });

    const outcome = await pairNode(deps, 'bad-composition');

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('composition data could not be parsed');
    // No half-created device: the store never gained a node entry, and the
    // address this attempt burned is never reused (see pairing.ts's own
    // module header) — but nothing claims to have paired successfully.
    expect(store.getState().nodes).toHaveLength(0);
    // THE HALF THAT ACTUALLY MATTERS (review finding, HIGH): a failure
    // after provisioning succeeded must not orphan the node. The message
    // says the node was reset...
    expect(outcome.message).toContain('the node has been reset and can be paired again');
    // ...and it is provably true, not merely asserted: the SAME peripheral
    // is scannable as an unprovisioned node again, exactly as it was before
    // this attempt ever started.
    const candidates = await scanForUnprovisionedNodes(bluetooth);
    expect(candidates.map((c) => c.peripheralId)).toContain('bad-composition');
  });
});

// ===========================================================================
// The node REFUSES part of the configuration exchange (beyond the brief's
// own list — a node that answers every request but says no to one of them
// is a different, equally real failure mode from a reply that fails to
// parse at all, and nothing above exercises it).
// ===========================================================================

describe('a multi-element node whose configuration fails', () => {
  test('still reserves its extra elements\' addresses — review finding (MEDIUM): the same root cause as the orphaning finding, since the node occupies those addresses the moment it is provisioned, independent of whether configuration ever completes', async () => {
    const twoElementComposition = Buffer.from([
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header, all zero
      0x00, 0x00, 0x01, 0x00, 0x00, 0x10, // element 0: sigModels=[0x1000]
      0x00, 0x00, 0x00, 0x00, // element 1: no models
    ]);
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'multi-element-fails', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'multi-element-fails', 1, 2, {
      compositionAccessPayload: Buffer.concat([Buffer.from([0x02, 0x00]), twoElementComposition]),
      appKeyStatus: 0x05, // refused — configuration never reaches "ok"
    });

    const outcome = await pairNode(deps, 'multi-element-fails');

    expect(outcome.kind).toBe('failed');
    expect(store.getState().nodes).toHaveLength(0); // no device — configuration never completed
    // THE DISCRIMINATING ASSERTION: nextUnicastAddress is 4 (3, from the
    // ordinary +1 advance, PLUS 1 more for the second element), not 3 — the
    // extra element's address was reserved despite the failure.
    expect(store.getState().nextUnicastAddress).toBe(4);
  });
});

describe('the node refuses a configuration request', () => {
  test('a refused Config AppKey Add produces a clear failure, never a half-bound device', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'refuses-appkey', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'refuses-appkey', 1, 2, { appKeyStatus: 0x05 }); // 0x05 = Insufficient Resources (Table 4.308)

    const outcome = await pairNode(deps, 'refuses-appkey');

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('AppKey Add was refused');
    expect(outcome.message).toContain('Insufficient Resources');
    expect(store.getState().nodes).toHaveLength(0);
    // See the composition-parse-failure test above for why this half is
    // the one that matters: the bulb must not be bricked.
    expect(outcome.message).toContain('the node has been reset and can be paired again');
    const candidates = await scanForUnprovisionedNodes(bluetooth);
    expect(candidates.map((c) => c.peripheralId)).toContain('refuses-appkey');
  });

  test('a refused Config Model App Bind produces a clear failure, never a half-bound device', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'refuses-bind', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'refuses-bind', 1, 2, { modelAppStatus: 0x0d }); // 0x0d = Cannot Bind (Table 4.308)

    const outcome = await pairNode(deps, 'refuses-bind');

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('Model App Bind was refused');
    expect(outcome.message).toContain('Cannot Bind');
    expect(store.getState().nodes).toHaveLength(0);
    expect(outcome.message).toContain('the node has been reset and can be paired again');
    const candidates = await scanForUnprovisionedNodes(bluetooth);
    expect(candidates.map((c) => c.peripheralId)).toContain('refuses-bind');
  });

  test('when the reset itself ALSO fails, that is reported too, never silently swallowed', async () => {
    const { bluetooth, store, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'refuses-both', -50);
    // modelAppStatus triggers the original failure; the Node Reset request
    // that follows is answered with 'succeed' writeBehavior but no
    // responder reply configured for it, which — bounded by the pairing
    // clock — eventually surfaces as its own stall.
    installSuccessfulNodeBehaviour(bluetooth, 'refuses-both', 1, 2, { modelAppStatus: 0x0d, failReset: true });

    const outcomePromise = pairNode(deps, 'refuses-both');
    // Wait for BOTH: the Node Reset request has actually been written (the
    // refused Model App Bind's own failWithReset has run), AND a new timer
    // is pending on the fake clock (that write's own withTimeout has armed
    // its wait) — only then is it safe to advance, per `waitUntil`'s own
    // doc comment. 6 provisioning writes + 4 config writes (Composition
    // Get, 2x AppKey Add, Model App Bind) = 10; the Node Reset is #11.
    await waitUntil(() => bluetooth.writesReceived.length >= 11 && clock.pendingCount() >= 1);
    await clock.advance(DEFAULT_PAIRING_STEP_TIMEOUT_MS);
    const outcome = await outcomePromise;

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('Model App Bind was refused');
    expect(outcome.message).toContain('attempted to reset the node');
    expect(outcome.message).toContain('that also failed');
    expect(outcome.message).toContain('manual factory reset');
    expect(store.getState().nodes).toHaveLength(0);
  });

  test('when the reset is answered with the WRONG status message type, that is reported as a failure too, never treated as a successful reset', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'reset-wrong-reply', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'reset-wrong-reply', 1, 2, { modelAppStatus: 0x0d, nodeResetWrongReply: true });

    const outcome = await pairNode(deps, 'reset-wrong-reply');

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('Model App Bind was refused');
    expect(outcome.message).toContain('attempted to reset the node');
    expect(outcome.message).toContain('that also failed');
    expect(outcome.message).toContain('node did not answer Config Node Reset with a Node Reset Status message');
    expect(outcome.message).toContain('manual factory reset');
    expect(store.getState().nodes).toHaveLength(0);
    // THE DISCRIMINATING ASSERTION: a silent-node reset failure
    // (the test above) and a wrong-reply-type reset failure both produce
    // "that also failed", so wording alone cannot tell them apart from a
    // mutation that stops checking `status.type`. This does: a node
    // answering with the wrong type was never actually moved back to the
    // unowned state (`reconfigureAsUnprovisioned` is only called on the
    // CORRECT-reply branch), so it must not show up in a fresh scan — a
    // mutation that accepted ANY decodable status as "reset successful"
    // would make this fail while the message assertions above would not.
    const candidates = await scanForUnprovisionedNodes(bluetooth);
    expect(candidates.map((c) => c.peripheralId)).not.toContain('reset-wrong-reply');
  });
});

// ===========================================================================
// Element attribution — this plan's own recurring hazard (task 3's report:
// "checking a positional first element rather than membership"; the plan's
// pre-flight conflict scan names it again for this task). A node whose
// SECOND element, not its first, declares a lighting model must get a
// Config Model App Bind addressed to the SECOND element's own address —
// every other test in this file has exactly one matching element, which
// cannot tell "always binds element 0" apart from "binds the right one".
// ===========================================================================

describe('element attribution', () => {
  test('a two-element node where BOTH elements declare Generic OnOff Server gets two Model App Binds, addressed to their own elements', async () => {
    const twoLightingElementComposition = Buffer.from([
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header, all zero
      0x00, 0x00, 0x01, 0x00, 0x00, 0x10, // element 0: sigModels=[0x1000]
      0x00, 0x00, 0x01, 0x00, 0x00, 0x10, // element 1: sigModels=[0x1000]
    ]);
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'two-lighting-elements', -50);

    const boundElementAddresses: number[] = [];
    installProvisioningResponder(bluetooth, 'two-lighting-elements', {
      onComplete: () => {
        bluetooth.reconfigureAsProvisioned('two-lighting-elements', TEST_NET_KEY);
        let nodeSeq = 0;
        const allocateNodeSeq = (): number => nodeSeq++;
        const ourAddress = 1;
        const nodeAddress = 2;
        const sendAsNode = (accessPayload: Buffer): Buffer[] =>
          encodeMeshMessage({
            accessPayload,
            key: KAT_DEVICE_KEY,
            keyKind: 'device',
            src: nodeAddress,
            dst: ourAddress,
            netKey: TEST_NET_KEY,
            ivIndex: 0,
            allocateSeq: allocateNodeSeq,
          });
        let count = 0;
        bluetooth.setAutoResponder('two-lighting-elements', (data) => {
          count += 1;
          if (count === 1) {
            return sendAsNode(Buffer.concat([Buffer.from([0x02, 0x00]), twoLightingElementComposition]));
          }
          if (count === 3) {
            return sendAsNode(Buffer.from([0x80, 0x03, 0x00, 0x00, 0x00, 0x00]));
          }
          if (count === 4 || count === 5) {
            // Decode the DRIVER'S OWN Model App Bind request to read back
            // which ElementAddress it actually asked to bind — the
            // discriminating step: a responder that just assumed "element
            // 0 then element 1" would pass even if the driver sent the
            // wrong address twice.
            const net = decodeNetworkPdu({ networkKey: TEST_NET_KEY, ivIndex: 0, pdu: data });
            if (net === null) throw new Error('test fixture error: Model App Bind request did not decode');
            const lower = decodeUnsegmentedAccess(net.transportPdu);
            if (lower === null) throw new Error('test fixture error: Model App Bind request was not unsegmented');
            const accessPayload = decryptUpperTransport({
              key: KAT_DEVICE_KEY,
              keyKind: 'device',
              seq: net.seq,
              src: net.src,
              dst: net.dst,
              ivIndex: 0,
              szmic: false,
              upperTransportPdu: lower.upperTransportPdu,
            });
            if (accessPayload === null) throw new Error('test fixture error: Model App Bind request did not authenticate');
            const message = decodeAccessMessage(accessPayload);
            if (message === null) throw new Error('test fixture error: Model App Bind request did not decode as an Access message');
            const elementAddress = message.parameters.readUInt16LE(0);
            boundElementAddresses.push(elementAddress);
            const elementAddressLe = Buffer.alloc(2);
            elementAddressLe.writeUInt16LE(elementAddress, 0);
            const modelIdLe = Buffer.alloc(2);
            modelIdLe.writeUInt16LE(0x1000, 0);
            return sendAsNode(
              Buffer.concat([Buffer.from([0x80, 0x3e, 0x00]), elementAddressLe, Buffer.from([0x00, 0x00]), modelIdLe]),
            );
          }
          return undefined;
        });
      },
    });

    const outcome = await pairNode(deps, 'two-lighting-elements');

    expect(outcome.kind).toBe('paired');
    // THE DISCRIMINATING ASSERTION: element 0 bound at address 2 (nodeAddress+0),
    // element 1 bound at address 3 (nodeAddress+1) — never the same address
    // twice, and never in the wrong order.
    expect(boundElementAddresses).toEqual([2, 3]);
    expect(store.getState().nodes[0]?.composition.elements).toHaveLength(2);
  });
});

// ===========================================================================
// A node that answers with the WRONG status message type — representative
// of the three symmetric "did not answer X with Y" checks in
// pairing.ts#runConfigExchange (Composition Data Get/AppKey Add/Model App
// Bind each expect one specific status type back); only the first is
// exercised here; the other two share the exact same shape of check.
// ===========================================================================

describe('a node that answers a Config request with the wrong status message type', () => {
  test('a Config AppKey Status in reply to Composition Data Get produces a clear failure, not a crash or a false success', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'wrong-status-type', -50);
    installProvisioningResponder(bluetooth, 'wrong-status-type', {
      onComplete: () => {
        bluetooth.reconfigureAsProvisioned('wrong-status-type', TEST_NET_KEY);
        let nodeSeq = 0;
        const allocateNodeSeq = (): number => nodeSeq++;
        bluetooth.setAutoResponder('wrong-status-type', () =>
          encodeMeshMessage({
            // An AppKey Status (opcode 0x8003), not the Composition Data
            // Status the driver's first request expects.
            accessPayload: Buffer.from([0x80, 0x03, 0x00, 0x00, 0x00, 0x00]),
            key: KAT_DEVICE_KEY,
            keyKind: 'device',
            src: 2,
            dst: 1,
            netKey: TEST_NET_KEY,
            ivIndex: 0,
            allocateSeq: allocateNodeSeq,
          }),
        );
      },
    });

    const outcome = await pairNode(deps, 'wrong-status-type');

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('did not answer Config Composition Data Get with a Composition Data Status message');
    expect(store.getState().nodes).toHaveLength(0);
  });
});

// ===========================================================================
// parseBleUuid / bleUuidString — review finding (MEDIUM): moved here, under
// the gate, from driver.ts (outside it) specifically because the naive
// version had three real bugs — a test per shape, including the two that
// were previously silent/wrong rather than merely untested.
// ===========================================================================

describe('parseBleUuid', () => {
  test('a bare 4-hex-digit short form parses directly', () => {
    expect(parseBleUuid('1827')).toBe(0x1827);
    expect(parseBleUuid('2ADE')).toBe(0x2ade); // case-insensitive
  });

  test('a canonical, dashed 128-bit UUID embedding a 16-bit short UUID via the Bluetooth Base UUID parses to that short UUID', () => {
    expect(parseBleUuid('00001827-0000-1000-8000-00805f9b34fb')).toBe(0x1827);
    expect(parseBleUuid('00002ADE-0000-1000-8000-00805F9B34FB')).toBe(0x2ade);
  });

  test('the same 128-bit UUID with no dashes parses the same way', () => {
    expect(parseBleUuid('0000182700001000800000805f9b34fb')).toBe(0x1827);
  });

  // THE FIRST PREVIOUSLY-SILENT BUG: a full 128-bit UUID that is NOT a
  // 16-bit short UUID's Base-UUID embedding used to parse via a bare
  // parseInt as one enormous number that could never match any of this
  // project's constants — now a thrown, clear error instead.
  test('a 128-bit UUID that does NOT embed a 16-bit short UUID throws, rather than silently returning an unmatchable enormous number', () => {
    expect(() => parseBleUuid('6e400001-b5a3-f393-e0a9-e50e24dcca9e')).toThrow('does not embed a 16-bit Bluetooth SIG short UUID');
  });

  // THE SECOND PREVIOUSLY-SILENT BUG: a dashed form whose middle segments
  // do NOT match the Bluetooth Base UUID used to silently truncate at the
  // first dash and return whatever the leading 8 hex digits happened to be
  // — right only by coincidence for the exact short-UUID embedding, wrong
  // and unguarded for anything else.
  test('a dashed 128-bit UUID whose base does not match the Bluetooth Base UUID throws, rather than silently truncating at the first dash', () => {
    expect(() => parseBleUuid('00001827-abcd-1000-8000-00805f9b34fb')).toThrow('does not embed a 16-bit Bluetooth SIG short UUID');
  });

  test('a non-hex string throws, rather than silently producing NaN', () => {
    expect(() => parseBleUuid('not-a-uuid-zzzz')).toThrow('is not a hexadecimal UUID string');
  });

  test('an empty string throws', () => {
    expect(() => parseBleUuid('')).toThrow('is not a hexadecimal UUID string');
  });

  test('a well-formed hex string of an unrecognised length throws', () => {
    expect(() => parseBleUuid('182')).toThrow('is not a recognised UUID shape');
    expect(() => parseBleUuid('1827182718271827')).toThrow('is not a recognised UUID shape');
  });
});

describe('bleUuidString', () => {
  test('round-trips with parseBleUuid for every one of this project\'s own constants', () => {
    for (const uuid of [0x1827, 0x1828, 0x2adb, 0x2adc, 0x2add, 0x2ade]) {
      expect(parseBleUuid(bleUuidString(uuid))).toBe(uuid);
    }
  });

  test('rejects a value outside the 16-bit range', () => {
    expect(() => bleUuidString(0x10000)).toThrow('is not a 16-bit UUID');
    expect(() => bleUuidString(-1)).toThrow('is not a 16-bit UUID');
  });
});

// ===========================================================================
// Characteristic lookup discrimination — review finding (smaller item): the
// shared fake exposes exactly one GATT profile at a time
// (`gattProfile: 'provisioning' | 'proxy'`), so nothing in the rest of this
// file ever puts TWO services' characteristics in front of
// `connectForProvisioning`'s own `.find((c) => c.serviceUuid === ... &&
// c.characteristicUuid === ...)` at once — which means dropping the
// `serviceUuid` half of that check would still pass every test above. A
// real peripheral's `discoverAllServicesAndCharacteristics()` returns EVERY
// service it has, with no such isolation; a hand-rolled port (not the
// shared fixture, precisely so it CAN return two services at once) is what
// it takes to exercise this.
// ===========================================================================

describe('characteristic lookup discriminates by BOTH service and characteristic UUID', () => {
  test('picks the characteristic under the correct service, even when a DIFFERENT (real, unrelated) service happens to expose a characteristic with the same UUID number', async () => {
    const writesTo: unknown[] = [];
    const port: BluetoothPort = {
      scan: async (): Promise<ScanResult[]> => [],
      connect: async (): Promise<unknown> => ({}),
      discover: async (): Promise<DiscoveredCharacteristic[]> => [
        // Device Information Service (a real, standard 16-bit UUID, 0x180A)
        // — coincidentally reusing the SAME characteristic UUID numbers the
        // Mesh Provisioning Service does, which cannot happen for real
        // (Bluetooth SIG characteristic UUIDs are globally unique per
        // purpose) but is exactly the shape needed to prove the lookup
        // does not just match on characteristicUuid alone.
        { serviceUuid: 0x180a, characteristicUuid: MESH_PROVISIONING_DATA_IN_UUID, handle: 'wrong-service-in' },
        { serviceUuid: 0x180a, characteristicUuid: MESH_PROVISIONING_DATA_OUT_UUID, handle: 'wrong-service-out' },
        { serviceUuid: MESH_PROVISIONING_SERVICE_UUID, characteristicUuid: MESH_PROVISIONING_DATA_IN_UUID, handle: 'right-in' },
        { serviceUuid: MESH_PROVISIONING_SERVICE_UUID, characteristicUuid: MESH_PROVISIONING_DATA_OUT_UUID, handle: 'right-out' },
      ],
      read: async (): Promise<Buffer> => Buffer.alloc(0),
      write: async (handle: unknown): Promise<void> => {
        writesTo.push(handle);
      },
      subscribe: async (): Promise<Subscription> => ({ unsubscribe: (): void => {} }),
      disconnect: async (): Promise<void> => {},
    };

    const clock = createFakeClock();
    const session = await connectForProvisioning(port, 'peripheral-x', clock, DEFAULT_PAIRING_STEP_TIMEOUT_MS);
    await session.write(Buffer.from([0x00, 0x00]));

    // THE DISCRIMINATING ASSERTION: a lookup that dropped the serviceUuid
    // half of its check would find 'wrong-service-in' FIRST (array order)
    // and write there instead.
    expect(writesTo).toEqual(['right-in']);
  });
});

// ===========================================================================
// GATT connection failures — review finding (smaller item): the shared
// fixture already supports every one of these (`connectBehavior`/
// `discoverBehavior`/`subscribeBehavior: 'fail'`), and they are exactly the
// design's "clear message in the wizard" paths, but nothing exercised them.
// ===========================================================================

describe('a GATT connection failure during provisioning', () => {
  test('connect() failing produces a clear failure, not a crash or a hang', async () => {
    const { store, deps } = setUp();
    const bluetooth = new FakeBluetoothPort();
    bluetooth.addNode({
      id: 'connect-fails',
      rssi: -50,
      serviceUuid: MESH_PROVISIONING_SERVICE_UUID,
      serviceDataOverride: UNPROVISIONED_SERVICE_DATA,
      gattProfile: 'provisioning',
      connectBehavior: 'fail',
    });

    const outcome = await pairNode({ ...deps, bluetooth }, 'connect-fails');

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('could not connect to "connect-fails" for provisioning');
    expect(store.getState().nodes).toHaveLength(0);
  });

  test('discover() failing produces a clear failure, not a crash or a hang', async () => {
    const { store, deps } = setUp();
    const bluetooth = new FakeBluetoothPort();
    bluetooth.addNode({
      id: 'discover-fails',
      rssi: -50,
      serviceUuid: MESH_PROVISIONING_SERVICE_UUID,
      serviceDataOverride: UNPROVISIONED_SERVICE_DATA,
      gattProfile: 'provisioning',
      discoverBehavior: 'fail',
    });

    const outcome = await pairNode({ ...deps, bluetooth }, 'discover-fails');

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    // openSession's discover() failure surfaces through connectForProvisioning's
    // own caller in pairNode, the same as a connect() failure — both are
    // "could not even establish the provisioning session", one message.
    expect(outcome.message).toContain('could not connect to "discover-fails" for provisioning');
    expect(store.getState().nodes).toHaveLength(0);
  });

  test('subscribe() failing produces a clear failure, not a crash or a hang', async () => {
    const { store, deps } = setUp();
    const bluetooth = new FakeBluetoothPort();
    bluetooth.addNode({
      id: 'subscribe-fails',
      rssi: -50,
      serviceUuid: MESH_PROVISIONING_SERVICE_UUID,
      serviceDataOverride: UNPROVISIONED_SERVICE_DATA,
      gattProfile: 'provisioning',
      subscribeBehavior: 'fail',
    });

    const outcome = await pairNode({ ...deps, bluetooth }, 'subscribe-fails');

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('could not connect to "subscribe-fails" for provisioning');
    expect(store.getState().nodes).toHaveLength(0);
  });
});

describe('a GATT connection failure during configuration (after provisioning succeeded)', () => {
  test('discover() failing on the reconnect for configuration produces a clear failure naming that the node may need a manual reset', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'config-discover-fails', -50);
    installProvisioningResponder(bluetooth, 'config-discover-fails', {
      onComplete: () => {
        bluetooth.reconfigureAsProvisioned('config-discover-fails', TEST_NET_KEY);
        bluetooth.setDiscoverBehavior('config-discover-fails', 'fail');
      },
    });

    const outcome = await pairNode(deps, 'config-discover-fails');

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('could not reconnect for configuration');
    expect(outcome.message).toContain('manual factory reset');
    expect(store.getState().nodes).toHaveLength(0);
  });
});

// ===========================================================================
// Every GATT operation is bounded by the clock — review finding (HIGH,
// re-review): the first bounding pass wrapped only the wait for a reply.
// `connect`, `discover`, `subscribe`, `write` and `disconnect` could each
// hang a real pairing attempt forever — and two of those (`write`,
// `disconnect`) were not even disclosed as gaps. The shared fixture's own
// `writeBehavior: 'hold'` mode (modelling a congested transmit queue,
// documented in fakeBluetooth.ts) is reused below to prove `write` with the
// real `pairNode` pipeline; it does not model a HUNG (as opposed to failed)
// connect/discover/subscribe/disconnect, so those four use a hand-rolled
// `BluetoothPort` instead — the same reason the characteristic-lookup-
// discrimination test above uses one.
// ===========================================================================

/** Deliberately never resolves or rejects — the only way to prove a bound
 *  actually exists, rather than merely a graceful failure path. */
function neverSettles<T>(): Promise<T> {
  return new Promise<T>(() => {});
}

/** A `BluetoothPort` that completes a provisioning GATT session
 *  (`connect`→`discover`→`subscribe`) successfully and immediately by
 *  default — `overrides` replaces exactly one operation, typically with
 *  `neverSettles()`, to prove THAT operation alone is bounded. */
function fastProvisioningPort(overrides: Partial<BluetoothPort> = {}): BluetoothPort {
  return {
    scan: async (): Promise<ScanResult[]> => [],
    connect: async (): Promise<unknown> => ({}),
    discover: async (): Promise<DiscoveredCharacteristic[]> => [
      { serviceUuid: MESH_PROVISIONING_SERVICE_UUID, characteristicUuid: MESH_PROVISIONING_DATA_IN_UUID, handle: 'in' },
      { serviceUuid: MESH_PROVISIONING_SERVICE_UUID, characteristicUuid: MESH_PROVISIONING_DATA_OUT_UUID, handle: 'out' },
    ],
    read: async (): Promise<Buffer> => Buffer.alloc(0),
    write: async (): Promise<void> => {},
    subscribe: async (): Promise<Subscription> => ({ unsubscribe: (): void => {} }),
    disconnect: async (): Promise<void> => {},
    ...overrides,
  };
}

describe('every GATT operation openSession performs is bounded by the clock', () => {
  test('a connect() that never settles fails the attempt once the deadline passes, instead of hanging it forever', async () => {
    const clock = createFakeClock();
    const port = fastProvisioningPort({ connect: (): Promise<unknown> => neverSettles() });

    const promise = connectForProvisioning(port, 'peripheral-x', clock, 50);
    promise.catch(() => {}); // a handler must exist before clock.advance() below, or Node reports an unhandled rejection
    await waitUntil(() => clock.pendingCount() >= 1);
    await clock.advance(50);

    await expect(promise).rejects.toThrow('provisioning: connecting');
  });

  test('a discover() that never settles fails the attempt once the deadline passes, instead of hanging it forever', async () => {
    const clock = createFakeClock();
    let discoverCalled = false;
    const port = fastProvisioningPort({
      discover: (): Promise<DiscoveredCharacteristic[]> => {
        // Flips SYNCHRONOUSLY the instant discover() is actually invoked —
        // unlike `clock.pendingCount() >= 1` alone, this cannot be
        // satisfied by connect()'s OWN still-pending timer (reachable only
        // AFTER connect's bound has already settled, by construction of
        // the `await` chain in openSession), so it does not race against
        // connect's real (fast) resolution.
        discoverCalled = true;
        return neverSettles();
      },
    });

    const promise = connectForProvisioning(port, 'peripheral-x', clock, 50);
    promise.catch(() => {});
    await waitUntil(() => discoverCalled && clock.pendingCount() >= 1);
    await clock.advance(50);

    await expect(promise).rejects.toThrow('provisioning: discovering services');
  });

  test('a subscribe() that never settles fails the attempt once the deadline passes, instead of hanging it forever', async () => {
    const clock = createFakeClock();
    let subscribeCalled = false;
    const port = fastProvisioningPort({
      subscribe: (): Promise<Subscription> => {
        subscribeCalled = true; // see the discover() test's own comment on why this, not bare pendingCount
        return neverSettles();
      },
    });

    const promise = connectForProvisioning(port, 'peripheral-x', clock, 50);
    promise.catch(() => {});
    await waitUntil(() => subscribeCalled && clock.pendingCount() >= 1);
    await clock.advance(50);

    await expect(promise).rejects.toThrow('provisioning: subscribing to notifications');
  });

  test('a write() that never settles — the shared fixture\'s own "congested transmit queue" model, and the review\'s own one-line repro — fails the whole pairing attempt instead of hanging the wizard forever', async () => {
    const { bluetooth, store, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'write-hangs', -50);
    bluetooth.setWriteBehavior('write-hangs', 'hold');

    const outcomePromise = pairNode(deps, 'write-hangs');
    // Invite is the very first write — `writesReceived` only grows once
    // connect/discover/subscribe have ALL already settled for real, so
    // this (the same combined condition the existing "silent node" test
    // uses) cannot fire on an earlier stage's own still-pending timer.
    await waitUntil(() => bluetooth.writesReceived.length >= 1 && clock.pendingCount() >= 1);
    await clock.advance(DEFAULT_PAIRING_STEP_TIMEOUT_MS);
    const outcome = await outcomePromise;

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('provisioning: writing to the node');
    expect(store.getState().nodes).toHaveLength(0);
  });

  test('a disconnect() that never settles on the QUIET post-provisioning disconnect does not hang an otherwise-successful pairing forever', async () => {
    const { bluetooth: fake, store, clock, deps } = setUp();
    addUnprovisionedNode(fake, 'disconnect-hangs', -50);
    installSuccessfulNodeBehaviour(fake, 'disconnect-hangs', 1, 2);

    // THE PATH THE REVIEW NAMED: `disconnectQuietly`'s own try/catch only
    // reacts to a REJECTION — it does nothing for a promise that simply
    // never settles. The FIRST disconnect() call is exactly that quiet
    // call, right after provisioning succeeds (pairNode's own
    // `disconnectQuietly(provisioningSession)`); the second is the
    // configuration session's own quiet disconnect once config succeeds,
    // left to behave normally so the attempt can actually finish.
    let disconnectCalls = 0;
    const bluetooth: BluetoothPort = {
      scan: (durationMs) => fake.scan(durationMs),
      connect: (peripheralId, onDisconnect) => fake.connect(peripheralId, onDisconnect),
      discover: (connection) => fake.discover(connection),
      read: (characteristic) => fake.read(characteristic),
      write: (characteristic, data) => fake.write(characteristic, data),
      subscribe: (characteristic, onNotify) => fake.subscribe(characteristic, onNotify),
      disconnect: (connection): Promise<void> => {
        disconnectCalls += 1;
        if (disconnectCalls === 1) {
          // The underlying connection genuinely closes (so the SECOND
          // connect(), for the configuration session, does not find the
          // fixture still thinking it is connected) — only the
          // ACKNOWLEDGEMENT back to the caller never arrives, which is
          // exactly what the review named: `disconnectQuietly`'s own
          // try/catch does nothing for a promise that simply never
          // settles.
          void fake.disconnect(connection);
          return neverSettles();
        }
        return fake.disconnect(connection);
      },
    };

    const outcomePromise = pairNode({ ...deps, bluetooth }, 'disconnect-hangs');
    // The held disconnect() never settles on its own — only the clock can
    // rescue `disconnectQuietly`'s bounded wait for it. Advance past its
    // deadline once it is actually the one pending.
    await waitUntil(() => disconnectCalls >= 1 && clock.pendingCount() >= 1);
    await clock.advance(DEFAULT_PAIRING_STEP_TIMEOUT_MS);
    const outcome = await outcomePromise;

    expect(outcome.kind).toBe('paired');
    expect(store.getState().nodes).toHaveLength(1);
  });
});

// ===========================================================================
// tryParseBleUuid / filterKnownServiceData / filterKnownCharacteristics —
// review finding (smaller item): this filtering logic used to live entirely
// inside driver.ts, the one file this project's gate cannot see (it imports
// `homey`) — nothing proved the non-throwing wrapper's SKIP behaviour, as
// opposed to a THROWING form that would brick every real scan/discover call
// the moment an unrelated service showed up, was load-bearing (a reviewer
// demonstrated the entire gate passing with the throwing form substituted
// in). Moved here, under the gate, as pure functions over already-
// discovered raw (Homey-shaped) services/characteristics; `driver.ts` keeps
// nothing but the Homey API calls and a reshape of their results.
// ===========================================================================

describe('tryParseBleUuid', () => {
  test('returns the parsed number for a well-formed UUID', () => {
    expect(tryParseBleUuid('1827')).toBe(0x1827);
  });

  test('returns null, never throws, for anything parseBleUuid itself throws for', () => {
    expect(tryParseBleUuid('not-a-uuid')).toBeNull(); // non-hex garbage
    // A genuine custom (vendor) 128-bit UUID — does NOT embed a 16-bit
    // short UUID via the Bluetooth Base UUID, the one well-formed shape
    // parseBleUuid itself throws for (see that function's own tests).
    expect(tryParseBleUuid('a1b2c3d4-5e6f-4a1b-8c2d-1234567890ab')).toBeNull();
  });
});

describe('filterKnownServiceData', () => {
  test('keeps every well-formed UUID (translated to the numeric convention), dropping only what does not parse at all', () => {
    // THE MUTATION THIS CLOSES: substituting the throwing `parseBleUuid`
    // for `tryParseBleUuid` inside this function would make THIS call
    // throw on the first malformed entry below, instead of returning the
    // filtered array. Narrowing down to the SPECIFIC two services this
    // app cares about is a DIFFERENT, later step (`findServiceData` /
    // `scanForUnprovisionedNodes`) — this function only drops what
    // `parseBleUuid` itself would throw for.
    const customVendorUuid = 'a1b2c3d4-5e6f-4a1b-8c2d-1234567890ab'; // does not embed via the Bluetooth Base UUID
    const result = filterKnownServiceData([
      { uuid: '180a', data: Buffer.from([0xaa]) }, // Device Information Service — well-formed, but not ours; kept anyway
      { uuid: bleUuidString(MESH_PROVISIONING_SERVICE_UUID), data: Buffer.from([0x01]) },
      { uuid: customVendorUuid, data: Buffer.from([0xbb]) }, // malformed for this parser — dropped, not thrown
      { uuid: 'not-a-uuid', data: Buffer.from([0xcc]) }, // non-hex garbage — also dropped
      { uuid: bleUuidString(MESH_PROXY_SERVICE_UUID), data: Buffer.from([0x02]) },
    ]);

    expect(result).toEqual([
      { serviceUuid: 0x180a, data: Buffer.from([0xaa]) },
      { serviceUuid: MESH_PROVISIONING_SERVICE_UUID, data: Buffer.from([0x01]) },
      { serviceUuid: MESH_PROXY_SERVICE_UUID, data: Buffer.from([0x02]) },
    ]);
  });

  test('an empty input produces an empty result, not an error', () => {
    expect(filterKnownServiceData([])).toEqual([]);
  });
});

describe('filterKnownCharacteristics', () => {
  test('drops only a service/characteristic whose UUID does not parse at all, translating everything else, order preserved', () => {
    // THE MUTATION THIS CLOSES: same as filterKnownServiceData's own test —
    // a throwing parser substituted in would throw on the first malformed
    // entry below instead of skipping it.
    const customVendorServiceUuid = 'a1b2c3d4-5e6f-4a1b-8c2d-1234567890ab'; // does not embed via the Bluetooth Base UUID
    const result = filterKnownCharacteristics([
      {
        uuid: customVendorServiceUuid, // malformed for this parser — entire service dropped
        characteristics: [{ uuid: bleUuidString(MESH_PROVISIONING_DATA_IN_UUID), handle: 'irrelevant' }],
      },
      {
        // Device Information Service — well-formed, but not one of this
        // app's two services; kept anyway (narrowing to a SPECIFIC
        // service/characteristic pair is openSession's own job, a later
        // step this function does not perform).
        uuid: '180a',
        characteristics: [{ uuid: '2a29', handle: 'manufacturer-name' }],
      },
      {
        uuid: bleUuidString(MESH_PROVISIONING_SERVICE_UUID),
        characteristics: [
          { uuid: 'not-a-uuid', handle: 'dropped' }, // malformed characteristic — dropped, service kept
          { uuid: bleUuidString(MESH_PROVISIONING_DATA_IN_UUID), handle: 'in-handle' },
          { uuid: bleUuidString(MESH_PROVISIONING_DATA_OUT_UUID), handle: 'out-handle' },
        ],
      },
    ]);

    expect(result).toEqual([
      { serviceUuid: 0x180a, characteristicUuid: 0x2a29, handle: 'manufacturer-name' },
      { serviceUuid: MESH_PROVISIONING_SERVICE_UUID, characteristicUuid: MESH_PROVISIONING_DATA_IN_UUID, handle: 'in-handle' },
      { serviceUuid: MESH_PROVISIONING_SERVICE_UUID, characteristicUuid: MESH_PROVISIONING_DATA_OUT_UUID, handle: 'out-handle' },
    ]);
  });

  test('an empty input produces an empty result, not an error', () => {
    expect(filterKnownCharacteristics([])).toEqual([]);
  });
});
