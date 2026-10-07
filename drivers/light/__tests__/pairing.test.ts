import {
  pairNode,
  scanForUnprovisionedNodes,
  type PairingDeps,
  type ProvisioningRandomSource,
} from '../pairing';
import { NetworkStore, type SettingsPort } from '../../../lib/adapter/store';
import { FakeBluetoothPort, type AutoResponder } from '../../../lib/adapter/__tests__/fakeBluetooth';
import { MESH_PROVISIONING_SERVICE_UUID } from '../../../lib/adapter/connection';
import { encodeMeshMessage } from '../../../lib/adapter/meshMessage';
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

function setUp(randomQueue: readonly Buffer[] = [TEST_NET_KEY, TEST_APP_KEY, KAT_RANDOM_PROVISIONER, KAT_RANDOM_PROVISIONER]): {
  bluetooth: FakeBluetoothPort;
  store: NetworkStore;
  random: FixedRandomSource;
  deps: PairingDeps;
} {
  const bluetooth = new FakeBluetoothPort();
  const store = new NetworkStore(new FakeSettingsPort());
  const random = new FixedRandomSource(randomQueue, KAT_EPHEMERAL_KEY_PAIR);
  return { bluetooth, store, random, deps: { bluetooth, store, random } };
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

  let count = 0;
  const responder: AutoResponder = () => {
    count += 1;
    if (count === 1) {
      // Config Composition Data Get -> Config Composition Data Status.
      return sendAsNode(compositionAccessPayload);
    }
    if (count === 3) {
      // Config AppKey Add (2 writes, segmented) -> Config AppKey Status.
      // NetKeyIndex=AppKeyIndex=0 (packed bytes are all-zero regardless of
      // packing scheme when both indexes are zero).
      const status = options.appKeyStatus ?? 0x00;
      return sendAsNode(Buffer.from([0x80, 0x03, status, 0x00, 0x00, 0x00]));
    }
    if (count === 4) {
      // Config Model App Bind (Generic OnOff Server, element 0) -> Config
      // Model App Status.
      const status = options.modelAppStatus ?? 0x00;
      const elementAddressLe = Buffer.alloc(2);
      elementAddressLe.writeUInt16LE(nodeAddress, 0);
      const modelIdLe = Buffer.alloc(2);
      modelIdLe.writeUInt16LE(0x1000, 0);
      return sendAsNode(Buffer.concat([Buffer.from([0x80, 0x3e, status]), elementAddressLe, Buffer.from([0x00, 0x00]), modelIdLe]));
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
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'bulb-1', -55);
    // Deterministic per this project's own allocator (MIN_UNICAST_ADDRESS):
    // our own address is 1 (first-run), the first node paired is 2.
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-1', 1, 2);

    const outcome = await pairNode(deps, 'bulb-1');

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
  });
});

// ===========================================================================
// The node REFUSES part of the configuration exchange (beyond the brief's
// own list — a node that answers every request but says no to one of them
// is a different, equally real failure mode from a reply that fails to
// parse at all, and nothing above exercises it).
// ===========================================================================

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
