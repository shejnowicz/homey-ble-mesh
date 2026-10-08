import {
  pairNode,
  pairNodes,
  scanForUnprovisionedNodes,
  connectForProvisioning,
  parseBleUuid,
  bleUuidString,
  tryParseBleUuid,
  filterKnownServiceData,
  filterKnownCharacteristics,
  DEFAULT_PAIRING_STEP_TIMEOUT_MS,
  type MultiPairingProgress,
  type PairingDeps,
  type PairingOutcome,
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
import {
  encodeMeshMessage,
  acceptIncomingPdu,
  POINT_TO_POINT_TTL,
  type MeshReceiveState,
  type MeshReceiveContext,
} from '../../../lib/mesh/packet/message';
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
import { PROXY_SAR_TIMEOUT_MS } from '../../../lib/mesh/packet/proxyPdu';
import { COMPOSITION_DATA_PAGE0_SAMPLE } from '../../../lib/mesh/config/__tests__/vectors';
import { k4 } from '../../../lib/mesh/crypto/derive';
import type { ProbedModel } from '../../../lib/models/capabilities';

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
  /** When true, a Config Model App Bind gets NO reply at all — the
   *  owner's own hardware failure of 2026-10-08 ("node did not answer
   *  Config Model App Bind"), which `modelAppStatus` cannot model: a
   *  REFUSAL is an answer, and the bulb that was lost never answered at
   *  all. Default false (answers with `modelAppStatus`). */
  readonly silentModelAppBind?: boolean;
  /** When true, a Config Node Reset request gets NO reply at all (modelling
   *  a node that is unreachable for the reset too) — default false
   *  (replies with Node Reset Status and returns to the unowned state). */
  readonly failReset?: boolean;
  /** When true, a Config Node Reset request is answered with the WRONG
   *  status message type (an AppKey Status) instead of silence or a
   *  correct Node Reset Status — a node that is reachable but misbehaves,
   *  as opposed to one that is merely unreachable (`failReset`). Since the
   *  hardware round of 2026-10-08 this no longer settles the wait: a reply
   *  that is not the status the request asked for is discarded and the
   *  request waits out its own deadline (see `sendConfigRequest`), so a
   *  test using this must advance the clock. Use `nodeResetMalformedReply`
   *  instead where the point is only that the reset was not confirmed. */
  readonly nodeResetWrongReply?: boolean;
  /** When true, a Config Node Reset request is answered with a Node Reset
   *  Status carrying PARAMETERS, where Table 4.136 defines none — the right
   *  message, malformed. It satisfies the opcode match and then fails to
   *  decode, so the reset is reported as unconfirmed WITHOUT any waiting:
   *  the no-clock-advancing way to leave a node recorded rather than
   *  forgotten. */
  readonly nodeResetMalformedReply?: boolean;
  /**
   * When true, every Config reply this node sends is preceded by an exact
   * repeat of the PREVIOUS Config reply — the same bytes, the same sequence
   * number, delivered again.
   *
   * THE HARDWARE ROUND OF 2026-10-08, in a fixture. Every notification was
   * reaching the app more than once (leaked GATT subscriptions), so the
   * duplicate of the previous request's reply arrived where the next
   * request's reply was being waited for, and was consumed as it. A mesh
   * node is also entitled to retransmit on its own account, so this is not
   * only a model of this project's own bug.
   */
  readonly repeatPreviousReplyFirst?: boolean;
  /**
   * An Access message (Opcode||Parameters) this node sends, unprompted,
   * immediately before every Config reply — a status nobody asked for,
   * which a mesh model may publish at any time. Distinct from
   * `repeatPreviousReplyFirst` in that it is never an answer to ANY request
   * in this exchange.
   */
  readonly unsolicitedBeforeEachReply?: Buffer;
  /**
   * WHICH LIGHTING MODELS THIS FAKE NODE ACTUALLY RUNS, as opposed to which
   * ones its composition declares - the whole point of the capability probe
   * (`drivers/light/modelProbe.ts`). A model listed here as `'silent'`
   * receives the probe's messages and answers nothing, exactly like the
   * owner's own bulb does for `Light CTL Set`; a model not listed answers
   * normally. Default: every model answers, which is what the pre-probe
   * tests in this file implicitly assume about a well-behaved node.
   */
  readonly silentModels?: ReadonlyArray<ProbedModel>;
  /**
   * What this node answers a `Light CTL Temperature Range Get` with.
   *   - a `{min, max}` pair: a node that reports its range (Table 6.79);
   *   - `'unknown'`: a node that answers with Table 6.8's own 0xFFFF row;
   *   - `'silent'` (the default): a node that never answers it at all -
   *     the owner's own bulb's measured behaviour.
   */
  readonly temperatureRangeReply?: { readonly min: number; readonly max: number } | 'unknown' | 'silent';
}

/** Every fake lamp's own live state, by peripheral id — so a test can
 *  assert the probe's no-op writes left the lamp exactly as it found it. */
const lampStateByPeripheral = new Map<string, { onOff: number; lightness: number; temperature: number; deltaUv: number; hue: number; saturation: number }>();

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
      // This fake node is answering over the very link it is connected by —
      // the same point-to-point exchange `pairing.ts` itself uses.
      ttl: POINT_TO_POINT_TTL,
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
  /** The exact PDUs of the last Config reply this node sent — kept so
   *  `repeatPreviousReplyFirst` can send THOSE BYTES again (same sequence
   *  number and all), which is what a retransmission, and what a
   *  twice-delivered notification, actually looks like. */
  let previousConfigReply: Buffer[] | null = null;
  let driverRequestState: MeshReceiveState | undefined;
  const driverRequestContext: MeshReceiveContext = {
    key: KAT_DEVICE_KEY,
    keyKind: 'device',
    netKey: TEST_NET_KEY,
    ivIndex: 0,
    expectedSrc: ourAddress,
  };

  // ---------------------------------------------------------------------
  // THE LIGHTING HALF OF THIS FAKE NODE (capability probe round). Every
  // message above is DEVICE-key-secured, because they are Config messages;
  // the probe's are APPLICATION-key-secured, because the lighting models
  // answer on the key that was just bound to them. So this responder now
  // tries two contexts, in that order, with separate reassembly state for
  // each — a PDU that does not authenticate under one is `'ignored'` and
  // leaves that context's state untouched (`acceptIncomingPdu`'s own
  // contract), so trying both costs nothing and confuses nothing.
  //
  // WHAT IT MODELS: a well-behaved node answers every acknowledged Set with
  // its own Status, which is exactly what the probe measures. `silentModels`
  // makes one model answer nothing instead — the owner's own bulb's
  // measured behaviour for `Light CTL Set` — so a test can assert the probe
  // tells the two apart.
  const appKeyRequestContext: MeshReceiveContext = {
    key: TEST_APP_KEY,
    keyKind: 'application',
    netKey: TEST_NET_KEY,
    ivIndex: 0,
    expectedSrc: ourAddress,
  };
  let appKeyRequestState: MeshReceiveState | undefined;
  const sendAsNodeAppKey = (accessPayload: Buffer): Buffer[] =>
    encodeMeshMessage({
      accessPayload,
      key: TEST_APP_KEY,
      keyKind: 'application',
      aid: k4(TEST_APP_KEY),
      src: nodeAddress,
      dst: ourAddress,
      netKey: TEST_NET_KEY,
      ivIndex: 0,
      ttl: POINT_TO_POINT_TTL,
      allocateSeq: allocateNodeSeq,
    });
  const silent = (model: ProbedModel): boolean => (options.silentModels ?? []).includes(model);
  const u16le = (value: number): Buffer => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(value, 0);
    return b;
  };
  /** This fake lamp's own current state — read back by the probe's Gets and
   *  echoed by its Sets, so a probe that is NOT a no-op write would be
   *  visible here as a changed value. */
  const lamp = { onOff: 0x01, lightness: 0x8000, temperature: 0x1194, deltaUv: 0x0000, hue: 0x4000, saturation: 0x2000 };
  const lightingReply = (opcode: number, parameters: Buffer): Buffer[] | undefined => {
    switch (opcode) {
      case 0x8201: // Generic OnOff Get
        return sendAsNodeAppKey(Buffer.from([0x82, 0x04, lamp.onOff]));
      case 0x8202: // Generic OnOff Set
        if (silent('genericOnOff')) return undefined;
        lamp.onOff = parameters[0] as number;
        return sendAsNodeAppKey(Buffer.from([0x82, 0x04, lamp.onOff]));
      case 0x824b: // Light Lightness Get
        return sendAsNodeAppKey(Buffer.concat([Buffer.from([0x82, 0x4e]), u16le(lamp.lightness)]));
      case 0x824c: // Light Lightness Set
        if (silent('lightLightness')) return undefined;
        lamp.lightness = parameters.readUInt16LE(0);
        return sendAsNodeAppKey(Buffer.concat([Buffer.from([0x82, 0x4e]), u16le(lamp.lightness)]));
      case 0x825d: // Light CTL Get
        return sendAsNodeAppKey(Buffer.concat([Buffer.from([0x82, 0x60]), u16le(lamp.lightness), u16le(lamp.temperature)]));
      case 0x825e: // Light CTL Set
        if (silent('lightCtl')) return undefined;
        lamp.lightness = parameters.readUInt16LE(0);
        lamp.temperature = parameters.readUInt16LE(2);
        lamp.deltaUv = parameters.readUInt16LE(4);
        return sendAsNodeAppKey(Buffer.concat([Buffer.from([0x82, 0x60]), u16le(lamp.lightness), u16le(lamp.temperature)]));
      case 0x8264: // Light CTL Temperature Set
        if (silent('lightCtlTemperature')) return undefined;
        lamp.temperature = parameters.readUInt16LE(0);
        lamp.deltaUv = parameters.readUInt16LE(2);
        return sendAsNodeAppKey(Buffer.concat([Buffer.from([0x82, 0x66]), u16le(lamp.temperature), u16le(lamp.deltaUv)]));
      case 0x826d: // Light HSL Get
        return sendAsNodeAppKey(
          Buffer.concat([Buffer.from([0x82, 0x78]), u16le(lamp.lightness), u16le(lamp.hue), u16le(lamp.saturation)]),
        );
      case 0x8276: // Light HSL Set
        if (silent('lightHsl')) return undefined;
        lamp.lightness = parameters.readUInt16LE(0);
        lamp.hue = parameters.readUInt16LE(2);
        lamp.saturation = parameters.readUInt16LE(4);
        return sendAsNodeAppKey(
          Buffer.concat([Buffer.from([0x82, 0x78]), u16le(lamp.lightness), u16le(lamp.hue), u16le(lamp.saturation)]),
        );
      case 0x8262: {
        // Light CTL Temperature Range Get -> Range Status (Table 6.79).
        const reply = options.temperatureRangeReply ?? 'silent';
        if (reply === 'silent') return undefined;
        const [min, max] = reply === 'unknown' ? [0xffff, 0xffff] : [reply.min, reply.max];
        return sendAsNodeAppKey(Buffer.concat([Buffer.from([0x82, 0x63, 0x00]), u16le(min as number), u16le(max as number)]));
      }
      default:
        return undefined;
    }
  };
  /** The fake lamp's own state, for a test that wants to prove the probe left it alone. */
  lampStateByPeripheral.set(peripheralId, lamp);

  const responder: AutoResponder = (data) => {
    // EVERY PDU GOES THROUGH BOTH CONTEXTS, with neither short-circuiting
    // the other — subtle and load-bearing. Reassembly (`acceptSegment`) is
    // key-INDEPENDENT: a segmented Config AppKey Add's first segment reads
    // as `'incomplete'` under the application-key context too, so an
    // earlier version of this responder that returned as soon as the
    // app-key context said `'incomplete'` never showed that segment to the
    // device-key context at all, and the real request could never
    // reassemble. Feeding both, always, and dispatching on whichever
    // actually AUTHENTICATED is the only arrangement that is correct for
    // both message families at once.
    const appKeyResult = acceptIncomingPdu(appKeyRequestState, appKeyRequestContext, data);
    appKeyRequestState = appKeyResult.kind === 'complete' ? undefined : appKeyResult.state;
    const result = acceptIncomingPdu(driverRequestState, driverRequestContext, data);
    driverRequestState = result.kind === 'complete' ? undefined : result.state;

    if (appKeyResult.kind === 'complete') {
      return lightingReply(appKeyResult.message.opcode, appKeyResult.message.parameters);
    }
    if (result.kind !== 'complete') {
      return undefined; // mid-segmented-request (AppKey Add's first segment) — no reply yet
    }

    const configReply = (): Buffer[] | undefined => {
      if (result.kind !== 'complete') return undefined; // narrowing only; checked above
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
        if (options.silentModelAppBind) return undefined; // the owner's own lost bulb
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
        if (options.nodeResetMalformedReply) {
          // The RIGHT message, malformed: Table 4.136 gives Config Node Reset
          // Status no parameters at all, and this one carries two.
          return sendAsNode(Buffer.from([0x80, 0x4a, 0xde, 0xad]));
        }
        bluetooth.reconfigureAsUnprovisioned(peripheralId, UNPROVISIONED_SERVICE_DATA);
        return sendAsNode(Buffer.from([0x80, 0x4a])); // Config Node Reset Status — no parameters.
      }
      return undefined;
    };

    const reply = configReply();
    if (reply === undefined) return undefined;
    // NOISE ON THE WIRE, ahead of the real answer — see
    // `repeatPreviousReplyFirst`/`unsolicitedBeforeEachReply`. Both are
    // prepended rather than appended on purpose: a reply-matching rule that
    // takes the first decodable message is wrong precisely when the wrong
    // message arrives FIRST.
    const prefix: Buffer[] = [];
    if (options.unsolicitedBeforeEachReply) prefix.push(...sendAsNode(options.unsolicitedBeforeEachReply));
    if (options.repeatPreviousReplyFirst && previousConfigReply !== null) prefix.push(...previousConfigReply);
    previousConfigReply = reply;
    return [...prefix, ...reply];
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
    // segmented) + 1 (Model App Bind) = 4 config writes, then the
    // capability probe's own 2 (Generic OnOff Get, then the no-op Generic
    // OnOff Set it builds from the answer — the published composition
    // sample declares Generic OnOff Server and none of the other four
    // lighting models, so that is the whole probe for this node) = 12
    // total.
    expect(bluetooth.writesReceived).toHaveLength(12);
    const configWrites = bluetooth.writesReceived.slice(6, 10);
    const probeWrites = bluetooth.writesReceived.slice(10);
    expect(bluetooth.writesReceived.every((w) => w.peripheralId === 'bulb-1')).toBe(true);
    // THE PROBE COMES LAST, AND THAT IS LOAD-BEARING: it is
    // application-key-secured, and the application key is only bound to the
    // node's models by the Model App Bind two writes earlier. A probe that
    // ran before the bind would be answered by nothing and would conclude
    // the node implements no models at all.
    expect(probeWrites.map((w) => w.messageType)).toEqual([0x00, 0x00]);
    const probeOpcodes = probeWrites.map((w) => {
      const pdu = decodeNetworkPdu({ networkKey: TEST_NET_KEY, ivIndex: 0, pdu: w.data });
      if (pdu === null) throw new Error('test fixture error: a probe write did not decode as a Network PDU');
      const unsegmented = decodeUnsegmentedAccess(pdu.transportPdu);
      if (unsegmented === null) throw new Error('test fixture error: a probe write was not unsegmented');
      const payload = decryptUpperTransport({
        key: TEST_APP_KEY,
        keyKind: 'application',
        seq: pdu.seq,
        src: pdu.src,
        dst: pdu.dst,
        ivIndex: 0,
        szmic: false,
        upperTransportPdu: unsegmented.upperTransportPdu,
      });
      if (payload === null) throw new Error('test fixture error: a probe write did not authenticate under TEST_APP_KEY');
      return decodeAccessMessage(payload)?.opcode;
    });
    // Generic OnOff Get (0x8201) then Generic OnOff Set (0x8202) — read
    // first, write back, exactly as `modelProbe.ts` promises.
    expect(probeOpcodes).toEqual([0x8201, 0x8202]);

    // THE PROXY PDU ENVELOPE, on both sessions and with the RIGHT message
    // type on each (review finding, final wave — before this round both
    // sessions wrote bare PDUs, which no node can interpret). Table 6.3:
    // 0x03 Provisioning PDU for the Mesh Provisioning characteristics,
    // 0x00 Network PDU for the Mesh Proxy ones. `writesReceived` here is
    // the REASSEMBLED message the fake node put back together, so the fact
    // these ten exist at all is already the envelope working end to end.
    expect(bluetooth.writesReceived.slice(0, 6).map((w) => w.messageType)).toEqual([0x03, 0x03, 0x03, 0x03, 0x03, 0x03]);
    expect(configWrites.map((w) => w.messageType)).toEqual([0x00, 0x00, 0x00, 0x00]);

    // ...and SEGMENTATION is not theoretical here: a Provisioning Public Key
    // PDU is 65 octets, far past one write on a minimal link, so it reaches
    // the node as several raw GATT writes carrying first/continuation/last
    // SAR values. Counted on the raw writes, which is where the envelope is
    // visible at all.
    expect(bluetooth.rawWritesReceived.length).toBeGreaterThan(bluetooth.writesReceived.length);
    const sarValues = new Set(bluetooth.rawWritesReceived.map((w) => ((w.data[0] as number) >> 6) & 0b11));
    expect(sarValues.has(0b01)).toBe(true); // a first segment
    expect(sarValues.has(0b10)).toBe(true); // a continuation segment
    expect(sarValues.has(0b11)).toBe(true); // a last segment
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
    // DEFECT B (hardware round, 2026-10-08). The reset failed too, so this
    // bulb is provisioned, holds our network key, has left the Mesh
    // Provisioning Service for the Proxy Service — and a later scan can
    // therefore never find it again. The ONE thing that keeps it
    // recoverable rather than scrap is its own store entry: the address it
    // took and the device key it answers to, recorded before the first bind
    // precisely for this moment. It must NOT look like a finished node.
    const stranded = store.getState().nodes;
    expect(stranded).toHaveLength(1);
    expect(stranded[0]?.address).toBe(2);
    expect(stranded[0]?.deviceKey).toEqual(KAT_DEVICE_KEY);
    expect(stranded[0]?.incomplete).toBe(true);
    expect(stranded[0]?.probe).toBeUndefined();
  });

  test('when the reset is answered with the WRONG status message type, that is reported as a failure too, never treated as a successful reset', async () => {
    const { bluetooth, store, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'reset-wrong-reply', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'reset-wrong-reply', 1, 2, { modelAppStatus: 0x0d, nodeResetWrongReply: true });

    // Since 2026-10-08 a reply that is not the status the request asked for
    // does not settle the wait at all — it is discarded and the request
    // waits out its own deadline, exactly as it would for silence — so this
    // advances the clock the same way the silent-node tests do.
    const outcomePromise = pairNode(deps, 'reset-wrong-reply');
    let settled = false;
    void outcomePromise.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    for (let i = 0; i < 5 && !settled; i++) {
      await waitUntil(() => clock.pendingCount() >= 1 || settled);
      if (settled) break;
      await clock.advance(DEFAULT_PAIRING_STEP_TIMEOUT_MS);
    }
    const outcome = await outcomePromise;

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('Model App Bind was refused');
    expect(outcome.message).toContain('attempted to reset the node');
    expect(outcome.message).toContain('that also failed');
    // IT SAYS WHAT ARRIVED, and does not claim silence: the node DID answer,
    // with the wrong message. "Did not answer" is reserved for a node that
    // said nothing at all (the test above this one).
    expect(outcome.message).toContain('node answered Config Node Reset with Config AppKey Status');
    expect(outcome.message).toContain('instead of a Config Node Reset Status message');
    expect(outcome.message).not.toContain('did not answer Config Node Reset');
    expect(outcome.message).toContain('manual factory reset');
    // DEFECT B (hardware round, 2026-10-08). The reset failed too, so this
    // bulb is provisioned, holds our network key, has left the Mesh
    // Provisioning Service for the Proxy Service — and a later scan can
    // therefore never find it again. The ONE thing that keeps it
    // recoverable rather than scrap is its own store entry: the address it
    // took and the device key it answers to, recorded before the first bind
    // precisely for this moment. It must NOT look like a finished node.
    const stranded = store.getState().nodes;
    expect(stranded).toHaveLength(1);
    expect(stranded[0]?.address).toBe(2);
    expect(stranded[0]?.deviceKey).toEqual(KAT_DEVICE_KEY);
    expect(stranded[0]?.incomplete).toBe(true);
    expect(stranded[0]?.probe).toBeUndefined();
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
// DEFECT B (hardware round, 2026-10-08): a configuration failure after
// successful provisioning must not STRAND the bulb.
//
// What happened: three bulbs in one run, and `dc2351a643d7` never answered
// its Config Model App Bind. Node entries were written only on complete
// success, so the app kept nothing — not the unicast address, not the
// device key. The bulb, meanwhile, had accepted our network key and moved
// from the Mesh Provisioning Service to the Mesh Proxy Service, so no later
// scan could find it and no message could reach it: recoverable only by a
// physical factory reset. The entry is now written the moment the node is
// ours (`pairing.ts#recordProvisionedNode`), carrying
// `store.ts#NodeEntry.incomplete` so nothing mistakes it for a finished
// pairing, and the outcome the user sees is still a failure with no Homey
// device created.
// ===========================================================================

describe('a configuration failure after provisioning succeeded', () => {
  test('THE HARDWARE CASE: a bulb that never answers Config Model App Bind, and never answers the reset either, is left RECORDED rather than stranded', async () => {
    const { bluetooth, store, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'dc2351a643d7', -58);
    installSuccessfulNodeBehaviour(bluetooth, 'dc2351a643d7', 1, 2, { silentModelAppBind: true, failReset: true });

    const outcomePromise = pairNode(deps, 'dc2351a643d7');
    let settled = false;
    void outcomePromise.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    // Two stalls in a row — the bind's own reply wait, then the Node Reset
    // wait that `failWithReset` starts — so advance once per pending timer
    // rather than assuming a fixed number (the same loop the silent-node
    // tests above use, and for the same reason).
    for (let i = 0; i < 5 && !settled; i++) {
      await waitUntil(() => clock.pendingCount() >= 1 || settled);
      if (settled) break;
      await clock.advance(DEFAULT_PAIRING_STEP_TIMEOUT_MS);
    }
    const outcome = await outcomePromise;

    // The user's outcome is unchanged, and must stay unchanged:
    // configuration genuinely did not complete.
    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('manual factory reset');

    // THE DISCRIMINATING ASSERTION, and the whole point of the fix: the
    // bulb is still reachable in principle, because this app kept the two
    // things it takes to reach it.
    const nodes = store.getState().nodes;
    expect(nodes).toHaveLength(1);
    expect(nodes[0]?.address).toBe(2);
    expect(nodes[0]?.deviceKey).toEqual(KAT_DEVICE_KEY);
    // ...and it is honestly marked as what it is, so nothing downstream
    // treats it as a node paired before the probe existed.
    expect(nodes[0]?.incomplete).toBe(true);
    expect(nodes[0]?.probe).toBeUndefined();
    // The scan can no longer see it (it left the Provisioning Service when
    // it was provisioned), which is exactly why the entry has to exist.
    const candidates = await scanForUnprovisionedNodes(bluetooth);
    expect(candidates.map((c) => c.peripheralId)).not.toContain('dc2351a643d7');
  });

  test('THE ENTRY IS WRITTEN BEFORE THE APPLICATION KEY, not merely before the binds — a node that refuses AppKey Add is recorded too', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'refuses-appkey-no-reset', -50);
    // Refused AppKey Add, and a reset whose reply is the right message
    // MALFORMED — so the node never returns to the unowned state and the
    // entry must survive. Written this way rather than with `failReset` so
    // the test needs no clock advancing at all (and no longer with
    // `nodeResetWrongReply`, which since 2026-10-08 is discarded as not
    // being an answer to the request at all, and therefore waits).
    installSuccessfulNodeBehaviour(bluetooth, 'refuses-appkey-no-reset', 1, 2, {
      appKeyStatus: 0x05,
      nodeResetMalformedReply: true,
    });

    const outcome = await pairNode(deps, 'refuses-appkey-no-reset');

    expect(outcome.kind).toBe('failed');
    const nodes = store.getState().nodes;
    expect(nodes).toHaveLength(1);
    expect(nodes[0]?.address).toBe(2);
    expect(nodes[0]?.deviceKey).toEqual(KAT_DEVICE_KEY);
    expect(nodes[0]?.incomplete).toBe(true);
    // The composition the node DID report is kept with it: it is what a
    // later retry or a reset needs in order to know what it is talking to.
    expect(nodes[0]?.composition.elements).toHaveLength(1);
  });

  test('A NODE WHOSE RESET WAS ANSWERED IS FORGOTTEN AGAIN — the store never claims a node the user has just been told is unowned', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'refuses-and-resets', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'refuses-and-resets', 1, 2, { modelAppStatus: 0x0d });

    const outcome = await pairNode(deps, 'refuses-and-resets');

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.message).toContain('the node has been reset and can be paired again');
    // THE DISCRIMINATING ASSERTION: the message and the store agree. The
    // node answered its reset, so it is genuinely unowned again — provably,
    // since it is scannable — and keeping an entry for it would make this
    // app claim a bulb it does not have.
    expect(store.getState().nodes).toHaveLength(0);
    const candidates = await scanForUnprovisionedNodes(bluetooth);
    expect(candidates.map((c) => c.peripheralId)).toContain('refuses-and-resets');
    // The address it burned is still gone, per store.ts's never-reclaim
    // rule — forgetting the node must not rewind the allocator.
    expect(store.getState().nextUnicastAddress).toBe(3);
  });

  test('NOTHING IS RECORDED BEFORE THE COMPOSITION IS KNOWN: a node whose composition does not parse leaves no entry', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'bad-composition-no-reset', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'bad-composition-no-reset', 1, 2, {
      compositionAccessPayload: Buffer.from([0x02, 0x00, 0xaa, 0xbb]),
      nodeResetMalformedReply: true, // so a kept entry would survive and be visible here
    });

    const outcome = await pairNode(deps, 'bad-composition-no-reset');

    expect(outcome.kind).toBe('failed');
    // An entry needs an element count to be worth anything (and a composition
    // to store at all), and this node never gave one. Disclosed as a residual
    // gap rather than papered over with an invented composition.
    expect(store.getState().nodes).toHaveLength(0);
  });

  test('A SUCCESSFUL PAIRING LEAVES ONE ROW, NOT TWO: the provisional entry is replaced, flag gone, probe present', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'bulb-1', -55);
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-1', 1, 2);

    const outcome = await pairNode(deps, 'bulb-1');

    expect(outcome.kind).toBe('paired');
    const nodes = store.getState().nodes;
    // THE DISCRIMINATING ASSERTION: an implementation that APPENDED the
    // finished entry beside the provisional one would leave two rows for
    // one bulb here, while every other assertion in this file (which looks
    // at `nodes[0]`) would still pass.
    expect(nodes).toHaveLength(1);
    expect(nodes[0]?.address).toBe(2);
    expect(nodes[0]?.incomplete).toBeUndefined();
    expect(nodes[0]?.probe).toBeDefined();
  });

  test('ONE FAILURE AMONG SEVERAL: a multi-bulb run records the stranded bulb and still creates devices only for the others', async () => {
    const { bluetooth, store, deps } = setUp([
      TEST_NET_KEY,
      TEST_APP_KEY,
      KAT_RANDOM_PROVISIONER,
      KAT_RANDOM_PROVISIONER,
      KAT_RANDOM_PROVISIONER,
    ]);
    addUnprovisionedNode(bluetooth, 'good-1', -50);
    addUnprovisionedNode(bluetooth, 'stranded', -51);
    addUnprovisionedNode(bluetooth, 'good-2', -52);
    installSuccessfulNodeBehaviour(bluetooth, 'good-1', 1, 2);
    installSuccessfulNodeBehaviour(bluetooth, 'stranded', 1, 3, { modelAppStatus: 0x0d, nodeResetMalformedReply: true });
    installSuccessfulNodeBehaviour(bluetooth, 'good-2', 1, 4);

    const result = await pairNodes(deps, ['good-1', 'stranded', 'good-2']);

    expect(result.entries.map((e) => e.outcome.kind)).toEqual(['paired', 'failed', 'paired']);
    // Only the two that finished are offered to Homey as devices...
    expect(result.paired.map((d) => d.data.id)).toEqual(['2', '4']);
    // ...but all three are recorded, and only the middle one is flagged.
    const nodes = store.getState().nodes;
    expect(nodes.map((n) => n.address)).toEqual([2, 3, 4]);
    expect(nodes.map((n) => n.incomplete)).toEqual([undefined, true, undefined]);
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
            ttl: POINT_TO_POINT_TTL,
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

    // PROBE BUDGET ZERO: this test's fake node answers by counting writes,
    // so it cannot answer the capability probe's application-key traffic —
    // and it does not need to, because what it pins is the BIND addressing,
    // not the probe. A zero budget means `probeModels` has no time to send
    // anything and records every declared model `'unknown'` without a
    // single write (pinned directly in `modelProbe.test.ts`), which leaves
    // the write sequence this responder counts exactly as it was before the
    // probe existed.
    const outcome = await pairNode({ ...deps, probeBudgetMs: 0 }, 'two-lighting-elements');

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
  test('a Config AppKey Status in reply to Composition Data Get produces a clear failure that NAMES what arrived, not a crash or a false success', async () => {
    const { bluetooth, store, clock, deps } = setUp();
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
            ttl: POINT_TO_POINT_TTL,
            allocateSeq: allocateNodeSeq,
          }),
        );
      },
    });

    const outcomePromise = pairNode(deps, 'wrong-status-type');
    let settled = false;
    void outcomePromise.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    // The wrong message no longer settles the wait (hardware round,
    // 2026-10-08): it is discarded and the request goes on waiting for its
    // own reply, so the deadline is what ends this — for the request AND for
    // the Config Node Reset that `failWithReset` sends afterwards, which
    // this node answers with the same wrong message.
    for (let i = 0; i < 5 && !settled; i++) {
      await waitUntil(() => clock.pendingCount() >= 1 || settled);
      if (settled) break;
      await clock.advance(DEFAULT_PAIRING_STEP_TIMEOUT_MS);
    }
    const outcome = await outcomePromise;

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    // THE POINT OF THIS TEST SINCE 2026-10-08: the message distinguishes a
    // node that said the wrong thing from one that said nothing. The old
    // wording claimed the node "did not answer", which is what sent a human
    // looking for a dead bulb that was in fact talking.
    expect(outcome.message).toContain('node answered Config Composition Data Get with Config AppKey Status');
    expect(outcome.message).toContain('instead of a Config Composition Data Status message');
    expect(outcome.message).not.toContain('did not answer Config Composition Data Get');
    expect(store.getState().nodes).toHaveLength(0);
  });
});

// ===========================================================================
// DEFECT A (hardware round, 2026-10-08): A REPLY MUST ANSWER THE REQUEST
// THAT IS WAITING FOR IT.
//
// What happened: three bulbs, one run, all three reported as never having
// answered Config Model App Bind. They had answered. Every notification was
// reaching the app more than once — twice for the first two nodes, three
// times for the third — because each GATT session subscribed to the Data Out
// characteristic and never released the subscription, so the duplicate of the
// PREVIOUS request's Config AppKey Status was waiting in the channel when the
// bind's reply was asked for, and `sendConfigRequest` returned the first
// thing that decoded. The caller saw a message that was not a Model App
// Status and reported silence; the real Model App Status was still in flight.
//
// Both halves are pinned here: the matching (these tests) and the release
// (the describe block after this one). The matching is the one that holds
// even if duplicates ever come back — a mesh node may publish an unsolicited
// status or retransmit one at any time, so "the first decodable message" was
// never a safe rule.
// ===========================================================================

describe('a reply must answer the request that is waiting for it', () => {
  test('A DUPLICATE OF THE PREVIOUS REPLY does not satisfy the next request — the real reply is still awaited, and the pairing finishes', async () => {
    const { bluetooth, store, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'echoes', -55);
    // Every Config reply is preceded by an exact repeat of the previous one:
    // the AppKey Add's own reply arrives behind a second copy of the
    // Composition Data Status, the bind's behind a second copy of the AppKey
    // Status. Precisely the owner's capture.
    installSuccessfulNodeBehaviour(bluetooth, 'echoes', 1, 2, { repeatPreviousReplyFirst: true });

    const outcome = await pairNode(deps, 'echoes');

    // THE DISCRIMINATING ASSERTION: this is a complete, successful pairing.
    // Returning the first decodable message instead of the right one fails
    // it at the Config AppKey Add — whose "reply" would be the duplicated
    // Composition Data Status — long before the bind the hardware died on.
    expect(outcome.kind).toBe('paired');
    if (outcome.kind !== 'paired') return;
    expect(outcome.device.capabilities).toEqual(['onoff']);
    expect(store.getState().nodes[0]?.incomplete).toBeUndefined();
    // Nothing was left waiting: no stage timer survived the run.
    expect(clock.pendingCount()).toBe(0);
  });

  test('AN UNSOLICITED STATUS nobody asked for is discarded, not returned as the reply', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'chatty', -55);
    // A Config Node Reset Status (opcode 0x804A, no parameters) ahead of
    // every reply: a perfectly well-formed Config status, decodable by this
    // project, and never an answer to any request this exchange sends until
    // the very end — the shape of an unsolicited publication.
    installSuccessfulNodeBehaviour(bluetooth, 'chatty', 1, 2, {
      unsolicitedBeforeEachReply: Buffer.from([0x80, 0x4a]),
    });

    const outcome = await pairNode(deps, 'chatty');

    expect(outcome.kind).toBe('paired');
    if (outcome.kind !== 'paired') return;
    expect(outcome.device.capabilities).toEqual(['onoff']);
    expect(store.getState().nodes).toHaveLength(1);
  });

  test('GENUINE SILENCE still times out, and the message says silence rather than naming a message that never came', async () => {
    const { bluetooth, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'mute-bind', -55);
    installSuccessfulNodeBehaviour(bluetooth, 'mute-bind', 1, 2, { silentModelAppBind: true, failReset: true });

    const outcomePromise = pairNode(deps, 'mute-bind');
    let settled = false;
    void outcomePromise.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    for (let i = 0; i < 5 && !settled; i++) {
      await waitUntil(() => clock.pendingCount() >= 1 || settled);
      if (settled) break;
      await clock.advance(DEFAULT_PAIRING_STEP_TIMEOUT_MS);
    }
    const outcome = await outcomePromise;

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    // "Did not answer" means the node said NOTHING — and names which request
    // went unanswered, down to the element and the model.
    expect(outcome.message).toContain(
      'node did not answer Config Model App Bind (element 0, model 0x1000) with a Config Model App Status message',
    );
    // ...and does not describe something as having arrived, because nothing did.
    expect(outcome.message).not.toContain('node answered Config Model App Bind');
    expect(outcome.message).not.toContain('instead of a Config Model App Status');
    // The underlying reason the wait ended is carried too, never swallowed:
    // "the node said nothing" and "the link died" are not the same problem.
    expect(outcome.message).toContain('configuration exchange stalled');
  });
});

// ===========================================================================
// DEFECT A's CAUSE: the subscriptions themselves. `pairing.ts` called
// `bluetooth.subscribe` once per GATT session and never once called
// `unsubscribe` — the word did not appear in the file. Two sessions per node
// and several nodes per run is how one notification came to be delivered
// three times.
//
// The fake counts LIVE subscriptions (handed out, minus released) and
// deliberately does not count a dropped link as a release — see
// `FakeBluetoothPort#liveSubscriptionCount`.
// ===========================================================================

describe('a GATT session releases the notification subscription it took', () => {
  test('on the SUCCESS path: a completed pairing leaves none of its two sessions subscribed', async () => {
    const { bluetooth, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'bulb-1', -55);
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-1', 1, 2);

    const outcome = await pairNode(deps, 'bulb-1');

    expect(outcome.kind).toBe('paired');
    // Guards the guard: a run that never subscribed would satisfy the
    // assertion below for the wrong reason. Two sessions, two subscriptions
    // (provisioning, then configuration — see pairing.ts's own "TWO GATT
    // SESSIONS" note).
    expect(bluetooth.subscriptionCount()).toBe(2);
    expect(bluetooth.liveSubscriptionCount()).toBe(0);
  });

  test('on the FAILURE path: a configuration that fails leaves nothing subscribed either', async () => {
    const { bluetooth, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'refuses-bind', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'refuses-bind', 1, 2, { modelAppStatus: 0x0d });

    const outcome = await pairNode(deps, 'refuses-bind');

    expect(outcome.kind).toBe('failed');
    expect(bluetooth.subscriptionCount()).toBe(2);
    expect(bluetooth.liveSubscriptionCount()).toBe(0);
  });

  test('ACROSS A WHOLE RUN of three bulbs — the shape of the owner\'s own failed run — nothing accumulates', async () => {
    const { bluetooth, deps } = setUp([
      TEST_NET_KEY,
      TEST_APP_KEY,
      KAT_RANDOM_PROVISIONER,
      KAT_RANDOM_PROVISIONER,
      KAT_RANDOM_PROVISIONER,
    ]);
    addUnprovisionedNode(bluetooth, 'bulb-a', -50);
    addUnprovisionedNode(bluetooth, 'bulb-b', -51);
    addUnprovisionedNode(bluetooth, 'bulb-c', -52);
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-a', 1, 2);
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-b', 1, 3);
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-c', 1, 4);

    const result = await pairNodes(deps, ['bulb-a', 'bulb-b', 'bulb-c']);

    expect(result.paired.map((d) => d.data.id)).toEqual(['2', '3', '4']);
    // THE DISCRIMINATING ASSERTION, and the measured defect: six sessions,
    // six subscriptions, none of them still live. Before the fix this was 6
    // — which is why the third bulb saw every notification three times.
    expect(bluetooth.subscriptionCount()).toBe(6);
    expect(bluetooth.liveSubscriptionCount()).toBe(0);
  });

  test('a session abandoned BEFORE it was ever handed to a caller releases its subscription too', async () => {
    // discover() fails on the reconnect for configuration: provisioning
    // succeeded (one subscription, released with that session), and the
    // configuration session dies inside openSession, where no caller ever
    // receives a GattSession to disconnect.
    const { bluetooth, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'discover-fails-later', -50);
    installProvisioningResponder(bluetooth, 'discover-fails-later', {
      onComplete: () => {
        bluetooth.reconfigureAsProvisioned('discover-fails-later', TEST_NET_KEY);
        bluetooth.setDiscoverBehavior('discover-fails-later', 'fail');
      },
    });

    const outcome = await pairNode(deps, 'discover-fails-later');

    expect(outcome.kind).toBe('failed');
    expect(bluetooth.subscriptionCount()).toBe(1); // only the provisioning session ever subscribed
    expect(bluetooth.liveSubscriptionCount()).toBe(0);
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

/**
 * FINAL RE-REVIEW, FINDING 2 (MEDIUM). This session used to have no SAR
 * timer of its own, and the comment defending that was arithmetically
 * backwards: it argued "20 seconds is longer than any `timeoutMs` this
 * project passes, so the stage timeout always fires first", when
 * DEFAULT_PAIRING_STEP_TIMEOUT_MS is 30 000 and PROXY_SAR_TIMEOUT_MS is
 * 20 000 — the project's timeout is the LONGER one. The consequence was
 * real, not merely rhetorical: a node that sent a first segment and then
 * went quiet held the radio for the full 30 s and the disconnect Section
 * 6.3.2.2 requires at 20 s never happened at all.
 *
 * This session is unambiguously bound by that rule. Section 5.2.2
 * "PB-GATT": "When PB-GATT is used, the Provisioner shall use the PB-GATT
 * Client role and the unprovisioned device shall use the PB-GATT Server
 * role." and "The PB-GATT Server shall use the Provisioning Server role
 * (see Section 6.2.2) and the PB-GATT Client shall use the Provisioning
 * Client role (see Section 6.2.2)."; Section 6.2.2 "Provisioning PB-GATT
 * bearer roles": "The Provisioning Client is a node that supports the Proxy
 * PDU Client and supports transporting Provisioning PDUs using the Proxy
 * protocol." So the Proxy PDU Client rules of Section 6.3.2.2 are this
 * session's rules, on both of its characteristic pairs.
 */
describe('the Proxy PDU Client rules apply to this session too (final re-review, finding 2)', () => {
  /** The relationship the old comment asserted backwards, pinned so the
   *  argument can never be made from memory again. */
  test('the SAR timeout is SHORTER than the pairing step timeout, not longer', () => {
    expect(PROXY_SAR_TIMEOUT_MS).toBeLessThan(DEFAULT_PAIRING_STEP_TIMEOUT_MS);
  });

  test('a reply that stops arriving mid-message disconnects at 20 seconds and fails the wait, naming why', async () => {
    const { bluetooth, clock } = setUp();
    addUnprovisionedNode(bluetooth, 'stalls', -50);
    const session = await connectForProvisioning(bluetooth, 'stalls', clock, DEFAULT_PAIRING_STEP_TIMEOUT_MS);

    const pending = session.next();
    const rejection = expect(pending).rejects.toThrow(/SAR transfer timed out/);
    // 0b01_000011: a FIRST segment of a Provisioning PDU (Table 6.2 SAR
    // 0b01, Table 6.3 MessageType 0x03), and then silence.
    bluetooth.simulateRawNotification('stalls', Buffer.from([0x43, 0x11]));

    await clock.advance(PROXY_SAR_TIMEOUT_MS - 1);
    expect(() => bluetooth.simulateDisconnect('stalls')).not.toThrow(); // still connected, correctly...
    // ...so put the link back and let the deadline actually arrive.
    const second = await connectForProvisioning(bluetooth, 'stalls', clock, DEFAULT_PAIRING_STEP_TIMEOUT_MS);
    const secondPending = second.next();
    const secondRejection = expect(secondPending).rejects.toThrow(/SAR transfer timed out/);
    bluetooth.simulateRawNotification('stalls', Buffer.from([0x43, 0x11]));

    await clock.advance(PROXY_SAR_TIMEOUT_MS);
    // The link is gone — Section 6.3.2.2's "shall disconnect", performed at
    // the deadline rather than ten seconds after it.
    expect(() => bluetooth.simulateDisconnect('stalls')).toThrow('is not currently connected');
    await secondRejection;

    // The first session's own stalled wait is still bounded by its stage
    // timeout, as it always was.
    await clock.advance(DEFAULT_PAIRING_STEP_TIMEOUT_MS);
    await rejection.catch(() => {});
    await expect(pending).rejects.toThrow();
  });

  test('an unexpected SAR value disconnects and fails the wait, rather than being ignored until the stage timeout', async () => {
    const { bluetooth, clock } = setUp();
    addUnprovisionedNode(bluetooth, 'bad-sar', -50);
    const session = await connectForProvisioning(bluetooth, 'bad-sar', clock, DEFAULT_PAIRING_STEP_TIMEOUT_MS);

    const pending = session.next();
    const rejection = expect(pending).rejects.toThrow(/unexpected SAR value 0b10/);
    // 0b10_000011: a continuation segment with nothing being reassembled.
    bluetooth.simulateRawNotification('bad-sar', Buffer.from([0x83, 0x11]));

    // No clock advance at all: the violation is acted on when it arrives,
    // not when some unrelated deadline expires.
    expect(() => bluetooth.simulateDisconnect('bad-sar')).toThrow('is not currently connected');
    await rejection;
  });

  /**
   * Note on what this has to assert, and why the obvious version is not
   * enough. "The link is never dropped" does NOT discriminate: the timer
   * callback re-checks `reassembly` and returns harmlessly when a message
   * has completed, so DELETING `clearSarTimer()` from the complete case
   * leaves behaviour identical — I verified that by mutation, and the first
   * version of this test passed unchanged. What the mutation really breaks
   * is the CLOCK: a stranded timer per completed message keeps a real event
   * loop alive and holds this session's closure reachable until it fires,
   * which is exactly the argument `queue.test.ts` already makes about its
   * own `clearTimer`. So this counts timers, as that test does.
   */
  test('a message that completes cancels the SAR timer rather than leaving it to fire later', async () => {
    const { bluetooth, clock } = setUp();
    addUnprovisionedNode(bluetooth, 'fine', -50);
    const session = await connectForProvisioning(bluetooth, 'fine', clock, DEFAULT_PAIRING_STEP_TIMEOUT_MS);

    bluetooth.simulateRawNotification('fine', Buffer.from([0x43, 0x11])); // first segment...
    expect(clock.pendingCount()).toBe(1); // ...armed a SAR timer...
    bluetooth.simulateRawNotification('fine', Buffer.from([0xc3, 0x22])); // ...and its last
    await expect(session.next()).resolves.toEqual(Buffer.from([0x11, 0x22]));

    expect(clock.pendingCount()).toBe(0); // the timer was actually cancelled, not merely made harmless
    await clock.advance(PROXY_SAR_TIMEOUT_MS * 2);
    expect(() => bluetooth.simulateDisconnect('fine')).not.toThrow(); // never dropped
  });

  test('a session the caller disconnects leaves no SAR timer pending', async () => {
    const { bluetooth, clock } = setUp();
    addUnprovisionedNode(bluetooth, 'tidy', -50);
    const session = await connectForProvisioning(bluetooth, 'tidy', clock, DEFAULT_PAIRING_STEP_TIMEOUT_MS);

    bluetooth.simulateRawNotification('tidy', Buffer.from([0x43, 0x11])); // a reassembly is now in progress
    expect(clock.pendingCount()).toBe(1); // its SAR timer

    await session.disconnect();
    expect(clock.pendingCount()).toBe(0);
  });
});

// ===========================================================================
// THE CAPABILITY PROBE, end to end through the real pairing flow — the
// hardware round's own measurement, driven here against a fake node that
// behaves the way the owner's bulb actually does.
//
// `modelProbe.test.ts` enumerates node BEHAVIOURS against the narrow
// transport seam; these tests prove the probe is wired into the real
// sequence at all: after the AppKey binds, over the application key, with
// its result reaching both the store and the device's capabilities.
// ===========================================================================

/** A composition declaring every lighting model this project probes — the
 *  published sample declares only Generic OnOff, which is not enough to show
 *  one model being told apart from another. Header fields are all zero (this
 *  test is about the probe, not composition.ts's own decoding, which has its
 *  own tests); element 0 declares five SIG models. */
const ALL_LIGHTING_MODELS_COMPOSITION = Buffer.from([
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header
  0x00, 0x00, 0x05, 0x00, // loc=0x0000, NumS=5, NumV=0
  0x00, 0x10, // Generic OnOff Server
  0x00, 0x13, // Light Lightness Server
  0x03, 0x13, // Light CTL Server
  0x06, 0x13, // Light CTL Temperature Server
  0x07, 0x13, // Light HSL Server
]);

const ALL_MODELS_COMPOSITION_PAYLOAD = Buffer.concat([Buffer.from([0x02, 0x00]), ALL_LIGHTING_MODELS_COMPOSITION]);

/** A tunable-white bulb with no colour emitters AND no HSL declaration —
 *  the shape that seeds the colour-mode setting to `warm`. Same header as
 *  above; element 0 declares four SIG models, the Light HSL Server omitted. */
const CTL_ONLY_COMPOSITION = Buffer.from([
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header
  0x00, 0x00, 0x04, 0x00, // loc=0x0000, NumS=4, NumV=0
  0x00, 0x10, // Generic OnOff Server
  0x00, 0x13, // Light Lightness Server
  0x03, 0x13, // Light CTL Server
  0x06, 0x13, // Light CTL Temperature Server
]);

const CTL_ONLY_COMPOSITION_PAYLOAD = Buffer.concat([Buffer.from([0x02, 0x00]), CTL_ONLY_COMPOSITION]);

/**
 * Short probe timings for the tests below, injected rather than waited on.
 * The production numbers (1500 ms per probe, 9000 ms total) are pinned in
 * `modelProbe.test.ts`; what matters here is only that the probe's own
 * timeouts fire far inside the 30 s pairing step timeout, so a test
 * exercising a silent model is measuring the probe rather than the stage
 * bound around it.
 */
const PROBE_TEST_TIMING = { probeTimeoutMs: 100, probeBudgetMs: 3000 };

/**
 * Runs a pairing to completion while VIRTUAL TIME moves, which a silent
 * capability probe needs and nothing before it did.
 *
 * Every earlier wait in this file resolves because something ANSWERS; the
 * probe's does not — its negative result IS a timeout, and a `FakeClock`
 * fires no timer until a test advances it. So a test exercising a node that
 * stays silent for one model has to drive the clock alongside the pairing
 * rather than simply awaiting it.
 *
 * THE MACROTASK DRAIN IS NOT DECORATION. `FakeClock.advance` yields a full
 * macrotask after each timer it FIRES, but returns almost immediately when
 * nothing is due — so a bare `advance` loop lets the pairing's own promise
 * chain progress by only a tick or two per iteration, and a pairing that
 * needs dozens of GATT round trips crawls (measured: one write per seven
 * virtual seconds, never finishing). Draining first, advancing second, is
 * what makes each iteration mean "let everything that can happen happen,
 * then release the next timeout."
 */
async function pairWhileAdvancing(deps: PairingDeps, peripheralId: string, clock: FakeClock): Promise<PairingOutcome> {
  let settled = false;
  const pairing = pairNode({ ...deps, ...PROBE_TEST_TIMING }, peripheralId).finally(() => {
    settled = true;
  });
  for (let step = 0; step < 200 && !settled; step++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
    if (settled) break;
    await clock.advance(PROBE_TEST_TIMING.probeTimeoutMs);
  }
  return pairing;
}

describe('the capability probe, through a real pairing', () => {
  test("THE OWNER'S OWN BULB: declares both colour-temperature models, answers only 0x8264 — and keeps light_temperature", async () => {
    const { bluetooth, store, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'tuya-cct', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'tuya-cct', 1, 2, {
      compositionAccessPayload: ALL_MODELS_COMPOSITION_PAYLOAD,
      silentModels: ['lightCtl'],
    });

    const outcome = await pairWhileAdvancing(deps, 'tuya-cct', clock);

    expect(outcome.kind).toBe('paired');
    if (outcome.kind !== 'paired') return;
    const probe = store.getState().nodes[0]?.probe;
    expect(probe?.models).toEqual({
      genericOnOff: 'supported',
      lightLightness: 'supported',
      // Declared, bound, written to — and silent. Measured, not assumed.
      lightCtl: 'unsupported',
      lightCtlTemperature: 'supported',
      lightHsl: 'supported',
    });
    // The lamp can plainly change colour temperature, so the capability
    // stays even though one of the two declared models is a lie.
    expect(outcome.device.capabilities).toContain('light_temperature');
  });

  test('a node that answers NEITHER colour-temperature model loses light_temperature, and light_mode with it', async () => {
    const { bluetooth, store, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'no-cct', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'no-cct', 1, 2, {
      compositionAccessPayload: ALL_MODELS_COMPOSITION_PAYLOAD,
      silentModels: ['lightCtl', 'lightCtlTemperature'],
    });

    const outcome = await pairWhileAdvancing(deps, 'no-cct', clock);

    expect(outcome.kind).toBe('paired');
    if (outcome.kind !== 'paired') return;
    expect(outcome.device.capabilities).not.toContain('light_temperature');
    expect(outcome.device.capabilities).not.toContain('light_mode');
    // ...and the models it DID answer are untouched.
    expect(outcome.device.capabilities).toEqual(['onoff', 'dim', 'light_hue', 'light_saturation']);
    expect(store.getState().nodes[0]?.probe?.models.lightCtlTemperature).toBe('unsupported');
  });

  test('the probe leaves the lamp exactly as it found it — every write is the value its own read returned', async () => {
    const { bluetooth, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'untouched', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'untouched', 1, 2, {
      compositionAccessPayload: ALL_MODELS_COMPOSITION_PAYLOAD,
    });
    // The fake lamp's starting state, written out rather than snapshotted:
    // the responder (and with it the lamp) only comes into existence once
    // provisioning completes, so there is nothing to snapshot beforehand —
    // and a literal is the stronger assertion anyway, since it cannot be
    // satisfied by an empty object.
    const untouched = { onOff: 0x01, lightness: 0x8000, temperature: 4500, deltaUv: 0x0000, hue: 0x4000, saturation: 0x2000 };

    await pairWhileAdvancing(deps, 'untouched', clock);

    expect(lampStateByPeripheral.get('untouched')).toEqual(untouched);
  });

  test("a node that reports its colour-temperature range has it stored, and seeds the device's own settings", async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'reports-range', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'reports-range', 1, 2, {
      compositionAccessPayload: ALL_MODELS_COMPOSITION_PAYLOAD,
      temperatureRangeReply: { min: 2200, max: 6500 },
    });

    const outcome = await pairNode(deps, 'reports-range');

    expect(outcome.kind).toBe('paired');
    if (outcome.kind !== 'paired') return;
    expect(store.getState().nodes[0]?.probe?.temperatureRange).toEqual({ minKelvin: 2200, maxKelvin: 6500 });
    expect(outcome.device.settings).toEqual({
      temperature_min_kelvin: 2200,
      temperature_max_kelvin: 6500,
      colour_mode: 'multicolor',
    });
  });

  test("a node that never answers Range Get (the owner's own bulb) falls back to the documented default in its settings", async () => {
    const { bluetooth, store, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'silent-range', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'silent-range', 1, 2, {
      compositionAccessPayload: ALL_MODELS_COMPOSITION_PAYLOAD,
      temperatureRangeReply: 'silent',
    });

    const outcome = await pairWhileAdvancing(deps, 'silent-range', clock);

    expect(outcome.kind).toBe('paired');
    if (outcome.kind !== 'paired') return;
    expect(store.getState().nodes[0]?.probe?.temperatureRange).toBeNull();
    // The full legal span, not any particular lamp's output — see
    // temperatureRange.ts's own header for why a bulb that rescales makes a
    // measured-from-one-bulb default the wrong choice.
    expect(outcome.device.settings).toEqual({
      temperature_min_kelvin: 800,
      temperature_max_kelvin: 20000,
      colour_mode: 'multicolor',
    });
  });

  test("a node answering Table 6.8's own 0xFFFF \"unknown\" row is treated as having said nothing, not as a 65535 K bulb", async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'unknown-range', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'unknown-range', 1, 2, {
      compositionAccessPayload: ALL_MODELS_COMPOSITION_PAYLOAD,
      temperatureRangeReply: 'unknown',
    });

    const outcome = await pairNode(deps, 'unknown-range');

    expect(outcome.kind).toBe('paired');
    if (outcome.kind !== 'paired') return;
    expect(store.getState().nodes[0]?.probe?.temperatureRange).toBeNull();
    expect(outcome.device.settings).toEqual({
      temperature_min_kelvin: 800,
      temperature_max_kelvin: 20000,
      colour_mode: 'multicolor',
    });
  });

  // =========================================================================
  // THE COLOUR-MODE SEED. `lib/models/capabilities.ts`'s own "WHAT THE PROBE
  // CANNOT SETTLE" note: no wire probe can tell whether a lamp has colour
  // LEDs, because a lamp with none still acknowledges `Light HSL Set` with a
  // correct echo. Pairing therefore seeds the per-device setting from what
  // it DOES know, and the user corrects it.
  // =========================================================================

  test('HSL declared seeds the new device as multicolor — the guess the user corrects', async () => {
    const { bluetooth, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'seed-colour', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'seed-colour', 1, 2, {
      compositionAccessPayload: ALL_MODELS_COMPOSITION_PAYLOAD,
    });

    const outcome = await pairWhileAdvancing(deps, 'seed-colour', clock);

    expect(outcome.kind).toBe('paired');
    if (outcome.kind !== 'paired') return;
    expect(outcome.device.capabilities).toContain('light_hue');
    expect(outcome.device.settings.colour_mode).toBe('multicolor');
  });

  test('a node measured to run NEITHER colour-temperature model, and declaring no HSL, seeds as monocolor', async () => {
    // COMPOSITION_DATA_PAGE0_SAMPLE declares Generic OnOff Server and
    // nothing else this design maps — no Lightness, no CTL, no HSL — so
    // there is neither a temperature nor a colour to seed from.
    const { bluetooth, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'seed-mono', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'seed-mono', 1, 2);

    const outcome = await pairNode(deps, 'seed-mono');

    expect(outcome.kind).toBe('paired');
    if (outcome.kind !== 'paired') return;
    expect(outcome.device.capabilities).toEqual(['onoff']);
    expect(outcome.device.settings.colour_mode).toBe('monocolor');
  });

  test('a node with colour temperature but no HSL seeds as warm', async () => {
    const { bluetooth, clock, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'seed-warm', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'seed-warm', 1, 2, {
      compositionAccessPayload: CTL_ONLY_COMPOSITION_PAYLOAD,
    });

    const outcome = await pairWhileAdvancing(deps, 'seed-warm', clock);

    expect(outcome.kind).toBe('paired');
    if (outcome.kind !== 'paired') return;
    expect(outcome.device.capabilities).toContain('light_temperature');
    expect(outcome.device.capabilities).not.toContain('light_hue');
    expect(outcome.device.settings.colour_mode).toBe('warm');
  });
});

// ===========================================================================
// pairNodes — several bulbs in one run of the pairing wizard.
// ===========================================================================

describe('pairNodes', () => {
  test('pairs every selected bulb and gives each its own address, one after another', async () => {
    // Three attempts need three RandomProvisioner values after the
    // network's own two keys — see `FixedRandomSource`.
    const { bluetooth, store, deps } = setUp([TEST_NET_KEY, TEST_APP_KEY, KAT_RANDOM_PROVISIONER, KAT_RANDOM_PROVISIONER, KAT_RANDOM_PROVISIONER]);
    for (const [index, id] of ['bulb-1', 'bulb-2', 'bulb-3'].entries()) {
      addUnprovisionedNode(bluetooth, id, -50 - index);
      installSuccessfulNodeBehaviour(bluetooth, id, 1, 2 + index);
    }

    const result = await pairNodes(deps, ['bulb-1', 'bulb-2', 'bulb-3']);

    expect(result.entries.map((e) => e.outcome.kind)).toEqual(['paired', 'paired', 'paired']);
    expect(result.paired).toHaveLength(3);
    // THE DISCRIMINATING ASSERTION for the one shared store: three distinct,
    // consecutive addresses. A loop that cached state across iterations
    // would reissue the first one.
    expect(result.paired.map((d) => d.data.id)).toEqual(['2', '3', '4']);
    expect(store.getState().nodes.map((n) => n.address)).toEqual([2, 3, 4]);
    expect(store.getState().nextUnicastAddress).toBe(5);
  });

  test('ONE AT A TIME: the next bulb is not even connected to until the previous one has finished', async () => {
    const { bluetooth, deps } = setUp();
    for (const [index, id] of ['bulb-1', 'bulb-2'].entries()) {
      addUnprovisionedNode(bluetooth, id, -50 - index);
      installSuccessfulNodeBehaviour(bluetooth, id, 1, 2 + index);
    }

    await pairNodes(deps, ['bulb-1', 'bulb-2']);

    // Every write to bulb-2 comes after every write to bulb-1 — i.e. the
    // two attempts never interleave. Two simultaneous GATT connections from
    // one Homey radio are unverified (app.ts's own note), and a
    // `Promise.all` here would be a correctness bug, not a speed-up.
    const order = bluetooth.writesReceived.map((w) => w.peripheralId);
    expect(order.lastIndexOf('bulb-1')).toBeLessThan(order.indexOf('bulb-2'));
  });

  test('ONE FAILURE DOES NOT ABANDON THE REST: the bulbs after it are still paired, and the failure is named', async () => {
    const { bluetooth, store, deps } = setUp([TEST_NET_KEY, TEST_APP_KEY, KAT_RANDOM_PROVISIONER, KAT_RANDOM_PROVISIONER, KAT_RANDOM_PROVISIONER]);
    addUnprovisionedNode(bluetooth, 'good-1', -50);
    addUnprovisionedNode(bluetooth, 'refuses', -51);
    addUnprovisionedNode(bluetooth, 'good-2', -52);
    installSuccessfulNodeBehaviour(bluetooth, 'good-1', 1, 2);
    // Address 3 is consumed by the failed attempt and never reclaimed
    // (store.ts's own deliberate rule), so the third bulb gets 4.
    installSuccessfulNodeBehaviour(bluetooth, 'refuses', 1, 3, { appKeyStatus: 0x01 });
    installSuccessfulNodeBehaviour(bluetooth, 'good-2', 1, 4);

    const result = await pairNodes(deps, ['good-1', 'refuses', 'good-2']);

    expect(result.entries.map((e) => e.outcome.kind)).toEqual(['paired', 'failed', 'paired']);
    expect(result.paired.map((d) => d.data.id)).toEqual(['2', '4']);
    const failure = result.entries[1]!;
    expect(failure.peripheralId).toBe('refuses');
    if (failure.outcome.kind !== 'failed') throw new Error('test fixture error: expected a failure');
    expect(failure.outcome.message).toContain('Config AppKey Add was refused');
    // A partial result is a success for the bulbs that worked: both are in
    // the store, with their own entries.
    expect(store.getState().nodes.map((n) => n.address)).toEqual([2, 4]);
  });

  test('a bulb that is not there at all fails on its own and costs the others nothing', async () => {
    const { bluetooth, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'present', -50);
    // Address 2, not 3: the missing bulb fails while CONNECTING, before
    // anything allocates an address, so it consumes none.
    installSuccessfulNodeBehaviour(bluetooth, 'present', 1, 2);

    const result = await pairNodes(deps, ['missing', 'present']);

    expect(result.entries[0]?.outcome.kind).toBe('failed');
    expect(result.entries[1]?.outcome.kind).toBe('paired');
    expect(result.paired).toHaveLength(1);
  });

  test('reports progress before and after each bulb, in order, so a long run is not a frozen screen', async () => {
    const { bluetooth, deps } = setUp();
    for (const [index, id] of ['bulb-1', 'bulb-2'].entries()) {
      addUnprovisionedNode(bluetooth, id, -50 - index);
      installSuccessfulNodeBehaviour(bluetooth, id, 1, 2 + index);
    }

    const progress: MultiPairingProgress[] = [];
    await pairNodes(deps, ['bulb-1', 'bulb-2'], (p) => progress.push(p));

    expect(progress.map((p) => `${p.phase}:${p.peripheralId}`)).toEqual([
      'start:bulb-1',
      'done:bulb-1',
      'start:bulb-2',
      'done:bulb-2',
    ]);
    expect(progress.every((p) => p.total === 2)).toBe(true);
    expect(progress.map((p) => p.index)).toEqual([0, 0, 1, 1]);
    const last = progress[3]!;
    if (last.phase !== 'done') throw new Error('test fixture error: expected a done event');
    expect(last.outcome.kind).toBe('paired');
  });

  test('a progress listener that throws does not take the run down with it', async () => {
    const { bluetooth, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'bulb-1', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-1', 1, 2);

    const result = await pairNodes(deps, ['bulb-1'], () => {
      throw new Error('the pairing view blew up');
    });

    expect(result.paired).toHaveLength(1);
  });

  test('the same bulb selected twice is paired once — never consuming two addresses for one node', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'bulb-1', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-1', 1, 2);

    const result = await pairNodes(deps, ['bulb-1', 'bulb-1']);

    expect(result.entries).toHaveLength(1);
    expect(store.getState().nodes).toHaveLength(1);
    expect(store.getState().nextUnicastAddress).toBe(3);
  });

  test('an empty selection is an empty result, not an error', async () => {
    const { deps } = setUp();
    await expect(pairNodes(deps, [])).resolves.toEqual({ entries: [], paired: [] });
  });

  test('the single-bulb path still works, unchanged, alongside the multi-bulb one', async () => {
    const { bluetooth, store, deps } = setUp();
    addUnprovisionedNode(bluetooth, 'bulb-1', -50);
    installSuccessfulNodeBehaviour(bluetooth, 'bulb-1', 1, 2);

    const outcome = await pairNode(deps, 'bulb-1');

    expect(outcome.kind).toBe('paired');
    expect(store.getState().nodes).toHaveLength(1);
  });
});
