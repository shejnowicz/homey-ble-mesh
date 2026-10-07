import { randomBytes as nodeRandomBytes } from 'node:crypto';
import {
  MESH_PROVISIONING_DATA_IN_UUID,
  MESH_PROVISIONING_DATA_OUT_UUID,
  MESH_PROVISIONING_SERVICE_UUID,
  MESH_PROXY_DATA_IN_UUID,
  MESH_PROXY_DATA_OUT_UUID,
  MESH_PROXY_SERVICE_UUID,
  findServiceData,
  type BluetoothPort,
  type ConnectionHandle,
} from '../../lib/adapter/connection';
import { NetworkStore } from '../../lib/adapter/store';
import { encodeMeshMessage, acceptIncomingPdu, type MeshReceiveState, type MeshReceiveContext } from '../../lib/adapter/meshMessage';
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
  decodeConfigStatus,
} from '../../lib/mesh/config/client';
import { encodeAccessMessage, type AccessMessage } from '../../lib/mesh/packet/access';
import { parseCompositionData, type CompositionData } from '../../lib/mesh/config/composition';
import { mapCompositionToCapabilities, LIGHTING_SERVER_MODEL_IDS, type HomeyCapability } from '../../lib/models/capabilities';

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
 * (`lib/mesh/packet/*.ts`, composed by `lib/adapter/meshMessage.ts`), the
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
 * disconnect and reconnect — consistent with this project's existing,
 * disclosed simplification that `connection.ts`/`queue.ts` write raw
 * Network PDU bytes directly to the Mesh Proxy Data In characteristic with
 * no Proxy PDU SAR/Message-Type envelope of their own (Section 6.3.1); if a
 * real bulb needs either a settling delay or that envelope, this is the
 * first place to look, the same way `machine.ts`'s own CMAC-only limitation
 * is documented as the first thing to suspect for a refused provisioning.
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
 * NODE ENTRIES ARE WRITTEN ONLY ON COMPLETE SUCCESS. The allocated node
 * address, by contrast, is NEVER reclaimed on failure — once
 * `store.allocateUnicastAddress()` hands one out, this module simply
 * abandons it if anything later fails, the same way a real provisioner
 * cannot safely reuse an address a partially-provisioned node might
 * already have recorded. This is deliberate, not an oversight: see
 * `store.ts`'s own module header for why handing out the same address
 * twice is the one failure this design treats as worse than wasting a
 * unicast address.
 *
 * THE INHERITED ADDRESS-ADVANCE HAZARD (plan 1, carried into this task's
 * brief). `store.allocateUnicastAddress()` hands out exactly ONE address,
 * but a node occupies as many CONSECUTIVE unicast addresses as it has
 * elements — and composition data, which reveals the element count, is only
 * read AFTER provisioning assigns the node's own (single) address. This
 * module advances `nextUnicastAddress` past the extra elements itself, in
 * `finishPairing` below, the ONE place this module writes to `nodes` at
 * all — and does so from a FRESH `store.getState()` read taken immediately
 * before that single `setState` call, never from a state snapshot read
 * before `allocateUnicastAddress()` ran, per that method's own loud
 * CALLER HAZARD comment (reading-before-allocating and writing after would
 * silently rewind the pointer and reissue an address already handed out —
 * see `ensureNetworkInitialized` below for the other call site with the
 * exact same discipline).
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
  private waiting: ((data: Buffer) => void) | null = null;

  push(data: Buffer): void {
    if (this.waiting !== null) {
      const resolve = this.waiting;
      this.waiting = null;
      resolve(data);
      return;
    }
    this.queue.push(data);
  }

  next(): Promise<Buffer> {
    const queued = this.queue.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    return new Promise<Buffer>((resolve) => {
      this.waiting = resolve;
    });
  }
}

interface GattSession {
  write(data: Buffer): Promise<void>;
  next(): Promise<Buffer>;
  disconnect(): Promise<void>;
}

async function openSession(
  bluetooth: BluetoothPort,
  peripheralId: string,
  serviceUuid: number,
  dataInUuid: number,
  dataOutUuid: number,
): Promise<GattSession> {
  const connection: ConnectionHandle = await bluetooth.connect(peripheralId, () => {
    // An unexpected mid-session disconnect simply stops this channel from
    // ever receiving anything further; whatever this module is currently
    // awaiting (`next()`) then never resolves, and the pairing attempt is
    // left to the caller's own judgement (there is no retry/backoff here —
    // pairing is a one-shot, user-initiated action the design says can
    // simply be retried, not a persistent connection with its own recovery
    // policy the way `ProxyConnectionManager` is).
  });
  const characteristics = await bluetooth.discover(connection);
  const dataIn = characteristics.find((c) => c.serviceUuid === serviceUuid && c.characteristicUuid === dataInUuid);
  const dataOut = characteristics.find((c) => c.serviceUuid === serviceUuid && c.characteristicUuid === dataOutUuid);
  if (!dataIn || !dataOut) {
    throw new Error(
      `peripheral "${peripheralId}" does not expose both required characteristics for service 0x${serviceUuid.toString(16)} (0x${dataInUuid.toString(16)}/0x${dataOutUuid.toString(16)})`,
    );
  }
  const channel = new NotificationChannel();
  await bluetooth.subscribe(dataOut.handle, (data) => channel.push(data));
  return {
    write: (data: Buffer): Promise<void> => bluetooth.write(dataIn.handle, data),
    next: (): Promise<Buffer> => channel.next(),
    disconnect: (): Promise<void> => bluetooth.disconnect(connection),
  };
}

/** Connects for the PROVISIONING phase (Mesh Provisioning Service). */
function connectForProvisioning(bluetooth: BluetoothPort, peripheralId: string): Promise<GattSession> {
  return openSession(bluetooth, peripheralId, MESH_PROVISIONING_SERVICE_UUID, MESH_PROVISIONING_DATA_IN_UUID, MESH_PROVISIONING_DATA_OUT_UUID);
}

/** Connects for the CONFIGURATION phase (Mesh Proxy Service) — see the
 *  module header's "TWO GATT SESSIONS" note for why this is a fresh
 *  connection, not the same one. */
function connectForConfiguration(bluetooth: BluetoothPort, peripheralId: string): Promise<GattSession> {
  return openSession(bluetooth, peripheralId, MESH_PROXY_SERVICE_UUID, MESH_PROXY_DATA_IN_UUID, MESH_PROXY_DATA_OUT_UUID);
}

// ===========================================================================
// The provisioning exchange.
// ===========================================================================

/**
 * Drives `machine.ts`'s `beginProvisioning`/`step` to a terminal phase over
 * `session`, writing every PDU the machine produces and feeding back every
 * notification the channel delivers, in order, until the state reaches
 * `'provisioned'`, `'unsupported'` or `'failed'`.
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

export type ConfigExchangeResult = { readonly kind: 'ok'; readonly composition: CompositionData } | { readonly kind: 'failed'; readonly message: string };

/** Sends one device-key-secured Config message and waits for the (possibly
 *  segmented) reply, decoded all the way to an `AccessMessage`. */
async function sendConfigRequest(input: ConfigExchangeInput, accessPayload: Buffer): Promise<AccessMessage> {
  const pdus = encodeMeshMessage({
    accessPayload,
    key: input.deviceKey,
    keyKind: 'device',
    src: input.ourAddress,
    dst: input.nodeAddress,
    netKey: input.netKey,
    ivIndex: input.ivIndex,
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
 * Reads composition data, adds the application key, and binds it to every
 * one of the node's SIG models this design maps to a Homey capability
 * (`LIGHTING_SERVER_MODEL_IDS`) — the design's "adds the application key,
 * reads the composition data and binds the key to the node's models", in
 * that dependency order (binding needs to know WHICH models exist, which
 * composition data is what reveals).
 */
export async function runConfigExchange(input: ConfigExchangeInput): Promise<ConfigExchangeResult> {
  const compositionReply = toConfigStatus(await sendConfigRequest(input, encodeConfigCompositionDataGet(0)));
  if (compositionReply === null || compositionReply.type !== 'compositionData') {
    return { kind: 'failed', message: 'node did not answer Config Composition Data Get with a Composition Data Status message' };
  }
  if (compositionReply.composition === null) {
    // See the module header's COMPOSITION DATA THAT DOES NOT PARSE note —
    // genuinely cannot say more than this without guessing.
    return {
      kind: 'failed',
      message: "the node's composition data could not be parsed (malformed or truncated Composition Data Page 0)",
    };
  }
  const composition = compositionReply.composition;

  const appKeyReply = toConfigStatus(
    await sendConfigRequest(
      input,
      encodeConfigAppKeyAdd({ netKeyIndex: input.netKeyIndex, appKeyIndex: input.appKeyIndex, appKey: input.appKey }),
    ),
  );
  if (appKeyReply === null || appKeyReply.type !== 'appKey') {
    return { kind: 'failed', message: 'node did not answer Config AppKey Add with an AppKey Status message' };
  }
  if (appKeyReply.status !== 0x00) {
    return {
      kind: 'failed',
      message: `Config AppKey Add was refused: ${appKeyReply.statusName ?? `status 0x${appKeyReply.status.toString(16)}`}`,
    };
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
        return {
          kind: 'failed',
          message: `node did not answer Config Model App Bind (element ${elementIndex}, model 0x${modelId.toString(16)}) with a Model App Status message`,
        };
      }
      if (bindReply.status !== 0x00) {
        return {
          kind: 'failed',
          message: `Config Model App Bind was refused for element ${elementIndex}, model 0x${modelId.toString(16)}: ${bindReply.statusName ?? `status 0x${bindReply.status.toString(16)}`}`,
        };
      }
    }
  }

  return { kind: 'ok', composition };
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
}

export type PairingOutcome =
  | { readonly kind: 'paired'; readonly device: PairedDeviceDescriptor }
  | { readonly kind: 'unsupported'; readonly reason: string }
  | { readonly kind: 'failed'; readonly message: string };

async function disconnectQuietly(session: GattSession): Promise<void> {
  try {
    await session.disconnect();
  } catch {
    // A failed disconnect of a session we are already done with is not
    // worth failing the whole pairing attempt over — the peripheral either
    // already dropped the link itself or will time it out on its own.
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
  let provisioningSession: GattSession;
  try {
    provisioningSession = await connectForProvisioning(deps.bluetooth, peripheralId);
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
      configSession = await connectForConfiguration(deps.bluetooth, peripheralId);
    } catch (err) {
      return { kind: 'failed', message: `provisioned "${peripheralId}", but could not reconnect for configuration: ${errorMessage(err)}` };
    }

    try {
      const exchangeResult = await runConfigExchange({
        session: configSession,
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

      if (exchangeResult.kind === 'failed') {
        return { kind: 'failed', message: exchangeResult.message };
      }
      return finishPairing(deps.store, peripheralId, nodeAddress, deviceKey, exchangeResult.composition);
    } catch (err) {
      await disconnectQuietly(configSession);
      return { kind: 'failed', message: `configuring "${peripheralId}" failed: ${errorMessage(err)}` };
    }
  } catch (err) {
    await disconnectQuietly(provisioningSession);
    return { kind: 'failed', message: `pairing "${peripheralId}" failed: ${errorMessage(err)}` };
  }
}

/** The ONE place this module writes a node entry — see the module header's
 *  two notes on why this is also the only place `nextUnicastAddress`
 *  advances past a multi-element node's extra elements. */
function finishPairing(
  store: NetworkStore,
  peripheralId: string,
  nodeAddress: number,
  deviceKey: Buffer,
  composition: CompositionData,
): PairingOutcome {
  const fresh = store.getState();
  store.setState({
    ...fresh,
    nextUnicastAddress: fresh.nextUnicastAddress + (composition.elements.length - 1),
    nodes: [...fresh.nodes, { address: nodeAddress, deviceKey, composition }],
  });

  const assignments = mapCompositionToCapabilities(composition);
  const capabilities: HomeyCapability[] = [];
  for (const assignment of assignments) {
    if (!capabilities.includes(assignment.capability)) capabilities.push(assignment.capability);
  }

  return {
    kind: 'paired',
    device: {
      name: `Mesh light ${nodeAddress}`,
      data: { id: String(nodeAddress) },
      capabilities,
      store: { peripheralId },
    },
  };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
