import { randomBytes } from 'node:crypto';
import {
  MeshLightController,
  CONNECTION_UNAVAILABLE_MESSAGE,
  __testing,
  type DeviceCapabilityPort,
} from '../meshLight';
import { NetworkStore, EMPTY_NETWORK_STATE, type SettingsPort } from '../../../lib/adapter/store';
import { ProxyConnectionManager, SCAN_DURATION_MS } from '../../../lib/adapter/connection';
import { TrafficQueue } from '../../../lib/adapter/queue';
import { FakeBluetoothPort, type AutoResponder } from '../../../lib/adapter/__tests__/fakeBluetooth';
import { createFakeClock, type FakeClock } from '../../../lib/adapter/__tests__/fakeClock';
import {
  encodeMeshMessage,
  acceptIncomingPdu,
  RELAYED_TTL,
  type MeshReceiveContext,
} from '../../../lib/mesh/packet/message';
import { encodeAccessMessage, type AccessMessage } from '../../../lib/mesh/packet/access';
import { decodeNetworkPdu } from '../../../lib/mesh/packet/network';
import { k4 } from '../../../lib/mesh/crypto/derive';
import type { CompositionData } from '../../../lib/mesh/config/composition';
import type { HomeyCapability, NodeProbeResult, TemperatureRange } from '../../../lib/models/capabilities';
import { DEFAULT_TEMPERATURE_RANGE } from '../temperatureRange';

/** Waits a full macrotask turn — same technique, and same reason, as
 *  `fakeClock.ts`'s own private `flushMicrotasks` (queue.test.ts's own
 *  module header explains it in full): the unsolicited handler below is
 *  fire-and-forget from `simulateNotification`'s own perspective (queued as
 *  a `.catch()`ed promise, never awaited by the caller), and its own
 *  `applyStatus` chain is a SEQUENCE of several awaited
 *  `setCapabilityValue` calls — the Light HSL case alone awaits FOUR in a
 *  row. A fixed, small number of bare `await Promise.resolve()` calls is not
 *  reliably enough to drain a chain that long (review finding — the first
 *  version of this file used exactly that, and it was tall enough to hide
 *  a genuine, reachable failure this file's own git history can show): a
 *  `setImmediate` macrotask only fires once Node's entire microtask queue
 *  — however many `await`s deep — has already drained. */
function flushMicrotasks(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

/**
 * Drives the REAL `ProxyConnectionManager` + `TrafficQueue` (over the
 * shared `FakeBluetoothPort`/`FakeClock` fixtures every earlier task's own
 * adapter tests use) and the REAL `NetworkStore` (over a local
 * `FakeSettingsPort`, the same test-local shape `store.test.ts`/
 * `pairing.test.ts` both already use rather than a shared fixture file, per
 * this project's own established convention for that one) — never a
 * hand-rolled mock of either, per the plan's "T5 must not re-declare the
 * port" ruling and its queue.ts/pairing.ts precedent.
 *
 * THE FAKE NODE replies the way a real bulb would: it remembers its own
 * on/off, lightness, colour-temperature and hue/saturation state, applies
 * whatever a Set message asks (unless a test configures it to disagree —
 * `onOffOverrideReply`, modelling a node that refuses or clamps a command)
 * and answers a Get with its CURRENT state. Every reply is a real,
 * encrypted, segmented-if-needed Network PDU built with this module's own
 * `encodeMeshMessage` (`sendAsNode` below) — not a canned buffer compared
 * against itself. There is no "decode a Set" function in `lighting.ts` (this
 * project only ever SENDS Set/Get and DECODES Status — see that module's own
 * design note), so the fake node's own Set handling below hand-parses the
 * known field layout directly, the same way `pairing.test.ts`'s own
 * `installConfigResponder` hand-builds Status replies for messages this
 * project has no encoder for on the SENDING side.
 *
 * OPCODES ARE TRANSCRIBED HERE, NOT IMPORTED — `lighting.ts` keeps them
 * module-private (this project's own convention: `capabilities.ts` exports
 * its model IDs because a second module needs the same identifiers;
 * `lighting.ts`'s opcodes have no such second consumer in production code),
 * so this file names them the same way `pairing.test.ts`'s own
 * `installConfigResponder` names `config/client.ts`'s opcodes: as literal,
 * commented hex values, cross-checked directly against `lighting.ts`'s own
 * source at the point this file was written.
 */

// ===========================================================================
// Fixtures
// ===========================================================================

const OUR_ADDRESS = 0x0001;
const NODE_ADDRESS = 0x0002;
const NODE_PERIPHERAL_ID = 'node-1';

// lighting.ts's own module-private opcodes (see this file's own header).
const OP_ONOFF_GET = 0x8201;
const OP_ONOFF_SET = 0x8202;
const OP_ONOFF_STATUS = 0x8204;
const OP_LIGHTNESS_GET = 0x824b;
const OP_LIGHTNESS_SET = 0x824c;
const OP_LIGHTNESS_STATUS = 0x824e;
const OP_CTL_GET = 0x825d;
const OP_CTL_SET = 0x825e;
const OP_CTL_STATUS = 0x8260;
const OP_CTL_TEMPERATURE_SET = 0x8264;
const OP_CTL_TEMPERATURE_STATUS = 0x8266;
const OP_HSL_GET = 0x826d;
const OP_HSL_SET = 0x8276;
const OP_HSL_STATUS = 0x8278;
// config/client.ts's own opcodes, same transcription precedent as
// pairing.test.ts's installConfigResponder.
const OP_NODE_RESET = 0x8049;
const OP_NODE_RESET_STATUS = 0x804a;
const OP_APPKEY_STATUS = 0x8003; // used only to model a wrong-type reset reply.

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

/** Records every call, in order, so a test can assert not just the FINAL
 *  capability value but the SEQUENCE of updates (optimistic, then settled —
 *  see the module header's note on why value-based discrimination is used
 *  instead of a timing trick). */
class FakeDevicePort implements DeviceCapabilityPort {
  readonly capabilityValues = new Map<string, unknown>();
  readonly setCalls: Array<{ capability: string; value: unknown }> = [];
  readonly availabilityCalls: Array<{ available: boolean; message?: string }> = [];

  constructor(private readonly capabilities: ReadonlySet<string>) {}

  hasCapability(capabilityId: string): boolean {
    return this.capabilities.has(capabilityId);
  }
  getCapabilityValue(capabilityId: string): unknown {
    return this.capabilityValues.get(capabilityId) ?? null;
  }
  async setCapabilityValue(capabilityId: string, value: unknown): Promise<void> {
    this.capabilityValues.set(capabilityId, value);
    this.setCalls.push({ capability: capabilityId, value });
  }
  async setAvailable(): Promise<void> {
    this.availabilityCalls.push({ available: true });
  }
  async setUnavailable(message?: string): Promise<void> {
    this.availabilityCalls.push({ available: false, message });
  }
}

interface FakeNodeState {
  onOff: number;
  lightness: number;
  temperature: number;
  deltaUv: number;
  hue: number;
  saturation: number;
}

/**
 * A node MEASURED to run the composite Light CTL Server and NOT the Light
 * CTL Temperature Server — the one probe result that makes
 * `setLightTemperature` send a `Light CTL Set` (which, unlike the
 * Temperature Set, carries a mandatory Lightness field). Used by the tests
 * that are about that Lightness field rather than about the model choice.
 */
const COMPOSITE_CTL_PROBE: NodeProbeResult = {
  models: { lightCtlTemperature: 'unsupported', lightCtl: 'supported' },
  temperatureRange: null,
};

function defaultNodeState(): FakeNodeState {
  return { onOff: 0, lightness: 0, temperature: DEFAULT_TEMPERATURE_RANGE.minKelvin, deltaUv: 0, hue: 0, saturation: 0 };
}

/** For Lightness/CTL/HSL Status, whose fields (Table 6.53/6.71/6.87) are all
 *  2-octet little-endian. Generic OnOff Status is DIFFERENT — Table 3.39's
 *  Present OnOff is a single octet — so it gets its own, narrower helper
 *  below rather than being forced through this one (an earlier version of
 *  this fixture did exactly that and silently built a 2-octet payload for a
 *  1-octet field, which `decodeGenericOnOffStatus`'s own length check then
 *  rejected outright — caught by the suite hanging until every retry was
 *  exhausted, not by a clean assertion failure, which is itself worth
 *  recording: a fixture bug in the REPLY can look exactly like a timeout in
 *  the code under test). */
function statusPayload(opcode: number, fields: number[]): Buffer {
  const parameters = Buffer.alloc(fields.length * 2);
  fields.forEach((value, i) => parameters.writeUInt16LE(value, i * 2));
  return encodeAccessMessage({ opcode, parameters });
}

function onOffStatusPayload(presentOnOff: number): Buffer {
  return encodeAccessMessage({ opcode: OP_ONOFF_STATUS, parameters: Buffer.from([presentOnOff & 0xff]) });
}

interface LightingResponderOptions {
  readonly ourAddress: number;
  readonly nodeAddress: number;
  readonly netKey: Buffer;
  readonly appKey: Buffer;
  readonly deviceKey: Buffer;
  readonly state: FakeNodeState;
  /** When set, a Generic OnOff Set replies with THIS value instead of what
   *  was commanded — models a node that disagrees with (refuses/clamps) a
   *  command, per the brief's own second required behaviour. */
  readonly onOffOverrideReply?: number;
  /** Opcodes (application-key-secured) this node never answers at all —
   *  models a node that does not respond to one particular request. */
  readonly silentOpcodes?: ReadonlySet<number>;
  /** Config Node Reset gets no reply at all. */
  readonly failReset?: boolean;
  /** Config Node Reset is answered with a DIFFERENT status type (Config
   *  AppKey Status) instead of Node Reset Status — a node that is reachable
   *  but misbehaves, as opposed to one that is merely unreachable. */
  readonly wrongReplyReset?: boolean;
  /** A Generic OnOff Set is answered with a Light Lightness Status instead
   *  of a Generic OnOff Status — models a node whose reply does not match
   *  the model the command was actually for (never reachable by a
   *  disagreeing VALUE alone, since that still answers with the right
   *  message TYPE). */
  readonly onOffSetRepliesWithWrongType?: boolean;
  /** Opcodes this node stays silent on for their FIRST occurrence only —
   *  every later write of the SAME opcode is answered normally. Models a
   *  node that didn't hear the first attempt (so the queue's own bounded
   *  retry fires) without simulating a dropped write at the GATT layer —
   *  used to observe that the retry resends byte-identical bytes. */
  readonly silentOnFirstAttemptForOpcodes?: ReadonlySet<number>;
  /** Called synchronously, inside `write()`, the instant a Config Node
   *  Reset request arrives — BEFORE this responder builds or sends any
   *  reply — so a test can observe exactly what else is true at that
   *  moment (e.g. whether the store entry has been removed yet). */
  readonly onNodeResetReceived?: () => void;
}

function installLightingResponder(bluetooth: FakeBluetoothPort, peripheralId: string, opts: LightingResponderOptions): void {
  let nodeSeq = 0;
  const allocateNodeSeq = (): number => nodeSeq++;
  const opcodeSeenCount = new Map<number, number>();
  /** Returns true the FIRST time it is called for `opcode` when `opcode` is
   *  one of `silentOnFirstAttemptForOpcodes` — see that option's own doc
   *  comment. */
  const shouldStaySilent = (opcode: number): boolean => {
    const seenBefore = opcodeSeenCount.get(opcode) ?? 0;
    opcodeSeenCount.set(opcode, seenBefore + 1);
    return seenBefore === 0 && (opts.silentOnFirstAttemptForOpcodes?.has(opcode) ?? false);
  };
  const sendAsNode = (accessPayload: Buffer, key: Buffer, keyKind: 'application' | 'device'): Buffer[] =>
    encodeMeshMessage({
      accessPayload,
      key,
      keyKind,
      aid: keyKind === 'application' ? k4(opts.appKey) : undefined,
      src: opts.nodeAddress,
      dst: opts.ourAddress,
      netKey: opts.netKey,
      ivIndex: 0,
      // The fake node replies with the same relayed TTL a real one would
      // use for a status crossing the mesh back to us.
      ttl: RELAYED_TTL,
      allocateSeq: allocateNodeSeq,
    });

  const applicationContext: MeshReceiveContext = {
    key: opts.appKey,
    keyKind: 'application',
    netKey: opts.netKey,
    ivIndex: 0,
    expectedSrc: opts.ourAddress,
  };
  const deviceContext: MeshReceiveContext = {
    key: opts.deviceKey,
    keyKind: 'device',
    netKey: opts.netKey,
    ivIndex: 0,
    expectedSrc: opts.ourAddress,
  };

  const responder: AutoResponder = (data) => {
    const appResult = acceptIncomingPdu(undefined, applicationContext, data);
    if (appResult.kind === 'complete') {
      const { opcode, parameters } = appResult.message;
      if (opts.silentOpcodes?.has(opcode)) return undefined;
      // Checked (and counted) for EVERY opcode, including ones with no
      // silence configured at all — shouldStaySilent's own counting must
      // run unconditionally so a LATER write of the same opcode is
      // correctly recognised as "not the first" even when this test never
      // asked for silence on it.
      if (shouldStaySilent(opcode)) return undefined;
      switch (opcode) {
        case OP_ONOFF_GET:
          return sendAsNode(onOffStatusPayload(opts.state.onOff), opts.appKey, 'application');
        case OP_ONOFF_SET: {
          const requested = parameters[0] as number;
          opts.state.onOff = opts.onOffOverrideReply ?? requested;
          if (opts.onOffSetRepliesWithWrongType) {
            return sendAsNode(statusPayload(OP_LIGHTNESS_STATUS, [opts.state.lightness]), opts.appKey, 'application');
          }
          return sendAsNode(onOffStatusPayload(opts.state.onOff), opts.appKey, 'application');
        }
        case OP_LIGHTNESS_GET:
          return sendAsNode(statusPayload(OP_LIGHTNESS_STATUS, [opts.state.lightness]), opts.appKey, 'application');
        case OP_LIGHTNESS_SET: {
          opts.state.lightness = parameters.readUInt16LE(0);
          return sendAsNode(statusPayload(OP_LIGHTNESS_STATUS, [opts.state.lightness]), opts.appKey, 'application');
        }
        case OP_CTL_GET:
          return sendAsNode(statusPayload(OP_CTL_STATUS, [opts.state.lightness, opts.state.temperature]), opts.appKey, 'application');
        case OP_CTL_SET: {
          opts.state.lightness = parameters.readUInt16LE(0);
          opts.state.temperature = parameters.readUInt16LE(2);
          return sendAsNode(statusPayload(OP_CTL_STATUS, [opts.state.lightness, opts.state.temperature]), opts.appKey, 'application');
        }
        case OP_CTL_TEMPERATURE_SET: {
          // Table 6.73: Temperature || Delta UV || TID — NO lightness, which
          // is exactly why this fake leaves `lightness` alone here.
          opts.state.temperature = parameters.readUInt16LE(0);
          opts.state.deltaUv = parameters.readUInt16LE(2);
          return sendAsNode(
            statusPayload(OP_CTL_TEMPERATURE_STATUS, [opts.state.temperature, opts.state.deltaUv]),
            opts.appKey,
            'application',
          );
        }
        case OP_HSL_GET:
          return sendAsNode(
            statusPayload(OP_HSL_STATUS, [opts.state.lightness, opts.state.hue, opts.state.saturation]),
            opts.appKey,
            'application',
          );
        case OP_HSL_SET: {
          opts.state.lightness = parameters.readUInt16LE(0);
          opts.state.hue = parameters.readUInt16LE(2);
          opts.state.saturation = parameters.readUInt16LE(4);
          return sendAsNode(
            statusPayload(OP_HSL_STATUS, [opts.state.lightness, opts.state.hue, opts.state.saturation]),
            opts.appKey,
            'application',
          );
        }
        default:
          return undefined;
      }
    }

    const deviceResult = acceptIncomingPdu(undefined, deviceContext, data);
    if (deviceResult.kind === 'complete' && deviceResult.message.opcode === OP_NODE_RESET) {
      opts.onNodeResetReceived?.();
      if (opts.failReset) return undefined;
      if (opts.wrongReplyReset) {
        return sendAsNode(
          encodeAccessMessage({ opcode: OP_APPKEY_STATUS, parameters: Buffer.from([0x00, 0x00, 0x00, 0x00]) }),
          opts.deviceKey,
          'device',
        );
      }
      return sendAsNode(encodeAccessMessage({ opcode: OP_NODE_RESET_STATUS, parameters: Buffer.alloc(0) }), opts.deviceKey, 'device');
    }
    return undefined;
  };
  bluetooth.setAutoResponder(peripheralId, responder);
}

/** Decodes a PDU as the node itself would decode something WE sent — used
 *  by tests to verify the actual wire content of a command, not merely that
 *  SOME write happened (this project's own repeatedly-paid-for lesson about
 *  fakes that record "what" but not "whether it was right"). */
function decodeOurCommand(pdu: Buffer, netKey: Buffer, appKey: Buffer): AccessMessage | null {
  const context: MeshReceiveContext = { key: appKey, keyKind: 'application', netKey, ivIndex: 0, expectedSrc: OUR_ADDRESS };
  const result = acceptIncomingPdu(undefined, context, pdu);
  return result.kind === 'complete' ? result.message : null;
}

/** Builds one unsolicited notification as the node itself would send it,
 *  bypassing the responder entirely (no command provoked this). */
function buildNodeNotification(netKey: Buffer, appKey: Buffer, accessPayload: Buffer, srcAddress: number = NODE_ADDRESS): Buffer {
  const pdus = encodeMeshMessage({
    accessPayload,
    key: appKey,
    keyKind: 'application',
    aid: k4(appKey),
    src: srcAddress,
    dst: OUR_ADDRESS,
    netKey,
    ivIndex: 0,
    ttl: RELAYED_TTL,
    allocateSeq: () => 777,
  });
  return pdus[0] as Buffer;
}

const ALL_CAPABILITIES: ReadonlySet<HomeyCapability> = new Set([
  'onoff',
  'dim',
  'light_temperature',
  'light_hue',
  'light_saturation',
  'light_mode',
]);

interface Harness {
  bluetooth: FakeBluetoothPort;
  clock: FakeClock;
  manager: ProxyConnectionManager;
  queue: TrafficQueue;
  store: NetworkStore;
  device: FakeDevicePort;
  controller: MeshLightController;
  /** How many commands the CONTROLLER has handed to the shared queue — the
   *  measure the C3 tests below need, and the one `writesReceived` cannot
   *  give: the queue serialises, so a hundred commands enqueued against an
   *  unreachable node still produce only ONE write until the first gives up.
   *  Counting at `send()` is counting what actually piles up. */
  queueSends: () => number;
  netKey: Buffer;
  appKey: Buffer;
  deviceKey: Buffer;
  nodeState: FakeNodeState;
}

function setUp(
  options: {
    capabilities?: ReadonlySet<HomeyCapability>;
    queueOptions?: { timeoutMs?: number; maxAttempts?: number };
    nodeState?: Partial<FakeNodeState>;
    /** What this node was measured to do at pairing time, as the store would
     *  hold it. Omitted = a node paired before the probe existed. */
    probe?: NodeProbeResult;
    /** This device's own resolved colour-temperature range — omitted means
     *  the documented fallback, exactly as a device with no setting and no
     *  reported range gets. */
    temperatureRange?: TemperatureRange;
    responderOptions?: Partial<Omit<LightingResponderOptions, 'ourAddress' | 'nodeAddress' | 'netKey' | 'appKey' | 'deviceKey' | 'state'>>;
  } = {},
): Harness {
  // Deliberately independent, non-palindromic random buffers (this plan's
  // own fixture-value lesson) — netKey/appKey/deviceKey must never be
  // confusable with one another.
  const netKey = randomBytes(16);
  const appKey = randomBytes(16);
  const deviceKey = randomBytes(16);

  const clock = createFakeClock();
  const bluetooth = new FakeBluetoothPort();
  bluetooth.addNode({ id: NODE_PERIPHERAL_ID, rssi: -50, networkKey: netKey });
  const manager = new ProxyConnectionManager(bluetooth, clock, netKey);
  const queue = new TrafficQueue(manager, clock, options.queueOptions);

  const store = new NetworkStore(new FakeSettingsPort());
  const composition: CompositionData = {
    cid: 0,
    pid: 0,
    vid: 0,
    crpl: 0,
    features: { relay: false, proxy: false, friend: false, lowPower: false },
    elements: [],
  };
  store.setState({
    ...EMPTY_NETWORK_STATE,
    netKey,
    netKeyIndex: 0,
    appKey,
    appKeyIndex: 0,
    ivIndex: 0,
    ourUnicastAddress: OUR_ADDRESS,
    nextUnicastAddress: NODE_ADDRESS + 1,
    nodes: [{ address: NODE_ADDRESS, deviceKey, composition, ...(options.probe === undefined ? {} : { probe: options.probe }) }],
  });

  const device = new FakeDevicePort(options.capabilities ?? ALL_CAPABILITIES);
  // The controller talks to the REAL queue through a counting pass-through —
  // nothing is stubbed, only observed (see `Harness.queueSends`).
  let sends = 0;
  const countingQueue = {
    send: (command: Parameters<TrafficQueue['send']>[0]): Promise<Buffer> => {
      sends += 1;
      return queue.send(command);
    },
    onUnsolicited: (listener: (data: Buffer) => void): (() => void) => queue.onUnsolicited(listener),
  };
  const controller = new MeshLightController({
    queue: countingQueue,
    store,
    clock,
    device,
    address: NODE_ADDRESS,
    temperatureRange: options.temperatureRange,
  });

  const nodeState: FakeNodeState = { ...defaultNodeState(), ...options.nodeState };
  installLightingResponder(bluetooth, NODE_PERIPHERAL_ID, {
    ourAddress: OUR_ADDRESS,
    nodeAddress: NODE_ADDRESS,
    netKey,
    appKey,
    deviceKey,
    state: nodeState,
    ...options.responderOptions,
  });

  return {
    bluetooth,
    clock,
    manager,
    queue,
    store,
    device,
    controller,
    queueSends: () => sends,
    netKey,
    appKey,
    deviceKey,
    nodeState,
  };
}

async function connectManager(manager: ProxyConnectionManager, clock: FakeClock): Promise<void> {
  manager.start();
  await clock.advance(SCAN_DURATION_MS);
  expect(manager.getState().status).toBe('connected');
}

// ===========================================================================
// Unit conversions
// ===========================================================================

describe('unit conversions', () => {
  test('fractionToWire/wireToFraction span the full 16-bit domain', () => {
    expect(__testing.fractionToWire(0)).toBe(0x0000);
    expect(__testing.fractionToWire(1)).toBe(0xffff);
    expect(__testing.wireToFraction(0x0000)).toBe(0);
    expect(__testing.wireToFraction(0xffff)).toBe(1);
  });

  test('fractionToWire clamps out-of-range/non-finite input rather than producing an invalid wire value', () => {
    expect(__testing.fractionToWire(-1)).toBe(0x0000);
    expect(__testing.fractionToWire(2)).toBe(0xffff);
    expect(__testing.fractionToWire(Number.NaN)).toBe(0x0000);
  });

  test('homeyToKelvin: 0 is cold (the range maximum), 1 is warm (the range minimum)', () => {
    expect(__testing.homeyToKelvin(0, DEFAULT_TEMPERATURE_RANGE)).toBe(DEFAULT_TEMPERATURE_RANGE.maxKelvin);
    expect(__testing.homeyToKelvin(1, DEFAULT_TEMPERATURE_RANGE)).toBe(DEFAULT_TEMPERATURE_RANGE.minKelvin);
  });

  test('kelvinToHomey inverts homeyToKelvin at the range edges', () => {
    expect(__testing.kelvinToHomey(DEFAULT_TEMPERATURE_RANGE.maxKelvin, DEFAULT_TEMPERATURE_RANGE)).toBe(0);
    expect(__testing.kelvinToHomey(DEFAULT_TEMPERATURE_RANGE.minKelvin, DEFAULT_TEMPERATURE_RANGE)).toBe(1);
  });

  test('kelvinToHomey clamps a value outside this bulb\'s range (but spec-legal) instead of leaving the 0..1 domain', () => {
    expect(__testing.kelvinToHomey(800, DEFAULT_TEMPERATURE_RANGE)).toBe(1); // below the range min (but >= Table 6.6's 800 K floor) -> fully warm
    expect(__testing.kelvinToHomey(20000, DEFAULT_TEMPERATURE_RANGE)).toBe(0); // above the range max (but <= Table 6.6's 20000 K ceiling) -> fully cold
  });

  test('THE RANGE IS THE ARGUMENT, not a constant: the same Homey value maps to a different kelvin on a different bulb', () => {
    // The discriminating case for the whole per-device-range change: a
    // module that still carried its own constants would produce the same
    // number for both of these.
    const narrow: TemperatureRange = { minKelvin: 2700, maxKelvin: 3000 };
    const wide: TemperatureRange = { minKelvin: 2000, maxKelvin: 10000 };
    expect(__testing.homeyToKelvin(0.5, narrow)).toBe(2850);
    expect(__testing.homeyToKelvin(0.5, wide)).toBe(6000);
    // ...and each one's own inverse round-trips within its own range.
    expect(__testing.kelvinToHomey(2850, narrow)).toBeCloseTo(0.5, 6);
    expect(__testing.kelvinToHomey(6000, wide)).toBeCloseTo(0.5, 6);
    // A value fully inside the WIDE range but outside the NARROW one
    // clamps on the narrow bulb — it genuinely cannot produce it.
    expect(__testing.kelvinToHomey(6000, narrow)).toBe(0);
  });
});

// ===========================================================================
// setOnOff — "sends the acknowledged command and updates the capability
// immediately" + "the node's status is what the capability settles on,
// including when it disagrees with what was commanded".
// ===========================================================================

describe('setOnOff', () => {
  test('optimistic update happens immediately, and the node agreeing leaves both updates at the same value', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);

    await h.controller.setOnOff(true);

    const onOffCalls = h.device.setCalls.filter((c) => c.capability === 'onoff');
    // Two distinct updates: the optimistic one and the ack-driven one — not
    // just one call that happens to be right, which a "only ever applies
    // the status, no optimism at all" implementation would also produce.
    expect(onOffCalls).toEqual([
      { capability: 'onoff', value: true },
      { capability: 'onoff', value: true },
    ]);
    expect(h.device.availabilityCalls.at(-1)).toEqual({ available: true });

    // The actual wire bytes, decoded independently — not merely "a write happened".
    expect(h.bluetooth.writesReceived).toHaveLength(1);
    const sent = decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey);
    expect(sent?.opcode).toBe(OP_ONOFF_SET);
    expect(sent?.parameters[0]).toBe(0x01); // On
  });

  test('the node disagreeing with the command settles the capability on the NODE\'s truth, not the command', async () => {
    const h = setUp({ responderOptions: { onOffOverrideReply: 0 } }); // node always reports OFF regardless of what was asked
    await connectManager(h.manager, h.clock);

    await h.controller.setOnOff(true);

    const onOffCalls = h.device.setCalls.filter((c) => c.capability === 'onoff');
    expect(onOffCalls).toEqual([
      { capability: 'onoff', value: true }, // optimistic — the command
      { capability: 'onoff', value: false }, // settled — the node's disagreeing truth
    ]);
    expect(h.device.getCapabilityValue('onoff')).toBe(false);
  });
});

// ===========================================================================
// The transaction identifier — review finding: nothing in the suite ever
// looked at one. A constant TID would make a node's own deduplication
// (Section 3.3.1.2.2 et al. — same SRC/DST/TID within 6 s is treated as a
// retransmission, not applied) silently drop the second of two genuinely
// different commands: "I pressed it twice and the second did nothing",
// undiagnosable from outside. The retry half is the opposite risk: if a
// RETRY ever allocated a NEW TID, the node would see it as a brand new
// command rather than recognise the retransmission, defeating the dedup
// the TID exists for in the other direction.
// ===========================================================================

describe('transaction identifier', () => {
  test('three successive NEW commands each get a DIFFERENT transaction identifier', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);

    // Three, not two — an allocator that advances once and then sticks
    // (0, 1, 1, 1, ...) would still pass a two-command check; it fails a
    // third one exactly where it stops advancing.
    await h.controller.setOnOff(true);
    await h.controller.setOnOff(false);
    await h.controller.setOnOff(true);

    expect(h.bluetooth.writesReceived).toHaveLength(3);
    // Table 3.37: Opcode(2) || OnOff(1) || TID(1) — the TID is parameters[1].
    const tids = h.bluetooth.writesReceived.map((w) => decodeOurCommand(w.data, h.netKey, h.appKey)?.parameters[1]);
    expect(new Set(tids).size).toBe(3);
  });

  test('a RETRY carries the SAME transaction identifier (and still reaches the node)', async () => {
    const h = setUp({
      queueOptions: { timeoutMs: 50, maxAttempts: 2 },
      responderOptions: { silentOnFirstAttemptForOpcodes: new Set([OP_ONOFF_SET]) },
    });
    await connectManager(h.manager, h.clock);

    const promise = h.controller.setOnOff(true);
    // Let setOnOff's own first await (the optimistic setCapabilityValue
    // call) resolve before the queue's write()/timer-arm chain runs — same
    // reasoning as the wrong-type-reply test above.
    await flushMicrotasks();await h.clock.advance(50); // attempt 1 times out (silent); attempt 2 fires and is answered
    await promise;

    expect(h.bluetooth.writesReceived).toHaveLength(2);
    const tids = h.bluetooth.writesReceived.map((w) => decodeOurCommand(w.data, h.netKey, h.appKey)?.parameters[1]);
    expect(tids[0]).toBe(tids[1]);
    expect(tids[0]).not.toBeUndefined();
  });

  /**
   * C4, THE DEFECT THIS TEST EXISTS FOR. Retries used to re-send the EXACT
   * buffer the first attempt sent — a design note argued, correctly, that
   * this made "the transaction identifier stays stable" free. It was silent
   * about the SEQUENCE NUMBER living inside those same bytes. Section 3.9.8
   * "Message replay protection": a message whose IVISeq is "lower than or
   * equal to the last valid IVISeq value" from that element is discarded.
   * So a byte-identical retry could only ever succeed in the one case where
   * the original never reached the node's model at all; in the single most
   * likely case for retrying — the command ARRIVED and the status was lost
   * — every retry was dropped as a replay and the user was told the command
   * failed on a lamp that had changed.
   *
   * Both halves are asserted on the SAME three attempts, because they are
   * in tension: a fix that rebuilt everything would give three different
   * TIDs (defeating the node's own deduplication in the other direction),
   * and the old behaviour gave three identical sequence numbers.
   */
  test('three attempts carry THREE DIFFERENT sequence numbers and ONE transaction identifier', async () => {
    const h = setUp({
      queueOptions: { timeoutMs: 50, maxAttempts: 3 },
      responderOptions: { silentOpcodes: new Set([OP_ONOFF_SET]) }, // never answered, so all three attempts fire
    });
    await connectManager(h.manager, h.clock);

    const promise = h.controller.setOnOff(true);
    const rejection = expect(promise).rejects.toThrow(/no status received after 3 attempts/);
    await flushMicrotasks();
    await h.clock.advance(50);
    await h.clock.advance(50);
    await h.clock.advance(50);
    await rejection;

    expect(h.bluetooth.writesReceived).toHaveLength(3);

    const seqs = h.bluetooth.writesReceived.map(
      (w) => decodeNetworkPdu({ networkKey: h.netKey, ivIndex: 0, pdu: w.data })?.seq,
    );
    expect(seqs.every((s) => typeof s === 'number')).toBe(true);
    expect(new Set(seqs).size).toBe(3); // three DIFFERENT sequence numbers...
    expect(seqs[1]).toBeGreaterThan(seqs[0] as number); // ...strictly increasing, which is what replay protection requires
    expect(seqs[2]).toBeGreaterThan(seqs[1] as number);

    // Table 3.37: Opcode(2) || OnOff(1) || TID(1).
    const tids = h.bluetooth.writesReceived.map((w) => decodeOurCommand(w.data, h.netKey, h.appKey)?.parameters[1]);
    expect(new Set(tids).size).toBe(1); // ...and ONE transaction identifier
    expect(tids[0]).not.toBeUndefined();
  });

  /** The same two properties for the Config Node Reset path, which has no
   *  transaction identifier of its own but is just as replay-protected —
   *  and whose failure (a bulb left bound to a network nobody owns) is the
   *  most expensive one in the app. */
  test('a retried Config Node Reset carries a fresh sequence number each attempt', async () => {
    const h = setUp({ queueOptions: { timeoutMs: 50, maxAttempts: 3 }, responderOptions: { failReset: true } });
    await connectManager(h.manager, h.clock);

    const promise = h.controller.remove();
    const rejection = expect(promise).rejects.toThrow(/failed to reset node/);
    await flushMicrotasks();
    await h.clock.advance(50);
    await h.clock.advance(50);
    await h.clock.advance(50);
    await rejection;

    expect(h.bluetooth.writesReceived).toHaveLength(3);
    const seqs = h.bluetooth.writesReceived.map(
      (w) => decodeNetworkPdu({ networkKey: h.netKey, ivIndex: 0, pdu: w.data })?.seq,
    );
    expect(new Set(seqs).size).toBe(3);
  });
});

// ===========================================================================
// Unsolicited status
// ===========================================================================

describe('unsolicited status', () => {
  test('a status nobody asked for updates the capability, with no command ever sent', async () => {
    const h = setUp();
    h.controller.start();
    await connectManager(h.manager, h.clock);

    const pdu = buildNodeNotification(h.netKey, h.appKey, onOffStatusPayload(1));
    h.bluetooth.simulateNotification(NODE_PERIPHERAL_ID, pdu);
    await flushMicrotasks();
    expect(h.device.getCapabilityValue('onoff')).toBe(true);
    expect(h.bluetooth.writesReceived).toHaveLength(0); // genuinely unsolicited: nothing was sent
    expect(h.device.availabilityCalls.at(-1)).toEqual({ available: true });
  });

  test('an unsolicited Light CTL status refreshes both light_temperature and dim (the bound Lightness state)', async () => {
    const h = setUp();
    h.controller.start();
    await connectManager(h.manager, h.clock);

    const pdu = buildNodeNotification(h.netKey, h.appKey, statusPayload(OP_CTL_STATUS, [32768, 4000]));
    h.bluetooth.simulateNotification(NODE_PERIPHERAL_ID, pdu);
    await flushMicrotasks();expect(h.device.getCapabilityValue('light_temperature')).toBeCloseTo(__testing.kelvinToHomey(4000, DEFAULT_TEMPERATURE_RANGE), 6);
    expect(h.device.getCapabilityValue('dim')).toBeCloseTo(__testing.wireToFraction(32768), 6);
    expect(h.bluetooth.writesReceived).toHaveLength(0);
  });

  test('a status addressed to a DIFFERENT node on the same shared connection is ignored, never applied here', async () => {
    const h = setUp();
    h.controller.start();
    await connectManager(h.manager, h.clock);

    const otherNodeAddress = NODE_ADDRESS + 1;
    const pdu = buildNodeNotification(h.netKey, h.appKey, onOffStatusPayload(1), otherNodeAddress);
    h.bluetooth.simulateNotification(NODE_PERIPHERAL_ID, pdu);
    await flushMicrotasks();expect(h.device.getCapabilityValue('onoff')).toBeNull();
    expect(h.device.availabilityCalls).toEqual([{ available: false, message: CONNECTION_UNAVAILABLE_MESSAGE }]);
  });

  /**
   * REVIEW FINDING (final wave): the expected-source check was pinned for
   * the UNSOLICITED path (the test above) and at the decoder (message.test.
   * ts), but NOT on the path this module's own header calls out as the
   * thing it exists for — "a command's own `isStatus` predicate is
   * therefore the ONLY thing stopping one node's status from being mistaken
   * for another's answer, which matters because every bulb uses the SAME
   * application key". A status from bulb B, perfectly valid and perfectly
   * decryptable with the shared application key, must not resolve bulb A's
   * pending command: that is the whole of how three bulbs share one queue.
   */
  test('a status from a DIFFERENT node never resolves this node\'s pending command', async () => {
    const h = setUp({
      queueOptions: { timeoutMs: 50, maxAttempts: 1 },
      responderOptions: { silentOpcodes: new Set([OP_ONOFF_SET]) }, // our own node says nothing
    });
    h.controller.start();
    await connectManager(h.manager, h.clock);

    const promise = h.controller.setOnOff(true);
    const rejection = expect(promise).rejects.toThrow(/no status received after 1 attempt/);
    await flushMicrotasks();

    // Another bulb on the same mesh, same NetKey, same application key, a
    // genuine Generic OnOff Status — everything matches except the source.
    h.bluetooth.simulateNotification(
      NODE_PERIPHERAL_ID,
      buildNodeNotification(h.netKey, h.appKey, onOffStatusPayload(0), NODE_ADDRESS + 1),
    );
    await flushMicrotasks();

    // Not resolved by it, and not applied to this device's capability either.
    await h.clock.advance(50);
    await rejection;
    expect(h.device.setCalls.filter((c) => c.capability === 'onoff')).toEqual([{ capability: 'onoff', value: true }]);
  });

  test('hearing from the node marks it available again even without a reconnection event', async () => {
    const h = setUp();
    h.controller.start();
    await connectManager(h.manager, h.clock);
    await h.controller.onConnectionStateChange('unavailable');
    expect(h.device.availabilityCalls.at(-1)).toEqual({ available: false, message: CONNECTION_UNAVAILABLE_MESSAGE });

    const pdu = buildNodeNotification(h.netKey, h.appKey, onOffStatusPayload(1));
    h.bluetooth.simulateNotification(NODE_PERIPHERAL_ID, pdu);
    await flushMicrotasks();expect(h.device.availabilityCalls.at(-1)).toEqual({ available: true });
  });

  test('a command\'s own isStatus rejects a WRONG-TYPE reply from the same node; the unsolicited listener catches it instead', async () => {
    const h = setUp({
      queueOptions: { timeoutMs: 50, maxAttempts: 1 },
      responderOptions: { onOffSetRepliesWithWrongType: true },
      nodeState: { lightness: 12345 },
    });
    h.controller.start(); // must be subscribed for the fallthrough-to-unsolicited half of this test
    await connectManager(h.manager, h.clock);

    const promise = h.controller.setOnOff(true);
    // Attach the rejection assertion BEFORE advancing the clock (same
    // pattern as the "failed reset" test below) — attaching it only AFTER
    // the clock advance leaves `promise` briefly unhandled the instant it
    // actually rejects, which Node reports as an unhandled rejection rather
    // than letting this test's own assertion observe it.
    const rejection = expect(promise).rejects.toThrow(/no status received/);
    // setOnOff's own first `await` (the optimistic setCapabilityValue call)
    // must resolve before the queue's write()/timer-arm chain even runs —
    // flush that one microtask turn before advancing virtual time, or the
    // timer this test needs to fire is armed too late to be seen.
    await flushMicrotasks();await h.clock.advance(50);
    await rejection;

    // The wrong-type reply was not silently lost — it fell through to the
    // unsolicited path and updated 'dim', the capability IT actually belongs to.
    expect(h.device.getCapabilityValue('dim')).toBeCloseTo(__testing.wireToFraction(12345), 6);
    // And 'onoff' itself only ever shows the optimistic value — the command
    // never genuinely settled.
    expect(h.device.setCalls.filter((c) => c.capability === 'onoff')).toEqual([{ capability: 'onoff', value: true }]);
  });

  test('a stop()ped controller no longer reacts to unsolicited status', async () => {
    const h = setUp();
    h.controller.start();
    await connectManager(h.manager, h.clock);
    h.controller.stop();

    const pdu = buildNodeNotification(h.netKey, h.appKey, onOffStatusPayload(1));
    h.bluetooth.simulateNotification(NODE_PERIPHERAL_ID, pdu);
    await flushMicrotasks();expect(h.device.getCapabilityValue('onoff')).toBeNull();
  });
});

// ===========================================================================
// setDim / setLightTemperature / setColor — wire correctness, and that
// changing colour/temperature never clobbers the independently-tracked
// brightness.
// ===========================================================================

describe('setDim', () => {
  test('sends a Light Lightness Set and settles on the node\'s reported value', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);

    await h.controller.setDim(0.5);

    const sent = decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey);
    expect(sent?.opcode).toBe(OP_LIGHTNESS_SET);
    expect(sent?.parameters.readUInt16LE(0)).toBe(__testing.fractionToWire(0.5));
    expect(h.device.getCapabilityValue('dim')).toBeCloseTo(0.5, 3);
  });
});

describe('setLightTemperature', () => {
  test('sends a Light CTL TEMPERATURE Set (0x8264) by default — the message the owner\'s own bulb answers', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);
    h.device.capabilityValues.set('dim', 0.25);

    await h.controller.setLightTemperature(0.5);

    const sent = decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey);
    expect(sent?.opcode).toBe(OP_CTL_TEMPERATURE_SET);
    // Table 6.73: Temperature || Delta UV || TID — temperature FIRST, and
    // no Lightness field anywhere, which is the point.
    expect(sent?.parameters.readUInt16LE(0)).toBe(__testing.homeyToKelvin(0.5, DEFAULT_TEMPERATURE_RANGE));
    expect(sent?.parameters).toHaveLength(5);
    expect(h.device.getCapabilityValue('light_temperature')).toBeCloseTo(0.5, 3);
  });

  test('CANNOT disturb brightness: the node\'s own lightness is untouched by a temperature change, and `dim` is left alone', async () => {
    // The practical reason the Temperature model is preferred. A composite
    // Light CTL Set would have had to state SOME brightness.
    const h = setUp({ nodeState: { lightness: 40000 } });
    await connectManager(h.manager, h.clock);
    h.device.capabilityValues.set('dim', 0.25);

    await h.controller.setLightTemperature(0.5);

    expect(h.nodeState.lightness).toBe(40000);
    expect(h.device.getCapabilityValue('dim')).toBeCloseTo(0.25, 6);
  });

  test('settles on the node\'s own Light CTL Temperature Status (0x8266), not on what was commanded', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);

    await h.controller.setLightTemperature(1); // the range minimum

    const reported = h.nodeState.temperature;
    expect(reported).toBe(DEFAULT_TEMPERATURE_RANGE.minKelvin);
    expect(h.device.getCapabilityValue('light_temperature')).toBeCloseTo(
      __testing.kelvinToHomey(reported, DEFAULT_TEMPERATURE_RANGE),
      6,
    );
    // The status also tells Homey which picker is driving the lamp.
    expect(h.device.getCapabilityValue('light_mode')).toBe('temperature');
  });

  test('falls back to the composite Light CTL Set for a node MEASURED to run that one and not the Temperature model', async () => {
    // THE DISCRIMINATING CASE for `chooseTemperatureWriteModel`: the only
    // measurement that moves off the default is a positive 'unsupported'
    // for the Temperature model AND a positive 'supported' for the
    // composite one.
    const h = setUp({
      probe: { models: { lightCtlTemperature: 'unsupported', lightCtl: 'supported' }, temperatureRange: null },
    });
    await connectManager(h.manager, h.clock);
    h.device.capabilityValues.set('dim', 0.25);

    await h.controller.setLightTemperature(0.5);

    const sent = decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey);
    expect(sent?.opcode).toBe(OP_CTL_SET);
    expect(sent?.parameters.readUInt16LE(0)).toBe(__testing.fractionToWire(0.25)); // lightness preserved
    expect(sent?.parameters.readUInt16LE(2)).toBe(__testing.homeyToKelvin(0.5, DEFAULT_TEMPERATURE_RANGE));
  });

  test('on the composite fallback with no prior dim value, defaults to full brightness rather than an arbitrary one', async () => {
    const h = setUp({
      probe: { models: { lightCtlTemperature: 'unsupported', lightCtl: 'supported' }, temperatureRange: null },
    });
    await connectManager(h.manager, h.clock);

    await h.controller.setLightTemperature(0.2);

    const sent = decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey);
    expect(sent?.parameters.readUInt16LE(0)).toBe(0xffff);
  });

  test.each([
    ['nothing measured at all (a node paired before the probe existed)', undefined],
    ['both models measured unknown', { models: {}, temperatureRange: null }],
    ['the Temperature model measured unsupported but the composite one NOT measured supported', { models: { lightCtlTemperature: 'unsupported' as const }, temperatureRange: null }],
    ['both measured supported', { models: { lightCtlTemperature: 'supported' as const, lightCtl: 'supported' as const }, temperatureRange: null }],
  ])('keeps the 0x8264 default when the measurement does not positively contradict it: %s', async (_label, probe) => {
    const h = setUp({ probe });
    await connectManager(h.manager, h.clock);

    await h.controller.setLightTemperature(0.5);

    expect(decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey)?.opcode).toBe(OP_CTL_TEMPERATURE_SET);
  });

  test('uses THIS device\'s own range, not a module constant — the kelvin on the wire follows the range it was given', async () => {
    const narrow: TemperatureRange = { minKelvin: 2700, maxKelvin: 3000 };
    const h = setUp({ temperatureRange: narrow });
    await connectManager(h.manager, h.clock);

    await h.controller.setLightTemperature(0);

    expect(decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey)?.parameters.readUInt16LE(0)).toBe(3000);
  });

  test('setTemperatureRange accepts a usable range and takes effect on the NEXT command; an unusable one is refused and changes nothing', async () => {
    const h = setUp({ temperatureRange: { minKelvin: 2700, maxKelvin: 3000 } });
    await connectManager(h.manager, h.clock);

    expect(h.controller.setTemperatureRange({ minKelvin: 2000, maxKelvin: 6500 })).toBe(true);
    await h.controller.setLightTemperature(0);
    expect(decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey)?.parameters.readUInt16LE(0)).toBe(6500);

    // Inverted, and outside Table 6.6 — both refused, and the accepted
    // range above is still the one in force.
    expect(h.controller.setTemperatureRange({ minKelvin: 6000, maxKelvin: 3000 })).toBe(false);
    expect(h.controller.setTemperatureRange({ minKelvin: 100, maxKelvin: 30000 })).toBe(false);
    await h.controller.setLightTemperature(0);
    expect(decodeOurCommand(h.bluetooth.writesReceived[1]!.data, h.netKey, h.appKey)?.parameters.readUInt16LE(0)).toBe(6500);
  });
});

describe('setColor', () => {
  test('preserves the CURRENT dim value in the HSL Set and sends both hue and saturation together', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);
    h.device.capabilityValues.set('dim', 0.75);

    await h.controller.setColor(0.3, 0.6);

    const sent = decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey);
    expect(sent?.opcode).toBe(OP_HSL_SET);
    expect(sent?.parameters.readUInt16LE(0)).toBe(__testing.fractionToWire(0.75)); // lightness preserved
    expect(sent?.parameters.readUInt16LE(2)).toBe(__testing.fractionToWire(0.3)); // hue
    expect(sent?.parameters.readUInt16LE(4)).toBe(__testing.fractionToWire(0.6)); // saturation
    expect(h.device.getCapabilityValue('light_hue')).toBeCloseTo(0.3, 3);
    expect(h.device.getCapabilityValue('light_saturation')).toBeCloseTo(0.6, 3);
  });
});

// ===========================================================================
// Availability — the design's own two quoted clauses.
// ===========================================================================

describe('availability', () => {
  test('connection lost marks the device unavailable rather than leaving stale values on display', async () => {
    const h = setUp();
    h.controller.start();

    await h.controller.onConnectionStateChange('unavailable');

    expect(h.device.availabilityCalls.at(-1)).toEqual({ available: false, message: CONNECTION_UNAVAILABLE_MESSAGE });
  });

  test('reconnection re-reads every present capability and only THEN marks the device available', async () => {
    const h = setUp({ nodeState: { onOff: 1, lightness: 40000, temperature: 4000, hue: 11000, saturation: 22000 } });
    await connectManager(h.manager, h.clock);

    await h.controller.onConnectionStateChange('connected');

    const opcodesSent = h.bluetooth.writesReceived.map((w) => decodeOurCommand(w.data, h.netKey, h.appKey)?.opcode);
    expect(new Set(opcodesSent)).toEqual(new Set([OP_ONOFF_GET, OP_LIGHTNESS_GET, OP_CTL_GET, OP_HSL_GET]));

    expect(h.device.getCapabilityValue('onoff')).toBe(true);
    expect(h.device.getCapabilityValue('dim')).toBeCloseTo(__testing.wireToFraction(40000), 6);
    expect(h.device.getCapabilityValue('light_temperature')).toBeCloseTo(__testing.kelvinToHomey(4000, DEFAULT_TEMPERATURE_RANGE), 6);
    expect(h.device.getCapabilityValue('light_hue')).toBeCloseTo(__testing.wireToFraction(11000), 6);
    expect(h.device.getCapabilityValue('light_saturation')).toBeCloseTo(__testing.wireToFraction(22000), 6);
    expect(h.device.availabilityCalls.at(-1)).toEqual({ available: true });
  });

  test('a node that never answers while reconnecting stays unavailable rather than being assumed reachable', async () => {
    const h = setUp({
      capabilities: new Set(['onoff']),
      queueOptions: { timeoutMs: 50, maxAttempts: 1 },
      responderOptions: { silentOpcodes: new Set([OP_ONOFF_GET]) },
    });
    await connectManager(h.manager, h.clock);

    const promise = h.controller.onConnectionStateChange('connected');
    await h.clock.advance(50);
    await promise;

    expect(h.device.availabilityCalls.at(-1)?.available).toBe(false);
    // Never once claimed available during this failed reconnection attempt.
    expect(h.device.availabilityCalls.some((c) => c.available)).toBe(false);
  });

  // Review finding: having introduced PER-NODE unavailability (the design's
  // own availability clause is connection-level), this module owes that a
  // retry. app.ts now calls onConnectionStateChange('connected') on EVERY
  // poll tick rather than only when the SHARED status changes (see its own
  // module header) precisely so a node whose own re-read failed once gets
  // tried again — this test pins the controller-side half of that fix: a
  // repeated 'connected' call, with the shared status never having dipped
  // to 'unavailable' in between, must still attempt a fresh re-read rather
  // than treating the earlier failure as final.
  test('a failed re-read is retried on the NEXT onConnectionStateChange("connected") call, not treated as final', async () => {
    const h = setUp({
      capabilities: new Set(['onoff']),
      queueOptions: { timeoutMs: 50, maxAttempts: 1 },
      // Silent only for the Get's FIRST occurrence — the second is answered.
      responderOptions: { silentOnFirstAttemptForOpcodes: new Set([OP_ONOFF_GET]) },
    });
    await connectManager(h.manager, h.clock);

    const firstAttempt = h.controller.onConnectionStateChange('connected');
    await h.clock.advance(50);
    await firstAttempt;
    expect(h.device.availabilityCalls.at(-1)?.available).toBe(false);

    // queue.ts's own documented, deliberate "late status" guard: once an
    // attempt is abandoned, its predicate is kept for EXACTLY the next
    // inbound notification, so a stray late reply of the SAME shape is not
    // mistaken for the answer to whatever is active now. Retrying the exact
    // same Get immediately would otherwise have ITS OWN legitimate reply
    // caught by that one-shot guard (it still matches "is this an OnOff
    // status", which is all the abandoned predicate checks) — a genuine
    // interaction this test must account for, not a bug in this module.
    // One harmless, unrelated notification consumes that one-shot guard
    // first (matching nothing active, since nothing is active right now).
    h.bluetooth.simulateNotification(
      NODE_PERIPHERAL_ID,
      buildNodeNotification(h.netKey, h.appKey, statusPayload(OP_LIGHTNESS_STATUS, [0])),
    );
    await flushMicrotasks();

    // SAME status, called again — nothing told this controller the shared
    // connection ever went down and came back; it still must not assume.
    // RATE LIMITED since the final fix wave (C3): the retry is real, but it
    // waits out the backoff first. The tick that arrives before the backoff
    // has elapsed does nothing at all — that is the whole point — so this
    // test now proves BOTH halves at once: suppressed while throttled, and
    // genuinely retried once the throttle is up.
    await h.controller.onConnectionStateChange('connected');
    expect(h.bluetooth.writesReceived).toHaveLength(1); // still throttled: no new Get

    await h.clock.advance(__testing.RE_READ_BACKOFF_BASE_MS);
    await h.controller.onConnectionStateChange('connected');

    expect(h.bluetooth.writesReceived).toHaveLength(2); // the retry's own Get, not skipped
    expect(h.device.availabilityCalls.at(-1)).toEqual({ available: true });
  });

  test('calling onConnectionStateChange("connected") twice in a row only re-reads once', async () => {
    const h = setUp({ capabilities: new Set(['onoff']) });
    await connectManager(h.manager, h.clock);

    await h.controller.onConnectionStateChange('connected');
    await h.controller.onConnectionStateChange('connected');

    expect(h.bluetooth.writesReceived).toHaveLength(1);
  });
});

// ===========================================================================
// C3 — ONE UNREACHABLE BULB MUST NOT SATURATE THE SHARED QUEUE.
//
// The defect, as a reviewer measured it: app.ts fans
// `onConnectionStateChange('connected')` out to every controller on every
// poll tick (deliberately, to close an earlier finding), and a controller
// whose node is silent never records that it is connected — so every tick
// started another full state re-read, each enqueuing Gets that take the full
// retry budget to fail, on the one queue every device shares. Two hundred
// ticks produced two hundred re-reads started, sixteen settled, and a
// backlog of one hundred and eighty-four growing linearly.
//
// These tests MEASURE, as the reviewer did, rather than assert that
// something eventually happened: they drive a fixed number of ticks against
// a silent node and count how many re-reads were actually STARTED.
// ===========================================================================

describe('a silent node is retried, but rate-limited', () => {
  /** Drives `ticks` poll ticks exactly as app.ts does — one call per
   *  controller per tick, never awaited by the caller — advancing virtual
   *  time by `pollMs` between them. Returns how many Gets actually reached
   *  the radio, which is the measure that matters: each one is a queue
   *  entry competing with every other device's traffic. */
  async function pollFor(
    h: Harness,
    ticks: number,
    pollMs: number,
  ): Promise<{ reReadsStarted: number; writes: number }> {
    for (let i = 0; i < ticks; i += 1) {
      void h.controller.onConnectionStateChange('connected').catch(() => undefined);
      await flushMicrotasks();
      await h.clock.advance(pollMs);
    }
    await flushMicrotasks();
    // `queueSends` is the measure that matters, NOT `writesReceived`: the
    // queue serialises, so a hundred Gets enqueued against a silent node
    // still produce only one WRITE until the first gives up. What grew in
    // the reviewer's measurement was the backlog, and the backlog is fed by
    // `send()`.
    return { reReadsStarted: h.queueSends(), writes: h.bluetooth.writesReceived.length };
  }

  test('two hundred poll ticks against a node that never answers start a BOUNDED number of re-reads, not two hundred', async () => {
    const h = setUp({
      capabilities: new Set(['onoff']), // one Get per re-read, so writes == re-reads started
      queueOptions: { timeoutMs: 1000, maxAttempts: 1 },
      responderOptions: { silentOpcodes: new Set([OP_ONOFF_GET]) }, // the node is simply gone
    });
    await connectManager(h.manager, h.clock);

    // 200 ticks at the app's own poll interval (2 s) = 400 s of virtual
    // time. Before this fix that produced ~200 re-reads started and a
    // backlog that grew with every one of them.
    const { reReadsStarted, writes } = await pollFor(h, 200, 2000);

    // MEASURED: the in-flight flag alone caps this at one re-read per
    // completed attempt; the backoff then spaces those out. Over 400 s,
    // with a 30 s base doubling to a 300 s cap, that is a handful — the
    // exact number is asserted so a weakened guard shows up as a number
    // going UP rather than as a vague "not too many".
    expect(reReadsStarted).toBe(4);
    expect(writes).toBe(4); // one Get per re-read, none of them queued behind another
    // Nothing accumulated: every re-read that started also finished before
    // the next one began, so the shared queue is EMPTY and a user command on
    // another bulb reaches the radio on the very next microtask rather than
    // queuing behind a pile. Measured the same way — by counting writes.
    const userCommand = h.queue.send({
      build: () => Buffer.from([0x00]),
      description: 'a user command',
      isStatus: () => false,
    });
    const rejection = expect(userCommand).rejects.toThrow('a user command: no status received after 1 attempt');
    await flushMicrotasks();
    expect(h.bluetooth.writesReceived).toHaveLength(writes + 1); // went out at once, behind nothing
    await h.clock.advance(1000);
    await rejection;
  });

  test('a re-read still running swallows every tick that arrives while it runs (the in-flight flag alone)', async () => {
    const h = setUp({
      capabilities: new Set(['onoff']),
      queueOptions: { timeoutMs: 10_000, maxAttempts: 1 }, // one slow attempt
      responderOptions: { silentOpcodes: new Set([OP_ONOFF_GET]) },
    });
    await connectManager(h.manager, h.clock);

    // Five ticks inside the first attempt's own 10 s window. Counted at
    // `send()`, because the queue would have hidden four extra enqueued Gets
    // behind the one in flight — which is exactly how this defect stayed
    // invisible in the first place.
    const { reReadsStarted, writes } = await pollFor(h, 5, 1000);
    expect(reReadsStarted).toBe(1); // one re-read started, four ticks ignored
    expect(writes).toBe(1);
  });

  test('the backoff grows and is capped, and is cleared by hearing from the node', async () => {
    expect(__testing.reReadBackoffMs(0)).toBe(0);
    expect(__testing.reReadBackoffMs(1)).toBe(__testing.RE_READ_BACKOFF_BASE_MS);
    expect(__testing.reReadBackoffMs(2)).toBe(__testing.RE_READ_BACKOFF_BASE_MS * 2);
    expect(__testing.reReadBackoffMs(3)).toBe(__testing.RE_READ_BACKOFF_BASE_MS * 4);
    expect(__testing.reReadBackoffMs(__testing.MAX_RE_READ_FAILURE_STREAK)).toBe(__testing.RE_READ_BACKOFF_MAX_MS);
    expect(__testing.RE_READ_BACKOFF_BASE_MS).toBe(30_000);
    expect(__testing.RE_READ_BACKOFF_MAX_MS).toBe(300_000);
  });

  test('an unsolicited status clears the backoff, so a bulb that comes back is not throttled for minutes', async () => {
    const h = setUp({
      capabilities: new Set(['onoff']),
      queueOptions: { timeoutMs: 50, maxAttempts: 1 },
      responderOptions: { silentOnFirstAttemptForOpcodes: new Set([OP_ONOFF_GET]) },
    });
    h.controller.start();
    await connectManager(h.manager, h.clock);

    const failing = h.controller.onConnectionStateChange('connected');
    await h.clock.advance(50);
    await failing;
    expect(h.bluetooth.writesReceived).toHaveLength(1);

    // Throttled: a tick right now does nothing.
    await h.controller.onConnectionStateChange('connected');
    expect(h.bluetooth.writesReceived).toHaveLength(1);

    // The node speaks for itself. It consumes the queue's own one-shot
    // late-status guard on the way (same documented interaction as the
    // retry test above), so a second notification is what actually lands.
    for (let i = 0; i < 2; i += 1) {
      h.bluetooth.simulateNotification(NODE_PERIPHERAL_ID, buildNodeNotification(h.netKey, h.appKey, onOffStatusPayload(1)));
      await flushMicrotasks();
    }
    expect(h.device.availabilityCalls.at(-1)).toEqual({ available: true });

    // ...and the next tick is free to re-read immediately, with no wait.
    await h.controller.onConnectionStateChange('unavailable');
    await h.controller.onConnectionStateChange('connected');
    expect(h.bluetooth.writesReceived).toHaveLength(2);
  });

  test('a disconnect clears the backoff too — a link that went and came back is new information', async () => {
    const h = setUp({
      capabilities: new Set(['onoff']),
      queueOptions: { timeoutMs: 50, maxAttempts: 1 },
      responderOptions: { silentOnFirstAttemptForOpcodes: new Set([OP_ONOFF_GET]) },
    });
    await connectManager(h.manager, h.clock);

    const failing = h.controller.onConnectionStateChange('connected');
    await h.clock.advance(50);
    await failing;
    expect(h.bluetooth.writesReceived).toHaveLength(1);

    await h.controller.onConnectionStateChange('unavailable');
    // Not awaited: this retry's own reply is eaten by the queue's documented
    // one-shot late-status guard (see the retry test above), so awaiting it
    // would wait out the attempt timeout for no reason. What this test is
    // about is WHETHER the Get went out at all, and when.
    const retry = h.controller.onConnectionStateChange('connected').catch(() => undefined);
    await flushMicrotasks();

    expect(h.bluetooth.writesReceived).toHaveLength(2); // retried at once, not after 30 s
    await h.clock.advance(50);
    await retry;
  });
});

// ===========================================================================
// The brightness a colour/temperature command has to state — review finding
// (final wave): unpinned, and user-visible when there is nothing to read.
// ===========================================================================

describe('the dim fraction a Light CTL / Light HSL Set carries', () => {
  test('the no-value and no-capability fallbacks are both full brightness, deliberately', () => {
    expect(__testing.currentDimFractionFallback('no-capability')).toBe(1);
    expect(__testing.currentDimFractionFallback('no-value')).toBe(1);
  });

  test('a device whose dim is already known carries THAT brightness, not the fallback', async () => {
    // Driven through the COMPOSITE Light CTL Set, because that is the
    // message with a Lightness field at all — the default Light CTL
    // Temperature Set has none, which is exactly why it cannot get this
    // wrong (see `setLightTemperature`'s own tests above).
    const h = setUp({ probe: COMPOSITE_CTL_PROBE });
    await connectManager(h.manager, h.clock);
    await h.device.setCapabilityValue('dim', 0.25);

    await h.controller.setLightTemperature(0.5);

    const sent = decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey);
    expect(sent?.opcode).toBe(OP_CTL_SET);
    // Table 6.71: CTL Lightness is the first 2-octet little-endian field.
    expect(sent?.parameters.readUInt16LE(0)).toBe(__testing.fractionToWire(0.25));
  });

  test('a device whose dim has no value yet carries full brightness — the decision, pinned', async () => {
    const h = setUp({ probe: COMPOSITE_CTL_PROBE });
    await connectManager(h.manager, h.clock);
    expect(h.device.getCapabilityValue('dim')).toBeNull(); // nothing has populated it

    await h.controller.setLightTemperature(0.5);

    const sent = decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey);
    expect(sent?.parameters.readUInt16LE(0)).toBe(0xffff);
  });

  test('a device with no dim capability at all also carries full brightness', async () => {
    const h = setUp({ capabilities: new Set(['light_hue', 'light_saturation']) });
    await connectManager(h.manager, h.clock);

    await h.controller.setColor(0.5, 0.5);

    const sent = decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey);
    expect(sent?.opcode).toBe(OP_HSL_SET);
    // Table 6.87: HSL Lightness is the first 2-octet little-endian field.
    expect(sent?.parameters.readUInt16LE(0)).toBe(0xffff);
  });
});

// ===========================================================================
// Removal — the design's own second quoted clause.
// ===========================================================================

describe('remove', () => {
  test('sends a Config Node Reset BEFORE removing the node from the store', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);
    let nodeStillInStoreWhenResetArrived: boolean | null = null;
    installLightingResponder(h.bluetooth, NODE_PERIPHERAL_ID, {
      ourAddress: OUR_ADDRESS,
      nodeAddress: NODE_ADDRESS,
      netKey: h.netKey,
      appKey: h.appKey,
      deviceKey: h.deviceKey,
      state: h.nodeState,
      onNodeResetReceived: () => {
        nodeStillInStoreWhenResetArrived = h.store.getState().nodes.some((n) => n.address === NODE_ADDRESS);
      },
    });

    await h.controller.remove();

    expect(nodeStillInStoreWhenResetArrived).toBe(true);
    expect(h.store.getState().nodes.some((n) => n.address === NODE_ADDRESS)).toBe(false);
  });

  test('a failed reset is reported (the promise rejects), not swallowed — yet the store entry is still removed', async () => {
    const h = setUp({ queueOptions: { timeoutMs: 50, maxAttempts: 1 }, responderOptions: { failReset: true } });
    await connectManager(h.manager, h.clock);

    const promise = h.controller.remove();
    const rejection = expect(promise).rejects.toThrow(/failed to reset node/);
    await h.clock.advance(50);
    await rejection;

    expect(h.store.getState().nodes.some((n) => n.address === NODE_ADDRESS)).toBe(false);
  });

  test('a node answering Config Node Reset with the WRONG status type is treated as a failure, not a false success', async () => {
    const h = setUp({ responderOptions: { wrongReplyReset: true } });
    await connectManager(h.manager, h.clock);

    await expect(h.controller.remove()).rejects.toThrow(/did not answer Config Node Reset with a Node Reset Status/);
    expect(h.store.getState().nodes.some((n) => n.address === NODE_ADDRESS)).toBe(false);
  });

  test('removing a node with no store entry at all is a harmless no-op (nothing to reset)', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);
    h.store.setState({ ...h.store.getState(), nodes: [] });

    await expect(h.controller.remove()).resolves.toBeUndefined();
    expect(h.bluetooth.writesReceived).toHaveLength(0);
  });
});

// ===========================================================================
// Time to live — REVIEW FINDING (final wave). Every lighting command and
// every node reset went out at TTL 0, inherited silently from an encoder
// default that was correct only for the point-to-point pairing session.
// Table 3.12 "TTL field values" defines 0 as "Network PDU has not been
// relayed and will not be relayed", so a command for any bulb except the one
// currently holding the single shared GATT connection was never forwarded by
// anything — and the reviewer confirmed by execution that EVERY PDU in a
// full end-to-end run carried it.
//
// These assert the LITERAL value on the wire, on both paths, decoded out of
// the real Network PDU. The constant is deliberately not referenced: an
// assertion against `RELAYED_TTL` would pass for any value that constant
// happened to hold, which is precisely the tautology that let this through.
// ===========================================================================

describe('time to live', () => {
  /** The TTL field of one written Network PDU, decoded rather than
   *  recomputed — the fake has already stripped the Proxy PDU envelope. */
  function ttlOf(write: { data: Buffer }, netKey: Buffer): number | undefined {
    return decodeNetworkPdu({ networkKey: netKey, ivIndex: 0, pdu: write.data })?.ttl;
  }

  test('an application-key lighting command goes out at TTL 127, not 0', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);

    await h.controller.setOnOff(true);

    expect(h.bluetooth.writesReceived).toHaveLength(1);
    expect(ttlOf(h.bluetooth.writesReceived[0]!, h.netKey)).toBe(127);
  });

  test('every command shape — Set and Get, all four models — goes out at TTL 127', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);

    // The four Gets first: `onConnectionStateChange('connected')` is a no-op
    // once anything has already proved the node reachable, and every Set
    // below does exactly that by applying its own status.
    await h.controller.onConnectionStateChange('connected'); // four Gets
    await h.controller.setOnOff(true);
    await h.controller.setDim(0.5);
    await h.controller.setLightTemperature(0.25);
    await h.controller.setColor(0.3, 0.7);

    expect(h.bluetooth.writesReceived).toHaveLength(8);
    const ttls = h.bluetooth.writesReceived.map((w) => ttlOf(w, h.netKey));
    expect(new Set(ttls)).toEqual(new Set([127]));
  });

  test('a Config Node Reset goes out at TTL 127 too — the most expensive one to get wrong', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);

    await h.controller.remove();

    expect(h.bluetooth.writesReceived).toHaveLength(1);
    expect(ttlOf(h.bluetooth.writesReceived[0]!, h.netKey)).toBe(127);
  });
});

// ===========================================================================
// start()/stop()
// ===========================================================================

describe('start/stop', () => {
  test('start() marks the device unavailable immediately, before any connection signal arrives', () => {
    const h = setUp();
    h.controller.start();
    expect(h.device.availabilityCalls).toEqual([{ available: false, message: CONNECTION_UNAVAILABLE_MESSAGE }]);
  });

  test('stop() is safe to call without a prior start(), and safe to call twice', () => {
    const h = setUp();
    expect(() => h.controller.stop()).not.toThrow();
    h.controller.start();
    expect(() => {
      h.controller.stop();
      h.controller.stop();
    }).not.toThrow();
  });
});

// ===========================================================================
// Review finding: a lost-then-restored connection. Nothing previously drove
// connected -> unavailable -> connected TWICE, so an implementation that
// left its own "connected" flag set across the unavailable transition (the
// flag only ever meant to be read, not also written there) would still have
// passed the entire suite — the second "connected" call would then see
// itself as already connected and skip the re-read silently.
// ===========================================================================

describe('a lost-then-restored connection', () => {
  test('the SECOND reconnection re-reads again, not just the first', async () => {
    const h = setUp({ capabilities: new Set(['onoff']) });
    await connectManager(h.manager, h.clock);

    await h.controller.onConnectionStateChange('connected');
    expect(h.bluetooth.writesReceived).toHaveLength(1); // first re-read
    expect(h.device.availabilityCalls.at(-1)).toEqual({ available: true });

    await h.controller.onConnectionStateChange('unavailable');
    expect(h.device.availabilityCalls.at(-1)).toEqual({ available: false, message: CONNECTION_UNAVAILABLE_MESSAGE });

    await h.controller.onConnectionStateChange('connected'); // restored
    expect(h.bluetooth.writesReceived).toHaveLength(2); // re-read AGAIN — not skipped as "already connected"
    expect(h.device.availabilityCalls.at(-1)).toEqual({ available: true });
  });
});

// ===========================================================================
// Review finding: light_mode is never initialised and never follows an
// incoming status, so a colour change made by some other means left Homey
// showing the wrong picker — one of the design's own hardware acceptance
// items. CTL_MODEL/HSL_MODEL's own applyStatus now set it; these tests pin
// that directly (device.ts's own user-driven listener is untestable here —
// it is wired in the untested file, see its own module header).
// ===========================================================================

describe('light_mode follows incoming status', () => {
  test('a Light CTL status sets light_mode to "temperature"', async () => {
    const h = setUp();
    h.controller.start();
    await connectManager(h.manager, h.clock);

    const pdu = buildNodeNotification(h.netKey, h.appKey, statusPayload(OP_CTL_STATUS, [32768, 4000]));
    h.bluetooth.simulateNotification(NODE_PERIPHERAL_ID, pdu);
    await flushMicrotasks();expect(h.device.getCapabilityValue('light_mode')).toBe('temperature');
  });

  test('a Light HSL status sets light_mode to "color"', async () => {
    const h = setUp();
    h.controller.start();
    await connectManager(h.manager, h.clock);

    const pdu = buildNodeNotification(h.netKey, h.appKey, statusPayload(OP_HSL_STATUS, [1000, 2000, 3000]));
    h.bluetooth.simulateNotification(NODE_PERIPHERAL_ID, pdu);
    await flushMicrotasks();expect(h.device.getCapabilityValue('light_mode')).toBe('color');
  });

  test('a device without the light_mode capability is never written to', async () => {
    const h = setUp({ capabilities: new Set(['light_temperature', 'dim']) }); // no light_mode
    h.controller.start();
    await connectManager(h.manager, h.clock);

    const pdu = buildNodeNotification(h.netKey, h.appKey, statusPayload(OP_CTL_STATUS, [32768, 4000]));
    h.bluetooth.simulateNotification(NODE_PERIPHERAL_ID, pdu);
    await flushMicrotasks();expect(h.device.setCalls.some((c) => c.capability === 'light_mode')).toBe(false);
  });
});

// ===========================================================================
// Review finding: every STATUS application checks hasCapability before
// writing, but the OPTIMISTIC write a command makes up front did not — an
// inconsistency between two call sites writing the same capabilities.
// Exercised directly (not reachable through this project's own device.ts
// wiring, which never calls a set* method for a capability it did not
// register) so the guard itself is pinned, not merely assumed consistent.
// ===========================================================================

describe('optimistic writes respect capability presence', () => {
  test('setOnOff writes nothing at all when the device has no onoff capability', async () => {
    const h = setUp({ capabilities: new Set() });
    await connectManager(h.manager, h.clock);
    await h.controller.setOnOff(true);
    expect(h.device.setCalls.filter((c) => c.capability === 'onoff')).toEqual([]);
  });

  test('setDim writes nothing at all when the device has no dim capability', async () => {
    const h = setUp({ capabilities: new Set() });
    await connectManager(h.manager, h.clock);
    await h.controller.setDim(0.5);
    expect(h.device.setCalls.filter((c) => c.capability === 'dim')).toEqual([]);
  });

  test('setLightTemperature writes nothing at all when the device has no light_temperature capability', async () => {
    const h = setUp({ capabilities: new Set() });
    await connectManager(h.manager, h.clock);
    await h.controller.setLightTemperature(0.5);
    expect(h.device.setCalls.filter((c) => c.capability === 'light_temperature')).toEqual([]);
  });

  test('setColor writes nothing at all when the device has no hue/saturation capabilities', async () => {
    const h = setUp({ capabilities: new Set() });
    await connectManager(h.manager, h.clock);
    await h.controller.setColor(0.3, 0.6);
    expect(h.device.setCalls.filter((c) => c.capability === 'light_hue' || c.capability === 'light_saturation')).toEqual([]);
  });
});
