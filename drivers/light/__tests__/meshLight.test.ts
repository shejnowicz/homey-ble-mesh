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
import { encodeMeshMessage, acceptIncomingPdu, type MeshReceiveContext } from '../../../lib/mesh/packet/message';
import { encodeAccessMessage, type AccessMessage } from '../../../lib/mesh/packet/access';
import { k4 } from '../../../lib/mesh/crypto/derive';
import type { CompositionData } from '../../../lib/mesh/config/composition';
import type { HomeyCapability } from '../../../lib/models/capabilities';

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
  hue: number;
  saturation: number;
}

function defaultNodeState(): FakeNodeState {
  return { onOff: 0, lightness: 0, temperature: __testing.MIN_PRACTICAL_KELVIN, hue: 0, saturation: 0 };
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
  /** Called synchronously, inside `write()`, the instant a Config Node
   *  Reset request arrives — BEFORE this responder builds or sends any
   *  reply — so a test can observe exactly what else is true at that
   *  moment (e.g. whether the store entry has been removed yet). */
  readonly onNodeResetReceived?: () => void;
}

function installLightingResponder(bluetooth: FakeBluetoothPort, peripheralId: string, opts: LightingResponderOptions): void {
  let nodeSeq = 0;
  const allocateNodeSeq = (): number => nodeSeq++;
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
    nodes: [{ address: NODE_ADDRESS, deviceKey, composition }],
  });

  const device = new FakeDevicePort(options.capabilities ?? ALL_CAPABILITIES);
  const controller = new MeshLightController({ queue, store, device, address: NODE_ADDRESS });

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

  return { bluetooth, clock, manager, queue, store, device, controller, netKey, appKey, deviceKey, nodeState };
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

  test('homeyToKelvin: 0 is cold (the practical maximum), 1 is warm (the practical minimum)', () => {
    expect(__testing.homeyToKelvin(0)).toBe(__testing.MAX_PRACTICAL_KELVIN);
    expect(__testing.homeyToKelvin(1)).toBe(__testing.MIN_PRACTICAL_KELVIN);
  });

  test('kelvinToHomey inverts homeyToKelvin at the practical range edges', () => {
    expect(__testing.kelvinToHomey(__testing.MAX_PRACTICAL_KELVIN)).toBe(0);
    expect(__testing.kelvinToHomey(__testing.MIN_PRACTICAL_KELVIN)).toBe(1);
  });

  test('kelvinToHomey clamps a value outside the practical (but spec-legal) range instead of leaving the 0..1 domain', () => {
    expect(__testing.kelvinToHomey(800)).toBe(1); // below practical min (but >= Table 6.6's 800 K floor) -> fully warm
    expect(__testing.kelvinToHomey(20000)).toBe(0); // above practical max (but <= Table 6.6's 20000 K ceiling) -> fully cold
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
// Unsolicited status
// ===========================================================================

describe('unsolicited status', () => {
  test('a status nobody asked for updates the capability, with no command ever sent', async () => {
    const h = setUp();
    h.controller.start();
    await connectManager(h.manager, h.clock);

    const pdu = buildNodeNotification(h.netKey, h.appKey, onOffStatusPayload(1));
    h.bluetooth.simulateNotification(NODE_PERIPHERAL_ID, pdu);
    await Promise.resolve();
    await Promise.resolve(); // let the fire-and-forget handler's internal awaits settle

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
    await Promise.resolve();
    await Promise.resolve();

    expect(h.device.getCapabilityValue('light_temperature')).toBeCloseTo(__testing.kelvinToHomey(4000), 6);
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
    await Promise.resolve();
    await Promise.resolve();

    // This controller owns NODE_ADDRESS, not otherNodeAddress — a message
    // from a different node must never be mistaken for one of its own,
    // even though both travel over the SAME shared connection/queue.
    expect(h.device.getCapabilityValue('onoff')).toBeNull();
    expect(h.device.availabilityCalls).toEqual([{ available: false, message: CONNECTION_UNAVAILABLE_MESSAGE }]);
  });

  test('hearing from the node marks it available again even without a reconnection event', async () => {
    const h = setUp();
    h.controller.start();
    await connectManager(h.manager, h.clock);
    await h.controller.onConnectionStateChange('unavailable');
    expect(h.device.availabilityCalls.at(-1)).toEqual({ available: false, message: CONNECTION_UNAVAILABLE_MESSAGE });

    const pdu = buildNodeNotification(h.netKey, h.appKey, onOffStatusPayload(1));
    h.bluetooth.simulateNotification(NODE_PERIPHERAL_ID, pdu);
    await Promise.resolve();
    await Promise.resolve();

    expect(h.device.availabilityCalls.at(-1)).toEqual({ available: true });
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
    await Promise.resolve();
    await Promise.resolve();
    await h.clock.advance(50);
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
    await Promise.resolve();
    await Promise.resolve();

    expect(h.device.getCapabilityValue('onoff')).toBeNull();
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
  test('preserves the CURRENT dim value in the CTL Set rather than defaulting it', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);
    h.device.capabilityValues.set('dim', 0.25); // as if a previous read/command already established this

    await h.controller.setLightTemperature(0.5);

    const sent = decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey);
    expect(sent?.opcode).toBe(OP_CTL_SET);
    expect(sent?.parameters.readUInt16LE(0)).toBe(__testing.fractionToWire(0.25)); // lightness preserved
    expect(sent?.parameters.readUInt16LE(2)).toBe(__testing.homeyToKelvin(0.5)); // temperature requested
    expect(h.device.getCapabilityValue('light_temperature')).toBeCloseTo(0.5, 3);
  });

  test('with no prior dim value, defaults to full brightness rather than an arbitrary one', async () => {
    const h = setUp();
    await connectManager(h.manager, h.clock);

    await h.controller.setLightTemperature(0.2);

    const sent = decodeOurCommand(h.bluetooth.writesReceived[0]!.data, h.netKey, h.appKey);
    expect(sent?.parameters.readUInt16LE(0)).toBe(0xffff);
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
    expect(h.device.getCapabilityValue('light_temperature')).toBeCloseTo(__testing.kelvinToHomey(4000), 6);
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

  test('calling onConnectionStateChange("connected") twice in a row only re-reads once', async () => {
    const h = setUp({ capabilities: new Set(['onoff']) });
    await connectManager(h.manager, h.clock);

    await h.controller.onConnectionStateChange('connected');
    await h.controller.onConnectionStateChange('connected');

    expect(h.bluetooth.writesReceived).toHaveLength(1);
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
