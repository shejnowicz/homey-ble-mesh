import {
  encodeGenericOnOffSet,
  encodeGenericOnOffGet,
  decodeGenericOnOffStatus,
  type GenericOnOffStatus,
  encodeLightLightnessSet,
  encodeLightLightnessGet,
  decodeLightLightnessStatus,
  type LightLightnessStatus,
  encodeLightCtlSet,
  encodeLightCtlGet,
  decodeLightCtlStatus,
  type LightCtlStatus,
  encodeLightHslSet,
  encodeLightHslGet,
  decodeLightHslStatus,
  type LightHslStatus,
} from '../../lib/models/lighting';
import { encodeMeshMessage, acceptIncomingPdu, type MeshReceiveContext } from '../../lib/mesh/packet/message';
import { encodeAccessMessage, type AccessMessage } from '../../lib/mesh/packet/access';
import { encodeConfigNodeReset, decodeConfigStatus } from '../../lib/mesh/config/client';
import { k4 } from '../../lib/mesh/crypto/derive';
import { NetworkStore } from '../../lib/adapter/store';
import type { QueuedCommand } from '../../lib/adapter/queue';
import type { HomeyCapability } from '../../lib/models/capabilities';

/**
 * The device layer (docs/superpowers/specs/2026-10-06-ble-mesh-provisioner-
 * design.md, "The Homey layer" > "Commands and state" / "Availability", and
 * "Persistence, sequence numbers and removal"): "A command sets the
 * capability immediately so the interface stays responsive, but the node's
 * status message is what counts as true." / "When no node answers, the
 * devices are marked unavailable rather than left showing their last known
 * values. On reconnection the nodes are queried for their current state." /
 * "Deleting a device in Homey must first send the node a reset message so
 * it returns to the unowned state... Without that step the bulb stays bound
 * to a network nobody owns and only a physical reset recovers it."
 *
 * THE SEAM (task brief's own "WHAT YOU NEED TO KNOW", echoing the previous
 * task's rejection): this file holds every bit of real logic — command
 * encoding, status decoding, availability, removal — and imports no `homey`,
 * so it is testable without a hub (see `__tests__/meshLight.test.ts`). Homey
 * requires the literal file `drivers/light/device.ts` to be the actual
 * `Homey.Device` subclass (confirmed by reading the installed Homey CLI's
 * own driver-scaffolding source, `copyDriverAndDeviceTemplate` in
 * `lib/App.js` of the globally-installed `homey` package, which always
 * copies a `device.ts`/`device.js` template into every new driver — there is
 * no manifest field to point it elsewhere, unlike `onMapDeviceClass`'s
 * narrower role of choosing AMONG classes once one is already resolved) —
 * so that file cannot also be this one: a jest run that merely IMPORTS a
 * file doing `import Homey from` the `homey` package fails outright, because
 * only `@types/homey` (types, no runtime) is installed, not a real `homey`
 * package (confirmed the same way `pairing.ts`'s own module header already
 * documents for `driver.ts`). This mirrors the `pairing.ts`/`driver.ts`
 * split exactly: this module is this task's `pairing.ts`, and
 * `drivers/light/device.ts` is this task's thin `driver.ts`-shaped wrapper.
 * See the task report for why this deviates from the brief's literal
 * filename and why that deviation is necessary, not a convenience.
 *
 * THE TRANSACTION IDENTIFIER (queue.ts's own module header, read first per
 * the brief): "THE TRANSACTION IDENTIFIER LIVES ONE LAYER UP, DELIBERATELY
 * ... The allocator therefore belongs in the device layer (Task 7), which
 * calls `encodeGenericOnOffSet({ tid, ... })` ONCE per logical command and
 * hands this queue the resulting bytes; every RETRY this module performs
 * simply re-sends that exact, unchanged buffer." This module is exactly
 * that caller: `allocateTid()` below is consulted ONCE per `set*` method
 * invocation (never per retry — the queue's own retry resends the identical
 * `Buffer` this module built once), which is what makes "a retransmission
 * carries the same identifier" fall out for free rather than needing to be
 * remembered. One counter per node instance (not per model) is deliberate —
 * the specification only requires uniqueness within (SRC, DST) inside a
 * 6-second window per RECEIVING model (Section 3.3.1.2.2 restated per model
 * in `lighting.ts`'s own JSDoc), so a single shared, incrementing,
 * wrapping-at-256 counter satisfies every model's own, looser requirement
 * at once — simpler than four independent counters for no behavioural cost.
 *
 * COMMANDS AND STATUS, ONE SHARED QUEUE FOR THE WHOLE MESH. Every device
 * shares the SAME `TrafficQueue` instance (design: "All mesh traffic passes
 * through one queue so commands never flood the network") — a command's own
 * `isStatus` predicate is therefore the ONLY thing stopping one node's
 * status from being mistaken for another's answer, which matters because
 * every bulb uses the SAME application key: `acceptIncomingPdu`'s own
 * `expectedSrc` check (this node's address) rejects any notification that
 * decrypts cleanly but originates from a different node before this module
 * ever asks whether it LOOKS like the right kind of status. Each command's
 * predicate also checks the SPECIFIC model it is waiting for (never "any of
 * the four decode"), so a chatty node's unrelated status cannot
 * accidentally satisfy a different pending command from the same node.
 * `queue.onUnsolicited`, by contrast, genuinely does not know which model is
 * coming, so it tries each of the four decoders in turn — safe because the
 * four opcodes are disjoint (Assigned Numbers), so at most one ever matches.
 *
 * AVAILABILITY IS CONNECTION-LEVEL, NOT PER-NODE. The design's own words —
 * "One connection serves the whole mesh" and "When no node answers, the
 * devices are marked unavailable" — describe ONE shared signal (the proxy
 * connection manager's own `getState().status`), not independent liveness
 * tracking per bulb; this module therefore exposes `onConnectionStateChange`
 * for whoever polls that shared state (app.ts — the one place in this
 * project allowed to own wall-clock time, same as the plan's own
 * self-review note puts it) to call for every registered controller when it
 * changes, rather than this module owning a poll loop or a `ClockPort` of
 * its own. "Re-read rather than assumed" (design, quoted above) is
 * `reReadState()`: `setAvailable()` is only ever called once the node has
 * actually been asked for its state and answered — never merely because the
 * shared connection came back. A node that stays unreachable even though
 * the shared proxy connection is otherwise up (e.g. genuinely out of range)
 * has no OTHER retry path in this design beyond the next time the shared
 * connection itself cycles down and up — a disclosed, deliberate
 * simplification matching the design's own framing of availability as a
 * property of the ONE connection, not of each bulb individually.
 *
 * HEARING FROM A NODE IS EVIDENCE IT IS REACHABLE. Every successfully
 * decoded status this module ever accepts — whether as a command's own ack,
 * an unsolicited report, or a reconnection Get's reply — also marks the
 * device available (`applyDecodedStatus`'s own `setAvailable()` call). This
 * is a deliberate, symmetrical reading of the design's own "silence is not
 * evidence" rule (already applied elsewhere in this project): the
 * contrapositive, a presence genuinely IS evidence of reachability, so a
 * node that is marked unavailable but then unexpectedly answers (a Get this
 * module is not even currently making — e.g. it keeps relaying for others
 * and that is somehow observed) is not left stuck showing stale
 * unavailability either.
 *
 * REMOVAL: ALWAYS RESET, ALWAYS REMOVE, NEVER SWALLOW. `remove()` always
 * attempts a Config Node Reset FIRST (matching the design's own ordering —
 * "must first send the node a reset message") and ALWAYS removes the node's
 * store entry afterward, REGARDLESS of whether the reset itself succeeded —
 * deliberately, not merely "the simplest option": Homey is deleting this
 * device either way (this module has no way to stop that, and no reason to
 * try — see `device.ts`'s own module header), so refusing to tidy up this
 * project's OWN bookkeeping would only leave a dangling node entry nothing
 * will ever use again (the address itself is never reclaimed regardless,
 * per `store.ts`'s own established convention). What the brief's "a failure
 * to send that reset is reported rather than swallowed" actually governs is
 * therefore NOT whether removal happens, but whether the CALLER (`device.ts`
 * -> Homey's own `onDeleted`) ever learns the reset failed: `remove()`
 * throws, after removing, so a caller that does not catch it sees the
 * failure, and `device.ts` catches it only to log it (there is nowhere else
 * for `onDeleted` to surface an error to — see that file's own comment).
 *
 * CTL's PRACTICAL KELVIN RANGE is an engineering choice, not a specification
 * value — see `MIN_PRACTICAL_KELVIN`/`MAX_PRACTICAL_KELVIN` below for why.
 *
 * `light_mode` CARRIES NO WIRE TRAFFIC. It only tells Homey which of the two
 * pickers (colour wheel vs. temperature slider) to show — the Light CTL and
 * Light HSL models this project drives are each independently addressable
 * at all times (the bulb's own underlying Lightness state is bound to both,
 * per the Mesh Model specification, but nothing about "mode" needs to be
 * sent to the node for either model's own Set/Get/Status to keep working).
 * `device.ts` sets this capability directly with no call into this module
 * at all — the only capability handled that way, because it is the only one
 * with no decode/encode/availability logic worth gating.
 *
 * NULLISH CONVENTION: `null` throughout (matching every other lib/adapter
 * module) — a decode that cannot resolve to a specific status is `null`,
 * never `undefined`.
 */

// ===========================================================================
// Ports — narrow, homey-free, mirroring the pairing.ts/connection.ts
// convention: this module depends on exactly the members it uses, never on
// `Homey.Device`/`TrafficQueue` themselves.
// ===========================================================================

/** Exactly the `Homey.Device` members this module needs — see the module
 *  header's THE SEAM note. `device.ts`'s thin wrapper satisfies this with no
 *  adapter code (every member below already exists on a real `Homey.Device`
 *  with this same signature). */
export interface DeviceCapabilityPort {
  hasCapability(capabilityId: HomeyCapability): boolean;
  getCapabilityValue(capabilityId: HomeyCapability): unknown;
  setCapabilityValue(capabilityId: HomeyCapability, value: unknown): Promise<void>;
  setAvailable(): Promise<void>;
  setUnavailable(message?: string): Promise<void>;
}

/** Exactly the two `TrafficQueue` members this module uses — a real
 *  `TrafficQueue` satisfies this with no adapter code, the same "narrow the
 *  next layer down one step further" move `queue.ts`'s own `TrafficPort`
 *  already makes against `ProxyConnectionManager`. */
export interface MeshTrafficPort {
  send(command: QueuedCommand): Promise<Buffer>;
  onUnsolicited(listener: (data: Buffer) => void): () => void;
}

export interface MeshLightControllerDeps {
  readonly queue: MeshTrafficPort;
  readonly store: NetworkStore;
  readonly device: DeviceCapabilityPort;
  /** This node's unicast address — Homey's own device `data.id`, parsed
   *  (see `pairing.ts#PairedDeviceDescriptor`'s own doc comment: "task 7's
   *  device.ts looks nodes up by it"). */
  readonly address: number;
}

// ===========================================================================
// Unit conversion — Homey's own 0..1 capability conventions versus this
// project's wire integers. Not specification values (the specification only
// defines the WIRE domain; Homey defines its own capability domain
// separately) — engineering choices, documented the same way store.ts/
// connection.ts document their own.
// ===========================================================================

const WIRE_MAX = 0xffff;

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  if (value < min) return min;
  if (value > max) return max;
  return value;
}

function clamp01(value: number): number {
  return clamp(value, 0, 1);
}

/** Homey's `dim`/`light_hue`/`light_saturation` convention: a 0..1 fraction
 *  of the wire field's full 16-bit domain (Table 6.2/6.12/6.15 — none of
 *  the three has a Prohibited sub-range, so the mapping is a plain linear
 *  one across the whole domain). */
function fractionToWire(value: number): number {
  return Math.round(clamp01(value) * WIRE_MAX);
}

function wireToFraction(value: number): number {
  return value / WIRE_MAX;
}

/**
 * Light CTL Temperature's own wire domain is 800-20000 K (Table 6.6) — the
 * FULL specification range, legitimately reachable by any compliant node.
 * Mapping that whole span onto Homey's 0..1 slider would make the
 * practically useful middle of it (ordinary tunable-white bulbs) a tiny
 * sliver of the control. 2700-6500 K is the common consumer tunable-white
 * range (warm white to cool daylight) — an engineering choice, not a
 * specification value, to verify against the owner's own three bulbs once
 * hardware is available (this project has not yet read their actual
 * supported range — Light CTL Temperature Range Get is out of this design's
 * scope) and adjust if they report something different.
 */
const MIN_PRACTICAL_KELVIN = 2700;
const MAX_PRACTICAL_KELVIN = 6500;

/** Homey's own `light_temperature` convention: 0 = cold, 1 = warm. */
function homeyToKelvin(value: number): number {
  const fraction = clamp01(value);
  return Math.round(MAX_PRACTICAL_KELVIN - fraction * (MAX_PRACTICAL_KELVIN - MIN_PRACTICAL_KELVIN));
}

/** Inverse of `homeyToKelvin` — a status reporting a value outside the
 *  practical range (legal per Table 6.6, e.g. a node controlled by some
 *  other means at 900 K) is clamped into it rather than producing a value
 *  outside Homey's own 0..1 domain. */
function kelvinToHomey(kelvin: number): number {
  const bounded = clamp(kelvin, MIN_PRACTICAL_KELVIN, MAX_PRACTICAL_KELVIN);
  return clamp01((MAX_PRACTICAL_KELVIN - bounded) / (MAX_PRACTICAL_KELVIN - MIN_PRACTICAL_KELVIN));
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ===========================================================================
// The four lighting models, table-driven — see the module header's
// "COMMANDS AND STATUS" note for why a command's own `isStatus` always
// names ONE specific model while the unsolicited dispatcher tries all four.
// ===========================================================================

interface LightingModel<S> {
  readonly name: string;
  decodeStatus(pdu: Buffer): S | null;
  applyStatus(device: DeviceCapabilityPort, status: S): Promise<void>;
}

const ONOFF_MODEL: LightingModel<GenericOnOffStatus> = {
  name: 'Generic OnOff',
  decodeStatus: decodeGenericOnOffStatus,
  async applyStatus(device, status) {
    if (!device.hasCapability('onoff')) return;
    // Table 3.1 only ever legally reports 0x00/0x01, but decode is lenient
    // (lighting.ts's own stance) — treated defensively as "any nonzero is
    // on", never thrown over.
    await device.setCapabilityValue('onoff', status.presentOnOff !== 0);
  },
};

const LIGHTNESS_MODEL: LightingModel<LightLightnessStatus> = {
  name: 'Light Lightness',
  decodeStatus: decodeLightLightnessStatus,
  async applyStatus(device, status) {
    if (!device.hasCapability('dim')) return;
    await device.setCapabilityValue('dim', wireToFraction(status.presentLightness));
  },
};

const CTL_MODEL: LightingModel<LightCtlStatus> = {
  name: 'Light CTL',
  decodeStatus: decodeLightCtlStatus,
  async applyStatus(device, status) {
    if (device.hasCapability('light_temperature')) {
      await device.setCapabilityValue('light_temperature', kelvinToHomey(status.presentTemperature));
    }
    // Light CTL Lightness is bound to the same underlying Lightness state
    // Light Lightness Server reports (Mesh Model specification) — kept in
    // sync here too, so a CTL-only change (or CTL's own ack) still refreshes
    // `dim` rather than leaving it stale until something else happens to
    // read Lightness.
    if (device.hasCapability('dim')) {
      await device.setCapabilityValue('dim', wireToFraction(status.presentLightness));
    }
  },
};

const HSL_MODEL: LightingModel<LightHslStatus> = {
  name: 'Light HSL',
  decodeStatus: decodeLightHslStatus,
  async applyStatus(device, status) {
    if (device.hasCapability('light_hue')) {
      await device.setCapabilityValue('light_hue', wireToFraction(status.hue));
    }
    if (device.hasCapability('light_saturation')) {
      await device.setCapabilityValue('light_saturation', wireToFraction(status.saturation));
    }
    if (device.hasCapability('dim')) {
      await device.setCapabilityValue('dim', wireToFraction(status.lightness));
    }
  },
};

const ALL_MODELS: ReadonlyArray<LightingModel<unknown>> = [ONOFF_MODEL, LIGHTNESS_MODEL, CTL_MODEL, HSL_MODEL];

/** The message Homey shows while no node has answered yet — set at
 *  construction (`start()`) and whenever the shared connection drops. */
export const CONNECTION_UNAVAILABLE_MESSAGE = 'Mesh connection unavailable — no node has answered';

/**
 * Owns one provisioned node's commands, status and availability — the
 * design's "Commands and state"/"Availability" sections for exactly one
 * device. See the module header for the design this implements and the
 * choices it makes that the design leaves open.
 *
 * LIFECYCLE: construct, call `start()` once (subscribes to the shared
 * queue's unsolicited notifications and marks the device unavailable until
 * a connection signal says otherwise), call `stop()` once when the device
 * is being torn down (unsubscribes; safe to call even if `start()` was
 * never called, and safe to call twice).
 */
export class MeshLightController {
  private readonly queue: MeshTrafficPort;
  private readonly store: NetworkStore;
  private readonly device: DeviceCapabilityPort;
  private readonly address: number;

  private nextTid = 0;
  private connected = false;
  private unsubscribeUnsolicited: (() => void) | null = null;

  constructor(deps: MeshLightControllerDeps) {
    this.queue = deps.queue;
    this.store = deps.store;
    this.device = deps.device;
    this.address = deps.address;
  }

  start(): void {
    if (this.unsubscribeUnsolicited === null) {
      this.unsubscribeUnsolicited = this.queue.onUnsolicited((data) => {
        // Fire-and-forget, deliberately: queue.ts's own notification
        // dispatch loop has no per-listener isolation of its own for a
        // THROWN error (it wraps the call itself, not a promise this
        // listener returns), and there is no error-reporting channel
        // reachable from inside a notification callback — same stance
        // queue.ts's own `safeIsStatus` documents for the identical reason.
        this.handleUnsolicited(data).catch(() => {
          // Nothing productive to do with a failure decoding/applying an
          // unsolicited status — it is simply not applied.
        });
      });
    }
    void this.device.setUnavailable(CONNECTION_UNAVAILABLE_MESSAGE);
  }

  stop(): void {
    this.unsubscribeUnsolicited?.();
    this.unsubscribeUnsolicited = null;
  }

  /**
   * Called whenever the shared proxy connection's status changes — see the
   * module header's "AVAILABILITY IS CONNECTION-LEVEL" note. Idempotent
   * against repeated calls with the same status (a 'connected' call while
   * already connected is a no-op, so a caller that polls need not track
   * transitions itself beyond "did the value change").
   */
  async onConnectionStateChange(status: 'connected' | 'unavailable'): Promise<void> {
    if (status === 'unavailable') {
      this.connected = false;
      await this.device.setUnavailable(CONNECTION_UNAVAILABLE_MESSAGE);
      return;
    }
    if (this.connected) return;
    try {
      await this.reReadState();
      this.connected = true;
      await this.device.setAvailable();
    } catch (err) {
      this.connected = false;
      await this.device.setUnavailable(`node did not respond after reconnecting (${errorMessage(err)})`);
    }
  }

  // --- Commands ----------------------------------------------------------

  async setOnOff(value: boolean): Promise<void> {
    const tid = this.allocateTid();
    const data = this.buildApplicationPdu(encodeGenericOnOffSet({ onOff: value ? 1 : 0, tid }));
    await this.device.setCapabilityValue('onoff', value); // optimistic — design: "sets the capability immediately"
    const reply = await this.queue.send({
      data,
      isStatus: (pdu) => this.tryDecodeModel(ONOFF_MODEL, pdu) !== null,
      description: `Generic OnOff Set (node ${this.address})`,
    });
    const status = this.tryDecodeModel(ONOFF_MODEL, reply);
    if (status !== null) await this.applyDecodedStatus(ONOFF_MODEL, status);
  }

  async setDim(value: number): Promise<void> {
    const tid = this.allocateTid();
    const data = this.buildApplicationPdu(encodeLightLightnessSet({ lightness: fractionToWire(value), tid }));
    await this.device.setCapabilityValue('dim', clamp01(value)); // optimistic
    const reply = await this.queue.send({
      data,
      isStatus: (pdu) => this.tryDecodeModel(LIGHTNESS_MODEL, pdu) !== null,
      description: `Light Lightness Set (node ${this.address})`,
    });
    const status = this.tryDecodeModel(LIGHTNESS_MODEL, reply);
    if (status !== null) await this.applyDecodedStatus(LIGHTNESS_MODEL, status);
  }

  async setLightTemperature(value: number): Promise<void> {
    const tid = this.allocateTid();
    const data = this.buildApplicationPdu(
      encodeLightCtlSet({
        lightness: fractionToWire(this.currentDimFraction()),
        temperature: homeyToKelvin(value),
        deltaUv: 0, // not exposed to Homey — see lighting.ts's own field doc comment.
        tid,
      }),
    );
    await this.device.setCapabilityValue('light_temperature', clamp01(value)); // optimistic
    const reply = await this.queue.send({
      data,
      isStatus: (pdu) => this.tryDecodeModel(CTL_MODEL, pdu) !== null,
      description: `Light CTL Set (node ${this.address})`,
    });
    const status = this.tryDecodeModel(CTL_MODEL, reply);
    if (status !== null) await this.applyDecodedStatus(CTL_MODEL, status);
  }

  /** Hue and saturation travel together (Light HSL Set's own single
   *  message) — `device.ts` registers both through ONE
   *  `registerMultipleCapabilityListener`, which always supplies both
   *  values even when the user only dragged one of the two controls. */
  async setColor(hue: number, saturation: number): Promise<void> {
    const tid = this.allocateTid();
    const data = this.buildApplicationPdu(
      encodeLightHslSet({
        lightness: fractionToWire(this.currentDimFraction()),
        hue: fractionToWire(hue),
        saturation: fractionToWire(saturation),
        tid,
      }),
    );
    await this.device.setCapabilityValue('light_hue', clamp01(hue)); // optimistic
    await this.device.setCapabilityValue('light_saturation', clamp01(saturation)); // optimistic
    const reply = await this.queue.send({
      data,
      isStatus: (pdu) => this.tryDecodeModel(HSL_MODEL, pdu) !== null,
      description: `Light HSL Set (node ${this.address})`,
    });
    const status = this.tryDecodeModel(HSL_MODEL, reply);
    if (status !== null) await this.applyDecodedStatus(HSL_MODEL, status);
  }

  /**
   * Sends a Config Node Reset before removing this node's store entry — see
   * the module header's "REMOVAL" note for why removal is unconditional and
   * what "reported rather than swallowed" actually means here. Always
   * removes the store entry (if one exists) even when the reset failed;
   * throws AFTER removing, naming the reset failure, so a caller that does
   * not catch this still sees the node is gone from the store but learns
   * the reset itself did not succeed.
   */
  async remove(): Promise<void> {
    const node = this.store.getState().nodes.find((n) => n.address === this.address);
    let resetError: Error | null = null;
    if (node !== undefined) {
      try {
        await this.sendNodeReset(node.deviceKey);
      } catch (err) {
        resetError = err instanceof Error ? err : new Error(String(err));
      }
    }
    const fresh = this.store.getState();
    this.store.setState({ ...fresh, nodes: fresh.nodes.filter((n) => n.address !== this.address) });
    if (resetError !== null) {
      throw new Error(`failed to reset node ${this.address} before removing it: ${resetError.message}`);
    }
  }

  // --- Internals -----------------------------------------------------------

  private allocateTid(): number {
    const tid = this.nextTid;
    this.nextTid = (this.nextTid + 1) & 0xff;
    return tid;
  }

  private currentDimFraction(): number {
    if (!this.device.hasCapability('dim')) return 1;
    const value = this.device.getCapabilityValue('dim');
    return typeof value === 'number' && Number.isFinite(value) ? clamp01(value) : 1;
  }

  /** The network/application-key material every ordinary (non-Config)
   *  command needs, read fresh every time rather than cached at
   *  construction — consistent with pairing.ts's own "re-read, never a
   *  stale snapshot" discipline. Throws if pairing has somehow not
   *  completed (should be unreachable: a device only exists once pairing
   *  wrote a node entry, which only happens once the network itself is
   *  initialized). */
  private currentNetworkContext(): { netKey: Buffer; appKey: Buffer; ivIndex: number; ourAddress: number } {
    const state = this.store.getState();
    if (state.netKey === null || state.appKey === null || state.ourUnicastAddress === null) {
      throw new Error(`mesh network is not initialized (node ${this.address})`);
    }
    return { netKey: state.netKey, appKey: state.appKey, ivIndex: state.ivIndex, ourAddress: state.ourUnicastAddress };
  }

  /** Builds one application-key-secured Network PDU ready to hand to the
   *  queue. Every message this module sends (the four lighting Set/Get
   *  pairs) is well within the unsegmented ceiling (Table 3.17), so exactly
   *  one PDU is always expected — the length check is a sanity guard
   *  against that assumption quietly breaking, not a real path. */
  private buildApplicationPdu(accessPayload: Buffer): Buffer {
    const { netKey, appKey, ivIndex, ourAddress } = this.currentNetworkContext();
    const pdus = encodeMeshMessage({
      accessPayload,
      key: appKey,
      keyKind: 'application',
      aid: k4(appKey),
      src: ourAddress,
      dst: this.address,
      netKey,
      ivIndex,
      allocateSeq: () => this.store.allocateSequenceBlock(),
    });
    if (pdus.length !== 1) {
      throw new Error(
        `meshLight: expected exactly one Network PDU for node ${this.address}'s command, got ${pdus.length} (unexpected segmentation)`,
      );
    }
    return pdus[0] as Buffer;
  }

  private applicationReceiveContext(): MeshReceiveContext {
    const { netKey, appKey, ivIndex } = this.currentNetworkContext();
    return { key: appKey, keyKind: 'application', netKey, ivIndex, expectedSrc: this.address };
  }

  /** Decrypts and decodes one inbound Network PDU to an `AccessMessage`, or
   *  `null` if it does not belong to this node or does not decode at all —
   *  every message this module ever receives fits in one PDU (same
   *  reasoning as `buildApplicationPdu`), so no reassembly state is carried
   *  across calls. */
  private decodeApplicationMessage(pdu: Buffer): AccessMessage | null {
    const result = acceptIncomingPdu(undefined, this.applicationReceiveContext(), pdu);
    return result.kind === 'complete' ? result.message : null;
  }

  private tryDecodeModel<S>(model: LightingModel<S>, pdu: Buffer): S | null {
    const message = this.decodeApplicationMessage(pdu);
    if (message === null) return null;
    return model.decodeStatus(encodeAccessMessage(message));
  }

  /** Applies a decoded status to its capabilities and marks the device
   *  available — see the module header's "HEARING FROM A NODE IS EVIDENCE"
   *  note for why every successful decode does the latter, not only a
   *  reconnection re-read. */
  private async applyDecodedStatus<S>(model: LightingModel<S>, status: S): Promise<void> {
    await model.applyStatus(this.device, status);
    this.connected = true;
    await this.device.setAvailable();
  }

  private async handleUnsolicited(data: Buffer): Promise<void> {
    const message = this.decodeApplicationMessage(data);
    if (message === null) return;
    const reencoded = encodeAccessMessage(message);
    for (const model of ALL_MODELS) {
      const status = model.decodeStatus(reencoded);
      if (status !== null) {
        await this.applyDecodedStatus(model, status);
        return;
      }
    }
  }

  /** Design: "On reconnection the nodes are queried for their current
   *  state." One Get per model this device actually has a capability for —
   *  simple and correct, at the cost of some overlap (e.g. both a Light
   *  Lightness Get and a Light CTL Get refresh `dim` when both capabilities
   *  are present); optimising away the overlap is not worth the added
   *  branching for three bulbs reconnecting occasionally. Propagates the
   *  first failure (a node that does not answer one of these) to the
   *  caller, which is what makes `onConnectionStateChange` keep the device
   *  unavailable rather than assume the rest would have succeeded too. */
  private async reReadState(): Promise<void> {
    if (this.device.hasCapability('onoff')) {
      await this.getAndApply(ONOFF_MODEL, encodeGenericOnOffGet());
    }
    if (this.device.hasCapability('dim')) {
      await this.getAndApply(LIGHTNESS_MODEL, encodeLightLightnessGet());
    }
    if (this.device.hasCapability('light_temperature')) {
      await this.getAndApply(CTL_MODEL, encodeLightCtlGet());
    }
    if (this.device.hasCapability('light_hue')) {
      await this.getAndApply(HSL_MODEL, encodeLightHslGet());
    }
  }

  private async getAndApply<S>(model: LightingModel<S>, getPayload: Buffer): Promise<void> {
    const data = this.buildApplicationPdu(getPayload);
    const reply = await this.queue.send({
      data,
      isStatus: (pdu) => this.tryDecodeModel(model, pdu) !== null,
      description: `${model.name} Get (node ${this.address})`,
    });
    const status = this.tryDecodeModel(model, reply);
    if (status !== null) await this.applyDecodedStatus(model, status);
  }

  private decodeDeviceMessage(receiveContext: MeshReceiveContext, pdu: Buffer): AccessMessage | null {
    const result = acceptIncomingPdu(undefined, receiveContext, pdu);
    return result.kind === 'complete' ? result.message : null;
  }

  /**
   * Secured with the node's OWN device key, never the shared application
   * key — Config messages are always device-key-secured (Section 4.3.1,
   * already quoted in message.ts's own module header), which is also
   * exactly why this needs `deviceKey` passed in rather than reusing
   * `buildApplicationPdu`/`applicationReceiveContext` above.
   *
   * `isStatus` deliberately accepts ANY complete, correctly-addressed
   * device-key message here — not specifically a Node Reset Status — unlike
   * every lighting command's own `isStatus` above (which always checks for
   * ONE specific model). The two are different on purpose: a lighting
   * command that resolved on the wrong model's status would silently eat a
   * notification the unsolicited listener should have seen instead (that
   * listener decodes APPLICATION-key traffic, same as every command), so
   * accepting only an exact type match there is what keeps a stray status
   * flowing to where it is actually used. A Config Node Reset has no such
   * sibling listener for device-key traffic to protect — nothing else in
   * this module ever consumes it — so resolving on any reply and checking
   * its TYPE afterward (mirroring `pairing.ts`'s own
   * `attemptNodeReset`/`toConfigStatus`) is safe, and gives a faster, more
   * specific failure ("answered, but not with what we asked for") instead of
   * indistinguishably timing out the same way silence would.
   */
  private async sendNodeReset(deviceKey: Buffer): Promise<void> {
    const { netKey, ivIndex, ourAddress } = this.currentNetworkContext();
    const pdus = encodeMeshMessage({
      accessPayload: encodeConfigNodeReset(),
      key: deviceKey,
      keyKind: 'device',
      src: ourAddress,
      dst: this.address,
      netKey,
      ivIndex,
      allocateSeq: () => this.store.allocateSequenceBlock(),
    });
    if (pdus.length !== 1) {
      throw new Error(
        `meshLight: expected exactly one Network PDU for node ${this.address}'s Config Node Reset, got ${pdus.length}`,
      );
    }
    const receiveContext: MeshReceiveContext = { key: deviceKey, keyKind: 'device', netKey, ivIndex, expectedSrc: this.address };
    const reply = await this.queue.send({
      data: pdus[0] as Buffer,
      isStatus: (pdu) => this.decodeDeviceMessage(receiveContext, pdu) !== null,
      description: `Config Node Reset (node ${this.address})`,
    });
    const message = this.decodeDeviceMessage(receiveContext, reply);
    const status = message === null ? null : decodeConfigStatus(encodeAccessMessage(message));
    if (status === null || status.type !== 'nodeReset') {
      throw new Error(`node ${this.address} did not answer Config Node Reset with a Node Reset Status message`);
    }
  }
}

// Exported for direct, precise unit testing of the conversion rules
// themselves (see the module header's unit-conversion section) — kept out
// of the class's own public surface since nothing outside this module and
// its tests needs them as a caller-facing API.
export const __testing = { fractionToWire, wireToFraction, homeyToKelvin, kelvinToHomey, MIN_PRACTICAL_KELVIN, MAX_PRACTICAL_KELVIN };
