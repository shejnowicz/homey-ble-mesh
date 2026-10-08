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
  encodeLightCtlTemperatureSet,
  decodeLightCtlTemperatureStatus,
  type LightCtlTemperatureStatus,
  encodeLightHslSet,
  encodeLightHslGet,
  decodeLightHslStatus,
  type LightHslStatus,
} from '../../lib/models/lighting';
import {
  encodeMeshMessage,
  acceptIncomingPdu,
  RELAYED_TTL,
  type MeshReceiveContext,
} from '../../lib/mesh/packet/message';
import { encodeAccessMessage, type AccessMessage } from '../../lib/mesh/packet/access';
import { encodeConfigNodeReset, decodeConfigStatus } from '../../lib/mesh/config/client';
import { k4 } from '../../lib/mesh/crypto/derive';
import { NetworkStore } from '../../lib/adapter/store';
import type { QueuedCommand } from '../../lib/adapter/queue';
import {
  chooseTemperatureWriteModel,
  type HomeyCapability,
  type NodeProbeResult,
  type TemperatureRange,
} from '../../lib/models/capabilities';
import { DEFAULT_TEMPERATURE_RANGE, isUsableRange } from './temperatureRange';
import { isMeaningfulProbeResult, probeModels, type ProbeTransport } from './modelProbe';

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
 * hands this queue a `build()` that re-encodes those same parameters per
 * attempt." This module is exactly that caller: `allocateTid()` below is
 * consulted ONCE per `set*` method invocation, and the resulting ACCESS
 * PAYLOAD (which carries the identifier) is built once, while the NETWORK
 * PDU around it (which carries the sequence number) is rebuilt on every
 * attempt — so "a retransmission carries the same identifier" and "a
 * retransmission carries a fresh sequence number" are each true for their
 * own reason rather than one being an accident of the other. See queue.ts's
 * own "A RETRY REBUILDS ITS BYTES" note for the defect that corrected. One counter per node instance (not per model) is deliberate —
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
 * ONE UNREACHABLE BULB MUST NOT SATURATE THE SHARED QUEUE (review finding,
 * final wave — the measured defect, not a theoretical one). `app.ts`'s
 * connection poll deliberately fans `onConnectionStateChange('connected')`
 * out to EVERY controller on EVERY tick, to close an earlier finding where a
 * controller whose own re-read had failed stayed latched unavailable with
 * nothing polling on its behalf. But a controller whose node is silent never
 * sets `connected`, so before this round every single tick started another
 * full `reReadState()` — each one enqueuing up to four Gets that take the
 * whole bounded-retry budget to fail, onto the ONE queue every device
 * shares. A reviewer measured it: two hundred ticks, two hundred re-reads
 * started, sixteen settled, a backlog of one hundred and eighty-four growing
 * linearly, and a user's command on a WORKING bulb queued behind all of it.
 * That is a direct breach of the clause the queue exists for — "All mesh
 * traffic passes through one queue so commands never flood the network".
 *
 * THE FIX IS TO MAKE THE RETRY EXPLICIT AND RATE-LIMITED rather than
 * re-entrant: `reReadInFlight` below means a tick arriving while a re-read
 * is still running is a no-op (one at a time, never a pile), and
 * `nextReReadAtMs` plus a doubling backoff means a FAILED re-read is not
 * retried on the very next tick either. A success, or any status heard from
 * the node, clears both. The shape mirrors `connection.ts`'s own
 * failure-streak backoff deliberately — the same problem (an attempt that
 * keeps failing must get slower, not faster) solved the same way, with the
 * same cap so it never grows without bound. This module therefore now takes
 * a `clock` port, for `now()` only: there is no timer here, because the
 * app's own poll already provides the ticks and this module only has to
 * decide which of them to act on.
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
 * `light_mode` CARRIES NO WIRE TRAFFIC OF ITS OWN. It only tells Homey which
 * of the two pickers (colour wheel vs. temperature slider) to show — the
 * Light CTL and Light HSL models this project drives are each independently
 * addressable at all times (the bulb's own underlying Lightness state is
 * bound to both, per the Mesh Model specification, but nothing about "mode"
 * needs to be sent to the node for either model's own Set/Get/Status to keep
 * working), so there is no `setLightMode` command method here and
 * `device.ts` wires the user's own mode-picker taps directly, with no call
 * into this module. Its VALUE, however, DOES follow incoming status
 * (`CTL_MODEL`/`HSL_MODEL`'s own `applyStatus`, review finding — see each
 * one's own comment): whichever of the two models' Status a node reports
 * — its own ack, an unsolicited change by other means, or a reconnection
 * Get — sets `light_mode` to match, so the picker never shows the wrong one
 * after an external change. `light_mode` only ever exists alongside both
 * `light_temperature` and `light_hue` (`capabilities.ts`'s own rule), so
 * either status is always a meaningful signal for it. One disclosed,
 * order-dependent consequence: `reReadState()` queries CTL before HSL, so a
 * BRAND NEW device's very first successful read always lands on `'color'`
 * regardless of which the bulb was actually last set to — the mesh has no
 * "current mode" concept to read instead (this comment's own earlier
 * paragraph), so this is the best available proxy, not a true initial read.
 *
 * MEASURING A BULB THAT PREDATES THE PROBE (`backfillProbe` below). Every
 * node paired before `modelProbe.ts` existed has a store entry carrying an
 * address, a device key and a composition and NO measurement — the owner's
 * own lamp among them. Such a node works today only because
 * `chooseTemperatureWriteModel`'s fallback happens to be the message it
 * obeys, which is luck rather than knowledge. This module therefore runs the
 * SAME probe over the ordinary traffic queue, once per such device per app
 * run, in the background: never retried in a loop, never run at all for a
 * node that already has a measurement, and never STORED unless it actually
 * learned something (a probe that merely timed out leaves the record
 * unmeasured so a later start can try again). It is started from the first
 * `'connected'` transition in which this node ACTUALLY ANSWERED — not from
 * device init, which would write its first message before the proxy
 * connection exists; see `startBackfillProbe` for the full argument.
 * It reuses `modelProbe.ts` through that module's own transport port rather
 * than duplicating the probe plan, and it borrows this controller's own
 * transaction-identifier counter so a probe's no-op write can never collide
 * with a user's command inside a node's six-second deduplication window.
 * See `backfillProbe`'s own doc comment for the one risk this accepts.
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

/** Exactly the one `ClockPort` member this module needs — see the module
 *  header's "ONE UNREACHABLE BULB" note. A real `ClockPort`
 *  (`lib/adapter/connection.ts`) and the test `FakeClock` both satisfy this
 *  structurally, with no adapter code; the narrowing is the same move
 *  `queue.ts`'s `TrafficPort` and this module's own `MeshTrafficPort`
 *  already make. Only `now()`: this module owns no timer. */
export interface MeshClockPort {
  now(): number;
}

/**
 * The ONE-AT-A-TIME gate every backfill probe passes through, shared by
 * every device in the app (`app.ts` owns the single instance, the same way
 * it owns the single queue).
 *
 * WHY IT EXISTS. Homey initialises every device at roughly the same moment,
 * so several controllers can reach `backfillProbe()` within the same tick.
 * The mesh carries one command at a time and the queue is shared: two
 * probes running at once do not go faster, they interleave their messages
 * onto the same queue, each waiting out the other's attempts, and both
 * sitting in front of whatever the user is pressing. Serialising them costs
 * nothing (a probe is a once-per-device-per-run background errand) and
 * keeps the shared queue's behaviour predictable.
 *
 * `run` resolves or rejects with its own task's own outcome, so a caller
 * still learns what happened to ITS probe and not to somebody else's.
 */
export interface ProbeRunnerPort {
  run<T>(task: () => Promise<T>): Promise<T>;
}

/**
 * A `ProbeRunnerPort` that chains tasks onto one promise, so the next starts
 * only once the previous has settled - WHETHER IT SUCCEEDED OR NOT. The
 * failure branch is the point: one unreachable bulb takes the queue's full
 * bounded-retry time to give up, and if that failure broke the chain, every
 * other bulb behind it would lose its measurement too.
 */
export function createSerialProbeRunner(): ProbeRunnerPort {
  let tail: Promise<unknown> = Promise.resolve();
  return {
    run<T>(task: () => Promise<T>): Promise<T> {
      // `then(task, task)` rather than `finally`/`catch`: the previous
      // task's REJECTION must start this one just as its fulfilment does,
      // and neither outcome is otherwise consulted.
      const result = tail.then(task, task);
      // The chain itself never carries a rejection forward - a rejected
      // `tail` would be an unhandled rejection the moment nothing else
      // attached to it. The caller still gets the real `result`.
      tail = result.then(
        () => undefined,
        () => undefined,
      );
      return result;
    },
  };
}

export interface MeshLightControllerDeps {
  readonly queue: MeshTrafficPort;
  readonly store: NetworkStore;
  readonly clock: MeshClockPort;
  readonly device: DeviceCapabilityPort;
  /** This node's unicast address — Homey's own device `data.id`, parsed
   *  (see `pairing.ts#PairedDeviceDescriptor`'s own doc comment: "task 7's
   *  device.ts looks nodes up by it"). */
  readonly address: number;
  /**
   * This device's own colour-temperature range, already resolved by
   * `device.ts` from the three sources `./temperatureRange.ts` describes
   * (the per-device setting, the node's own reported range, the documented
   * fallback). Passed IN rather than resolved here, so the conversion stays
   * pure and this module never reads a Homey setting; omit it and the
   * documented fallback is used. `setTemperatureRange` below updates it
   * when the user edits the setting.
   */
  readonly temperatureRange?: TemperatureRange;
  /**
   * The shared one-at-a-time gate the backfill probe runs through - see
   * `ProbeRunnerPort`. Omitted, this controller makes its own, which
   * serialises nothing but itself; `app.ts` supplies the real shared one.
   */
  readonly probeRunner?: ProbeRunnerPort;
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
 * sliver of the control, so the slider is mapped onto THIS BULB's own
 * range instead.
 *
 * THE RANGE IS NO LONGER A CONSTANT, and these two functions no longer own
 * it. It is resolved per device — from the node's own
 * `Light CTL Temperature Range Status` if it reports one, else from a
 * per-device setting the user can correct, else from a documented
 * fallback — in `./temperatureRange.ts`, which carries the full precedence
 * order and the consequence of getting it wrong. The maths stays PURE and
 * takes the range as an argument rather than reaching for device state, so
 * every combination is directly testable.
 *
 * Homey's own `light_temperature` convention: 0 = cold, 1 = warm.
 */
function homeyToKelvin(value: number, range: TemperatureRange): number {
  const fraction = clamp01(value);
  return Math.round(range.maxKelvin - fraction * (range.maxKelvin - range.minKelvin));
}

/** Inverse of `homeyToKelvin` — a status reporting a value outside this
 *  bulb's range (legal per Table 6.6, e.g. a node controlled by some
 *  other means at 900 K) is clamped into it rather than producing a value
 *  outside Homey's own 0..1 domain. */
function kelvinToHomey(kelvin: number, range: TemperatureRange): number {
  const bounded = clamp(kelvin, range.minKelvin, range.maxKelvin);
  return clamp01((range.maxKelvin - bounded) / (range.maxKelvin - range.minKelvin));
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Light CTL Set and Light HSL Set both carry a MANDATORY Lightness field —
 * there is no "leave the brightness alone" encoding in either message — so a
 * colour or colour-temperature change always has to state a brightness.
 * Normally it states the one Homey already shows (`currentDimFraction` reads
 * the `dim` capability). This function is the two cases where there is
 * nothing to read, and it exists as a named, exported function rather than
 * two bare `return 1`s because this was an UNPINNED and USER-VISIBLE
 * fallback (review finding, final wave): on a device whose brightness has no
 * value yet, the first colour-temperature change sends FULL brightness, so
 * adjusting warmth on a dimmed lamp makes it jump to full.
 *
 * THE DECISION, deliberately, with the alternatives weighed rather than the
 * first answer kept:
 *   - `'no-capability'`: the device exposes no `dim` at all, so Homey has no
 *     brightness control for it and full is the only value that means
 *     anything. Not a guess.
 *   - `'no-value'`: the device HAS `dim` but nothing has ever populated it.
 *     Every option here is a blind guess, so the choice is which guess does
 *     least damage. 0 is strictly worse — Lightness 0 turns the lamp OFF, so
 *     a user nudging the warmth would be left in the dark. A middle value is
 *     an equally blind guess with no advantage and a stranger result. Full
 *     it stays; it is the only guess that leaves the lamp visible and whose
 *     effect the user can see and immediately undo.
 * WHY THE WINDOW IS NARROW IN PRACTICE, which is what makes the above
 * acceptable rather than merely least-bad: `reReadState()` issues a Light
 * Lightness Get on every reconnection and `applyDecodedStatus` writes `dim`
 * from any status at all, so `'no-value'` only holds between a device being
 * created and the first status ever arriving from its node — during which
 * the device is also marked unavailable. ONE OF THE THINGS TO WATCH ON THE
 * FIRST BULB: if a temperature change ever visibly jumps the brightness,
 * this is the reason, and the fix is to make the command wait for a
 * Lightness read rather than to change the number here.
 */
const DIM_FRACTION_FALLBACKS: Readonly<Record<'no-capability' | 'no-value', number>> = {
  // The same value for both, reached by two different arguments — kept as
  // two entries so each can be changed, and mutated, independently.
  'no-capability': 1,
  'no-value': 1,
};

export function currentDimFractionFallback(reason: 'no-capability' | 'no-value'): number {
  return DIM_FRACTION_FALLBACKS[reason];
}

// ===========================================================================
// The four lighting models, table-driven — see the module header's
// "COMMANDS AND STATUS" note for why a command's own `isStatus` always
// names ONE specific model while the unsolicited dispatcher tries all four.
// ===========================================================================

interface LightingModel<S> {
  readonly name: string;
  decodeStatus(pdu: Buffer): S | null;
  /** `range` is this device's own resolved colour-temperature range — only
   *  the two CTL models use it, but it is passed to all of them rather than
   *  giving one model a different signature from its siblings. */
  applyStatus(device: DeviceCapabilityPort, status: S, range: TemperatureRange): Promise<void>;
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
  async applyStatus(device, status, range) {
    if (device.hasCapability('light_temperature')) {
      await device.setCapabilityValue('light_temperature', kelvinToHomey(status.presentTemperature, range));
    }
    // Light CTL Lightness is bound to the same underlying Lightness state
    // Light Lightness Server reports (Mesh Model specification) — kept in
    // sync here too, so a CTL-only change (or CTL's own ack) still refreshes
    // `dim` rather than leaving it stale until something else happens to
    // read Lightness.
    if (device.hasCapability('dim')) {
      await device.setCapabilityValue('dim', wireToFraction(status.presentLightness));
    }
    // Review finding: `light_mode` was never updated by an incoming status,
    // so a colour-temperature change made by some OTHER means (the official
    // app, a flow, another controller) left Homey showing the wrong picker —
    // one of the design's own hardware acceptance items ("changing a light
    // by any other means produces an unsolicited status that updates
    // Homey"). `light_mode` only ever exists alongside both `light_temperature`
    // and `light_hue` (capabilities.ts's own rule), so this status is exactly
    // the signal that CTL is the model currently driving the lamp.
    if (device.hasCapability('light_mode')) {
      await device.setCapabilityValue('light_mode', 'temperature');
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
    // See CTL_MODEL's own identical note — this is the HSL half of the same fix.
    if (device.hasCapability('light_mode')) {
      await device.setCapabilityValue('light_mode', 'color');
    }
  },
};

/**
 * The SECOND colour-temperature model — a different model with different
 * opcodes, not a variant of the one above (see `lighting.ts`'s own section
 * header). This is the one the owner's bulb actually obeys.
 *
 * CARRIES NO LIGHTNESS, so unlike `CTL_MODEL` this one deliberately leaves
 * `dim` alone: Table 6.75 reports Temperature and Delta UV only, and
 * writing a brightness this status never mentioned would be inventing one.
 * That is also the whole reason this model is preferred for WRITING — a
 * temperature change through it cannot disturb the lamp's brightness.
 */
const CTL_TEMPERATURE_MODEL: LightingModel<LightCtlTemperatureStatus> = {
  name: 'Light CTL Temperature',
  decodeStatus: decodeLightCtlTemperatureStatus,
  async applyStatus(device, status, range) {
    if (device.hasCapability('light_temperature')) {
      await device.setCapabilityValue('light_temperature', kelvinToHomey(status.presentTemperature, range));
    }
    // Same reasoning as CTL_MODEL's own `light_mode` note: whichever
    // colour model a node reports is the one currently driving the lamp.
    if (device.hasCapability('light_mode')) {
      await device.setCapabilityValue('light_mode', 'temperature');
    }
  },
};

// The unsolicited dispatcher tries every one of these in turn — safe
// because all five opcodes are disjoint (Assigned Numbers), so at most one
// ever matches. `CTL_TEMPERATURE_MODEL` has to be here, not only on the
// command path: the owner's bulb answers a temperature change with an
// `0x8266`, and a change made by some OTHER means arrives the same way, so
// without it Homey would miss exactly the status this round added support
// for.
const ALL_MODELS: ReadonlyArray<LightingModel<unknown>> = [
  ONOFF_MODEL,
  LIGHTNESS_MODEL,
  CTL_MODEL,
  CTL_TEMPERATURE_MODEL,
  HSL_MODEL,
];

/** The message Homey shows while no node has answered yet — set at
 *  construction (`start()`) and whenever the shared connection drops. */
export const CONNECTION_UNAVAILABLE_MESSAGE = 'Mesh connection unavailable — no node has answered';

// ===========================================================================
// Re-read backoff — see the module header's "ONE UNREACHABLE BULB" note. Not
// specification values; engineering choices, the same way connection.ts's own
// backoff constants and queue.ts's timeouts are, and chosen against the same
// yardstick: one failed `reReadState()` already costs up to four queued Gets
// each burning the queue's full bounded-retry budget, so even the FIRST
// backoff step has to be comfortably longer than that, or the "rate limit"
// would only be a formality.
// ===========================================================================

const RE_READ_BACKOFF_BASE_MS = 30_000;
const RE_READ_BACKOFF_MAX_MS = 300_000;
/** Capped well before the doubling could produce an unreasonably large
 *  number — purely defensive, exactly as connection.ts's own
 *  MAX_FAILURE_STREAK is. */
const MAX_RE_READ_FAILURE_STREAK = 8;

function reReadBackoffMs(failureStreak: number): number {
  if (failureStreak <= 0) return 0;
  const scaled = RE_READ_BACKOFF_BASE_MS * 2 ** (failureStreak - 1);
  return Math.min(scaled, RE_READ_BACKOFF_MAX_MS);
}

// ===========================================================================
// The backfill probe's own budget. Not a specification value; an engineering
// choice, sized against the QUEUE rather than against the probe's own
// per-message timeout, because the queue is what paces it here (see
// `queueProbeTransport`).
// ===========================================================================

/**
 * 120 seconds for the whole backfill probe, checked before each message is
 * sent (`modelProbe.ts`'s own `outOfBudget`).
 *
 * WHY SO MUCH MORE THAN PAIRING'S OWN 9 SECONDS. There, every message rode a
 * dedicated GATT connection to the node being configured, with a 1500 ms
 * timeout and no retry; here each one is a queue entry with the queue's own
 * per-attempt timeout and bounded retry behind it (`queue.ts`'s
 * `DEFAULT_TIMEOUT_MS` x `DEFAULT_MAX_ATTEMPTS`), so a single UNANSWERED
 * message costs tens of seconds rather than one and a half. A budget sized
 * for pairing would therefore expire during the first silent model and
 * record every model after it `'unknown'` - which, for a bulb like the
 * owner's that is silent on exactly one message and answers everything else,
 * would throw away the whole measurement.
 *
 * It costs nothing to be generous. A long-running probe does NOT hold the
 * queue: each probe message is one entry, and a user's command enqueued
 * meanwhile is served between them, never behind all of them. And a node
 * that answers nothing at all still finishes well inside this, because every
 * one of its reads fails and each failed read skips its own write.
 */
export const BACKFILL_PROBE_BUDGET_MS = 120_000;

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
  private readonly clock: MeshClockPort;
  private readonly address: number;
  /** See `MeshLightControllerDeps.temperatureRange`. Mutable, because the
   *  user can change the per-device setting while the device is running. */
  private temperatureRange: TemperatureRange;

  private nextTid = 0;
  private connected = false;
  private unsubscribeUnsolicited: (() => void) | null = null;
  /** True while a `reReadState()` is running — see the module header's "ONE
   *  UNREACHABLE BULB" note. The single thing that stops the app's poll from
   *  starting a new full state read every tick against a silent node. */
  private reReadInFlight = false;
  /** Consecutive failed re-reads, driving `reReadBackoffMs`. Cleared by any
   *  success, by any status heard from the node, and by a genuine disconnect
   *  (a link that has gone and come back is new information, not a
   *  continuation of the old failure). */
  private reReadFailureStreak = 0;
  /** The earliest `clock.now()` at which another re-read may start. */
  private nextReReadAtMs = 0;
  /** The shared one-at-a-time gate for the backfill probe - see
   *  `ProbeRunnerPort`. */
  private readonly probeRunner: ProbeRunnerPort;
  /** Set the moment `backfillProbe()` is entered, BEFORE its first `await`:
   *  "at most once per device per app run" has to hold against two
   *  overlapping calls as well as two sequential ones, and `device.ts`
   *  starts this fire-and-forget. */
  private backfillAttempted = false;

  constructor(deps: MeshLightControllerDeps) {
    this.queue = deps.queue;
    this.store = deps.store;
    this.device = deps.device;
    this.clock = deps.clock;
    this.address = deps.address;
    this.temperatureRange = isUsableRange(deps.temperatureRange) ? deps.temperatureRange : DEFAULT_TEMPERATURE_RANGE;
    this.probeRunner = deps.probeRunner ?? createSerialProbeRunner();
  }

  /**
   * Replaces this device's colour-temperature range — `device.ts` calls it
   * from Homey's own `onSettings` when the user corrects the range by hand.
   * An unusable range (inverted, or outside Table 6.6's legal span) is
   * REFUSED rather than clamped into shape: the previous range stays, and
   * the caller is told, so a typo cannot silently leave the slider mapped
   * onto nonsense. Returns whether it was accepted.
   */
  setTemperatureRange(range: TemperatureRange): boolean {
    if (!isUsableRange(range)) return false;
    this.temperatureRange = range;
    return true;
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
      // The shared link itself went away; whatever this node's own recent
      // failures were, they are no longer the reason it is unreachable, so
      // the next 'connected' tick gets a clean, immediate attempt.
      this.reReadFailureStreak = 0;
      this.nextReReadAtMs = 0;
      await this.device.setUnavailable(CONNECTION_UNAVAILABLE_MESSAGE);
      return;
    }
    if (this.connected) return;
    // THE TWO GUARDS — see the module header's "ONE UNREACHABLE BULB" note.
    // Without the first, the app's poll starts a fresh four-Get state read
    // every tick against a node that is not answering, onto the one queue
    // every device shares. Without the second, the retry resumes the instant
    // the previous one gives up, which for a node that is simply gone is the
    // same flood at a slower constant rate.
    if (this.reReadInFlight) return;
    if (this.clock.now() < this.nextReReadAtMs) return;
    this.reReadInFlight = true;
    try {
      await this.reReadState();
      this.reReadFailureStreak = 0;
      this.nextReReadAtMs = 0;
      this.connected = true;
      await this.device.setAvailable();
      // THE BACKFILL PROBE'S ONE TRIGGER — here, at the moment this node has
      // actually ANSWERED, and nowhere else. See `startBackfillProbe` for
      // why this is the only honest moment to start it, and
      // `backfillProbe` for what it does. Deliberately not awaited: the
      // `finally` below must clear `reReadInFlight` now, not in two
      // minutes, or a probe against a slow bulb would block every re-read
      // behind it.
      this.startBackfillProbe();
    } catch (err) {
      this.connected = false;
      this.reReadFailureStreak = Math.min(this.reReadFailureStreak + 1, MAX_RE_READ_FAILURE_STREAK);
      this.nextReReadAtMs = this.clock.now() + reReadBackoffMs(this.reReadFailureStreak);
      await this.device.setUnavailable(`node did not respond after reconnecting (${errorMessage(err)})`);
    } finally {
      this.reReadInFlight = false;
    }
  }

  /**
   * Starts the backfill probe, fire-and-forget, the first time this node is
   * actually reachable.
   *
   * WHY NOT AT DEVICE INIT, which is where this used to be. Homey runs the
   * app's own `onInit` — which only STARTS the connection manager scanning —
   * to completion before any device's `onInit`, so a probe started there
   * writes its first message before the proxy connection exists. It
   * survived only on `queue.ts`'s bounded retry happening to outlast a
   * scan plus a connect, which is not a margin anyone designed: it shrinks
   * the day a scan runs long, or a second bulb is in the mesh, or the
   * connection backoff has already climbed because the lamp was off at the
   * wall. The probe would then spend its whole budget against a link that
   * was never up and leave the node unmeasured — exactly the state this
   * mechanism exists to end, and on the owner's one paired lamp it is the
   * path every app start would take. Hanging it off the first successful
   * re-read instead means the node has provably just answered us.
   *
   * CALLED ON EVERY POLL TICK'S WORTH OF `'connected'`, AND THAT IS FINE.
   * `app.ts` fans `onConnectionStateChange` out to every controller on
   * every tick rather than only on change (a deliberate earlier fix — see
   * that method's own comment). Two independent guards make this once per
   * device per app run anyway: `onConnectionStateChange` returns early
   * while `this.connected` is already true, so a tick storm never reaches
   * here twice; and `backfillProbe` sets `backfillAttempted` before its own
   * first `await`, so even a disconnect/reconnect cycle — which DOES clear
   * `connected` and so does reach here again — starts nothing a second
   * time, and neither does a tick arriving while a probe is still in
   * flight.
   *
   * ONE DISCLOSED GAP. `applyDecodedStatus` can also set `connected` —
   * hearing from a node is evidence it is reachable (see the module
   * header) — and it does NOT start the probe. If an unsolicited status
   * arrived in the narrow window before this controller's very first
   * `'connected'` tick was processed, every later tick would return early
   * and this run would never probe. That is left alone on purpose: adding a
   * second trigger there would start probes off the back of a user's own
   * command, which is the worst possible moment for the no-op write
   * `backfillProbe` documents as its accepted risk. The node simply stays
   * unmeasured until the next app start, which is this mechanism's own
   * retry model.
   */
  private startBackfillProbe(): void {
    // `backfillProbe` is written never to throw; this catch is the
    // belt-and-braces for that promise, since there is no error-reporting
    // channel reachable from here (the same stance `start()` takes for its
    // own fire-and-forget listener, and for the same reason).
    void this.backfillProbe().catch(() => {
      // Nothing productive to do: the record simply stays unmeasured and a
      // later app start tries again.
    });
  }

  // --- Commands ----------------------------------------------------------

  async setOnOff(value: boolean): Promise<void> {
    const tid = this.allocateTid();
    // The ACCESS payload is built once — it carries the transaction
    // identifier, which must be identical across retries. The NETWORK PDU
    // around it is rebuilt per attempt, because it carries the sequence
    // number, which must differ. See queue.ts's own "A RETRY REBUILDS ITS
    // BYTES" note.
    const accessPayload = encodeGenericOnOffSet({ onOff: value ? 1 : 0, tid });
    await this.setOptimistic('onoff', value); // design: "sets the capability immediately"
    const reply = await this.queue.send({
      build: () => this.buildApplicationPdu(accessPayload),
      isStatus: (pdu) => this.tryDecodeModel(ONOFF_MODEL, pdu) !== null,
      description: `Generic OnOff Set (node ${this.address})`,
    });
    const status = this.tryDecodeModel(ONOFF_MODEL, reply);
    if (status !== null) await this.applyDecodedStatus(ONOFF_MODEL, status);
  }

  async setDim(value: number): Promise<void> {
    const tid = this.allocateTid();
    const accessPayload = encodeLightLightnessSet({ lightness: fractionToWire(value), tid });
    await this.setOptimistic('dim', clamp01(value));
    const reply = await this.queue.send({
      build: () => this.buildApplicationPdu(accessPayload),
      isStatus: (pdu) => this.tryDecodeModel(LIGHTNESS_MODEL, pdu) !== null,
      description: `Light Lightness Set (node ${this.address})`,
    });
    const status = this.tryDecodeModel(LIGHTNESS_MODEL, reply);
    if (status !== null) await this.applyDecodedStatus(LIGHTNESS_MODEL, status);
  }

  /**
   * WHICH OF THE TWO COLOUR-TEMPERATURE MESSAGES THIS SENDS is decided per
   * node, from what the node was MEASURED to answer at pairing time
   * (`modelProbe.ts`), not from what it declared and not from a constant.
   * `chooseTemperatureWriteModel` carries the rule; the short version is
   * that `Light CTL Temperature Set` (`0x8264`) is the default and only a
   * positive measurement to the contrary moves off it.
   *
   * WHY THAT DEFAULT: on the owner's bulb, `Light CTL Set` (`0x825E`) is
   * declared and dead — three attempts at each of several values, no answer
   * ever — while `0x8264` is answered correctly and visibly changes the
   * lamp. It is also the better message independently of that bulb, because
   * it carries no Lightness field (Table 6.73 vs Table 6.69), so a
   * temperature change through it cannot disturb brightness. The composite
   * encoder stays in the codebase and stays used: this method still falls
   * back to it for a node measured to run that one and not this one, and
   * READING stays on `Light CTL Get` -> `Light CTL Status` throughout
   * (`reReadState` below), which is measured to work on the same bulb.
   */
  async setLightTemperature(value: number): Promise<void> {
    const tid = this.allocateTid();
    const temperature = homeyToKelvin(value, this.temperatureRange);
    await this.setOptimistic('light_temperature', clamp01(value));
    // The STATUS awaited is always the one belonging to the message
    // actually sent — a Light CTL Temperature Set is answered by `0x8266`,
    // never by the `0x8260` the composite Set would get — which is why each
    // branch names its own model rather than sharing one predicate.
    if (chooseTemperatureWriteModel(this.nodeProbe()) === 'lightCtl') {
      await this.sendModelCommand(
        CTL_MODEL,
        encodeLightCtlSet({
          lightness: fractionToWire(this.currentDimFraction()),
          temperature,
          deltaUv: 0, // not exposed to Homey — see lighting.ts's own field doc comment.
          tid,
        }),
      );
      return;
    }
    await this.sendModelCommand(CTL_TEMPERATURE_MODEL, encodeLightCtlTemperatureSet({ temperature, deltaUv: 0, tid }));
  }

  /** Sends one already-encoded command and applies whatever Status comes
   *  back for that same model — the shape every `set*` method above spells
   *  out inline, factored out here for `setLightTemperature`, whose model is
   *  chosen at runtime and so cannot be a single concrete type at the call
   *  site. */
  private async sendModelCommand<S>(model: LightingModel<S>, accessPayload: Buffer): Promise<void> {
    const reply = await this.queue.send({
      build: () => this.buildApplicationPdu(accessPayload),
      isStatus: (pdu) => this.tryDecodeModel(model, pdu) !== null,
      description: `${model.name} Set (node ${this.address})`,
    });
    const status = this.tryDecodeModel(model, reply);
    if (status !== null) await this.applyDecodedStatus(model, status);
  }

  /** What this node was measured to do at pairing time, read fresh from the
   *  shared store every time rather than cached at construction — the same
   *  "re-read, never a stale snapshot" discipline `currentNetworkContext`
   *  already follows, and it means a re-pair that measures differently takes
   *  effect without reloading the device. `null` for a node paired before the
   *  probe existed, which `chooseTemperatureWriteModel` reads as "no
   *  measurement, keep the default". */
  private nodeProbe(): NodeProbeResult | null {
    return this.store.getState().nodes.find((n) => n.address === this.address)?.probe ?? null;
  }

  /** Hue and saturation travel together (Light HSL Set's own single
   *  message) — `device.ts` registers both through ONE
   *  `registerMultipleCapabilityListener`, which always supplies both
   *  values even when the user only dragged one of the two controls. */
  async setColor(hue: number, saturation: number): Promise<void> {
    const tid = this.allocateTid();
    const accessPayload = encodeLightHslSet({
      lightness: fractionToWire(this.currentDimFraction()),
      hue: fractionToWire(hue),
      saturation: fractionToWire(saturation),
      tid,
    });
    await this.setOptimistic('light_hue', clamp01(hue));
    await this.setOptimistic('light_saturation', clamp01(saturation));
    const reply = await this.queue.send({
      build: () => this.buildApplicationPdu(accessPayload),
      isStatus: (pdu) => this.tryDecodeModel(HSL_MODEL, pdu) !== null,
      description: `Light HSL Set (node ${this.address})`,
    });
    const status = this.tryDecodeModel(HSL_MODEL, reply);
    if (status !== null) await this.applyDecodedStatus(HSL_MODEL, status);
  }

  /**
   * MEASURES A NODE THAT WAS PAIRED BEFORE THE PROBE EXISTED, once, in the
   * background, and stores the result. A no-op for every node that already
   * has a measurement, and for every call after the first in this app run.
   *
   * WHY THIS IS NEEDED AT ALL. The owner's own lamp was paired before
   * `modelProbe.ts` was written, so its stored node record carries an
   * address, a device key and a composition and nothing else. It works
   * today only because `chooseTemperatureWriteModel`'s FALLBACK happens to
   * be the message that bulb obeys - luck, not knowledge, and the wrong
   * message for a node that runs the composite model instead. Re-pairing
   * every bulb to fix that would be a worse answer than measuring them
   * where they stand.
   *
   * NEVER THROWS AND NEVER BLOCKS ANYTHING. `device.ts` starts this without
   * awaiting it, and a failure costs the measurement and nothing else: the
   * record simply stays unmeasured and the NEXT app start tries again. It
   * is never retried in a loop, and never retried within one run.
   *
   * SILENCE IS NOT STORED. A probe whose every verdict came back
   * `'unknown'` - a node that is merely unreachable right now - is
   * discarded rather than written (`modelProbe.ts#isMeaningfulProbeResult`),
   * because storing it would mark the node measured forever and end every
   * future attempt. A probe that learned even one thing is kept.
   *
   * THE CAPABILITIES ARE NOT RE-DERIVED from the new measurement, and that
   * is deliberate rather than an omission: this must be invisible to the
   * user, and silently taking a control off a lamp someone is using would
   * be the opposite of invisible. What the measurement DOES change is which
   * colour-temperature message this controller sends (`nodeProbe()` is read
   * fresh on every command) and what the user's own colour-mode setting was
   * seeded from, which is where capability changes belong.
   *
   * IT RUNS ONLY WHEN THE NODE HAS JUST ANSWERED. `startBackfillProbe` is
   * its one trigger and fires from the successful branch of
   * `onConnectionStateChange`, so by the time this method sends anything,
   * the proxy connection is up and this specific node has replied to a
   * full state re-read. A bulb that is genuinely out of range is never
   * probed at all rather than probed into its own timeout, and stays
   * unmeasured until a later start — the intended outcome.
   *
   * ONE DISCLOSED RISK, stated rather than glossed. Every probe message is a
   * no-op write - the value is READ and the same value written straight
   * back (`modelProbe.ts`'s own "EVERY PROBE IS A NO-OP WRITE" note). At
   * pairing time the lamp was in the user's hands and nothing else was
   * driving it. Here it is in service, so a probe write can in principle
   * land just after the user changed something by other means and put the
   * lamp back by a fraction of a second. The window is one queue round trip,
   * it happens at most once per bulb per app run, and the alternative -
   * leaving every pre-probe bulb permanently unmeasured - is worse. Sharing
   * the controller's own transaction-identifier counter (see
   * `allocateTid` below) is what keeps the probe from going further than
   * that and actually SWALLOWING a user's command as a duplicate.
   */
  async backfillProbe(): Promise<void> {
    if (this.backfillAttempted) return;
    this.backfillAttempted = true;
    const node = this.store.getState().nodes.find((n) => n.address === this.address);
    // `incomplete` is checked alongside "already measured" because the two
    // are the same question asked twice: is there anything here worth
    // measuring? A node whose configuration never completed
    // (`store.ts#NodeEntry.incomplete`) has no application key bound to its
    // models, so every probe message would go unanswered and the
    // measurement would record "this bulb runs nothing" — a confident,
    // wrong verdict that would then outlive the pairing failure that caused
    // it. DEFENCE IN DEPTH, not a reachable path today: `pairing.ts` creates
    // no Homey device for such a node, so no controller is ever constructed
    // over one; this is here so that stays true by construction rather than
    // by the two files agreeing about it.
    if (node === undefined || node.probe !== undefined || node.incomplete === true) return;
    const composition = node.composition;

    await this.probeRunner.run(async () => {
      let result: NodeProbeResult;
      try {
        result = await probeModels(
          {
            transport: this.queueProbeTransport(),
            clock: this.clock,
            probeBudgetMs: BACKFILL_PROBE_BUDGET_MS,
            // The controller's own counter, shared with every command this
            // device sends - see `ModelProbeDeps.allocateTid`'s own note for
            // the collision this prevents.
            allocateTid: () => this.allocateTid(),
          },
          composition,
        );
      } catch {
        // `probeModels` turns an unanswered message and a lost link into
        // ordinary verdicts, so reaching here means something else went
        // wrong entirely (a mesh that is not initialized, say). Leave the
        // record unmeasured; the next start tries again.
        return;
      }
      if (!isMeaningfulProbeResult(result)) return;
      try {
        this.storeProbeResult(result);
      } catch {
        // `NetworkStore.setState` validates every field before writing, so
        // it can refuse. Losing the measurement is the right cost; failing
        // the device's connection handling for it is not.
      }
    });
  }

  /** Writes the measurement into this node's store entry, re-reading the
   *  state immediately before the one `setState` (the discipline every
   *  writer in this project follows) and refusing to resurrect a node that
   *  has been removed meanwhile, or to overwrite a measurement that appeared
   *  while this probe was running. */
  private storeProbeResult(probe: NodeProbeResult): void {
    const fresh = this.store.getState();
    const index = fresh.nodes.findIndex((n) => n.address === this.address);
    if (index === -1) return;
    const current = fresh.nodes[index];
    if (current === undefined || current.probe !== undefined) return;
    const nodes = [...fresh.nodes];
    nodes[index] = { ...current, probe };
    this.store.setState({ ...fresh, nodes });
  }

  /**
   * `modelProbe.ts`'s own transport, over the ORDINARY shared traffic queue
   * rather than a dedicated connection - the probe already takes a transport
   * port precisely so it can be driven either way, and duplicating it here
   * would mean a second copy of the probe plan to keep in step.
   *
   * THE QUEUE OWNS THE PACING, not the probe. `request`'s own `timeoutMs`
   * argument is therefore ignored: the queue has its own per-attempt timeout
   * and its own bounded retry, and nothing here may shorten them without
   * reaching inside a shared object every other device is using too. What
   * this costs is that an unanswered probe message takes the queue's full
   * retry budget rather than `DEFAULT_PROBE_TIMEOUT_MS`, which is what
   * `BACKFILL_PROBE_BUDGET_MS` is sized for.
   *
   * A QUEUE REJECTION BECOMES `null`, NOT A THROW. `ProbeTransport`'s own
   * contract reserves rejection for "the link itself is gone", which ends
   * the probe; here, every attempt being exhausted is exactly the SILENCE
   * the probe is trying to measure, and reporting it as a lost link would
   * turn one model's silence into "stop, we learned nothing" for all the
   * models after it.
   */
  private queueProbeTransport(): ProbeTransport {
    return {
      request: async (accessPayload: Buffer, accept: (pdu: Buffer) => boolean): Promise<Buffer | null> => {
        const description = `capability probe 0x${accessPayload.subarray(0, 2).toString('hex')} (node ${this.address})`;
        let reply: Buffer;
        try {
          reply = await this.queue.send({
            build: () => this.buildApplicationPdu(accessPayload),
            // The SAME reshape every command's own `isStatus` performs:
            // decrypt, re-encode as Opcode || Parameters, and let the
            // probe's own predicate decide. `acceptIncomingPdu`'s
            // `expectedSrc` check inside `decodeApplicationMessage` is what
            // keeps another bulb's status off this request.
            isStatus: (pdu) => {
              const message = this.decodeApplicationMessage(pdu);
              return message !== null && accept(encodeAccessMessage(message));
            },
            description,
          });
        } catch {
          return null;
        }
        const message = this.decodeApplicationMessage(reply);
        return message === null ? null : encodeAccessMessage(message);
      },
    };
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

  /** Sets a capability's value ONLY if the device actually has it — review
   *  finding: every STATUS application already checked `hasCapability`
   *  before writing (each `LightingModel#applyStatus` above), but the
   *  OPTIMISTIC write a command makes up front did not, an inconsistency
   *  between two call sites writing the same capabilities. Harmless with
   *  this project's own wiring (`device.ts` only ever calls a `set*` method
   *  when the matching capability was registered), but defensive
   *  consistency is cheap and this module should not rely on a caller
   *  getting that right. */
  private async setOptimistic(capability: HomeyCapability, value: unknown): Promise<void> {
    if (!this.device.hasCapability(capability)) return;
    await this.device.setCapabilityValue(capability, value);
  }

  /** The brightness to put in a Light CTL Set / Light HSL Set, which both
   *  carry a mandatory Lightness field — see `currentDimFractionFallback`
   *  for the decision about what happens when there is nothing to read. */
  private currentDimFraction(): number {
    if (!this.device.hasCapability('dim')) return currentDimFractionFallback('no-capability');
    const value = this.device.getCapabilityValue('dim');
    if (typeof value !== 'number' || !Number.isFinite(value)) return currentDimFractionFallback('no-value');
    return clamp01(value);
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
      // RELAYED, not the point-to-point 0 this encoder used to default to:
      // this command has to reach THIS node, which is almost never the node
      // currently holding the single shared GATT connection — see
      // `message.ts`'s own TTL note, and the design's "The bulbs relay for
      // each other without our help."
      ttl: RELAYED_TTL,
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
    await model.applyStatus(this.device, status, this.temperatureRange);
    this.connected = true;
    // Hearing from the node is evidence it is reachable, so the re-read
    // backoff that was throttling attempts against its silence no longer
    // applies — otherwise a bulb that came back would stay throttled for up
    // to five minutes after it had already proved itself.
    this.reReadFailureStreak = 0;
    this.nextReReadAtMs = 0;
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
    const reply = await this.queue.send({
      build: () => this.buildApplicationPdu(getPayload),
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
    const buildResetPdu = (): Buffer => {
      const pdus = encodeMeshMessage({
        accessPayload: encodeConfigNodeReset(),
        key: deviceKey,
        keyKind: 'device',
        src: ourAddress,
        dst: this.address,
        netKey,
        ivIndex,
        // Relayed for the same reason a lighting command is: removal happens
        // long after pairing, over the shared proxy connection, and the node
        // being reset is almost never the one that connection is held to. A
        // reset that is never forwarded leaves the bulb bound to a network
        // nobody owns — the exact outcome the design's removal clause exists
        // to prevent, which makes this the single most expensive place in
        // the app to get the TTL wrong.
        ttl: RELAYED_TTL,
        allocateSeq: () => this.store.allocateSequenceBlock(),
      });
      if (pdus.length !== 1) {
        throw new Error(
          `meshLight: expected exactly one Network PDU for node ${this.address}'s Config Node Reset, got ${pdus.length}`,
        );
      }
      return pdus[0] as Buffer;
    };
    const receiveContext: MeshReceiveContext = { key: deviceKey, keyKind: 'device', netKey, ivIndex, expectedSrc: this.address };
    const reply = await this.queue.send({
      // Rebuilt per attempt, for the same reason every lighting command is:
      // a Config Node Reset has no transaction identifier at all, but it does
      // have a sequence number, and a replayed one is discarded. See
      // queue.ts's own "A RETRY REBUILDS ITS BYTES" note.
      build: buildResetPdu,
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
export const __testing = {
  fractionToWire,
  wireToFraction,
  homeyToKelvin,
  kelvinToHomey,
  currentDimFractionFallback,
  RE_READ_BACKOFF_BASE_MS,
  RE_READ_BACKOFF_MAX_MS,
  MAX_RE_READ_FAILURE_STREAK,
  reReadBackoffMs,
};
