import {
  encodeGenericOnOffGet,
  encodeGenericOnOffSet,
  decodeGenericOnOffStatus,
  encodeLightLightnessGet,
  encodeLightLightnessSet,
  decodeLightLightnessStatus,
  encodeLightCtlGet,
  encodeLightCtlSet,
  decodeLightCtlStatus,
  encodeLightCtlTemperatureSet,
  decodeLightCtlTemperatureStatus,
  encodeLightCtlTemperatureRangeGet,
  decodeLightCtlTemperatureRangeStatus,
  encodeLightHslGet,
  encodeLightHslSet,
  decodeLightHslStatus,
  CTL_TEMPERATURE_RANGE_UNKNOWN,
} from '../../lib/models/lighting';
import type {
  ModelProbeVerdict,
  NodeProbeResult,
  ProbedModel,
  TemperatureRange,
} from '../../lib/models/capabilities';
import type { CompositionData } from '../../lib/mesh/config/composition';

/**
 * MEASURING WHAT A NODE ACTUALLY DOES, instead of believing what it says.
 *
 * THE DEFECT THIS EXISTS FOR, measured on the owner's own bulb and not
 * theorised: a Tuya-made CCT lamp (cid=2000, pid=768, one element) declares
 * a Light CTL Server in its composition data and never answers a single
 * `Light CTL Set` (`0x825E`) at any value, three attempts each - while
 * answering `Light CTL Temperature Set` (`0x8264`) correctly, with the lamp
 * visibly changing colour. Composition data is a node's own claim about
 * itself, and this one is false. Hardcoding "use 0x8264" would be right for
 * this bulb and wrong as a rule, so this module measures instead, once, at
 * pairing time, and `lib/models/capabilities.ts` derives the Homey
 * capabilities from the measurement where there is one.
 *
 * WHY SILENCE IS CONCLUSIVE HERE, AND ONLY HERE. This project's standing
 * rule - written into `drivers/light/meshLight.ts`'s own header and the
 * design before it - is that silence is NOT evidence: a command's echo is
 * what we asked for, not what happened, and a node that says nothing has
 * told us nothing. That rule is about UNACKNOWLEDGED outcomes. Every
 * message this module sends is an ACKNOWLEDGED Set, and the specification
 * makes answering it mandatory for a server that implements the model:
 * e.g. Mesh Model Section 6.4.4.2.2, quoted, "If the received message is a
 * Light CTL Temperature Set message, the Light CTL Server shall respond
 * with a Light CTL Temperature Status message", and the identical "shall
 * respond" clause for each of the other models. So within this module's own
 * bounded window, over a direct GATT connection to the very node being
 * configured, with the application key just bound to its models, silence IS
 * the negative result - not an absence of evidence but the specified
 * behaviour of a node that does not implement the model. It is still a
 * measurement over a radio, so a false `'unsupported'` is possible (a lost
 * segment, a node busy at exactly the wrong moment); that is why an
 * `'unsupported'` only ever REMOVES a capability the node also has another
 * route to (see `capabilities.ts#mapCompositionToCapabilities`), never
 * strands a lamp with nothing.
 *
 * EVERY PROBE IS A NO-OP WRITE. The lamp is in the user's hands while
 * pairing runs, so a probe that changed what it looks like would be a
 * defect of its own. Each model is therefore READ first (its own Get, or
 * the composite `Light CTL Get` for the two colour-temperature models - see
 * `PROBE_PLAN` below) and then written back EXACTLY what came back. A model
 * whose current value cannot be read is not probed at all: it is recorded
 * `'unknown'` and its declaration stands, because there is no way to poke
 * it without possibly moving it.
 *
 * THE ONE FIELD THAT CANNOT BE READ BACK, disclosed rather than glossed:
 * CTL Delta UV. `Light CTL Status` (Table 6.71) does not carry it at all,
 * and the one message that does (`Light CTL Temperature Status`, Table
 * 6.75) only arrives in answer to the very Set this module is trying to
 * decide whether to send. Both colour-temperature probes therefore write
 * Delta UV 0 rather than the node's current value. This is not a free pass:
 * it means the probe can, in principle, move a lamp whose Delta UV is
 * non-zero. It is accepted because 0 is the exact value every Light CTL /
 * Light CTL Temperature Set this app will ever send already carries
 * (`meshLight.ts` never exposes Delta UV to Homey), so the probe cannot put
 * the lamp anywhere its ordinary use would not - and because the
 * alternative, skipping the colour-temperature probe entirely, would skip
 * the one measurement this whole module was written for.
 *
 * COST IS BOUNDED TWICE, because a node that answers nothing must not
 * stretch pairing by one timeout per model: a short PER-PROBE timeout
 * (`DEFAULT_PROBE_TIMEOUT_MS`) and a TOTAL budget
 * (`DEFAULT_PROBE_BUDGET_MS`) after which every model not yet reached is
 * recorded `'unknown'` and the probe returns. A read that goes unanswered
 * also skips its own write, so a completely silent node costs one timeout
 * per READ, not one per read and one per write.
 *
 * PURE, LIKE `pairing.ts` NEXT TO IT: this module imports no `homey` and
 * performs no I/O. It takes a `ProbeTransport` - one bounded
 * request/response over the configuration session, which `pairing.ts`
 * supplies - and a clock, so `__tests__/modelProbe.test.ts` can drive the
 * whole thing against a fake node that answers some models and not others.
 *
 * NULLISH CONVENTION: `null` throughout, matching every neighbouring
 * module - `temperatureRange` is `null` when nothing was measured, never
 * `undefined`.
 */

// ===========================================================================
// Ports.
// ===========================================================================

/**
 * One bounded request/response against the node being paired, secured with
 * the APPLICATION key (not the device key the Config messages use - the
 * lighting models answer on the key that was just bound to them).
 *
 * `accept` is what tells a real answer from an unrelated notification: the
 * implementation must keep waiting, within the same `timeoutMs` window, for
 * a PDU `accept` returns `true` for, rather than resolving on the first
 * thing that arrives. That matters because a previous probe's LATE answer
 * can still be in flight - resolving on it would turn one model's silence
 * into another model's false `'supported'`.
 *
 * Resolves `null` when the window closed with nothing acceptable - an
 * EXPECTED outcome here, the probe's negative result, never an error.
 * Rejects only when the link itself is gone, which ends the probe.
 */
export interface ProbeTransport {
  request(accessPayload: Buffer, accept: (pdu: Buffer) => boolean, timeoutMs: number): Promise<Buffer | null>;
}

/** Exactly the one `ClockPort` member this module needs - `now()` only, for the total budget; the per-probe timer belongs to the transport. */
export interface ProbeClockPort {
  now(): number;
}

export interface ModelProbeDeps {
  readonly transport: ProbeTransport;
  readonly clock: ProbeClockPort;
  /** Overrides `DEFAULT_PROBE_TIMEOUT_MS` - injected so tests drive it. */
  readonly probeTimeoutMs?: number;
  /** Overrides `DEFAULT_PROBE_BUDGET_MS` - injected so tests drive it. */
  readonly probeBudgetMs?: number;
}

// ===========================================================================
// Timing. Not specification values - engineering choices, documented the
// same way `pairing.ts`'s own DEFAULT_PAIRING_STEP_TIMEOUT_MS and
// `queue.ts`'s timeouts are.
// ===========================================================================

/**
 * 1500 ms per probe message.
 *
 * WHY THIS NUMBER. Every probe rides the SAME still-open GATT connection to
 * the very node being configured (`pairing.ts`'s configuration session), so
 * there is no relay hop and no shared-queue contention: it is one ATT write
 * and one notification over an already-established link. The Config
 * messages that ran moments earlier on this same session - Composition Data
 * Get, AppKey Add, one Model App Bind per model - are the same shape and
 * are measured in tens of milliseconds, so 1500 ms is roughly two orders of
 * magnitude of headroom over what an answering node needs, while being
 * short enough that the worst case stays comfortably inside pairing's own
 * 30 s step timeout rather than doubling the time a user waits.
 *
 * It is deliberately NOT generous. A long timeout here buys nothing: a node
 * that implements the model answers almost immediately or not at all, and
 * every second spent waiting is a second the user watches a spinner, once
 * per model, on every bulb they pair.
 */
export const DEFAULT_PROBE_TIMEOUT_MS = 1500;

/**
 * 9000 ms for the whole probe, checked before each message is sent.
 *
 * Six probe steps can be reached on a four-model node (one read per model,
 * one write per model that answered, plus the range query), so the per-probe
 * timeout alone bounds the worst case at about nine seconds - this budget
 * is what keeps that true if the plan ever grows another model, and what
 * stops a node that answers everything slowly from being probed for longer
 * than pairing can afford. Reached-the-budget is recorded as `'unknown'`,
 * never as `'unsupported'`: running out of time says nothing about the node.
 */
export const DEFAULT_PROBE_BUDGET_MS = 9000;

/** The TID every probe message carries - see `probeModels`'s own note. */
const PROBE_FIRST_TID = 0;

// ===========================================================================
// The probe plan: how each model is read, and what writing it back looks
// like.
// ===========================================================================

/** A value read back from a node, enough to write the identical thing again. */
interface ReadValue {
  readonly onOff?: number;
  readonly lightness?: number;
  readonly temperature?: number;
  readonly hue?: number;
  readonly saturation?: number;
}

/**
 * HOW EACH MODEL IS READ. Three of the five have their own Get; the two
 * colour-temperature models share the composite `Light CTL Get` (`0x825D`),
 * for two independent reasons:
 *   - it is MEASURED to work on the owner's bulb (it answers a `Light CTL
 *     Status` reporting the live temperature), whereas that same bulb was
 *     never observed answering `Light CTL Temperature Get` (`0x8261`) at
 *     all - that message was never actually probed, so nothing is known
 *     about it either way, and a read that is known to work beats one that
 *     is merely likely to;
 *   - the composite read answers BOTH models' needs in one message
 *     (Lightness for the composite Set, Temperature for both), which is one
 *     fewer round trip on every bulb this app will ever pair.
 */
type ReadKind = 'genericOnOff' | 'lightLightness' | 'lightCtl' | 'lightHsl';

interface ProbeStep {
  readonly model: ProbedModel;
  /** The SIG Model ID the element must declare for this step to run at all. */
  readonly modelId: number;
  /** Which read this step's no-op write is built from. */
  readonly readKind: ReadKind;
  /** Builds the no-op Set from what the read returned, or `null` when the read did not supply what this message needs. */
  buildSet(value: ReadValue, tid: number): Buffer | null;
  /** Does this PDU decode as this model's own Status? */
  isStatus(pdu: Buffer): boolean;
}

// SIG Model IDs - transcribed here from the Assigned Numbers document
// independently of `lib/models/capabilities.ts`'s own copy, deliberately:
// this module and that one must agree about which model a probe result is
// ABOUT, and a shared constant would make a transcription slip invisible in
// both at once. Section 4.1.1 "by Value" / Section 4.1.2 "by Name".
const MODEL_ID_GENERIC_ONOFF_SERVER = 0x1000;
const MODEL_ID_LIGHT_LIGHTNESS_SERVER = 0x1300;
const MODEL_ID_LIGHT_CTL_SERVER = 0x1303;
const MODEL_ID_LIGHT_CTL_TEMPERATURE_SERVER = 0x1306;
const MODEL_ID_LIGHT_HSL_SERVER = 0x1307;

/**
 * Light CTL Delta UV, written as 0 by both colour-temperature probes - see
 * the module header's "THE ONE FIELD THAT CANNOT BE READ BACK" note for why
 * this one field is not read first, and why that is acceptable rather than
 * merely convenient.
 */
const PROBE_DELTA_UV = 0;

const PROBE_PLAN: ReadonlyArray<ProbeStep> = [
  {
    model: 'genericOnOff',
    modelId: MODEL_ID_GENERIC_ONOFF_SERVER,
    readKind: 'genericOnOff',
    buildSet: (value, tid) =>
      value.onOff === undefined ? null : encodeGenericOnOffSet({ onOff: value.onOff === 0 ? 0 : 1, tid }),
    isStatus: (pdu) => decodeGenericOnOffStatus(pdu) !== null,
  },
  {
    model: 'lightLightness',
    modelId: MODEL_ID_LIGHT_LIGHTNESS_SERVER,
    readKind: 'lightLightness',
    buildSet: (value, tid) =>
      value.lightness === undefined ? null : encodeLightLightnessSet({ lightness: value.lightness, tid }),
    isStatus: (pdu) => decodeLightLightnessStatus(pdu) !== null,
  },
  {
    model: 'lightCtl',
    modelId: MODEL_ID_LIGHT_CTL_SERVER,
    readKind: 'lightCtl',
    buildSet: (value, tid) =>
      value.lightness === undefined || value.temperature === undefined
        ? null
        : encodeLightCtlSet({ lightness: value.lightness, temperature: value.temperature, deltaUv: PROBE_DELTA_UV, tid }),
    isStatus: (pdu) => decodeLightCtlStatus(pdu) !== null,
  },
  {
    model: 'lightCtlTemperature',
    modelId: MODEL_ID_LIGHT_CTL_TEMPERATURE_SERVER,
    readKind: 'lightCtl',
    buildSet: (value, tid) =>
      value.temperature === undefined
        ? null
        : encodeLightCtlTemperatureSet({ temperature: value.temperature, deltaUv: PROBE_DELTA_UV, tid }),
    isStatus: (pdu) => decodeLightCtlTemperatureStatus(pdu) !== null,
  },
  {
    model: 'lightHsl',
    modelId: MODEL_ID_LIGHT_HSL_SERVER,
    readKind: 'lightHsl',
    buildSet: (value, tid) =>
      value.lightness === undefined || value.hue === undefined || value.saturation === undefined
        ? null
        : encodeLightHslSet({ lightness: value.lightness, hue: value.hue, saturation: value.saturation, tid }),
    isStatus: (pdu) => decodeLightHslStatus(pdu) !== null,
  },
];

/** The Get message and reply decoder behind each `ReadKind`. */
const READS: Readonly<Record<ReadKind, { get(): Buffer; parse(pdu: Buffer): ReadValue | null }>> = {
  genericOnOff: {
    get: encodeGenericOnOffGet,
    parse: (pdu) => {
      const status = decodeGenericOnOffStatus(pdu);
      return status === null ? null : { onOff: status.presentOnOff };
    },
  },
  lightLightness: {
    get: encodeLightLightnessGet,
    parse: (pdu) => {
      const status = decodeLightLightnessStatus(pdu);
      return status === null ? null : { lightness: status.presentLightness };
    },
  },
  lightCtl: {
    get: encodeLightCtlGet,
    parse: (pdu) => {
      const status = decodeLightCtlStatus(pdu);
      return status === null ? null : { lightness: status.presentLightness, temperature: status.presentTemperature };
    },
  },
  lightHsl: {
    get: encodeLightHslGet,
    parse: (pdu) => {
      const status = decodeLightHslStatus(pdu);
      return status === null ? null : { lightness: status.lightness, hue: status.hue, saturation: status.saturation };
    },
  },
};

// ===========================================================================
// The probe itself.
// ===========================================================================

/** Every SIG model any element of this node declared, flattened - the probe
 *  asks about the NODE, because every message it sends is addressed to the
 *  node's primary unicast address, which is the only address pairing has
 *  allocated by the time this runs. */
function declaredModelIds(composition: CompositionData): ReadonlySet<number> {
  const ids = new Set<number>();
  for (const element of composition.elements) {
    for (const modelId of element.sigModels) ids.add(modelId);
  }
  return ids;
}

/**
 * Probes every lighting model `composition` declares and returns what each
 * one actually did, plus the node's own colour-temperature range if it is
 * willing to report one.
 *
 * NEVER THROWS for a probe that simply did not work out - an unanswered
 * message, a read that could not be parsed, a budget that ran out are all
 * ordinary results recorded as verdicts. A transport REJECTION (the link
 * itself is gone) ends the probe early: everything already measured is
 * kept, everything not yet reached stays `'unknown'`, and the caller gets
 * that partial result rather than an exception, because a probe is an
 * optimisation of a pairing that has otherwise already succeeded and must
 * never be the thing that fails it.
 *
 * THE TRANSACTION IDENTIFIER. Each probe Set carries its own TID from a
 * counter starting at `PROBE_FIRST_TID`, so two probes of DIFFERENT models
 * never collide on the (SRC, DST, TID) uniqueness key within the same 6
 * second window (`lighting.ts`'s own transcription of that rule). The
 * counter is local to one probe run because a probe run is the only thing
 * that exists at this point: the node has no `MeshLightController` yet, and
 * will allocate its own identifiers from zero when it gets one - harmless,
 * since by then this probe's own window has long closed and, more to the
 * point, writing back the value just read is a no-op whether it is applied
 * once or twice.
 */
export async function probeModels(deps: ModelProbeDeps, composition: CompositionData): Promise<NodeProbeResult> {
  const timeoutMs = deps.probeTimeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
  const budgetMs = deps.probeBudgetMs ?? DEFAULT_PROBE_BUDGET_MS;
  const deadline = deps.clock.now() + budgetMs;
  const declared = declaredModelIds(composition);

  const models: Partial<Record<ProbedModel, ModelProbeVerdict>> = {};
  const readCache = new Map<ReadKind, ReadValue | null>();
  let temperatureRange: TemperatureRange | null = null;
  let tid = PROBE_FIRST_TID;
  let linkLost = false;

  const outOfBudget = (): boolean => deps.clock.now() >= deadline;

  /** One bounded request, turning a lost link into "stop probing" rather than an exception. */
  const ask = async (payload: Buffer, accept: (pdu: Buffer) => boolean): Promise<Buffer | null> => {
    if (linkLost) return null;
    try {
      return await deps.transport.request(payload, accept, timeoutMs);
    } catch {
      linkLost = true;
      return null;
    }
  };

  /** Reads one value at most once per probe run - `lightCtl` is shared by two steps. */
  const readOnce = async (kind: ReadKind): Promise<ReadValue | null> => {
    const cached = readCache.get(kind);
    if (cached !== undefined) return cached;
    const read = READS[kind];
    const reply = await ask(read.get(), (pdu) => read.parse(pdu) !== null);
    const value = reply === null ? null : read.parse(reply);
    readCache.set(kind, value);
    return value;
  };

  for (const step of PROBE_PLAN) {
    if (!declared.has(step.modelId)) continue;
    // Declared but not reached: `'unknown'`, never `'unsupported'`. Running
    // out of time is not a measurement.
    if (linkLost || outOfBudget()) {
      models[step.model] = 'unknown';
      continue;
    }
    const value = await readOnce(step.readKind);
    if (value === null) {
      // No way to read the current value, so no no-op write to send - the
      // module header's own rule. Prefer the declaration.
      models[step.model] = 'unknown';
      continue;
    }
    const setPayload = step.buildSet(value, tid);
    if (setPayload === null) {
      models[step.model] = 'unknown';
      continue;
    }
    tid = (tid + 1) & 0xff;
    if (outOfBudget()) {
      models[step.model] = 'unknown';
      continue;
    }
    const reply = await ask(setPayload, step.isStatus);
    if (linkLost) {
      models[step.model] = 'unknown';
      continue;
    }
    // THE MEASUREMENT. An answer is support; silence is not - see the
    // module header's "WHY SILENCE IS CONCLUSIVE HERE" note for why this
    // one place is allowed to read silence as a negative at all.
    models[step.model] = reply === null ? 'unsupported' : 'supported';
  }

  // The range query is addressed to the Light CTL Server (Mesh Model
  // Section 6.4.3.3.1: "When a Light CTL Server receives a Light CTL
  // Temperature Range Get message, it shall respond with a Light CTL
  // Temperature Range Status message") - NOT to the Light CTL Temperature
  // Server, so it is asked whenever the composite model is declared,
  // independently of how the Set probes above turned out.
  if (declared.has(MODEL_ID_LIGHT_CTL_SERVER) && !linkLost && !outOfBudget()) {
    const reply = await ask(encodeLightCtlTemperatureRangeGet(), (pdu) => decodeLightCtlTemperatureRangeStatus(pdu) !== null);
    const status = reply === null ? null : decodeLightCtlTemperatureRangeStatus(reply);
    temperatureRange = status === null ? null : toTemperatureRange(status.rangeMin, status.rangeMax);
  }

  return { models, temperatureRange };
}

/**
 * Turns a Range Status's two raw fields into a usable range, or `null`.
 *
 * `null` for three distinct reasons, all of which mean "this node did not
 * actually tell us its range":
 *   - either field is Table 6.8's own 0xFFFF row, "The color temperature of
 *     white light is unknown" - an answer that says nothing;
 *   - either field is outside Table 6.6's legal 0x0320-0x4E20 span, which
 *     Table 6.8 calls Prohibited;
 *   - min is not below max, which is not a range.
 * The Status Code itself is deliberately NOT consulted: Table 7.1's
 * non-success codes ("Cannot Set Range Min/Max") describe the last attempt
 * to WRITE the range, which this app never makes, and a node reporting one
 * alongside a perfectly good range is reporting a perfectly good range.
 */
export function toTemperatureRange(rangeMin: number, rangeMax: number): TemperatureRange | null {
  if (rangeMin === CTL_TEMPERATURE_RANGE_UNKNOWN || rangeMax === CTL_TEMPERATURE_RANGE_UNKNOWN) return null;
  const legal = (value: number): boolean => value >= 0x0320 && value <= 0x4e20;
  if (!legal(rangeMin) || !legal(rangeMax)) return null;
  if (rangeMin >= rangeMax) return null;
  return { minKelvin: rangeMin, maxKelvin: rangeMax };
}
