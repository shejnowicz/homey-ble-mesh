import { CompositionData, ElementDescription } from '../mesh/config/composition';

/**
 * Decides which Homey capabilities a bulb gets, purely from what the node
 * itself declared in Composition Data Page 0
 * (`mesh/config/composition.ts`'s `parseCompositionData`) - never from a
 * hardcoded per-product list. Each element of the parsed composition is
 * examined independently for the four Server models this project's Homey
 * app actually drives (`models/lighting.ts`'s own four message sets):
 * Generic OnOff, Light Lightness, Light CTL and Light HSL. A capability is
 * attached to an element only when THAT element's own `sigModels` list
 * names the matching Server model; a model declared on one element never
 * grants a capability to another element.
 *
 * THE TABLE (design-fixed):
 *
 *   model reported by the node       | Homey capability
 *   ----------------------------------|--------------------------------
 *   Generic OnOff Server              | `onoff`
 *   Light Lightness Server            | `dim`
 *   Light CTL Server                  | `light_temperature`
 *   Light CTL Temperature Server      | `light_temperature`
 *   Light HSL Server                  | `light_hue`, `light_saturation`
 *
 * The fifth row is the hardware round's addition - see
 * `MODEL_ID_LIGHT_CTL_TEMPERATURE_SERVER` below for why the two
 * colour-temperature models earn the same capability rather than two.
 *
 * PLUS: an element reporting BOTH Light CTL Server and Light HSL Server
 * also gets `light_mode` (the capability a bulb uses to say which of the
 * two colour models currently drives it) - reporting only one of the two
 * grants only that row's own capabilities, never `light_mode` on its own.
 * A node reporting only some of the four rows gets only the matching
 * capabilities; one absent from `sigModels` contributes nothing.
 *
 * DECLARATION IS NO LONGER THE LAST WORD (hardware round). The sentence
 * above - "never from a hardcoded per-product list" - still stands and is
 * still the point; what changed is that a node's own declaration turned out
 * not to be reliable either. The owner's bulb declares a Light CTL Server
 * and never answers a single `Light CTL Set` at any value, and declares
 * Light HSL servers while having no colour emitters at all. So
 * `mapCompositionToCapabilities` now takes an OPTIONAL `probe` argument:
 * what the node was measured to actually do at pairing time
 * (`drivers/light/modelProbe.ts`). It can only ever subtract from the
 * declaration, never add to it, and only on a positive `'unsupported'`
 * measurement - which keeps "we never hardcode a product" true while no
 * longer requiring a node's word to be taken for everything.
 *
 * WHAT THE PROBE CANNOT SETTLE, and therefore what this module still takes
 * on trust:
 *   1. WHETHER A LAMP HAS COLOUR LEDS. The owner's bulb acknowledges
 *      `Light HSL Set` with a correct echo and emits only white; the
 *      manufacturer's own app confirms it is warm-to-cold white only. No
 *      wire probe can see that, so the HSL row stays declaration-driven
 *      here — and that is now only the SEED. The per-device
 *      monocolor/warm/multicolor setting this note used to call "planned"
 *      exists (`drivers/light/colourMode.ts`): what this function returns
 *      is what a lamp STARTS with, and the user's own answer overrides it
 *      afterward by adding and removing the capabilities directly. Do not
 *      try to infer colour emitters here; there is now somewhere proper for
 *      that answer to come from.
 *   2. THE COLOUR-TEMPERATURE RANGE. `Light CTL Temperature Range Get` is
 *      the SIG's own answer and some nodes simply never reply to it (the
 *      owner's does not), which is why `NodeProbeResult.temperatureRange`
 *      is nullable and why `drivers/light/meshLight.ts` resolves the range
 *      from the node, then a per-device setting, then a documented default.
 *
 * VENDOR MODELS (`element.vendorModels`, Table 3.64's 32-bit
 * Company-Identifier + Vendor-Model-Identifier space) are a disjoint
 * identifier space from the four 16-bit SIG Model IDs this function
 * matches against, so there is no numeric overlap to guard against by
 * construction. This function never reads `vendorModels` at all - matching
 * the design's "recorded for diagnostics and otherwise ignored": the
 * composition the caller already holds keeps every vendor model it parsed
 * (`composition.ts` never discards one), available for whatever
 * diagnostics screen elsewhere in the app wants to show it; this function
 * simply adds no capability for them.
 *
 * MODEL IDENTIFIER PROVENANCE - READ BEFORE TOUCHING ANY CONSTANT BELOW.
 * These four values are SIG Model IDs (Mesh Protocol specification,
 * Section 3.8.2: 16 bits, the same `number` representation
 * `composition.ts#ElementDescription.sigModels` already uses) - assigned
 * numbers, not prose, and NOT the same table as `models/lighting.ts`'s own
 * OPCODE constants (those are 2-octet MESSAGE opcodes; a Model ID
 * identifies the MODEL ITSELF, a completely separate Assigned-Numbers
 * table). Both live in the Bluetooth SIG "Assigned Numbers" document - the
 * same document `mesh/config/client.ts` and `models/lighting.ts` already
 * cite for their own opcode constants - re-fetched fresh for this task,
 * 2026-10-07, from
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Assigned_Numbers/out/en/Assigned_Numbers.pdf
 * (HTTP 200, 1,324,070 bytes, "Version Date: 2026-10-05" - byte-for-byte
 * and version-for-version identical to both of those modules' own recorded
 * fetches, confirming this is still the same, unchanged document), Section
 * 4.1 "Mesh Model Identifiers", Section 4.1.1 "Mesh Model Identifiers by
 * Value" and Section 4.1.2 "Mesh Model Identifiers by Name" (filename
 * `assigned_numbers/mesh/mesh_model_uuids.yaml`, "Last Modified:
 * 2024-02-05") - both tables agree, independently, for all four values
 * below. Cross-checked with two separate extractions of the same PDF:
 * `pdftotext -layout` (which lines up the two-column table) and plain
 * `pdftotext` with no layout flag (which still pairs every identifier
 * immediately before the name it belongs to, one per line) - both agree on
 * all four pairs, in both the by-value and the by-name table. Page numbers
 * below were read off by walking the extracted text in document order
 * against each page's own footer line ("Bluetooth SIG Proprietary ... Page
 * N of 446") - content printed before a page's footer is that page's own
 * content, content after it belongs to page N+1 - not guessed from a
 * remembered skim:
 *   - Generic OnOff Server   = 0x1000 (by-value table, Page 139 of 446;
 *     by-name table, Page 142).
 *   - Light Lightness Server = 0x1300 (Page 140; Page 143).
 *   - Light CTL Server       = 0x1303 (Page 140; Page 142).
 *   - Light HSL Server       = 0x1307 (Page 141; Page 143).
 * NOT to be confused with 0x1003 ("Generic Level Client", a neighbouring
 * but entirely different model) - the one published Composition Data Page
 * 0 sample this project already transcribed in
 * `mesh/config/__tests__/vectors.ts` happens to report 0x1003 among its SIG
 * Models, which is why this distinction is called out explicitly here
 * rather than left to be noticed by accident.
 *
 * SIBLING MODELS - NOT TO BE CONFUSED WITH THE SERVER MODEL EITHER. Each of
 * the four families above has at least one adjacent model one or two
 * values away that relates to the very same lamp but is NOT the Server
 * model this table matches on - a Setup Server (the model a config client
 * binds to for factory-reset-style administrative access, Mesh Model
 * specification Section 6.1 "Introduction") or a Client (the model a
 * controller - not the lamp - implements). Declaring only the sibling must
 * never grant the Server row's capability; `__tests__/capabilities.test.ts`
 * pins this per family, with each sibling transcribed from the same two
 * Assigned Numbers tables as the four Server values above, independently
 * of this file:
 *   - Generic OnOff Client   = 0x1001 (by-value Page 139; by-name Page
 *     142) - Generic OnOff has no Setup Server variant.
 *   - Light Lightness Setup Server = 0x1301 (Page 140; Page 143).
 *   - Light CTL Setup Server       = 0x1304 (Page 140; Page 142).
 *   - Light HSL Setup Server       = 0x1308 (Page 141; Page 143).
 *
 * ELEMENT ATTRIBUTION: a capability is recorded with the `elementIndex` of
 * the `CompositionData.elements` entry that declared its model - a plain
 * array index (0 = the primary element, Mesh Protocol Section 2.3.4), not a
 * unicast address (Composition Data Page 0 carries no address field at
 * all - see `composition.ts`'s own module header). A multi-element node
 * therefore yields separate capability assignments per element, each
 * tagged with the element that actually declared the underlying model.
 *
 * NULLISH CONVENTION: this module never produces or accepts `null`. Unlike
 * `composition.ts#parseCompositionData` (which decodes an untrusted wire
 * buffer and must reject malformed input) or `lighting.ts`'s Status
 * decoders (same reason), this function's only input is an
 * already-well-formed, compile-time-typed `CompositionData` - there is no
 * "cannot parse this" case for it to represent. A node matching none of the
 * four rows produces an empty `ReadonlyArray`, never `null`.
 */

// Section 4.1.1/4.1.2 of the Assigned Numbers document (see the module
// header's MODEL IDENTIFIER PROVENANCE note above).
const MODEL_ID_GENERIC_ONOFF_SERVER = 0x1000;
const MODEL_ID_LIGHT_LIGHTNESS_SERVER = 0x1300;
const MODEL_ID_LIGHT_CTL_SERVER = 0x1303;
/**
 * Light CTL Temperature Server - Assigned Numbers, by-value table Page 141
 * of 446, by-name table Page 142, read the same way as the four above.
 * A FIFTH ROW OF THE DESIGN TABLE, added in the hardware round: Mesh Model
 * Section 6.4.4 defines this as its own model (it is the one that answers
 * `Light CTL Temperature Set`, the message the owner's bulb actually obeys),
 * separate from the Light CTL Server next to it, and a node may implement
 * either. It earns the SAME capability as Light CTL Server does,
 * `light_temperature`, because from Homey's side both are simply "this lamp
 * can be told a colour temperature"; which of the two messages is used to
 * tell it is `drivers/light/meshLight.ts`'s decision, informed by the
 * pairing-time probe, not a second capability.
 */
const MODEL_ID_LIGHT_CTL_TEMPERATURE_SERVER = 0x1306;
const MODEL_ID_LIGHT_HSL_SERVER = 0x1307;

/**
 * The same four SIG Model IDs this module matches against (see the module
 * header's MODEL IDENTIFIER PROVENANCE note), exported so a caller that must
 * enumerate exactly "the node's models" this design's table cares about —
 * the pairing flow binds the application key to each one it finds, per
 * element (docs/superpowers/specs/2026-10-06-ble-mesh-provisioner-design.md:
 * "binds the key to the node's models") — reads the SAME set this function
 * matches, rather than re-transcribing these assigned numbers a second time
 * in `drivers/light/pairing.ts`. Order is this module's own table order; a
 * caller enumerating per-element bind targets should not rely on it for
 * anything beyond iteration (there is no ordering requirement on Model App
 * Bind, Section 4.3.2.46).
 */
export const LIGHTING_SERVER_MODEL_IDS: ReadonlyArray<number> = [
  MODEL_ID_GENERIC_ONOFF_SERVER,
  MODEL_ID_LIGHT_LIGHTNESS_SERVER,
  MODEL_ID_LIGHT_CTL_SERVER,
  // Bound TOO, and this is load-bearing rather than tidy: an application
  // key is bound per MODEL, so without this entry a node's Light CTL
  // Temperature Server would never accept an application-key-secured
  // `Light CTL Temperature Set` at all - the exact message the owner's bulb
  // is the only one it obeys. A node that does not declare this model
  // simply has nothing to bind here (the caller skips any model the element
  // does not list), so adding it costs a node that lacks it nothing.
  MODEL_ID_LIGHT_CTL_TEMPERATURE_SERVER,
  MODEL_ID_LIGHT_HSL_SERVER,
];

// ===========================================================================
// What a node was MEASURED to do, as opposed to what it declared - see
// `drivers/light/modelProbe.ts` for how this is obtained and
// `mapCompositionToCapabilities` below for how it overrides the declaration.
// ===========================================================================

/**
 * The lighting models this project can probe, named rather than numbered so
 * a stored probe result stays readable (and diff-able) in Homey's settings.
 * `lightCtl` and `lightCtlTemperature` are listed SEPARATELY on purpose:
 * they are different models with different opcodes, and the owner's own
 * bulb answers one and not the other while declaring both.
 */
export type ProbedModel = 'genericOnOff' | 'lightLightness' | 'lightCtl' | 'lightCtlTemperature' | 'lightHsl';

/**
 * What the probe concluded about one model.
 *   - `'supported'`: its acknowledged Set was answered with its own Status.
 *   - `'unsupported'`: its acknowledged Set was sent and nothing came back.
 *   - `'unknown'`: it was never probed, or could not be (no way to read the
 *     current value first, so no no-op write to send), or the probe ran out
 *     of its budget before reaching it. An `'unknown'` never overrides the
 *     declaration; only `'unsupported'` does.
 */
export type ModelProbeVerdict = 'supported' | 'unsupported' | 'unknown';

/** A kelvin range a node reported for itself (Mesh Model Table 6.8). */
export interface TemperatureRange {
  readonly minKelvin: number;
  readonly maxKelvin: number;
}

/**
 * One node's measured behaviour, stored alongside its composition (see
 * `lib/adapter/store.ts#NodeEntry`).
 *
 * `temperatureRange` is `null` whenever the node did not answer
 * `Light CTL Temperature Range Get`, or answered it with Table 6.8's own
 * 0xFFFF "unknown" row - both of which leave this app with no measured
 * range, which is a different thing from a range of zero width.
 */
export interface NodeProbeResult {
  readonly models: Readonly<Partial<Record<ProbedModel, ModelProbeVerdict>>>;
  readonly temperatureRange: TemperatureRange | null;
}

/** Reads one model's verdict, treating an absent entry as `'unknown'` - the conservative direction, since only `'unsupported'` ever removes a capability. */
export function probeVerdict(probe: NodeProbeResult | null | undefined, model: ProbedModel): ModelProbeVerdict {
  return probe?.models[model] ?? 'unknown';
}

/**
 * Which of the two colour-temperature models a controller should SEND to
 * this node.
 *
 * The default is `'lightCtlTemperature'` (`Light CTL Temperature Set`,
 * `0x8264`) and that is deliberately the FALLBACK rather than a rule: it is
 * what the owner's own bulb obeys, measured, and it is also the better
 * message on its own merits (it carries no Lightness field, so a
 * temperature change cannot disturb brightness - see `lighting.ts`'s own
 * note on Table 6.73 vs Table 6.69). The ONLY thing that moves this off the
 * default is a measurement that positively contradicts it: the Temperature
 * model probed `'unsupported'` AND the composite model probed
 * `'supported'`. Two `'unknown'`s, or a node that was never probed at all,
 * keep the default - silence from a probe is not evidence against it.
 */
export function chooseTemperatureWriteModel(probe: NodeProbeResult | null | undefined): 'lightCtl' | 'lightCtlTemperature' {
  const temperature = probeVerdict(probe, 'lightCtlTemperature');
  const composite = probeVerdict(probe, 'lightCtl');
  if (temperature === 'unsupported' && composite === 'supported') return 'lightCtl';
  return 'lightCtlTemperature';
}

/** The Homey capability identifiers this mapping ever produces: the design's fixed table, plus `light_mode`. */
export type HomeyCapability =
  | 'onoff'
  | 'dim'
  | 'light_temperature'
  | 'light_hue'
  | 'light_saturation'
  | 'light_mode';

/**
 * One capability the device should have, and the element that earned it -
 * `elementIndex` is a plain index into the `CompositionData.elements` array
 * that was passed to `mapCompositionToCapabilities` (see the module
 * header's ELEMENT ATTRIBUTION note).
 */
export interface CapabilityAssignment {
  readonly capability: HomeyCapability;
  readonly elementIndex: number;
}

/**
 * Maps a parsed composition to the Homey capabilities its elements earn,
 * per the module header's table. Order within one element's own
 * contribution is the table's row order (`onoff`, `dim`,
 * `light_temperature`, `light_hue`, `light_saturation`), with `light_mode`
 * appended last when both colour models are present; elements are visited
 * in `composition.elements` order. Never throws and never returns `null` -
 * see the module header's NULLISH CONVENTION note.
 *
 * `probe`, when supplied, is what the node was MEASURED to do at pairing
 * time (`drivers/light/modelProbe.ts`). It can only ever REMOVE a
 * capability the declaration would have granted, never add one: a model the
 * node never declared is never probed in the first place, and a probe
 * verdict of `'unknown'` leaves the declaration untouched. Omitting it
 * entirely reproduces this function's pre-probe behaviour exactly, which is
 * what every already-paired node (whose store entry has no probe result)
 * relies on.
 */
export function mapCompositionToCapabilities(
  composition: CompositionData,
  probe?: NodeProbeResult | null,
): ReadonlyArray<CapabilityAssignment> {
  const assignments: CapabilityAssignment[] = [];

  /** A model the element DECLARED and the probe did not positively rule
   *  out. Only `'unsupported'` - an acknowledged Set that was sent and
   *  never answered - removes anything; `'unknown'` leaves the declaration
   *  standing, which is what makes a node this app never probed behave
   *  exactly as it did before the probe existed. */
  const measuredAsPresent = (element: ElementDescription, modelId: number, model: ProbedModel): boolean =>
    element.sigModels.includes(modelId) && probeVerdict(probe, model) !== 'unsupported';

  composition.elements.forEach((element, elementIndex) => {
    const hasOnOff = measuredAsPresent(element, MODEL_ID_GENERIC_ONOFF_SERVER, 'genericOnOff');
    const hasLightness = measuredAsPresent(element, MODEL_ID_LIGHT_LIGHTNESS_SERVER, 'lightLightness');
    // EITHER colour-temperature model earns `light_temperature`, and the
    // capability survives as long as at least one of the two the element
    // actually declared was not ruled out. The owner's own bulb is exactly
    // this case: it declares both, the composite one is measured
    // `'unsupported'`, the Temperature one `'supported'` - and the lamp can
    // plainly change colour temperature, so dropping the capability because
    // one of the two models is a lie would be the wrong answer.
    const hasCtl =
      measuredAsPresent(element, MODEL_ID_LIGHT_CTL_SERVER, 'lightCtl') ||
      measuredAsPresent(element, MODEL_ID_LIGHT_CTL_TEMPERATURE_SERVER, 'lightCtlTemperature');
    // HSL IS DELIBERATELY NOT PROBE-GATED - see the module header's own
    // "WHAT THE PROBE CANNOT SETTLE" note. A bulb with no colour emitters
    // at all still acknowledges Light HSL Set with a correct echo, so the
    // probe's `'supported'` here means only "the model answers", never "the
    // lamp has colour LEDs", and its `'unsupported'` would be the only
    // useful half - too little to justify treating this row differently
    // from the declaration. The per-device monocolor/warm/multicolor
    // setting (`drivers/light/colourMode.ts`) is what resolves it properly,
    // one layer up: this row is the SEED that setting starts from, not the
    // last word on it.
    const hasHsl = element.sigModels.includes(MODEL_ID_LIGHT_HSL_SERVER);

    if (hasOnOff) {
      assignments.push({ capability: 'onoff', elementIndex });
    }
    if (hasLightness) {
      assignments.push({ capability: 'dim', elementIndex });
    }
    if (hasCtl) {
      assignments.push({ capability: 'light_temperature', elementIndex });
    }
    if (hasHsl) {
      assignments.push({ capability: 'light_hue', elementIndex });
      assignments.push({ capability: 'light_saturation', elementIndex });
    }
    if (hasCtl && hasHsl) {
      assignments.push({ capability: 'light_mode', elementIndex });
    }

    // `element.vendorModels` is deliberately never read here - see the
    // module header's VENDOR MODELS note.
  });

  return assignments;
}
