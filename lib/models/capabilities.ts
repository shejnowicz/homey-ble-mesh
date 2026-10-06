import { CompositionData } from '../mesh/config/composition';

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
 *   model reported by the node   | Homey capability
 *   ------------------------------|--------------------------------
 *   Generic OnOff Server          | `onoff`
 *   Light Lightness Server        | `dim`
 *   Light CTL Server              | `light_temperature`
 *   Light HSL Server              | `light_hue`, `light_saturation`
 *
 * PLUS: an element reporting BOTH Light CTL Server and Light HSL Server
 * also gets `light_mode` (the capability a bulb uses to say which of the
 * two colour models currently drives it) - reporting only one of the two
 * grants only that row's own capabilities, never `light_mode` on its own.
 * A node reporting only some of the four rows gets only the matching
 * capabilities; one absent from `sigModels` contributes nothing.
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
 * all four pairs, in both the by-value and the by-name table:
 *   - Generic OnOff Server   = 0x1000 (by-value table, Page 139 of 446;
 *     by-name table, Page 141).
 *   - Light Lightness Server = 0x1300 (Page 140; Page 142).
 *   - Light CTL Server       = 0x1303 (Page 140; Page 142).
 *   - Light HSL Server       = 0x1307 (Page 140; Page 142).
 * NOT to be confused with 0x1003 ("Generic Level Client", a neighbouring
 * but entirely different model) - the one published Composition Data Page
 * 0 sample this project already transcribed in
 * `mesh/config/__tests__/vectors.ts` happens to report 0x1003 among its SIG
 * Models, which is why this distinction is called out explicitly here
 * rather than left to be noticed by accident.
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
const MODEL_ID_LIGHT_HSL_SERVER = 0x1307;

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
 */
export function mapCompositionToCapabilities(
  composition: CompositionData,
): ReadonlyArray<CapabilityAssignment> {
  const assignments: CapabilityAssignment[] = [];

  composition.elements.forEach((element, elementIndex) => {
    const hasOnOff = element.sigModels.includes(MODEL_ID_GENERIC_ONOFF_SERVER);
    const hasLightness = element.sigModels.includes(MODEL_ID_LIGHT_LIGHTNESS_SERVER);
    const hasCtl = element.sigModels.includes(MODEL_ID_LIGHT_CTL_SERVER);
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
