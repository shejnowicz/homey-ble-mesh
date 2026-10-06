import { mapCompositionToCapabilities } from '../capabilities';
import { CompositionData, ElementDescription, VendorModelId } from '../../mesh/config/composition';

/**
 * SIG Model IDs used below (Bluetooth SIG Assigned Numbers document,
 * Section 4.1.1 "Mesh Model Identifiers by Value" / Section 4.1.2 "Mesh
 * Model Identifiers by Name" - see `../capabilities.ts`'s own MODEL
 * IDENTIFIER PROVENANCE note for the full fetch/version citation).
 * Transcribed independently here rather than imported from the
 * implementation module, so a transcription slip in one file is not
 * silently mirrored - and left undetected - by the other.
 */
const GENERIC_ONOFF_SERVER = 0x1000;
const LIGHT_LIGHTNESS_SERVER = 0x1300;
const LIGHT_CTL_SERVER = 0x1303;
const LIGHT_HSL_SERVER = 0x1307;

// Two real, but deliberately NON-matching, SIG Model IDs - used to prove
// "no capability" means "correctly discriminated", not "any input gives
// nothing".
const CONFIGURATION_SERVER = 0x0000; // Assigned Numbers, same two tables.
// Adjacent-looking but entirely different from Light CTL Server (0x1303) -
// `capabilities.ts`'s own header calls this swap out explicitly because the
// one published Composition Data Page 0 sample this project already
// transcribed (`mesh/config/__tests__/vectors.ts`) reports this exact value.
const GENERIC_LEVEL_CLIENT = 0x1003;

/**
 * Builds a `CompositionData` object directly, in the shape
 * `composition.ts#parseCompositionData` returns - never a hand-built wire
 * buffer pushed through the parser. The parser is already proven against
 * the Mesh Protocol document elsewhere (`composition.test.ts`); re-deriving
 * its output here from transcribed bytes would test this file's own
 * transcription a second time instead of testing the capability mapping
 * once. The header fields (cid/pid/vid/crpl/features) are irrelevant to
 * `mapCompositionToCapabilities` - fixed placeholders, not transcribed from
 * any sample - only `elements` drives the mapping under test.
 */
function composition(elements: ReadonlyArray<ElementDescription>): CompositionData {
  return {
    cid: 0x0000,
    pid: 0x0000,
    vid: 0x0000,
    crpl: 0x0000,
    features: { relay: false, proxy: false, friend: false, lowPower: false },
    elements,
  };
}

/** One element description - `loc` is likewise irrelevant to this module. */
function element(
  sigModels: ReadonlyArray<number>,
  vendorModels: ReadonlyArray<VendorModelId> = [],
): ElementDescription {
  return { loc: 0x0000, sigModels, vendorModels };
}

describe('mapCompositionToCapabilities', () => {
  describe('one case per row of the design table', () => {
    test('Generic OnOff Server (0x1000) alone gets only onoff', () => {
      const result = mapCompositionToCapabilities(composition([element([GENERIC_ONOFF_SERVER])]));
      expect(result).toEqual([{ capability: 'onoff', elementIndex: 0 }]);
    });

    test('Light Lightness Server (0x1300) alone gets only dim', () => {
      const result = mapCompositionToCapabilities(composition([element([LIGHT_LIGHTNESS_SERVER])]));
      expect(result).toEqual([{ capability: 'dim', elementIndex: 0 }]);
    });

    test('Light CTL Server (0x1303) alone gets only light_temperature - no light_mode without HSL too', () => {
      const result = mapCompositionToCapabilities(composition([element([LIGHT_CTL_SERVER])]));
      expect(result).toEqual([{ capability: 'light_temperature', elementIndex: 0 }]);
    });

    test('Light HSL Server (0x1307) alone gets light_hue and light_saturation - no light_mode without CTL too', () => {
      const result = mapCompositionToCapabilities(composition([element([LIGHT_HSL_SERVER])]));
      expect(result).toEqual([
        { capability: 'light_hue', elementIndex: 0 },
        { capability: 'light_saturation', elementIndex: 0 },
      ]);
    });
  });

  describe('light_mode: only when BOTH colour models are present', () => {
    test('Light CTL Server and Light HSL Server together add light_mode, after the other three', () => {
      const result = mapCompositionToCapabilities(
        composition([element([LIGHT_CTL_SERVER, LIGHT_HSL_SERVER])]),
      );
      expect(result).toEqual([
        { capability: 'light_temperature', elementIndex: 0 },
        { capability: 'light_hue', elementIndex: 0 },
        { capability: 'light_saturation', elementIndex: 0 },
        { capability: 'light_mode', elementIndex: 0 },
      ]);
    });

    test('the same two models declared in the opposite order yield the identical result - output order does not depend on declaration order', () => {
      const declaredCtlFirst = mapCompositionToCapabilities(
        composition([element([LIGHT_CTL_SERVER, LIGHT_HSL_SERVER])]),
      );
      const declaredHslFirst = mapCompositionToCapabilities(
        composition([element([LIGHT_HSL_SERVER, LIGHT_CTL_SERVER])]),
      );
      expect(declaredHslFirst).toEqual(declaredCtlFirst);
    });

    test('all four models on one element: onoff, dim, light_temperature, hue/saturation, then light_mode', () => {
      const result = mapCompositionToCapabilities(
        composition([
          element([GENERIC_ONOFF_SERVER, LIGHT_LIGHTNESS_SERVER, LIGHT_CTL_SERVER, LIGHT_HSL_SERVER]),
        ]),
      );
      expect(result).toEqual([
        { capability: 'onoff', elementIndex: 0 },
        { capability: 'dim', elementIndex: 0 },
        { capability: 'light_temperature', elementIndex: 0 },
        { capability: 'light_hue', elementIndex: 0 },
        { capability: 'light_saturation', elementIndex: 0 },
        { capability: 'light_mode', elementIndex: 0 },
      ]);
    });
  });

  describe('a node reporting only some of the four gets only the matching capabilities', () => {
    test('onoff + dim + CTL, no HSL: light_temperature present, light_mode absent', () => {
      const result = mapCompositionToCapabilities(
        composition([element([GENERIC_ONOFF_SERVER, LIGHT_LIGHTNESS_SERVER, LIGHT_CTL_SERVER])]),
      );
      expect(result).toEqual([
        { capability: 'onoff', elementIndex: 0 },
        { capability: 'dim', elementIndex: 0 },
        { capability: 'light_temperature', elementIndex: 0 },
      ]);
    });
  });

  describe('a node with none of the four models gets an empty list, not a crash', () => {
    test('no SIG models and no vendor models at all', () => {
      const result = mapCompositionToCapabilities(composition([element([])]));
      expect(result).toEqual([]);
    });

    test('an unrelated SIG model (Configuration Server, 0x0000) only', () => {
      const result = mapCompositionToCapabilities(composition([element([CONFIGURATION_SERVER])]));
      expect(result).toEqual([]);
    });

    test('Generic Level Client (0x1003) only - adjacent-looking to, but not, Light CTL Server (0x1303)', () => {
      const result = mapCompositionToCapabilities(composition([element([GENERIC_LEVEL_CLIENT])]));
      expect(result).toEqual([]);
    });
  });

  describe('a node declaring a vendor model only', () => {
    test('a vendor model with no SIG models at all yields an empty list, not a crash', () => {
      const result = mapCompositionToCapabilities(
        composition([element([], [{ companyId: 0x0059, modelId: 0x0002 }])]),
      );
      expect(result).toEqual([]);
    });
  });

  describe('a multi-element node: each capability is attributed to the element that declared it', () => {
    test('three elements, each with a different, non-overlapping subset of models', () => {
      const result = mapCompositionToCapabilities(
        composition([
          // Element 0 (primary): onoff plus a vendor model riding along, to
          // prove the vendor model neither contributes nor interferes.
          element([GENERIC_ONOFF_SERVER], [{ companyId: 0x0059, modelId: 0x0002 }]),
          // Element 1: both colour models - light_mode belongs here, and
          // only here.
          element([LIGHT_CTL_SERVER, LIGHT_HSL_SERVER]),
          // Element 2: dim only.
          element([LIGHT_LIGHTNESS_SERVER]),
        ]),
      );

      expect(result).toEqual([
        { capability: 'onoff', elementIndex: 0 },
        { capability: 'light_temperature', elementIndex: 1 },
        { capability: 'light_hue', elementIndex: 1 },
        { capability: 'light_saturation', elementIndex: 1 },
        { capability: 'light_mode', elementIndex: 1 },
        { capability: 'dim', elementIndex: 2 },
      ]);
    });
  });
});
