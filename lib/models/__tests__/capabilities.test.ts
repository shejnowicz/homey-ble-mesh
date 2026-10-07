import {
  mapCompositionToCapabilities,
  chooseTemperatureWriteModel,
  probeVerdict,
  LIGHTING_SERVER_MODEL_IDS,
  type NodeProbeResult,
} from '../capabilities';
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
// The fifth row of the design table, added in the hardware round: a
// SEPARATE model from Light CTL Server, and the one that answers the
// message the owner's bulb actually obeys (Mesh Model Section 6.4.4).
const LIGHT_CTL_TEMPERATURE_SERVER = 0x1306;
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
 * One adjacent sibling per Server model family above - the Setup Server or
 * Client variant that relates to the very same lamp but is NOT the Server
 * model the design's table matches on. Transcribed from the same two
 * Assigned Numbers tables, independently of `capabilities.ts` (see that
 * module's own SIBLING MODELS note) - not guessed from the family's own
 * numbering pattern, because the families are not uniformly spaced
 * (Generic OnOff has no Setup Server at all; the others do).
 */
const GENERIC_ONOFF_CLIENT = 0x1001; // Generic OnOff's only sibling - no Setup Server exists for it.
const LIGHT_LIGHTNESS_SETUP_SERVER = 0x1301;
const LIGHT_CTL_SETUP_SERVER = 0x1304;
const LIGHT_HSL_SETUP_SERVER = 0x1308;

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

  describe('a node declaring only a family sibling (Setup Server/Client) gets no capability for that family', () => {
    // Each sibling is a real, adjacent, same-family model that genuinely
    // relates to the same lamp (a config client binds to the Setup Server;
    // a controller implements the Client) - exactly the shape of model an
    // implementation might later be "helpfully" widened to also accept.
    // Declaring ONLY the sibling (never the Server itself) must still
    // yield no capability for that row.
    test('Generic OnOff Client (0x1001) only - not Generic OnOff Server - gets no onoff', () => {
      const result = mapCompositionToCapabilities(composition([element([GENERIC_ONOFF_CLIENT])]));
      expect(result).toEqual([]);
    });

    test('Light Lightness Setup Server (0x1301) only - not Light Lightness Server - gets no dim', () => {
      const result = mapCompositionToCapabilities(composition([element([LIGHT_LIGHTNESS_SETUP_SERVER])]));
      expect(result).toEqual([]);
    });

    test('Light CTL Setup Server (0x1304) only - not Light CTL Server - gets no light_temperature', () => {
      const result = mapCompositionToCapabilities(composition([element([LIGHT_CTL_SETUP_SERVER])]));
      expect(result).toEqual([]);
    });

    test('Light HSL Setup Server (0x1308) only - not Light HSL Server - gets no light_hue/light_saturation', () => {
      const result = mapCompositionToCapabilities(composition([element([LIGHT_HSL_SETUP_SERVER])]));
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

// ===========================================================================
// THE MEASUREMENT OVERRIDES THE DECLARATION (hardware round). A node's
// composition data is its own claim about itself, and the owner's bulb
// proved one can be false: it declares a Light CTL Server and answers no
// Light CTL Set at all.
// ===========================================================================

/** Every model probed and found working — the baseline a test varies one row of. */
const ALL_SUPPORTED: NodeProbeResult = {
  models: {
    genericOnOff: 'supported',
    lightLightness: 'supported',
    lightCtl: 'supported',
    lightCtlTemperature: 'supported',
    lightHsl: 'supported',
  },
  temperatureRange: null,
};

function capabilitiesOf(result: ReturnType<typeof mapCompositionToCapabilities>): string[] {
  return result.map((assignment) => assignment.capability);
}

describe('mapCompositionToCapabilities with a probe result', () => {
  test('Light CTL Temperature Server (0x1306) alone earns light_temperature, exactly as Light CTL Server does', () => {
    expect(capabilitiesOf(mapCompositionToCapabilities(composition([element([LIGHT_CTL_TEMPERATURE_SERVER])])))).toEqual([
      'light_temperature',
    ]);
  });

  test("THE OWNER'S OWN BULB: declares both colour-temperature models, answers only 0x8264, and KEEPS light_temperature", () => {
    // The case that matters most: the lamp plainly can change colour
    // temperature, so dropping the capability because one of the two
    // declared models is a lie would be the wrong answer.
    const probe: NodeProbeResult = {
      models: { ...ALL_SUPPORTED.models, lightCtl: 'unsupported' },
      temperatureRange: null,
    };
    const result = mapCompositionToCapabilities(
      composition([element([GENERIC_ONOFF_SERVER, LIGHT_LIGHTNESS_SERVER, LIGHT_CTL_SERVER, LIGHT_CTL_TEMPERATURE_SERVER, LIGHT_HSL_SERVER])]),
      probe,
    );
    expect(capabilitiesOf(result)).toContain('light_temperature');
    // ...and everything else is untouched by that one model's failure.
    expect(capabilitiesOf(result)).toEqual(['onoff', 'dim', 'light_temperature', 'light_hue', 'light_saturation', 'light_mode']);
  });

  test('light_temperature is dropped only when BOTH declared colour-temperature models were measured unsupported', () => {
    const probe: NodeProbeResult = {
      models: { ...ALL_SUPPORTED.models, lightCtl: 'unsupported', lightCtlTemperature: 'unsupported' },
      temperatureRange: null,
    };
    const result = mapCompositionToCapabilities(
      composition([element([LIGHT_CTL_SERVER, LIGHT_CTL_TEMPERATURE_SERVER, LIGHT_HSL_SERVER])]),
      probe,
    );
    expect(capabilitiesOf(result)).not.toContain('light_temperature');
    // ...and light_mode goes with it, since it only exists alongside both
    // colour models.
    expect(capabilitiesOf(result)).toEqual(['light_hue', 'light_saturation']);
  });

  test('a measured-unsupported Generic OnOff or Light Lightness loses its own capability and nothing else', () => {
    const probe: NodeProbeResult = {
      models: { ...ALL_SUPPORTED.models, genericOnOff: 'unsupported', lightLightness: 'unsupported' },
      temperatureRange: null,
    };
    const result = mapCompositionToCapabilities(
      composition([element([GENERIC_ONOFF_SERVER, LIGHT_LIGHTNESS_SERVER, LIGHT_CTL_SERVER])]),
      probe,
    );
    expect(capabilitiesOf(result)).toEqual(['light_temperature']);
  });

  test('`unknown` NEVER removes anything — a node this app could not measure behaves exactly as it did before the probe existed', () => {
    const declared = composition([
      element([GENERIC_ONOFF_SERVER, LIGHT_LIGHTNESS_SERVER, LIGHT_CTL_SERVER, LIGHT_HSL_SERVER]),
    ]);
    const allUnknown: NodeProbeResult = {
      models: { genericOnOff: 'unknown', lightLightness: 'unknown', lightCtl: 'unknown', lightCtlTemperature: 'unknown', lightHsl: 'unknown' },
      temperatureRange: null,
    };
    // Byte for byte the same as no probe at all, and as an empty one.
    expect(mapCompositionToCapabilities(declared, allUnknown)).toEqual(mapCompositionToCapabilities(declared));
    expect(mapCompositionToCapabilities(declared, { models: {}, temperatureRange: null })).toEqual(
      mapCompositionToCapabilities(declared),
    );
    expect(mapCompositionToCapabilities(declared, null)).toEqual(mapCompositionToCapabilities(declared));
  });

  test('the probe can only ever SUBTRACT: a model measured supported but never declared still earns nothing', () => {
    const probe: NodeProbeResult = { models: { lightHsl: 'supported', lightCtl: 'supported' }, temperatureRange: null };
    expect(capabilitiesOf(mapCompositionToCapabilities(composition([element([GENERIC_ONOFF_SERVER])]), probe))).toEqual(['onoff']);
  });

  test('HSL IS DELIBERATELY NOT PROBE-GATED: a measured-unsupported Light HSL keeps its capabilities', () => {
    // A bulb with no colour emitters at all still answers Light HSL Set
    // with a correct echo, so the probe's verdict on this model means less
    // than it appears to - and the owner's planned per-device
    // monocolor/multicolor/warm setting is where that actually gets
    // resolved. Pinned so the asymmetry is a decision, not an oversight.
    const probe: NodeProbeResult = { models: { lightHsl: 'unsupported' }, temperatureRange: null };
    const result = mapCompositionToCapabilities(composition([element([LIGHT_HSL_SERVER])]), probe);
    expect(capabilitiesOf(result)).toEqual(['light_hue', 'light_saturation']);
  });

  test('the probe is node-wide while the declaration stays per-element: a verdict does not move a capability between elements', () => {
    const probe: NodeProbeResult = { models: { lightCtl: 'unsupported', lightCtlTemperature: 'unsupported' }, temperatureRange: null };
    const result = mapCompositionToCapabilities(
      composition([element([GENERIC_ONOFF_SERVER]), element([LIGHT_CTL_SERVER]), element([LIGHT_LIGHTNESS_SERVER])]),
      probe,
    );
    expect(result).toEqual([
      { capability: 'onoff', elementIndex: 0 },
      { capability: 'dim', elementIndex: 2 },
    ]);
  });
});

describe('LIGHTING_SERVER_MODEL_IDS', () => {
  test('binds the Light CTL Temperature Server too — without it the one message the owner\'s bulb obeys would never be accepted', () => {
    // An application key is bound per MODEL. A Light CTL Temperature Server
    // that was never bound would silently reject every Light CTL
    // Temperature Set, which would look exactly like a bulb that does not
    // implement the model at all.
    expect([...LIGHTING_SERVER_MODEL_IDS]).toEqual([0x1000, 0x1300, 0x1303, 0x1306, 0x1307]);
  });
});

describe('chooseTemperatureWriteModel', () => {
  test('defaults to the Light CTL Temperature model when there is no measurement at all', () => {
    expect(chooseTemperatureWriteModel(null)).toBe('lightCtlTemperature');
    expect(chooseTemperatureWriteModel(undefined)).toBe('lightCtlTemperature');
    expect(chooseTemperatureWriteModel({ models: {}, temperatureRange: null })).toBe('lightCtlTemperature');
  });

  test('moves off the default ONLY on a positive measurement both ways', () => {
    expect(
      chooseTemperatureWriteModel({ models: { lightCtlTemperature: 'unsupported', lightCtl: 'supported' }, temperatureRange: null }),
    ).toBe('lightCtl');
  });

  test.each([
    ['the Temperature model unsupported but the composite one merely unknown', { lightCtlTemperature: 'unsupported' as const }],
    ['the Temperature model unsupported and the composite one ALSO unsupported', { lightCtlTemperature: 'unsupported' as const, lightCtl: 'unsupported' as const }],
    ['both supported', { lightCtlTemperature: 'supported' as const, lightCtl: 'supported' as const }],
    ['only the composite one supported, the Temperature one unknown', { lightCtl: 'supported' as const }],
  ])('keeps the default when the measurement does not positively contradict it: %s', (_label, models) => {
    expect(chooseTemperatureWriteModel({ models, temperatureRange: null })).toBe('lightCtlTemperature');
  });
});

describe('probeVerdict', () => {
  test('an absent entry, an absent probe and an explicit unknown all read as `unknown` — the conservative direction', () => {
    expect(probeVerdict(null, 'lightCtl')).toBe('unknown');
    expect(probeVerdict(undefined, 'lightCtl')).toBe('unknown');
    expect(probeVerdict({ models: {}, temperatureRange: null }, 'lightCtl')).toBe('unknown');
    expect(probeVerdict({ models: { lightCtl: 'unknown' }, temperatureRange: null }, 'lightCtl')).toBe('unknown');
  });

  test('a recorded verdict is returned as recorded', () => {
    expect(probeVerdict({ models: { lightCtl: 'unsupported' }, temperatureRange: null }, 'lightCtl')).toBe('unsupported');
    expect(probeVerdict(ALL_SUPPORTED, 'lightHsl')).toBe('supported');
  });
});
