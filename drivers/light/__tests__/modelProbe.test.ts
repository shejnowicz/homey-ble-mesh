import {
  probeModels,
  toTemperatureRange,
  isMeaningfulProbeResult,
  DEFAULT_PROBE_TIMEOUT_MS,
  DEFAULT_PROBE_BUDGET_MS,
  type ProbeTransport,
} from '../modelProbe';
import { createFakeClock } from '../../../lib/adapter/__tests__/fakeClock';
import { decodeAccessMessage, encodeAccessMessage } from '../../../lib/mesh/packet/access';
import type { CompositionData, ElementDescription } from '../../../lib/mesh/config/composition';

/**
 * The capability probe (`../modelProbe.ts`) against a FAKE NODE that answers
 * some models and not others — the thing the owner's own bulb turned out to
 * be, and which no amount of reading its composition data could have
 * revealed.
 *
 * WHY THIS IS A UNIT TEST AND NOT ONLY AN END-TO-END ONE. `pairing.test.ts`
 * drives the probe through the whole real stack (provisioning, the config
 * exchange, real encryption, the real fake Bluetooth port) and proves it
 * works in place. What it cannot do cheaply is enumerate node BEHAVIOURS —
 * answers nothing, answers only `0x8264`, answers its range, answers a
 * nonsense range, runs out of budget. Those are this file's job, against the
 * narrow `ProbeTransport` seam, with the real encoders and decoders on both
 * sides so the bytes are still real.
 *
 * SIG MODEL IDS are transcribed here independently of both `modelProbe.ts`
 * and `lib/models/capabilities.ts` (Assigned Numbers, Section 4.1.1 "by
 * Value" / 4.1.2 "by Name") — the same discipline `capabilities.test.ts`
 * already states for its own copies: a transcription slip that is mirrored
 * in the test is a slip nothing catches.
 */
const GENERIC_ONOFF_SERVER = 0x1000;
const LIGHT_LIGHTNESS_SERVER = 0x1300;
const LIGHT_CTL_SERVER = 0x1303;
const LIGHT_CTL_TEMPERATURE_SERVER = 0x1306;
const LIGHT_HSL_SERVER = 0x1307;

// Opcodes, likewise transcribed independently of `lib/models/lighting.ts`.
const OP_ONOFF_GET = 0x8201;
const OP_ONOFF_SET = 0x8202;
const OP_ONOFF_STATUS = 0x8204;
const OP_LIGHTNESS_GET = 0x824b;
const OP_LIGHTNESS_SET = 0x824c;
const OP_LIGHTNESS_STATUS = 0x824e;
const OP_CTL_GET = 0x825d;
const OP_CTL_SET = 0x825e;
const OP_CTL_STATUS = 0x8260;
const OP_CTL_TEMPERATURE_RANGE_GET = 0x8262;
const OP_CTL_TEMPERATURE_RANGE_STATUS = 0x8263;
const OP_CTL_TEMPERATURE_SET = 0x8264;
const OP_CTL_TEMPERATURE_STATUS = 0x8266;
const OP_HSL_GET = 0x826d;
const OP_HSL_SET = 0x8276;
const OP_HSL_STATUS = 0x8278;

function element(sigModels: ReadonlyArray<number>): ElementDescription {
  return { loc: 0x0000, sigModels, vendorModels: [] };
}

function composition(elements: ReadonlyArray<ElementDescription>): CompositionData {
  return {
    cid: 0x07d0, // the owner's own bulb's cid, for flavour — never read by the probe
    pid: 768,
    vid: 0x0000,
    crpl: 0x0000,
    features: { relay: false, proxy: false, friend: false, lowPower: false },
    elements,
  };
}

function u16le(value: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(value, 0);
  return b;
}

interface FakeLamp {
  onOff: number;
  lightness: number;
  temperature: number;
  deltaUv: number;
  hue: number;
  saturation: number;
}

interface FakeNodeOptions {
  /** Opcodes this node never answers — how a model that is declared but not implemented actually behaves. */
  readonly silentOpcodes?: ReadonlySet<number>;
  /** Range Status reply, or `null` for a node that never answers Range Get (the owner's bulb). */
  readonly range?: { readonly min: number; readonly max: number } | null;
  /** Milliseconds of virtual time each answered request costs — for the budget tests. */
  readonly latencyMs?: number;
}

/**
 * A node that speaks the real messages, built on the real access-layer
 * encoder/decoder. Records every request so a test can assert the ORDER
 * (read before write) and the no-op property (what was written back equals
 * what was read).
 */
function fakeNode(
  clock: ReturnType<typeof createFakeClock>,
  lamp: FakeLamp,
  options: FakeNodeOptions = {},
): { transport: ProbeTransport; requests: Array<{ opcode: number; parameters: Buffer }> } {
  const requests: Array<{ opcode: number; parameters: Buffer }> = [];
  const reply = (opcode: number, parameters: Buffer): Buffer => encodeAccessMessage({ opcode, parameters });

  const answer = (opcode: number, parameters: Buffer): Buffer | null => {
    if (options.silentOpcodes?.has(opcode)) return null;
    switch (opcode) {
      case OP_ONOFF_GET:
        return reply(OP_ONOFF_STATUS, Buffer.from([lamp.onOff]));
      case OP_ONOFF_SET:
        lamp.onOff = parameters[0] as number;
        return reply(OP_ONOFF_STATUS, Buffer.from([lamp.onOff]));
      case OP_LIGHTNESS_GET:
        return reply(OP_LIGHTNESS_STATUS, u16le(lamp.lightness));
      case OP_LIGHTNESS_SET:
        lamp.lightness = parameters.readUInt16LE(0);
        return reply(OP_LIGHTNESS_STATUS, u16le(lamp.lightness));
      case OP_CTL_GET:
        return reply(OP_CTL_STATUS, Buffer.concat([u16le(lamp.lightness), u16le(lamp.temperature)]));
      case OP_CTL_SET:
        lamp.lightness = parameters.readUInt16LE(0);
        lamp.temperature = parameters.readUInt16LE(2);
        lamp.deltaUv = parameters.readInt16LE(4);
        return reply(OP_CTL_STATUS, Buffer.concat([u16le(lamp.lightness), u16le(lamp.temperature)]));
      case OP_CTL_TEMPERATURE_SET:
        lamp.temperature = parameters.readUInt16LE(0);
        lamp.deltaUv = parameters.readInt16LE(2);
        return reply(OP_CTL_TEMPERATURE_STATUS, Buffer.concat([u16le(lamp.temperature), u16le(lamp.deltaUv & 0xffff)]));
      case OP_HSL_GET:
        return reply(OP_HSL_STATUS, Buffer.concat([u16le(lamp.lightness), u16le(lamp.hue), u16le(lamp.saturation)]));
      case OP_HSL_SET:
        lamp.lightness = parameters.readUInt16LE(0);
        lamp.hue = parameters.readUInt16LE(2);
        lamp.saturation = parameters.readUInt16LE(4);
        return reply(OP_HSL_STATUS, Buffer.concat([u16le(lamp.lightness), u16le(lamp.hue), u16le(lamp.saturation)]));
      case OP_CTL_TEMPERATURE_RANGE_GET: {
        const range = options.range ?? null;
        if (range === null) return null;
        return reply(
          OP_CTL_TEMPERATURE_RANGE_STATUS,
          Buffer.concat([Buffer.from([0x00]), u16le(range.min), u16le(range.max)]),
        );
      }
      default:
        return null;
    }
  };

  const transport: ProbeTransport = {
    async request(accessPayload, accept, timeoutMs) {
      const message = decodeAccessMessage(accessPayload);
      if (message === null) throw new Error('test fixture error: the probe sent something that is not an Access message');
      requests.push({ opcode: message.opcode, parameters: message.parameters });
      const answered = answer(message.opcode, message.parameters);
      // A real transport burns the whole window when nothing answers, and
      // only its own latency when something does — modelled here so the
      // budget tests measure what they claim to.
      await clock.advance(answered === null ? timeoutMs : (options.latencyMs ?? 0));
      if (answered === null) return null;
      return accept(answered) ? answered : null;
    },
  };
  return { transport, requests };
}

function defaultLamp(): FakeLamp {
  return { onOff: 0x01, lightness: 0x8000, temperature: 0x1194, deltaUv: 0x0000, hue: 0x4000, saturation: 0x2000 };
}

/** Every model this project probes, declared on one element — the shape of a bulb that claims to do everything. */
const DECLARES_EVERYTHING = composition([
  element([GENERIC_ONOFF_SERVER, LIGHT_LIGHTNESS_SERVER, LIGHT_CTL_SERVER, LIGHT_CTL_TEMPERATURE_SERVER, LIGHT_HSL_SERVER]),
]);

describe('probeModels', () => {
  test('a node that answers everything it declares is measured as supporting everything', async () => {
    const clock = createFakeClock();
    const node = fakeNode(clock, defaultLamp());

    const result = await probeModels({ transport: node.transport, clock }, DECLARES_EVERYTHING);

    expect(result.models).toEqual({
      genericOnOff: 'supported',
      lightLightness: 'supported',
      lightCtl: 'supported',
      lightCtlTemperature: 'supported',
      lightHsl: 'supported',
    });
  });

  test("THE OWNER'S OWN BULB: declares both colour-temperature models, answers only 0x8264", async () => {
    // The case this whole mechanism exists for. Everything else about this
    // node is well-behaved; only the composite Light CTL Set is dead.
    const clock = createFakeClock();
    const node = fakeNode(clock, defaultLamp(), { silentOpcodes: new Set([OP_CTL_SET]) });

    const result = await probeModels({ transport: node.transport, clock }, DECLARES_EVERYTHING);

    expect(result.models.lightCtl).toBe('unsupported');
    expect(result.models.lightCtlTemperature).toBe('supported');
    // ...and the models next to it are untouched by its failure.
    expect(result.models.genericOnOff).toBe('supported');
    expect(result.models.lightHsl).toBe('supported');
  });

  test('a model the composition never declared is never probed and never appears in the result', async () => {
    const clock = createFakeClock();
    const node = fakeNode(clock, defaultLamp());

    const result = await probeModels({ transport: node.transport, clock }, composition([element([GENERIC_ONOFF_SERVER])]));

    expect(result.models).toEqual({ genericOnOff: 'supported' });
    expect(node.requests.map((r) => r.opcode)).toEqual([OP_ONOFF_GET, OP_ONOFF_SET]);
  });

  test('READ FIRST, THEN WRITE BACK WHAT WAS READ — the probe is a no-op and the lamp is left exactly as it was', async () => {
    const clock = createFakeClock();
    const lamp = defaultLamp();
    const before = { ...lamp };
    const node = fakeNode(clock, lamp);

    await probeModels({ transport: node.transport, clock }, DECLARES_EVERYTHING);

    // Delta UV is the one field that cannot be read back (see
    // `modelProbe.ts`'s own disclosure) and the fixture starts it at 0,
    // which is what the probe writes — so every field, including that one,
    // is unchanged here.
    expect(lamp).toEqual(before);
    // ...and the order proves it was a read-then-write, not a guess: every
    // Set is preceded by the Get its value came from.
    expect(node.requests.map((r) => r.opcode)).toEqual([
      OP_ONOFF_GET,
      OP_ONOFF_SET,
      OP_LIGHTNESS_GET,
      OP_LIGHTNESS_SET,
      OP_CTL_GET,
      OP_CTL_SET,
      // The second colour-temperature probe reuses the SAME composite read
      // rather than issuing a second one — one fewer round trip per bulb.
      OP_CTL_TEMPERATURE_SET,
      OP_HSL_GET,
      OP_HSL_SET,
      OP_CTL_TEMPERATURE_RANGE_GET,
    ]);
  });

  test('each Set carries back exactly the value its own Get reported', async () => {
    const clock = createFakeClock();
    const lamp: FakeLamp = { onOff: 0x00, lightness: 0x1234, temperature: 0x0fa0, deltaUv: 0, hue: 0x5678, saturation: 0x9abc };
    const node = fakeNode(clock, lamp);

    await probeModels({ transport: node.transport, clock }, DECLARES_EVERYTHING);

    const sent = (opcode: number): Buffer => {
      const request = node.requests.find((r) => r.opcode === opcode);
      if (request === undefined) throw new Error(`test fixture error: the probe never sent 0x${opcode.toString(16)}`);
      return request.parameters;
    };
    expect(sent(OP_ONOFF_SET)[0]).toBe(0x00);
    expect(sent(OP_LIGHTNESS_SET).readUInt16LE(0)).toBe(0x1234);
    expect(sent(OP_CTL_SET).readUInt16LE(0)).toBe(0x1234); // lightness, from the composite read
    expect(sent(OP_CTL_SET).readUInt16LE(2)).toBe(0x0fa0); // temperature, from the same read
    expect(sent(OP_CTL_TEMPERATURE_SET).readUInt16LE(0)).toBe(0x0fa0);
    expect(sent(OP_HSL_SET).readUInt16LE(2)).toBe(0x5678);
    expect(sent(OP_HSL_SET).readUInt16LE(4)).toBe(0x9abc);
  });

  test('a model whose READ goes unanswered is `unknown`, not `unsupported`, and no Set is sent for it', async () => {
    // The module's own rule: with no way to read the current value there is
    // no no-op write to send, so the declaration stands. Writing a GUESSED
    // value to find out would be exactly the user-visible change the probe
    // promises never to make.
    const clock = createFakeClock();
    const lamp = defaultLamp();
    const node = fakeNode(clock, lamp, { silentOpcodes: new Set([OP_HSL_GET]) });

    const result = await probeModels({ transport: node.transport, clock }, DECLARES_EVERYTHING);

    expect(result.models.lightHsl).toBe('unknown');
    expect(node.requests.map((r) => r.opcode)).not.toContain(OP_HSL_SET);
  });

  test('a silent composite READ leaves BOTH colour-temperature models unknown — they share that read', async () => {
    const clock = createFakeClock();
    const node = fakeNode(clock, defaultLamp(), { silentOpcodes: new Set([OP_CTL_GET]) });

    const result = await probeModels({ transport: node.transport, clock }, DECLARES_EVERYTHING);

    expect(result.models.lightCtl).toBe('unknown');
    expect(result.models.lightCtlTemperature).toBe('unknown');
    // The shared read is attempted ONCE, not once per model that needs it.
    expect(node.requests.filter((r) => r.opcode === OP_CTL_GET)).toHaveLength(1);
  });

  test('a node that answers nothing at all costs ONE timeout per READ, not one per model', async () => {
    // "A node that answers nothing must not stretch pairing by a timeout
    // per model." Five declared models share four reads; a failed read
    // skips its own write.
    const clock = createFakeClock();
    const silent = new Set([OP_ONOFF_GET, OP_LIGHTNESS_GET, OP_CTL_GET, OP_HSL_GET, OP_CTL_TEMPERATURE_RANGE_GET]);
    const node = fakeNode(clock, defaultLamp(), { silentOpcodes: silent });
    const startedAt = clock.now();

    const result = await probeModels({ transport: node.transport, clock }, DECLARES_EVERYTHING);

    expect(Object.values(result.models)).toEqual(['unknown', 'unknown', 'unknown', 'unknown', 'unknown']);
    // Four reads plus the range query = five requests, no Sets at all.
    expect(node.requests).toHaveLength(5);
    expect(clock.now() - startedAt).toBe(5 * DEFAULT_PROBE_TIMEOUT_MS);
  });

  test('the total budget stops the probe rather than letting a slow node run past it, and what was not reached is `unknown`', async () => {
    const clock = createFakeClock();
    // Every answer takes a full second of virtual time, so the budget runs
    // out partway through rather than at a convenient boundary.
    const node = fakeNode(clock, defaultLamp(), { latencyMs: 1000 });

    const result = await probeModels({ transport: node.transport, clock, probeBudgetMs: 2500 }, DECLARES_EVERYTHING);

    expect(result.models.genericOnOff).toBe('supported');
    expect(result.models.lightHsl).toBe('unknown');
    expect(clock.now()).toBeLessThan(2500 + 1000); // stopped within one in-flight request of the budget
  });

  test('a zero budget sends nothing at all and records every declared model `unknown` — the switch pairing.test.ts leans on', async () => {
    const clock = createFakeClock();
    const node = fakeNode(clock, defaultLamp());

    const result = await probeModels({ transport: node.transport, clock, probeBudgetMs: 0 }, DECLARES_EVERYTHING);

    expect(node.requests).toHaveLength(0);
    expect(result.models).toEqual({
      genericOnOff: 'unknown',
      lightLightness: 'unknown',
      lightCtl: 'unknown',
      lightCtlTemperature: 'unknown',
      lightHsl: 'unknown',
    });
    expect(result.temperatureRange).toBeNull();
  });

  test('a lost link ends the probe without throwing, keeping what was already measured', async () => {
    const clock = createFakeClock();
    const lamp = defaultLamp();
    const inner = fakeNode(clock, lamp);
    let calls = 0;
    const transport: ProbeTransport = {
      async request(payload, accept, timeoutMs) {
        calls += 1;
        if (calls > 3) throw new Error('the link went away');
        return inner.transport.request(payload, accept, timeoutMs);
      },
    };

    const result = await probeModels({ transport, clock }, DECLARES_EVERYTHING);

    expect(result.models.genericOnOff).toBe('supported');
    // Everything after the link died is unknown — never `unsupported`,
    // which would be reading our own failure as the node's.
    expect(result.models.lightCtl).toBe('unknown');
    expect(result.models.lightCtlTemperature).toBe('unknown');
    expect(result.models.lightHsl).toBe('unknown');
    expect(result.temperatureRange).toBeNull();
  });

  test('the probe timeout and budget have the documented defaults', () => {
    expect(DEFAULT_PROBE_TIMEOUT_MS).toBe(1500);
    expect(DEFAULT_PROBE_BUDGET_MS).toBe(9000);
  });

  describe('the colour-temperature range', () => {
    test('a node that reports a range has it recorded', async () => {
      const clock = createFakeClock();
      const node = fakeNode(clock, defaultLamp(), { range: { min: 2700, max: 6500 } });

      const result = await probeModels({ transport: node.transport, clock }, DECLARES_EVERYTHING);

      expect(result.temperatureRange).toEqual({ minKelvin: 2700, maxKelvin: 6500 });
    });

    test("a node that never answers Range Get leaves it null — the owner's own bulb", async () => {
      const clock = createFakeClock();
      const node = fakeNode(clock, defaultLamp(), { range: null });

      const result = await probeModels({ transport: node.transport, clock }, DECLARES_EVERYTHING);

      expect(result.temperatureRange).toBeNull();
    });

    test('the range is asked of the LIGHT CTL Server, so a node declaring only the Temperature Server is not asked at all', async () => {
      // Mesh Model Section 6.4.3.3.1 puts Range Get on the Light CTL Server.
      const clock = createFakeClock();
      const node = fakeNode(clock, defaultLamp(), { range: { min: 2700, max: 6500 } });

      await probeModels({ transport: node.transport, clock }, composition([element([LIGHT_CTL_TEMPERATURE_SERVER])]));

      expect(node.requests.map((r) => r.opcode)).not.toContain(OP_CTL_TEMPERATURE_RANGE_GET);
    });
  });
});

describe('toTemperatureRange', () => {
  test('an ordinary range passes through', () => {
    expect(toTemperatureRange(2700, 6500)).toEqual({ minKelvin: 2700, maxKelvin: 6500 });
  });

  test("Table 6.8's own 0xFFFF row is an answer that says nothing, in either field", () => {
    expect(toTemperatureRange(0xffff, 0xffff)).toBeNull();
    expect(toTemperatureRange(2700, 0xffff)).toBeNull();
    expect(toTemperatureRange(0xffff, 6500)).toBeNull();
  });

  test('a value Table 6.6 calls Prohibited is refused rather than used', () => {
    expect(toTemperatureRange(799, 6500)).toBeNull(); // below 0x0320
    expect(toTemperatureRange(2700, 20001)).toBeNull(); // above 0x4E20
  });

  test('an inverted or zero-width range is not a range', () => {
    expect(toTemperatureRange(6500, 2700)).toBeNull();
    expect(toTemperatureRange(4000, 4000)).toBeNull();
  });

  test('the boundary values themselves are accepted', () => {
    expect(toTemperatureRange(800, 20000)).toEqual({ minKelvin: 800, maxKelvin: 20000 });
  });
});

// ===========================================================================
// THE TRANSACTION IDENTIFIER'S OWN SOURCE. The probe runs at pairing time
// against a node that has no controller yet, and (since the backfill) also
// at DEVICE INIT, against a node whose controller is live and allocating
// identifiers of its own. The two must not collide: a Set reaching a node
// with the same (SRC, DST, TID) inside six seconds is discarded as a
// retransmission, so a probe write landing on a number the user's own
// button press is about to use would silently swallow one of them.
// ===========================================================================

describe('the transaction identifier', () => {
  /** Table 3.37/6.53/6.69/6.73/6.87: every Set this module sends carries its
   *  TID as the LAST parameter octet. */
  function tidsOfSets(requests: ReadonlyArray<{ opcode: number; parameters: Buffer }>): number[] {
    const sets = new Set([OP_ONOFF_SET, OP_LIGHTNESS_SET, OP_CTL_SET, OP_CTL_TEMPERATURE_SET, OP_HSL_SET]);
    return requests.filter((r) => sets.has(r.opcode)).map((r) => r.parameters[r.parameters.length - 1] as number);
  }

  test('with no allocator supplied, the probe counts from its own zero (the pairing-time case, unchanged)', async () => {
    const clock = createFakeClock();
    const node = fakeNode(clock, defaultLamp());

    await probeModels({ transport: node.transport, clock }, DECLARES_EVERYTHING);

    expect(tidsOfSets(node.requests)).toEqual([0, 1, 2, 3, 4]);
  });

  test('an injected allocator is used instead, so a live controller\'s own counter covers the probe too', async () => {
    const clock = createFakeClock();
    const node = fakeNode(clock, defaultLamp());
    // Exactly the shape `MeshLightController#allocateTid` has: one shared,
    // incrementing, wrapping counter per node.
    let next = 200;
    const allocateTid = (): number => {
      const tid = next;
      next = (next + 1) & 0xff;
      return tid;
    };

    await probeModels({ transport: node.transport, clock, allocateTid }, DECLARES_EVERYTHING);

    expect(tidsOfSets(node.requests)).toEqual([200, 201, 202, 203, 204]);
    // ...and the allocator really was consumed, rather than merely offered.
    expect(next).toBe(205);
  });

  test('an allocator is only consulted for messages that HAVE a transaction identifier', async () => {
    // Gets and the Range Get carry none (Table 6.50/6.64/6.66/6.84 are
    // empty messages), so a probe against a node that answers no Set at all
    // must not burn identifiers on them.
    const clock = createFakeClock();
    const node = fakeNode(clock, defaultLamp(), {
      silentOpcodes: new Set([OP_ONOFF_GET, OP_LIGHTNESS_GET, OP_CTL_GET, OP_HSL_GET]),
    });
    let calls = 0;
    const allocateTid = (): number => {
      calls += 1;
      return 7;
    };

    await probeModels({ transport: node.transport, clock, allocateTid, probeBudgetMs: 1_000_000 }, DECLARES_EVERYTHING);

    expect(tidsOfSets(node.requests)).toEqual([]);
    expect(calls).toBe(0);
  });
});

// ===========================================================================
// WAS ANYTHING ACTUALLY MEASURED? The backfill needs this question answered
// and the pairing path never had to ask it: a probe where every single
// verdict came back `'unknown'` (a node that answered nothing, or a budget
// that ran out before the first reply) has learned nothing, and storing it
// would mark the node "measured" forever and stop any later retry.
// ===========================================================================

describe('isMeaningfulProbeResult', () => {
  test('a probe that measured one model either way is meaningful', () => {
    expect(isMeaningfulProbeResult({ models: { genericOnOff: 'supported' }, temperatureRange: null })).toBe(true);
    expect(isMeaningfulProbeResult({ models: { lightCtl: 'unsupported' }, temperatureRange: null })).toBe(true);
  });

  test('a range is a measurement too, even with every model unknown', () => {
    expect(
      isMeaningfulProbeResult({ models: { lightCtl: 'unknown' }, temperatureRange: { minKelvin: 2700, maxKelvin: 6500 } }),
    ).toBe(true);
  });

  test('all-unknown with no range is a probe that failed, not a measurement', () => {
    expect(isMeaningfulProbeResult({ models: {}, temperatureRange: null })).toBe(false);
    expect(
      isMeaningfulProbeResult({
        models: { genericOnOff: 'unknown', lightLightness: 'unknown', lightCtl: 'unknown' },
        temperatureRange: null,
      }),
    ).toBe(false);
  });

  test('a node that answers NOTHING produces a result this rejects — end to end, not by construction', async () => {
    const clock = createFakeClock();
    const node = fakeNode(clock, defaultLamp(), {
      silentOpcodes: new Set([
        OP_ONOFF_GET,
        OP_LIGHTNESS_GET,
        OP_CTL_GET,
        OP_HSL_GET,
        OP_CTL_TEMPERATURE_RANGE_GET,
      ]),
    });

    const result = await probeModels({ transport: node.transport, clock, probeBudgetMs: 1_000_000 }, DECLARES_EVERYTHING);

    expect(isMeaningfulProbeResult(result)).toBe(false);
  });

  test('...while the owner\'s own bulb produces one this accepts', async () => {
    const clock = createFakeClock();
    const node = fakeNode(clock, defaultLamp(), { silentOpcodes: new Set([OP_CTL_SET]) });

    const result = await probeModels({ transport: node.transport, clock }, DECLARES_EVERYTHING);

    expect(isMeaningfulProbeResult(result)).toBe(true);
  });
});
