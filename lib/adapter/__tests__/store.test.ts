import { randomBytes } from 'node:crypto';
import {
  NetworkStore,
  EMPTY_NETWORK_STATE,
  SEQ_BLOCK_SIZE,
  type NetworkState,
  type NodeEntry,
  type SettingsPort,
} from '../store';
import { parseCompositionData, type CompositionData } from '../../mesh/config/composition';
import { COMPOSITION_DATA_PAGE0_SAMPLE } from '../../mesh/config/__tests__/vectors';
import { MAX_SEQ } from '../../mesh/packet/ranges';

/**
 * A faithful stand-in for Homey's own settings manager: a missing key reads
 * back as `null` (never `undefined`), and every value actually round-trips
 * through JSON on `set`/`get` rather than being held as the exact object
 * reference the caller passed in. That second property matters here: a fake
 * that just aliased objects could hide a real bug (the store forgetting to
 * copy something) behind the test happening to reuse the same JS object for
 * what it wrote and what it later reads back. `setCallCount` lets a test
 * assert that a rejected write never reached the port at all.
 */
class FakeSettingsPort implements SettingsPort {
  private readonly data = new Map<string, string>();
  setCallCount = 0;

  get(key: string): unknown {
    const raw = this.data.get(key);
    return raw === undefined ? null : JSON.parse(raw);
  }

  set(key: string, value: unknown): void {
    this.setCallCount++;
    this.data.set(key, JSON.stringify(value));
  }
}

/**
 * The opposite fidelity choice from `FakeSettingsPort`: holds exactly the
 * object reference it was given, with no serialization at all -- plausible
 * for an in-process settings manager that keeps values in memory. Review
 * found that `FakeSettingsPort`'s own JSON round-trip was, by itself,
 * already deep-cloning everything `set`/`get` touched, which laundered
 * away any need for this module's OWN defensive copies (`encodeNetworkState`/
 * `decodeNetworkState`'s `JSON.parse(JSON.stringify(...))` of a node's
 * composition): a test using only the JSON-serializing fake could not tell
 * apart "the module copies" from "the fake copies for it." This fake makes
 * that distinction observable.
 */
class AliasingSettingsPort implements SettingsPort {
  private readonly data = new Map<string, unknown>();

  get(key: string): unknown {
    return this.data.has(key) ? this.data.get(key) : null;
  }

  set(key: string, value: unknown): void {
    this.data.set(key, value);
  }
}

/** A real, parser-produced `CompositionData`, not a hand-built object — see
 *  the plan's own guidance (task 3, step 2) for why: the parser is already
 *  proven against the specification, so building fixtures by hand here
 *  would test this file's own transcription instead of the store. */
function sampleComposition(): CompositionData {
  const parsed = parseCompositionData(Buffer.from(COMPOSITION_DATA_PAGE0_SAMPLE.message, 'hex'));
  if (parsed === null) {
    throw new Error('fixture setup: the published Composition Data Page 0 sample failed to parse');
  }
  return parsed;
}

function sampleNode(address: number): NodeEntry {
  return {
    address,
    deviceKey: randomBytes(16),
    composition: sampleComposition(),
  };
}

/**
 * The empty state's expected shape, spelled out as literals rather than
 * compared against the module's own `EMPTY_NETWORK_STATE` constant.
 * Comparing a read result to that constant is tautological if the
 * constant itself changed (e.g. a different starting IV index or first
 * unicast address) -- it would still equal itself. These literals are
 * what the design actually requires: no network exists yet, so every key
 * and address is unknown (`null`), the IV index starts at 0, and the
 * first address this store will ever offer is 0x0001.
 */
const EXPECTED_EMPTY_STATE = {
  netKey: null,
  netKeyIndex: null,
  appKey: null,
  appKeyIndex: null,
  ivIndex: 0,
  ourUnicastAddress: null,
  nextUnicastAddress: 1,
  nodes: [],
};

function sampleNetworkState(): NetworkState {
  return {
    netKey: randomBytes(16),
    netKeyIndex: 0,
    appKey: randomBytes(16),
    appKeyIndex: 0,
    ivIndex: 0,
    ourUnicastAddress: 1,
    nextUnicastAddress: 4,
    nodes: [sampleNode(2), sampleNode(3)],
  };
}

describe('NetworkStore persistence', () => {
  test('a state written by one instance is read identically by another', () => {
    const settings = new FakeSettingsPort();
    const writer = new NetworkStore(settings);
    const state = sampleNetworkState();

    writer.setState(state);

    const reader = new NetworkStore(settings);
    expect(reader.getState()).toEqual(state);
  });

  test('a missing settings key yields the defined empty state rather than throwing', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);

    let state: NetworkState | undefined;
    expect(() => {
      state = store.getState();
    }).not.toThrow();
    expect(state).toEqual(EXPECTED_EMPTY_STATE);
  });

  test('unreadable stored data yields the empty state rather than throwing', () => {
    const settings = new FakeSettingsPort();
    // Something that is valid JSON but not this module's own shape at all.
    settings.set('network', { unrelated: true, nodes: 'not-an-array' });
    const store = new NetworkStore(settings);

    expect(() => store.getState()).not.toThrow();
    expect(store.getState()).toEqual(EXPECTED_EMPTY_STATE);
  });

  test('round-trips the empty state itself (all-null key material) without throwing', () => {
    const settings = new FakeSettingsPort();
    const writer = new NetworkStore(settings);

    writer.setState(EMPTY_NETWORK_STATE);

    const reader = new NetworkStore(settings);
    expect(reader.getState()).toEqual(EXPECTED_EMPTY_STATE);
  });

  test('setState rejects a key of the wrong length, naming the field and the length', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);
    const bad: NetworkState = { ...sampleNetworkState(), netKey: randomBytes(15) };

    expect(() => store.setState(bad)).toThrow('network state field "netKey" must be 16 bytes, got 15');
  });

  test('setState rejects an out-of-range unicast address, naming the field', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);
    const bad: NetworkState = { ...sampleNetworkState(), ourUnicastAddress: 0x8000 };

    expect(() => store.setState(bad)).toThrow(/ourUnicastAddress/);
  });

  test('setState rejects an out-of-range ivIndex, naming the field', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);
    const bad: NetworkState = { ...sampleNetworkState(), ivIndex: -1 };

    expect(() => store.setState(bad)).toThrow(/ivIndex/);
  });

  // Every 16-byte key field gets the same length guard; exercised together
  // rather than three near-identical tests (an earlier mutation run found
  // that checking only `netKey` left `appKey` and a node's `deviceKey`
  // unguarded by this suite, even though the implementation guards all
  // three the same way).
  test.each([
    ['appKey', (s: NetworkState): NetworkState => ({ ...s, appKey: randomBytes(10) })],
    [
      'nodes[0].deviceKey',
      (s: NetworkState): NetworkState => ({
        ...s,
        nodes: [{ ...s.nodes[0]!, deviceKey: randomBytes(10) }, ...s.nodes.slice(1)],
      }),
    ],
  ])('setState rejects a wrong-length %s', (fieldName, corrupt) => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);
    const bad = corrupt(sampleNetworkState());

    expect(() => store.setState(bad)).toThrow(/16 bytes, got 10/);
  });

  // The same gap the review found in the length guards above: both key
  // INDEX range guards (netKeyIndex/appKeyIndex, Section 4.3.1.1's 12-bit
  // bound) and the node address range guard were already implemented but
  // had no test of their own.
  test.each([
    ['netKeyIndex', (s: NetworkState): NetworkState => ({ ...s, netKeyIndex: 0x1000 })],
    ['appKeyIndex', (s: NetworkState): NetworkState => ({ ...s, appKeyIndex: 0x1000 })],
  ])('setState rejects an out-of-range %s', (fieldName, corrupt) => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);
    const bad = corrupt(sampleNetworkState());

    expect(() => store.setState(bad)).toThrow(new RegExp(fieldName));
  });

  test('setState rejects a node address outside the unicast range, naming the field', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);
    const state = sampleNetworkState();
    const bad: NetworkState = { ...state, nodes: [{ ...state.nodes[0]!, address: 0x8000 }, ...state.nodes.slice(1)] };

    expect(() => store.setState(bad)).toThrow(/nodes\[0\]\.address/);
  });

  test('setState writes nothing at all when validation fails -- it validates before any write', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);
    const callsBefore = settings.setCallCount;
    const bad: NetworkState = { ...sampleNetworkState(), netKey: randomBytes(15) };

    expect(() => store.setState(bad)).toThrow();

    expect(settings.setCallCount).toBe(callsBefore);
  });

  test('malformed key hex in otherwise well-shaped stored data yields the empty state rather than throwing', () => {
    // A different corruption path than "nodes is not an array" (the
    // existing "unreadable stored data" test above): this value has the
    // right shape and type at every field -- it only fails the hex-decode
    // guard specifically.
    const settings = new FakeSettingsPort();
    settings.set('network', {
      netKey: 'not-valid-hex-and-also-wrong-length',
      netKeyIndex: null,
      appKey: null,
      appKeyIndex: null,
      ivIndex: 0,
      ourUnicastAddress: null,
      nextUnicastAddress: 1,
      nodes: [],
    });
    const store = new NetworkStore(settings);

    expect(() => store.getState()).not.toThrow();
    expect(store.getState()).toEqual(EXPECTED_EMPTY_STATE);
  });

  test('a stored nextUnicastAddress of 0 (the Unassigned address, never legal) is treated as corrupt, not accepted', () => {
    // Decode must RANGE-check, not just type-check: 0 is a `number`, so a
    // guard that only asked "is this a number" would let it through and
    // later hand address 0 out of allocateUnicastAddress -- Table 3.5's
    // Unassigned address, not a legal unicast one.
    const settings = new FakeSettingsPort();
    settings.set('network', {
      netKey: null,
      netKeyIndex: null,
      appKey: null,
      appKeyIndex: null,
      ivIndex: 0,
      ourUnicastAddress: null,
      nextUnicastAddress: 0,
      nodes: [],
    });
    const store = new NetworkStore(settings);

    expect(store.getState()).toEqual(EXPECTED_EMPTY_STATE);
  });

  test('getState never returns the same object instance twice, even for the empty-state fallback', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);

    const first = store.getState();
    (first.nodes as NodeEntry[]).push(sampleNode(5)); // mutate what this call returned

    const second = store.getState();
    expect(second.nodes).toHaveLength(0);
    expect(second).toEqual(EXPECTED_EMPTY_STATE);
  });

  test('encodeNetworkState deep-copies a node composition -- observable only with a fake that does not itself clone', () => {
    const settings = new AliasingSettingsPort();
    const store = new NetworkStore(settings);
    const state = sampleNetworkState();

    store.setState(state);
    // Mutate the CALLER's own composition object after the call returns.
    const original = state.nodes[0]!.composition as unknown as { elements: Array<{ loc: number }> };
    original.elements[0]!.loc = 0xdead;

    const readBack = store.getState();
    expect((readBack.nodes[0]!.composition as unknown as { elements: Array<{ loc: number }> }).elements[0]!.loc).not.toBe(
      0xdead,
    );
  });

  test('decodeNetworkState deep-copies a node composition on the way out -- observable only with a fake that does not itself clone', () => {
    const settings = new AliasingSettingsPort();
    const store = new NetworkStore(settings);
    store.setState(sampleNetworkState());

    const first = store.getState();
    (first.nodes[0]!.composition as unknown as { elements: Array<{ loc: number }> }).elements[0]!.loc = 0xdead;

    const second = store.getState();
    expect((second.nodes[0]!.composition as unknown as { elements: Array<{ loc: number }> }).elements[0]!.loc).not.toBe(0xdead);
  });

  test('setState does not mutate the caller-supplied state object', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);
    const state = sampleNetworkState();
    const netKeyBefore = Buffer.from(state.netKey as Buffer);
    const nodesBefore = state.nodes;

    store.setState(state);

    expect(state.netKey).toEqual(netKeyBefore);
    expect(state.nodes).toBe(nodesBefore); // same array reference, untouched
  });

  test('getState never hands back a buffer the caller can use to corrupt what is stored', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);
    store.setState(sampleNetworkState());

    const first = store.getState();
    first.nodes[0]?.deviceKey.fill(0); // mutate the buffer this call returned

    const second = store.getState();
    expect(second.nodes[0]?.deviceKey.equals(Buffer.alloc(16, 0))).toBe(false);
  });
});

describe('NetworkStore.allocateUnicastAddress', () => {
  test('hands out the next free address and moves the pointer past it', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);

    expect(store.allocateUnicastAddress()).toBe(0x0001);
    expect(store.getState().nextUnicastAddress).toBe(0x0002);
    expect(store.allocateUnicastAddress()).toBe(0x0002);
    expect(store.getState().nextUnicastAddress).toBe(0x0003);
  });

  test('never hands out the same address twice, even across a reload between every allocation', () => {
    const settings = new FakeSettingsPort();
    let store = new NetworkStore(settings);
    const seen = new Set<number>();

    for (let i = 0; i < 10; i++) {
      const address = store.allocateUnicastAddress();
      expect(seen.has(address)).toBe(false);
      seen.add(address);
      store = new NetworkStore(settings); // simulated reload
    }

    expect(seen.size).toBe(10);
  });

  test('throws a clear message once the unicast address range is exhausted', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);
    store.setState({ ...EMPTY_NETWORK_STATE, nextUnicastAddress: 0x7fff });

    expect(store.allocateUnicastAddress()).toBe(0x7fff); // the last legal unicast address
    expect(() => store.allocateUnicastAddress()).toThrow(/no unicast addresses remain/);
  });

  /**
   * THE critical finding from review: allocating an address must never
   * convert "the stored network state is unreadable" into "the stored
   * network state is gone." A naive read-empty-then-write-back allocator
   * would overwrite the only remaining chance of recovering the network
   * key, the application key and the node roster with a freshly empty
   * state plus one allocated address -- the single most expensive failure
   * this app can have, per the design's own accepted risk (losing these
   * settings means factory-resetting every bulb by hand).
   */
  test('refuses to allocate when the stored network state is present but unreadable, and does not overwrite it', () => {
    const settings = new FakeSettingsPort();
    // Valid JSON, but not this module's shape -- the same kind of corruption
    // as the persistence describe block's "unreadable stored data" case.
    const corrupt = { unrelated: true, nodes: 'not-an-array' };
    settings.set('network', corrupt);
    const store = new NetworkStore(settings);

    expect(() => store.allocateUnicastAddress()).toThrow(/unreadable/);

    // The stored value must be EXACTLY what it was before the call -- not
    // merely "still fails to decode by coincidence," but byte-for-byte the
    // same object this test put there, proving nothing was written.
    expect(settings.get('network')).toEqual(corrupt);
  });

  /**
   * THE second critical finding: allocating an address is a read-modify-
   * write of the WHOLE state, and nothing previously pinned that it
   * preserves everything OTHER than the field it means to change. Task 6
   * (pairing) does exactly "allocate an address, then separately write a
   * new node entry" -- if allocation silently dropped the keys or the
   * existing node roster, that task would have no test here to catch it.
   */
  test('allocating an address changes nothing else in the stored state', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);
    const seeded = sampleNetworkState();
    store.setState(seeded);

    const address = store.allocateUnicastAddress();

    expect(address).toBe(seeded.nextUnicastAddress);
    const after = store.getState();
    expect(after).toEqual({ ...seeded, nextUnicastAddress: seeded.nextUnicastAddress + 1 });
  });
});

describe('NetworkStore.allocateSequenceBlock', () => {
  test('hands out sequentially increasing numbers starting at 0 for a fresh store', () => {
    const settings = new FakeSettingsPort();
    const store = new NetworkStore(settings);

    expect(store.allocateSequenceBlock()).toBe(0);
    expect(store.allocateSequenceBlock()).toBe(1);
    expect(store.allocateSequenceBlock()).toBe(2);
  });

  /**
   * THE required property test (task brief, step 3): after any number of
   * allocations followed by a simulated power loss, the next number issued
   * must be greater than every number issued before it. Driven by a loop
   * that allocates, drops the in-memory store, reconstructs a fresh one
   * from the SAME fake settings (nothing survives this but what was
   * actually persisted), and continues — across a block boundary, and more
   * than once. The round sizes below are chosen so this is guaranteed
   * regardless of the allocator's internal block size: some rounds are
   * small, several are in the thousands, and there are eleven separate
   * simulated power losses, not one.
   */
  test('the next number issued after any simulated power loss is greater than every number issued before it', () => {
    const settings = new FakeSettingsPort();
    let store = new NetworkStore(settings);

    let highestIssued = -1;
    let totalIssued = 0;
    const roundSizes = [1, 3, 250, 999, 1000, 1, 1500, 2, 1, 3000, 1];

    for (const count of roundSizes) {
      for (let i = 0; i < count; i++) {
        const seq = store.allocateSequenceBlock();
        expect(seq).toBeGreaterThan(highestIssued);
        highestIssued = seq;
        totalIssued++;
      }
      store = new NetworkStore(settings); // simulated power loss: drop in-memory state, reload
    }

    expect(totalIssued).toBe(roundSizes.reduce((a, b) => a + b, 0));
    // Sanity on the test itself: this run must actually have allocated well
    // past a single block's worth of numbers, or the property above could
    // pass by accident (no boundary ever crossed). If this ever fails, the
    // round sizes above need to grow, not the assertion above shrink.
    expect(highestIssued).toBeGreaterThan(2000);
  });

  /**
   * The same property again, under many more — and randomly sized —
   * simulated power losses, seeded for reproducibility. Complements the
   * hand-picked round sizes above with a broader sweep of where, relative
   * to a block boundary, a "power loss" can land.
   */
  test('the property holds across 200 randomized power-loss rounds (seeded)', () => {
    const settings = new FakeSettingsPort();
    let store = new NetworkStore(settings);

    // A tiny, deterministic PRNG (mulberry32) so this test is reproducible
    // without needing a published fixture — this is a property test over
    // this module's own behaviour, not a known-answer test against the
    // specification.
    let seed = 0xc0ffee;
    const rand = (): number => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };

    let highestIssued = -1;
    let totalIssued = 0;

    for (let round = 0; round < 200; round++) {
      const count = 1 + Math.floor(rand() * 50); // 1..50 allocations this round
      for (let i = 0; i < count; i++) {
        const seq = store.allocateSequenceBlock();
        expect(seq).toBeGreaterThan(highestIssued);
        highestIssued = seq;
        totalIssued++;
      }
      store = new NetworkStore(settings);
    }

    expect(totalIssued).toBeGreaterThan(1000);
  });

  test('throws a clear message once the 24-bit sequence-number space is exhausted', () => {
    const settings = new FakeSettingsPort();
    // Seed the sequence state right at the top of the 24-bit range so the
    // very next block reservation would overflow it.
    settings.set('sequence', { reservedUpTo: 0xffffff });
    const store = new NetworkStore(settings);

    expect(() => store.allocateSequenceBlock()).toThrow(/sequence-number space exhausted/);
  });

  /**
   * Pins the overflow guard's edge exactly, rather than only from well past
   * it (the test above seeds `reservedUpTo` at `MAX_SEQ`, which overshoots
   * the boundary by a whole `SEQ_BLOCK_SIZE` and so cannot tell a correct
   * `> MAX_SEQ + 1` check apart from an off-by-one `> MAX_SEQ` check — both
   * reject that case identically). Reserving a block that lands EXACTLY on
   * `MAX_SEQ + 1` (every number in [0, MAX_SEQ] now reserved) is the last
   * legal reservation and must succeed; anything that would reserve even
   * one number past it must not.
   */
  test('allows reserving a block that lands exactly on the top of the sequence-number space', () => {
    const settings = new FakeSettingsPort();
    // A fresh store's in-memory cursor starts exactly at the persisted
    // ceiling (see the constructor), so its very first allocation always
    // triggers a new reservation. Seeded this way, that reservation's
    // `newCeiling` lands on EXACTLY `MAX_SEQ + 1` -- the last legal value,
    // one past the final allocatable sequence number `MAX_SEQ`.
    const reservedUpTo = MAX_SEQ + 1 - SEQ_BLOCK_SIZE;
    settings.set('sequence', { reservedUpTo });
    const store = new NetworkStore(settings);

    expect(() => store.allocateSequenceBlock()).not.toThrow();
  });
});
