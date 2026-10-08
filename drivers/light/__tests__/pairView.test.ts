import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The pairing view (`drivers/light/pair/list_devices.html`), driven as real
 * code rather than inspected as text.
 *
 * WHY THIS FILE EXISTS AT ALL. A Homey pairing view is a plain HTML page
 * with `Homey.emit`/`Homey.on`, so nothing in this project's gate — neither
 * `tsc` nor jest — had ever executed a single line of it. That is exactly
 * where the 2026-10-08 hardware defect lived: `Homey.emit('pair_nodes', …)`
 * is a pairing-session RPC that gives up after 30 seconds, three bulbs take
 * longer, and the page created its devices only from that call's result. The
 * driver paired two bulbs perfectly; the view had already fallen into its
 * catch branch, so `Homey.createDevice` never ran for either — two
 * provisioned bulbs, zero Homey devices, and a status line still reading
 * "Pairing dc2351a64076 (3/3)…" because the `pair_progress` events kept
 * arriving after the view had given up.
 *
 * HOW IT RUNS THE REAL FILE. The page's one `<script>` body is read out of
 * the HTML and evaluated with `new Function`, against the smallest possible
 * stand-ins for the four globals it uses: `document`, `Homey`, and the two
 * timer functions. That is deliberately NOT a browser — it cannot tell
 * anything about layout, styling or event bubbling — but it is the real
 * script, so a mutation to the page's own logic turns these tests red,
 * which is the one property source-text scanning (`device-wiring.test.ts`'s
 * technique, used there for a file that genuinely cannot be executed) could
 * never give. The stand-ins are hand-written rather than jsdom because this
 * project has no DOM dependency and this page needs about thirty lines of
 * one.
 *
 * TIMERS ARE FAKE AND NEVER FIRE ON THEIR OWN. The page arms a silence
 * watchdog while it is following a run whose batch call has already given
 * up; `FakeTimers` below records it and fires it only when a test asks, so
 * no test ever waits on wall-clock time and the watchdog's own behaviour is
 * still exercised.
 */

const VIEW_HTML = join(__dirname, '..', 'pair', 'list_devices.html');

function readViewScript(): string {
  const html = readFileSync(VIEW_HTML, 'utf8');
  const open = html.indexOf('<script>');
  const close = html.indexOf('</script>', open);
  if (open === -1 || close === -1) {
    throw new Error('pair view test: list_devices.html has no <script> block to run');
  }
  const script = html.slice(open + '<script>'.length, close);
  // A guard against this extraction silently finding an empty or wrong
  // block (e.g. if the page ever grows a second script): the page's own
  // entry point must be in what we are about to run.
  if (!script.includes('pairSelected')) {
    throw new Error('pair view test: the extracted <script> block does not contain the pairing logic');
  }
  return script;
}

// ===========================================================================
// The smallest DOM this page needs.
// ===========================================================================

class FakeElement {
  readonly children: FakeElement[] = [];
  private readonly listeners = new Map<string, Array<() => void>>();
  className = '';
  textContent = '';
  type = '';
  checked = false;
  disabled = false;

  /** The page only ever assigns `''` to clear the list before re-rendering. */
  set innerHTML(value: string) {
    if (value === '') this.children.length = 0;
  }

  get innerHTML(): string {
    return '';
  }

  appendChild(child: FakeElement): FakeElement {
    this.children.push(child);
    return child;
  }

  addEventListener(name: string, handler: () => void): void {
    const existing = this.listeners.get(name);
    if (existing === undefined) this.listeners.set(name, [handler]);
    else existing.push(handler);
  }

  click(): void {
    for (const handler of this.listeners.get('click') ?? []) handler();
  }
}

class FakeDocument {
  private readonly byId = new Map<string, FakeElement>();

  constructor(ids: readonly string[]) {
    for (const id of ids) this.byId.set(id, new FakeElement());
  }

  getElementById(id: string): FakeElement | null {
    return this.byId.get(id) ?? null;
  }

  createElement(): FakeElement {
    return new FakeElement();
  }

  element(id: string): FakeElement {
    const found = this.byId.get(id);
    if (found === undefined) throw new Error(`pair view test: no element "${id}" in the fake document`);
    return found;
  }
}

class FakeTimers {
  private nextId = 1;
  private readonly pending = new Map<number, () => void>();

  readonly setTimeout = (handler: () => void): number => {
    const id = this.nextId;
    this.nextId += 1;
    this.pending.set(id, handler);
    return id;
  };

  readonly clearTimeout = (id: number): void => {
    this.pending.delete(id);
  };

  get pendingCount(): number {
    return this.pending.size;
  }

  /** Fires every armed timer, as a stalled real clock eventually would. */
  fireAll(): void {
    const handlers = [...this.pending.values()];
    this.pending.clear();
    for (const handler of handlers) handler();
  }
}

// ===========================================================================
// The Homey pairing session, as this page sees it.
// ===========================================================================

interface PairedDescriptor {
  readonly name: string;
  readonly data: { readonly id: string };
  readonly store: { readonly peripheralId: string };
}

type Outcome =
  | { readonly kind: 'paired'; readonly device: PairedDescriptor }
  | { readonly kind: 'failed'; readonly message: string }
  | { readonly kind: 'unsupported'; readonly reason: string };

interface Progress {
  readonly phase: 'start' | 'done';
  readonly index: number;
  readonly total: number;
  readonly peripheralId: string;
  readonly outcome?: Outcome;
}

class FakeHomey {
  private readonly handlers = new Map<string, (payload: unknown) => void>();
  readonly createdDevices: PairedDescriptor[] = [];
  readonly batchRequests: string[][] = [];
  candidates: Array<{ peripheralId: string; rssi: number }> = [];
  createDeviceError: Error | null = null;
  doneCalls = 0;
  private batchSettle: { resolve: (value: unknown) => void; reject: (err: Error) => void } | null = null;

  ready(): void {
    // Nothing to do — the page only has to be able to call it.
  }

  on(event: string, handler: (payload: unknown) => void): void {
    this.handlers.set(event, handler);
  }

  emit(event: string, data: unknown): Promise<unknown> {
    if (event === 'list_devices') return Promise.resolve(this.candidates);
    if (event === 'pair_nodes') {
      this.batchRequests.push([...(data as { peripheralIds: string[] }).peripheralIds]);
      return new Promise<unknown>((resolve, reject) => {
        this.batchSettle = { resolve, reject };
      });
    }
    return Promise.resolve(undefined);
  }

  createDevice(device: PairedDescriptor): Promise<void> {
    if (this.createDeviceError !== null) return Promise.reject(this.createDeviceError);
    this.createdDevices.push(device);
    return Promise.resolve();
  }

  done(): Promise<void> {
    this.doneCalls += 1;
    return Promise.resolve();
  }

  // --- the test's own side -------------------------------------------------

  progress(progress: Progress): void {
    const handler = this.handlers.get('pair_progress');
    if (handler === undefined) throw new Error('pair view test: the page never registered a pair_progress handler');
    handler(progress);
  }

  /** Answers the pending `pair_nodes` call, the way the driver does when the
   *  whole run finished inside Homey's own 30-second RPC window. */
  resolveBatch(result: unknown): void {
    const settle = this.batchSettle;
    if (settle === null) throw new Error('pair view test: no pair_nodes call is in flight');
    this.batchSettle = null;
    settle.resolve(result);
  }

  /** The defect's own failure mode: the RPC gives up while the driver keeps
   *  pairing. */
  rejectBatch(err: Error): void {
    const settle = this.batchSettle;
    if (settle === null) throw new Error('pair view test: no pair_nodes call is in flight');
    this.batchSettle = null;
    settle.reject(err);
  }

  get batchInFlight(): boolean {
    return this.batchSettle !== null;
  }
}

// ===========================================================================
// Harness.
// ===========================================================================

const ELEMENT_IDS = ['status', 'devices', 'error', 'summary', 'pair', 'select-all'];

interface Harness {
  readonly doc: FakeDocument;
  readonly homey: FakeHomey;
  readonly timers: FakeTimers;
}

const VIEW_SCRIPT = readViewScript();

async function flush(turns = 30): Promise<void> {
  for (let i = 0; i < turns; i++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

async function setUp(candidates: ReadonlyArray<{ peripheralId: string; rssi: number }>): Promise<Harness> {
  const doc = new FakeDocument(ELEMENT_IDS);
  const homey = new FakeHomey();
  const timers = new FakeTimers();
  homey.candidates = [...candidates];
  const load = new Function('document', 'Homey', 'setTimeout', 'clearTimeout', VIEW_SCRIPT) as (
    documentArg: FakeDocument,
    homeyArg: FakeHomey,
    setTimeoutArg: FakeTimers['setTimeout'],
    clearTimeoutArg: FakeTimers['clearTimeout'],
  ) => void;
  load(doc, homey, timers.setTimeout, timers.clearTimeout);
  await flush(); // the page's own initial scan()
  return { doc, homey, timers };
}

function paired(peripheralId: string, address: string): Outcome {
  return {
    kind: 'paired',
    device: { name: `Mesh light ${address}`, data: { id: address }, store: { peripheralId } },
  };
}

/** The exact run the owner performed on 2026-10-08. */
const THREE_BULBS = [
  { peripheralId: 'dc2351a643d7', rssi: -58 },
  { peripheralId: 'dc2351a64438', rssi: -60 },
  { peripheralId: 'dc2351a64076', rssi: -71 },
];

async function startPairingAll(h: Harness): Promise<void> {
  h.doc.element('select-all').click();
  h.doc.element('pair').click();
  await flush();
}

// ===========================================================================
// Tests.
// ===========================================================================

describe('the pairing view lists what the scan found', () => {
  test('renders one row per candidate and only pairs the selected ones', async () => {
    const h = await setUp(THREE_BULBS);

    expect(h.doc.element('devices').children).toHaveLength(3);
    expect(h.doc.element('status').textContent).toBe('Select the bulbs to pair');

    h.doc.element('select-all').click();
    h.doc.element('pair').click();
    await flush();

    expect(h.homey.batchRequests).toEqual([['dc2351a643d7', 'dc2351a64438', 'dc2351a64076']]);
  });
});

describe('DEFECT A: the run outlives the call that started it', () => {
  test('THE HARDWARE CASE: a batch call that never answers still gets every paired bulb into Homey', async () => {
    const h = await setUp(THREE_BULBS);
    await startPairingAll(h);

    // The driver works through the three bulbs. The batch call is never
    // answered — in the real incident it rejected at 30 seconds, here it
    // simply never settles, which is the stronger version of the same thing.
    h.homey.progress({ phase: 'start', index: 0, total: 3, peripheralId: 'dc2351a643d7' });
    h.homey.progress({
      phase: 'done',
      index: 0,
      total: 3,
      peripheralId: 'dc2351a643d7',
      outcome: { kind: 'failed', message: 'node did not answer Config Model App Bind' },
    });
    h.homey.progress({ phase: 'start', index: 1, total: 3, peripheralId: 'dc2351a64438' });
    h.homey.progress({ phase: 'done', index: 1, total: 3, peripheralId: 'dc2351a64438', outcome: paired('dc2351a64438', '5') });
    h.homey.progress({ phase: 'start', index: 2, total: 3, peripheralId: 'dc2351a64076' });
    h.homey.progress({ phase: 'done', index: 2, total: 3, peripheralId: 'dc2351a64076', outcome: paired('dc2351a64076', '6') });
    await flush();

    // THE DISCRIMINATING ASSERTION, and the defect itself: on the old page
    // this was an empty array — the descriptors only ever reached
    // `createDevice` through the batch result, and there was no caller left
    // to receive it.
    expect(h.homey.batchInFlight).toBe(true);
    expect(h.homey.createdDevices.map((d) => d.data.id)).toEqual(['5', '6']);
  });

  test('a batch call that gives up mid-run keeps the page locked and following, then ends with an honest status', async () => {
    const h = await setUp(THREE_BULBS);
    await startPairingAll(h);

    h.homey.progress({ phase: 'start', index: 0, total: 3, peripheralId: 'dc2351a643d7' });
    await flush();
    // Homey's own pairing-RPC deadline, word for word.
    h.homey.rejectBatch(new Error('Timeout after 30000ms'));
    await flush();

    // Still locked: a second run would mean a second GATT session beside the
    // one the driver is still using.
    expect(h.doc.element('pair').disabled).toBe(true);
    expect(h.doc.element('select-all').disabled).toBe(true);

    h.homey.progress({
      phase: 'done',
      index: 0,
      total: 3,
      peripheralId: 'dc2351a643d7',
      outcome: { kind: 'failed', message: 'node did not answer Config Model App Bind' },
    });
    h.homey.progress({ phase: 'start', index: 1, total: 3, peripheralId: 'dc2351a64438' });
    h.homey.progress({ phase: 'done', index: 1, total: 3, peripheralId: 'dc2351a64438', outcome: paired('dc2351a64438', '5') });
    h.homey.progress({ phase: 'start', index: 2, total: 3, peripheralId: 'dc2351a64076' });
    h.homey.progress({ phase: 'done', index: 2, total: 3, peripheralId: 'dc2351a64076', outcome: paired('dc2351a64076', '6') });
    await flush();

    expect(h.homey.createdDevices.map((d) => d.data.id)).toEqual(['5', '6']);
    // THE OTHER HALF OF THE DEFECT: the screenshot's status line still read
    // "Pairing dc2351a64076 (3/3)…" after everything had finished. It must
    // now say what actually happened, and must not contradict the rows.
    expect(h.doc.element('status').textContent).toBe('Finished with some failures');
    expect(h.doc.element('summary').textContent).toContain('Added 2 of 3 to Homey');
    expect(h.doc.element('summary').textContent).toContain('dc2351a643d7: Failed: node did not answer Config Model App Bind');
    // The 30-second give-up is explained rather than presented as the run's
    // own failure.
    expect(h.doc.element('error').textContent).toBe('');
    expect(h.doc.element('summary').textContent).toContain('Homey stopped waiting for the pairing call');
    // ...and the page is usable again for the retry.
    expect(h.doc.element('select-all').disabled).toBe(false);
  });

  test('the same \'done\' event delivered twice creates ONE device, not two', async () => {
    // The guard's own path, independent of anything the batch result does:
    // nothing promises a pairing session delivers each event exactly once,
    // and `createDeviceOnce` claims a peripheral id BEFORE it awaits
    // `Homey.createDevice` precisely so a repeat cannot slip past while the
    // first call is still in flight.
    const h = await setUp(THREE_BULBS.slice(0, 1));
    await startPairingAll(h);

    const done = {
      phase: 'done' as const,
      index: 0,
      total: 1,
      peripheralId: 'dc2351a643d7',
      outcome: paired('dc2351a643d7', '5'),
    };
    h.homey.progress({ phase: 'start', index: 0, total: 1, peripheralId: 'dc2351a643d7' });
    h.homey.progress(done);
    h.homey.progress(done);
    await flush();

    expect(h.homey.createdDevices).toHaveLength(1);
    expect(h.doc.element('status').textContent).toBe('Done');
    expect(h.homey.doneCalls).toBe(1);
  });

  test('the batch result backstops a missing progress event, and still never adds a bulb twice', async () => {
    // Both halves of the ownership rule in one run: the page hears about the
    // FIRST bulb only through its progress event and about the SECOND only
    // through the batch result, and the batch result names both. The
    // assertion is an exact list, so a page that created from both paths
    // would show '5' twice here.
    const h = await setUp(THREE_BULBS.slice(0, 2));
    await startPairingAll(h);

    h.homey.progress({ phase: 'start', index: 0, total: 2, peripheralId: 'dc2351a643d7' });
    h.homey.progress({ phase: 'done', index: 0, total: 2, peripheralId: 'dc2351a643d7', outcome: paired('dc2351a643d7', '5') });
    await flush();
    expect(h.homey.createdDevices.map((d) => d.data.id)).toEqual(['5']);

    // ...and nothing at all is ever heard about the second bulb's own event.
    h.homey.resolveBatch({
      entries: [
        { peripheralId: 'dc2351a643d7', outcome: paired('dc2351a643d7', '5') },
        { peripheralId: 'dc2351a64438', outcome: paired('dc2351a64438', '6') },
      ],
      paired: [paired('dc2351a643d7', '5'), paired('dc2351a64438', '6')],
    });
    await flush();

    expect(h.homey.createdDevices.map((d) => d.data.id)).toEqual(['5', '6']);
    expect(h.doc.element('status').textContent).toBe('Done');
    expect(h.homey.doneCalls).toBe(1);
  });

  test('a call that fails before the run ever starts reports the failure and unlocks the page', async () => {
    const h = await setUp(THREE_BULBS.slice(0, 1));
    await startPairingAll(h);

    // No progress event has been seen at all: this is a genuine call
    // failure, not a run that outlived its call.
    h.homey.rejectBatch(new Error('the app is not running'));
    await flush();

    expect(h.doc.element('error').textContent).toBe('Pairing failed: the app is not running');
    expect(h.doc.element('status').textContent).toBe('Select the bulbs to pair');
    expect(h.doc.element('pair').disabled).toBe(false);
    expect(h.homey.createdDevices).toHaveLength(0);
  });

  test('a run that goes silent after its call gave up is eventually let go, and says so', async () => {
    const h = await setUp(THREE_BULBS);
    await startPairingAll(h);

    h.homey.progress({ phase: 'start', index: 0, total: 3, peripheralId: 'dc2351a643d7' });
    h.homey.progress({ phase: 'done', index: 0, total: 3, peripheralId: 'dc2351a643d7', outcome: paired('dc2351a643d7', '5') });
    h.homey.progress({ phase: 'start', index: 1, total: 3, peripheralId: 'dc2351a64438' });
    await flush();
    h.homey.rejectBatch(new Error('Timeout after 30000ms'));
    await flush();

    // The driver dies here: no further progress, ever.
    expect(h.timers.pendingCount).toBeGreaterThan(0);
    h.timers.fireAll();
    await flush();

    expect(h.homey.createdDevices.map((d) => d.data.id)).toEqual(['5']);
    expect(h.doc.element('status').textContent).toBe('Finished with some failures');
    expect(h.doc.element('summary').textContent).toContain('stopped reporting progress');
    // The bulb that was mid-pairing must not be left on screen claiming to
    // still be in progress.
    expect(h.doc.element('summary').textContent).toContain('dc2351a64438: No result');
    expect(h.doc.element('pair').disabled).toBe(false);
  });

  test('a device Homey refuses to add is reported as such, and never counted as added', async () => {
    const h = await setUp(THREE_BULBS.slice(0, 1));
    h.homey.createDeviceError = new Error('a device with this id already exists');
    await startPairingAll(h);

    h.homey.progress({ phase: 'start', index: 0, total: 1, peripheralId: 'dc2351a643d7' });
    h.homey.progress({ phase: 'done', index: 0, total: 1, peripheralId: 'dc2351a643d7', outcome: paired('dc2351a643d7', '5') });
    await flush();

    expect(h.homey.createdDevices).toHaveLength(0);
    expect(h.doc.element('status').textContent).toBe('Nothing was paired');
    expect(h.doc.element('summary').textContent).toContain('could not be added to Homey');
    expect(h.homey.doneCalls).toBe(0);
  });

  test('a run in which everything works closes the wizard exactly once', async () => {
    const h = await setUp(THREE_BULBS.slice(0, 2));
    await startPairingAll(h);

    h.homey.progress({ phase: 'start', index: 0, total: 2, peripheralId: 'dc2351a643d7' });
    h.homey.progress({ phase: 'done', index: 0, total: 2, peripheralId: 'dc2351a643d7', outcome: paired('dc2351a643d7', '5') });
    h.homey.progress({ phase: 'start', index: 1, total: 2, peripheralId: 'dc2351a64438' });
    h.homey.progress({ phase: 'done', index: 1, total: 2, peripheralId: 'dc2351a64438', outcome: paired('dc2351a64438', '6') });
    await flush();

    // Not even waiting for the batch call: every bulb reported done, so the
    // run is over.
    expect(h.homey.batchInFlight).toBe(true);
    expect(h.homey.createdDevices).toHaveLength(2);
    expect(h.doc.element('status').textContent).toBe('Done');
    expect(h.homey.doneCalls).toBe(1);
  });

  test('a progress event arriving after the run has been concluded cannot reopen the status line', async () => {
    const h = await setUp(THREE_BULBS.slice(0, 1));
    await startPairingAll(h);

    h.homey.progress({ phase: 'start', index: 0, total: 1, peripheralId: 'dc2351a643d7' });
    h.homey.progress({ phase: 'done', index: 0, total: 1, peripheralId: 'dc2351a643d7', outcome: paired('dc2351a643d7', '5') });
    await flush();
    expect(h.doc.element('status').textContent).toBe('Done');

    // A stray late event — the exact shape that left the old page claiming
    // to be pairing after it had stopped.
    h.homey.progress({ phase: 'start', index: 0, total: 1, peripheralId: 'dc2351a643d7' });
    await flush();

    expect(h.doc.element('status').textContent).toBe('Done');
    expect(h.homey.createdDevices).toHaveLength(1);
  });
});
