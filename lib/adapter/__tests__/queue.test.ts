import { randomBytes } from 'node:crypto';
import { ProxyConnectionManager, SCAN_DURATION_MS } from '../connection';
import { FakeBluetoothPort } from './fakeBluetooth';
import { createFakeClock, type FakeClock } from './fakeClock';
import { TrafficQueue, DEFAULT_TIMEOUT_MS, DEFAULT_MAX_ATTEMPTS, type QueuedCommand } from '../queue';

/** Waits a full macrotask turn, same technique (and same reason) as
 *  fakeClock.ts's own private `flushMicrotasks`: a rejection released via
 *  `FakeBluetoothPort.releaseWrite` propagates up through
 *  `ProxyConnectionManager.write`'s own `await` before reaching this
 *  module's `.catch()` handler -- more than one microtask hop, so a single
 *  `await Promise.resolve()` is not reliably enough to observe its effect
 *  before the next synchronous assertion. */
function flushMicrotasks(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

/**
 * The traffic queue has no published sample to anchor against (see
 * queue.ts's own module header) -- these tests ARE the specification for
 * its behaviour, driven against the SAME fixtures connection.test.ts uses
 * (FakeBluetoothPort, FakeClock), through a REAL `ProxyConnectionManager`
 * rather than a second, hand-rolled mock of it. This is what the plan's
 * pre-flight conflict scan means by "T5 must not re-declare the port": the
 * queue is tested exactly as it will really be used, writing through and
 * listening on an actual connection manager.
 *
 * SECOND PASS, after a review rejected the first: it found that a
 * disconnection mid-command produced one reconnect and ZERO retransmissions
 * rather than the design's "one reconnect and one retry" -- hidden behind a
 * green suite because every test here, and the shared fake's own default,
 * let `scan()` resolve instantly. `FakeBluetoothPort` now accepts an
 * optional `ClockPort` (see its own module header's "SCAN TIMING" note) so
 * a test can make `scan()` genuinely consume `SCAN_DURATION_MS` of virtual
 * time -- `realtimeScan: true` below. `setUp`/`connect` account for that;
 * every OTHER test still gets the original instant-scan behaviour (no
 * `realtimeScan`, same as before this review). The fixture also grew
 * `setWriteBehavior`/`releaseWrite` ('hold' a write open until a test
 * chooses to settle it) -- moved there from a task-local stub after review
 * feedback that a held-open write is a genuine, reusable BLE failure mode
 * (a congested transmit queue), not an invented one; see
 * "a write() that settles late" below, which now drives this through the
 * shared fixture and a real `ProxyConnectionManager` instead of a
 * hand-rolled `TrafficPort`.
 *
 * Every test uses ONE node, 'A', already connected, unless a test is
 * specifically about reconnection or about never having connected at all.
 */

function setUp(options?: { timeoutMs?: number; maxAttempts?: number; realtimeScan?: boolean }): {
  bluetooth: FakeBluetoothPort;
  clock: FakeClock;
  manager: ProxyConnectionManager;
  queue: TrafficQueue;
} {
  const netKey = randomBytes(16);
  const clock = createFakeClock();
  const bluetooth = new FakeBluetoothPort(options?.realtimeScan === true ? clock : undefined);
  const manager = new ProxyConnectionManager(bluetooth, clock, netKey);
  bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
  const queue = new TrafficQueue(manager, clock, { timeoutMs: options?.timeoutMs, maxAttempts: options?.maxAttempts });
  return { bluetooth, clock, manager, queue };
}

/** Advances through however long the initial scan genuinely takes --
 *  `SCAN_DURATION_MS` covers both the instant-scan fake (resolves long
 *  before that much virtual time is even checked) and the realtime-scan
 *  one (which needs exactly that much). */
async function connect(manager: ProxyConnectionManager, clock: FakeClock): Promise<void> {
  manager.start();
  await clock.advance(SCAN_DURATION_MS);
  expect(manager.getState().status).toBe('connected');
}

describe('constructor validation', () => {
  test.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])('rejects a non-positive-finite timeoutMs (%p), naming it', (timeoutMs) => {
    const { manager, clock } = setUp();
    expect(() => new TrafficQueue(manager, clock, { timeoutMs })).toThrow(
      `TrafficQueue: timeoutMs must be a positive finite number, got ${timeoutMs}`,
    );
  });

  test.each([0, -1, 1.5])('rejects a maxAttempts that is not a positive integer (%p), naming it', (maxAttempts) => {
    const { manager, clock } = setUp();
    expect(() => new TrafficQueue(manager, clock, { maxAttempts })).toThrow(
      `TrafficQueue: maxAttempts must be an integer >= 1, got ${maxAttempts}`,
    );
  });
});

describe('defaults', () => {
  /**
   * Unpinned behaviour, review finding: nothing previously asserted what
   * the actual default values were, even though the disconnection defect
   * turned on exactly this relationship (a per-attempt timeout equal to,
   * rather than comfortably longer than, one scan window).
   */
  test('DEFAULT_TIMEOUT_MS is comfortably longer than one scan window, not merely equal to it', () => {
    expect(DEFAULT_TIMEOUT_MS).toBeGreaterThan(SCAN_DURATION_MS);
    expect(DEFAULT_TIMEOUT_MS).toBe(SCAN_DURATION_MS * 2);
  });

  test('with no options given, retries are paced by DEFAULT_TIMEOUT_MS and bounded by DEFAULT_MAX_ATTEMPTS', async () => {
    const { bluetooth, clock, manager, queue } = setUp(); // no overrides at all
    await connect(manager, clock);

    const promise = queue.send({ data: Buffer.from([0x01]), description: 'test command', isStatus: () => false });
    const rejection = expect(promise).rejects.toThrow(
      `test command: no status received after ${DEFAULT_MAX_ATTEMPTS} attempts`,
    );

    for (let attempt = 1; attempt <= DEFAULT_MAX_ATTEMPTS; attempt += 1) {
      expect(bluetooth.writesReceived).toHaveLength(attempt);
      await clock.advance(DEFAULT_TIMEOUT_MS);
    }
    await rejection;
    expect(bluetooth.writesReceived).toHaveLength(DEFAULT_MAX_ATTEMPTS); // bounded, not one more
  });
});

describe('serialisation', () => {
  /**
   * Values chosen deliberately: the two commands' own bytes (0xa1/0xa2)
   * and the two statuses that answer them (0xf1/0xf2) are all distinct
   * from each other and from one another's counterpart, so a bug that
   * resolves a command with ITS OWN outgoing data instead of the
   * notification that answered it (or that answers the wrong one of the
   * two) is caught by `toEqual`, not hidden behind an accidental byte
   * coincidence.
   *
   * MUTATION (task brief): make the queue send both commands immediately
   * (e.g. have `send()` call `attempt()` directly instead of going through
   * `pump()`'s "only if nothing is active" guard). Verified this failed
   * the first assertion below (`writesReceived` had length 2 right after
   * both `send()` calls, not 1) before restoring the guard.
   */
  test('two commands issued at once are sent one after the other, not together', async () => {
    const { bluetooth, clock, manager, queue } = setUp();
    await connect(manager, clock);

    const a: QueuedCommand = { data: Buffer.from([0xa1]), description: 'command A', isStatus: (n) => n.equals(Buffer.from([0xf1])) };
    const b: QueuedCommand = { data: Buffer.from([0xa2]), description: 'command B', isStatus: (n) => n.equals(Buffer.from([0xf2])) };

    const pA = queue.send(a);
    const pB = queue.send(b);

    // Only A has reached the port -- B is still sitting in the backlog.
    expect(bluetooth.writesReceived.map((w) => w.data.toString('hex'))).toEqual(['a1']);

    bluetooth.simulateNotification('A', Buffer.from([0xf1]));
    await expect(pA).resolves.toEqual(Buffer.from([0xf1]));

    // Only NOW, after A settled, has B been written -- not at the same time as A.
    expect(bluetooth.writesReceived.map((w) => w.data.toString('hex'))).toEqual(['a1', 'a2']);

    bluetooth.simulateNotification('A', Buffer.from([0xf2]));
    await expect(pB).resolves.toEqual(Buffer.from([0xf2]));
  });

  /**
   * Unpinned behaviour, review finding: with only TWO commands and strict
   * serialisation, first-in-first-out and last-in-first-out are
   * indistinguishable -- there is only ever one candidate sitting in the
   * backlog when a choice has to be made about which one goes next. THREE
   * commands, all enqueued while A is still active (so B and C are BOTH
   * waiting in the backlog at once), make the choice observable: `pump()`
   * must pick the OLDEST (`Array.prototype.shift`), not the newest
   * (`.pop()`), of the two waiting behind A.
   */
  test('three commands issued at once are sent in first-in-first-out order, not last-in-first-out', async () => {
    const { bluetooth, clock, manager, queue } = setUp();
    await connect(manager, clock);

    const a = queue.send({ data: Buffer.from([0xa1]), description: 'A', isStatus: (n) => n.equals(Buffer.from([0xf1])) });
    const b = queue.send({ data: Buffer.from([0xa2]), description: 'B', isStatus: (n) => n.equals(Buffer.from([0xf2])) });
    const c = queue.send({ data: Buffer.from([0xa3]), description: 'C', isStatus: (n) => n.equals(Buffer.from([0xf3])) });

    expect(bluetooth.writesReceived.map((w) => w.data.toString('hex'))).toEqual(['a1']);

    bluetooth.simulateNotification('A', Buffer.from([0xf1]));
    await a;
    // B, enqueued BEFORE C, must go next -- a LIFO backlog would send C here instead.
    expect(bluetooth.writesReceived.map((w) => w.data.toString('hex'))).toEqual(['a1', 'a2']);

    bluetooth.simulateNotification('A', Buffer.from([0xf2]));
    await b;
    expect(bluetooth.writesReceived.map((w) => w.data.toString('hex'))).toEqual(['a1', 'a2', 'a3']);

    bluetooth.simulateNotification('A', Buffer.from([0xf3]));
    await expect(c).resolves.toEqual(Buffer.from([0xf3]));
  });

  /**
   * Unpinned behaviour, review finding: "removing the pump from your
   * failure path strands every command queued behind a failed one,
   * forever". Nothing previously enqueued a SECOND command behind one that
   * FAILS (as opposed to one that succeeds, already covered above) -- so a
   * missing `this.pump()` call in `fail()` passed the whole suite.
   */
  test('a command queued behind one that ultimately fails is still sent, not stranded forever', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 1 });
    await connect(manager, clock);

    const a = queue.send({ data: Buffer.from([0xa1]), description: 'A', isStatus: () => false });
    const aRejection = expect(a).rejects.toThrow('A: no status received after 1 attempt');
    const b = queue.send({ data: Buffer.from([0xa2]), description: 'B', isStatus: (n) => n.equals(Buffer.from([0xf2])) });

    expect(bluetooth.writesReceived.map((w) => w.data.toString('hex'))).toEqual(['a1']); // B still waiting behind A

    await clock.advance(1000); // A's only attempt times out -> A fails
    await aRejection;

    expect(bluetooth.writesReceived.map((w) => w.data.toString('hex'))).toEqual(['a1', 'a2']); // B was NOT stranded

    bluetooth.simulateNotification('A', Buffer.from([0xf2]));
    await expect(b).resolves.toEqual(Buffer.from([0xf2]));
  });
});

describe('a command whose status arrives', () => {
  /**
   * The command's own outgoing bytes (0x11, 0x22) and the status that
   * answers it (0x33, 0x44) are chosen to be clearly distinct from each
   * other -- a discriminating value, not a palindrome: an implementation
   * that accidentally resolved with the OUTGOING data instead of the
   * INCOMING notification (confusing "what we sent" with "what we
   * received", the same class of bug the project's own lessons warn
   * about for "what vs where") would fail `toEqual(status)` here, since
   * the two buffers do not share bytes.
   */
  test('resolves with that exact status', async () => {
    const { bluetooth, clock, manager, queue } = setUp();
    await connect(manager, clock);

    const data = Buffer.from([0x11, 0x22]);
    const status = Buffer.from([0x33, 0x44]);
    const promise = queue.send({ data, description: 'test command', isStatus: (n) => n.equals(status) });

    bluetooth.simulateNotification('A', status);

    await expect(promise).resolves.toEqual(status);
  });

  /**
   * Review correction: the first version of this test claimed removing
   * `clearTimer` from `succeed()` broke nothing observable, and concluded
   * the real protection was nulling `this.active`. That conclusion was
   * WRONG -- the timer IS independently reachable, in six lines, using
   * `FakeClock.pendingCount()` (documented there for exactly this: "for
   * assertions that want to know whether the manager is still waiting on
   * something... without inspecting any of its own fields"). With real
   * timers, a stranded timer per completed command keeps the event loop
   * alive and holds the `entry` closure alive with it -- a genuine
   * resource leak, not merely "harmless because unreachable". This test
   * now checks BOTH halves: the timer is actually cancelled (`pendingCount`
   * returns to its pre-send value), and nothing it could have fired later
   * produces a spurious write.
   *
   * MUTATIONS, both tried against this version:
   * (1) remove `this.clearTimer(entry)` from `succeed()` (keep
   * `this.active = null`) -- FAILS the `pendingCount` assertion now (it
   * stays one higher than before `send()`, instead of returning to the
   * same value): the gap this review found.
   * (2) remove `this.active = null` instead (keep `clearTimer`) -- does
   * NOT fail this test (a single command has nothing queued behind it to
   * get stuck), but DOES fail both "serialisation" tests above (the next
   * backlog entry can never start). Restored both; noted here so the
   * coverage for that second mutation is attributed to the right tests.
   */
  test('a settled command actually cancels its own timer, leaving nothing behind that could fire a spurious retry later', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 3 });
    await connect(manager, clock);
    const pendingBeforeSend = clock.pendingCount();

    const status = Buffer.from([0x77]);
    const promise = queue.send({ data: Buffer.from([0x01]), description: 'test command', isStatus: (n) => n.equals(status) });
    expect(clock.pendingCount()).toBe(pendingBeforeSend + 1); // this attempt's own timer is now pending

    bluetooth.simulateNotification('A', status); // resolves well before timeoutMs elapses
    await expect(promise).resolves.toEqual(status);
    expect(clock.pendingCount()).toBe(pendingBeforeSend); // the timer was actually cancelled, not merely made harmless

    await clock.advance(10_000); // far past where the original attempt's timeout would have fired
    expect(bluetooth.writesReceived).toHaveLength(1); // no retry ever happened
  });
});

describe('bounded retries', () => {
  /**
   * MUTATION (task brief): make the retry unbounded (e.g. drop the
   * `entry.attemptsMade < this.maxAttempts` check in `retryOrFail` and
   * always retry). Verified this made the queue retry forever: after
   * advancing the clock by several attempts' worth of timeouts,
   * `writesReceived` kept growing and the promise never settled. More
   * dramatically, the SAME mutation applied to the next test below (which
   * never connects at all, so every attempt fails outright rather than
   * timing out) crashed the whole Node process with a V8 out-of-memory
   * heap error, rather than merely failing an assertion -- see that test's
   * own comment. Restored the check.
   */
  test('a command whose status never arrives is retried a bounded number of times, then fails naming the command', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 3 });
    await connect(manager, clock);

    const promise = queue.send({ data: Buffer.from([0x01]), description: 'Generic OnOff Set 0x0042', isStatus: () => false });
    const rejection = expect(promise).rejects.toThrow('Generic OnOff Set 0x0042: no status received after 3 attempts');

    await clock.advance(1000); // attempt 1 times out -> retry (attempt 2)
    await clock.advance(1000); // attempt 2 times out -> retry (attempt 3)
    await clock.advance(1000); // attempt 3 times out -> bounded, gives up

    await rejection;
    expect(bluetooth.writesReceived).toHaveLength(3);

    // Not a generic "timeout" -- the message names the command.
    await expect(promise).rejects.not.toThrow('timeout');
  });

  /**
   * Beyond the brief's own list: `write()` itself can reject outright
   * (ProxyConnectionManager does exactly this whenever nothing is
   * connected) -- a different code path from "the write succeeded but no
   * status ever came back". This never calls `connect()`, so every
   * `manager.write()` call rejects every time.
   *
   * REVIEW FIX: the first version of this test needed no clock advancement
   * at all, because the original (defective) implementation retried
   * straight from the rejection handler with no delay -- the entire bound
   * attempt budget was spent inside one microtask chain. That is precisely
   * the defect the review found (see queue.ts's module header): a
   * rejected write is now a reason to WAIT for this attempt's own timer,
   * not a reason to retry instantly, so this test now paces through one
   * `clock.advance(timeoutMs)` per attempt, same as every other
   * bounded-retry test.
   */
  test('write() rejecting outright (never connected at all) is paced and bounded the same way, and the final failure carries the underlying reason', async () => {
    const { clock, queue } = setUp({ timeoutMs: 1000, maxAttempts: 2 });
    // Deliberately never call connect(): manager.write() always rejects.

    const promise = queue.send({ data: Buffer.from([0x01]), description: 'test command', isStatus: () => false });
    const rejection = expect(promise).rejects.toThrow(
      'test command: no status received after 2 attempts (last attempt: ProxyConnectionManager.write: no active proxy connection)',
    );

    await clock.advance(1000); // attempt 1's own timeout -> retry (attempt 2), which also rejects
    await clock.advance(1000); // attempt 2's own timeout -> bounded, gives up

    await rejection;
  });
});

describe('disconnection mid-command', () => {
  /**
   * THE DEFECT A REVIEW FOUND, and the mechanism fix. The ORIGINAL
   * implementation retried a rejected write straight from its `.catch()`
   * handler, with no delay -- so once the link was down, the remaining
   * attempt budget was consumed inside one microtask chain, against a
   * radio that provably was not there yet. This test forces EXACTLY that
   * situation: `timeoutMs` (1000ms) is deliberately much shorter than the
   * reconnect's own scan window (`realtimeScan: true`, `SCAN_DURATION_MS` =
   * 4000ms by default), so the FIRST retry's write is guaranteed to hit the
   * link while it is still reconnecting. The fixed implementation must
   * still only write once per elapsed `timeoutMs` -- never more than one
   * write per `clock.advance(1000)` call below -- and must eventually
   * succeed once the reconnect finishes.
   *
   * MUTATION: reverted `attempt`'s `write().catch()` handler to call
   * `this.retryOrFail(entry, ...)` directly (the original defect).
   * Verified this failed: `settled` was already `true` (the command had
   * REJECTED) right after the very first `clock.advance(1000)` below --
   * every remaining attempt (2 through 5) cascaded inside that one
   * `advance` call, each rejecting instantly because the link was still
   * down, with no clock time ever separating them. Restored the fix.
   *
   * NOTE on `writesReceived`: a write attempted while genuinely
   * disconnected never reaches `FakeBluetoothPort` at all --
   * `ProxyConnectionManager.write` rejects BEFORE calling
   * `bluetooth.write()` (see its own doc comment) -- so attempts 2
   * through 4 below add nothing to `writesReceived`; only attempt 1
   * (before the disconnect) and attempt 5 (after reconnection) do. The
   * thing this test actually has to observe is PACING, not a write count
   * that can't move while nothing is connected -- hence tracking
   * `settled` instead.
   */
  test('a write rejected because the link is not back yet paces retries by the clock rather than cascading instantly', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 5, realtimeScan: true });
    await connect(manager, clock); // now at t = SCAN_DURATION_MS
    expect(bluetooth.writesReceived).toHaveLength(0);

    const status = Buffer.from([0x42]);
    const promise = queue.send({ data: Buffer.from([0x01]), description: 'test command', isStatus: (n) => n.equals(status) });
    let settled = false;
    promise.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    expect(bluetooth.writesReceived).toHaveLength(1); // attempt 1's write succeeds -- still connected

    bluetooth.simulateDisconnect('A'); // the reconnect's own scan will take a full SCAN_DURATION_MS, for real

    // Attempts 2, 3 and 4 all happen while still reconnecting -- paced one
    // per `clock.advance(1000)` call, never cascading through the whole
    // remaining budget inside a single one of these calls.
    await clock.advance(1000); // attempt 1 times out -> attempt 2 (rejects, not reconnected yet)
    expect(settled).toBe(false);
    await clock.advance(1000); // attempt 3 (rejects)
    expect(settled).toBe(false);
    await clock.advance(1000); // attempt 4 (rejects)
    expect(settled).toBe(false);

    // 4000ms have now passed since the disconnect -- the reconnect's own
    // scan finishes at this same virtual instant, so attempt 5's write
    // lands on an already-restored connection.
    await clock.advance(1000);
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });
    expect(bluetooth.writesReceived).toHaveLength(2); // attempt 1's write, then attempt 5's

    bluetooth.simulateNotification('A', status);
    await expect(promise).resolves.toEqual(status);
  });

  /**
   * THE DESIGN'S OWN WORDING, pinned directly: "A disconnection mid-command
   * causes one reconnect and one retry" -- with the DEFAULT options (no
   * overrides) and a scan that genuinely takes its documented duration,
   * which is what let the original defect hide behind a green suite (see
   * queue.ts's module header and this file's own header above).
   */
  test('with default options and a scan that genuinely takes its documented duration, produces exactly one reconnect and exactly one retry', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ realtimeScan: true }); // DEFAULT_TIMEOUT_MS / DEFAULT_MAX_ATTEMPTS
    await connect(manager, clock);
    expect(bluetooth.connectCalls).toEqual(['A']);

    const status = Buffer.from([0x99]);
    const promise = queue.send({ data: Buffer.from([0x01]), description: 'test command', isStatus: (n) => n.equals(status) });
    expect(bluetooth.writesReceived).toHaveLength(1); // the first attempt's write went out before the disconnect

    bluetooth.simulateDisconnect('A'); // the link drops while we are waiting for a status
    expect(manager.getState().status).toBe('unavailable');

    await clock.advance(SCAN_DURATION_MS); // the reconnect's own scan, taking its full real duration
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });
    expect(bluetooth.connectCalls).toEqual(['A', 'A']); // exactly one reconnect
    expect(bluetooth.writesReceived).toHaveLength(1); // DEFAULT_TIMEOUT_MS has not elapsed yet -- no retry yet

    await clock.advance(DEFAULT_TIMEOUT_MS - SCAN_DURATION_MS); // reach the queue's own per-attempt timeout
    expect(bluetooth.writesReceived).toHaveLength(2); // exactly one retry write, landing on an already-restored link

    bluetooth.simulateNotification('A', status);
    await expect(promise).resolves.toEqual(status);

    // Advancing well past this must not produce another write or reconnect.
    await clock.advance(DEFAULT_TIMEOUT_MS * DEFAULT_MAX_ATTEMPTS);
    expect(bluetooth.writesReceived).toHaveLength(2);
    expect(bluetooth.connectCalls).toEqual(['A', 'A']);
  });
});

describe('unsolicited statuses', () => {
  /**
   * The notification that answers nothing (0x66) and the one that
   * genuinely answers the pending command (0x55) are distinct values, so
   * the final assertion -- that the real status resolved the command and
   * was NOT also handed to the unsolicited listener -- actually
   * discriminates a "forward to both paths" bug from correct behaviour.
   */
  test('is delivered to a listener and does not resolve or disturb a pending command', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 2 });
    await connect(manager, clock);

    const received: Buffer[] = [];
    queue.onUnsolicited((data) => received.push(data));

    const expectedStatus = Buffer.from([0x55]);
    const promise = queue.send({ data: Buffer.from([0x01]), description: 'test command', isStatus: (n) => n.equals(expectedStatus) });

    const unsolicited = Buffer.from([0x66]); // does not satisfy isStatus
    bluetooth.simulateNotification('A', unsolicited);

    expect(received).toHaveLength(1);
    expect(received[0]).toEqual(unsolicited);

    bluetooth.simulateNotification('A', expectedStatus);
    await expect(promise).resolves.toEqual(expectedStatus);
    expect(received).toHaveLength(1); // the real status was not ALSO forwarded as unsolicited
  });

  test('unsubscribing stops further delivery to that listener', async () => {
    const { bluetooth, clock, manager, queue } = setUp();
    await connect(manager, clock);

    const received: Buffer[] = [];
    const unsubscribe = queue.onUnsolicited((data) => received.push(data));
    bluetooth.simulateNotification('A', Buffer.from([0x01]));
    unsubscribe();
    bluetooth.simulateNotification('A', Buffer.from([0x02]));

    expect(received).toHaveLength(1);
  });

  test('one listener cannot corrupt what another receives by mutating its own copy', async () => {
    const { bluetooth, clock, manager, queue } = setUp();
    await connect(manager, clock);

    const secondReceived: Buffer[] = [];
    queue.onUnsolicited((data) => data.fill(0)); // mutates its own copy
    queue.onUnsolicited((data) => secondReceived.push(data));
    bluetooth.simulateNotification('A', Buffer.from([0x07, 0x08]));

    expect(secondReceived[0]?.toString('hex')).toBe('0708');
  });

  /**
   * Invented beyond the brief: a throwing listener must not stop delivery
   * to the OTHER listeners registered alongside it, and must not escape
   * into `ProxyConnectionManager`'s own notification dispatch loop.
   */
  test('a listener that throws does not stop delivery to the other listeners', async () => {
    const { bluetooth, clock, manager, queue } = setUp();
    await connect(manager, clock);

    const secondReceived: Buffer[] = [];
    queue.onUnsolicited(() => {
      throw new Error('boom');
    });
    queue.onUnsolicited((data) => secondReceived.push(data));

    expect(() => bluetooth.simulateNotification('A', Buffer.from([0x09]))).not.toThrow();
    expect(secondReceived).toHaveLength(1);
  });
});

describe('the subtle case: a late status for an abandoned command', () => {
  /**
   * The realistic hazard (task brief, and queue.ts's own module header):
   * a Status message carries no transaction identifier, so nothing on the
   * wire distinguishes "the belated answer to a command we already gave
   * up on" from "the answer to whatever is pending now", if both commands
   * use the same SHAPE of predicate -- entirely plausible, since a
   * predicate checking "is this a status for my model" should not also
   * check the requested value (status reports truth, which may legitimately
   * differ from what was asked). `isOnOffStatus` below is deliberately
   * that coarse: it matches on shape (first byte 0x01) only, identically
   * for command A and command B, exactly reproducing the danger rather
   * than dodging it with a conveniently specific predicate.
   *
   * The two payloads that follow that shared shape byte -- 0xaa (the
   * stale value A asked about) and 0xbb (the genuine value for B) -- are
   * chosen to be different from each other, so the final assertion
   * actually discriminates "B resolved with the correct, later status"
   * from "B resolved with the earlier, late one".
   *
   * Review finding: this test registered no unsolicited listener, so the
   * module header's own claim -- that forwarding a late status as
   * unsolicited would reproduce the harm the brief names, just via a
   * different path -- was argued but never checked. One is registered
   * below now; it must receive NOTHING for the whole test.
   *
   * MUTATION (task brief): make a late status resolve the current pending
   * command (deleted the `lastAbandoned` check in `handleNotification`,
   * i.e. went straight to checking `this.active`). Verified this failed:
   * after `simulateNotification('A', lateStatusForA)`, B's promise
   * resolved immediately with `0x01 0xaa` (the stale value), so the
   * "still waiting, produces a retry" assertion below failed (no 4th
   * write appeared -- the queue believed B was already done) and the
   * final `resolves.toEqual(realStatusForB)` assertion would also have
   * failed had the test continued (B was already settled with the wrong
   * bytes). Restored the check.
   */
  test('is ignored rather than resolving a later command, and is never forwarded as unsolicited either', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 2 });
    await connect(manager, clock);

    const received: Buffer[] = [];
    queue.onUnsolicited((data) => received.push(data));

    const isOnOffStatus = (n: Buffer): boolean => n.length >= 1 && n[0] === 0x01;

    const a = queue.send({ data: Buffer.from([0xa0]), description: 'command A', isStatus: isOnOffStatus });
    const aRejection = expect(a).rejects.toThrow('command A: no status received after 2 attempts');
    await clock.advance(1000); // attempt 1 times out -> retry
    await clock.advance(1000); // attempt 2 times out -> A gives up
    await aRejection;
    expect(bluetooth.writesReceived).toHaveLength(2); // A's two attempts

    const b = queue.send({ data: Buffer.from([0xb0]), description: 'command B', isStatus: isOnOffStatus });
    expect(bluetooth.writesReceived).toHaveLength(3); // B's first attempt

    // The late straggler: A's real (belated) status, arriving only now --
    // same shape as what B is waiting for, different payload.
    const lateStatusForA = Buffer.from([0x01, 0xaa]);
    bluetooth.simulateNotification('A', lateStatusForA);
    expect(received).toHaveLength(0); // ignored outright -- not even delivered as unsolicited

    // B must still be waiting: advancing past its attempt-1 timeout
    // produces a retry write. If the late notification had wrongly
    // resolved B already, no further write would appear here.
    await clock.advance(1000);
    expect(bluetooth.writesReceived).toHaveLength(4);

    const realStatusForB = Buffer.from([0x01, 0xbb]); // same shape, genuinely different value
    bluetooth.simulateNotification('A', realStatusForB);
    await expect(b).resolves.toEqual(realStatusForB);
    expect(received).toHaveLength(0); // the real answer to B was not forwarded as unsolicited either
  });

  /**
   * The one-shot scope of the guard, stated as its own behaviour: a
   * notification that does NOT match the abandoned command's predicate is
   * not swallowed by it -- only a matching one is, and only the very next
   * one. This is what keeps the safety net from permanently blinding the
   * queue to genuinely unsolicited traffic after any command happens to
   * fail.
   */
  test('does not suppress a genuinely unrelated notification arriving right after the abandonment', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 1 });
    await connect(manager, clock);

    const received: Buffer[] = [];
    queue.onUnsolicited((data) => received.push(data));

    const a = queue.send({ data: Buffer.from([0x01]), description: 'command A', isStatus: () => false });
    const aRejection = expect(a).rejects.toThrow('command A: no status received after 1 attempt');
    await clock.advance(1000); // A's only attempt times out -> gives up
    await aRejection;

    const unrelated = Buffer.from([0xde, 0xad]); // shares no shape with anything A was ever waiting for
    bluetooth.simulateNotification('A', unrelated);

    expect(received).toHaveLength(1);
    expect(received[0]).toEqual(unrelated);
  });

  /**
   * Invented beyond the brief: a throwing predicate (caller-supplied
   * business logic, so the most likely of this module's own inputs to
   * actually throw) must not stop the notification from being handled at
   * all -- it is treated as "does not match" rather than escaping into
   * `ProxyConnectionManager`'s own dispatch loop.
   */
  test('a throwing isStatus predicate is treated as a non-match rather than escaping the notification handler', async () => {
    const { bluetooth, clock, manager, queue } = setUp();
    await connect(manager, clock);

    const received: Buffer[] = [];
    queue.onUnsolicited((data) => received.push(data));

    const promise = queue.send({
      data: Buffer.from([0x01]),
      description: 'test command',
      isStatus: () => {
        throw new Error('predicate exploded');
      },
    });

    const data = Buffer.from([0x02]);
    expect(() => bluetooth.simulateNotification('A', data)).not.toThrow();
    expect(received).toHaveLength(1); // treated as "does not match" -> falls through to unsolicited
    expect(received[0]).toEqual(data);

    // The pending command is still pending -- not resolved, not corrupted.
    const stillPending = await Promise.race([promise.then(() => 'settled' as const), Promise.resolve('pending' as const)]);
    expect(stillPending).toBe('pending');
  });
});

describe('defensive copying', () => {
  /**
   * Mirrors connection.test.ts's own "passes k3 a copy" test, applied to
   * this module's own global-constraint obligation: `send()` must take an
   * immutable snapshot immediately, since a caller is free to reuse or
   * mutate its buffer right after calling `send()`, while the command may
   * still be sitting in the backlog or being retried much later.
   */
  test('send() snapshots the command data -- mutating the caller\'s buffer afterward does not change what gets (re)sent', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 2 });
    await connect(manager, clock);

    const data = Buffer.from([0x01, 0x02]);
    const promise = queue.send({ data, description: 'test command', isStatus: () => false });
    // Attached before the promise ever settles -- see the other tests'
    // identical pattern; attaching the rejection handler only after both
    // `advance()` calls below left a window where Node saw an unhandled
    // rejection and failed the test with it directly, rather than letting
    // this test's own assertions run.
    const rejection = expect(promise).rejects.toThrow('test command: no status received after 2 attempts');
    data.fill(0xff); // mutate the caller's own buffer right after send() returns

    await clock.advance(1000); // attempt 1 times out -> retry (attempt 2)
    expect(bluetooth.writesReceived.map((w) => w.data.toString('hex'))).toEqual(['0102', '0102']);

    await clock.advance(1000); // attempt 2 times out -> final failure, not the point of this test
    await rejection;
  });

  /**
   * Review finding: this module handed its OWN stored snapshot straight to
   * the transport (`this.transport.write(entry.data)`), relying on
   * `ProxyConnectionManager.write`'s own internal `Buffer.from(data)` copy
   * to keep that snapshot safe from a transport that mutates what it was
   * given -- a property of THAT implementation, not a documented contract
   * of `TrafficPort`. Since byte-identity across retries is the whole
   * premise the transaction-identifier argument rests on, `attempt()` now
   * copies again at the call site. A transport that writes into its own
   * argument -- plausible, and not something `TrafficPort`'s own contract
   * forbids -- must not corrupt a later retry of the same command.
   */
  test('a transport that mutates the buffer it was given does not corrupt a later retry of the same command', async () => {
    const clock = createFakeClock();
    const written: Buffer[] = [];
    const mutatingTransport = {
      write: async (data: Buffer): Promise<void> => {
        written.push(Buffer.from(data));
        data.fill(0xee); // a hostile (or merely careless) transport mutating its own argument
      },
      onNotification: (): (() => void) => () => {},
    };
    const queue = new TrafficQueue(mutatingTransport, clock, { timeoutMs: 1000, maxAttempts: 2 });

    const original = Buffer.from([0x01, 0x02]);
    const promise = queue.send({ data: original, description: 'test command', isStatus: () => false });
    const rejection = expect(promise).rejects.toThrow();

    await clock.advance(1000); // attempt 1 times out -> retry (attempt 2)
    expect(written.map((b) => b.toString('hex'))).toEqual(['0102', '0102']); // NOT ['0102', 'eeee']

    await clock.advance(1000);
    await rejection;
  });
});

describe('a write() that settles late, after its own attempt has already been superseded', () => {
  /**
   * `FakeBluetoothPort.setWriteBehavior(id, 'hold')` (added for this task,
   * after review feedback that a held-open write belongs in the shared
   * fixture -- see this file's own header) lets this test hold attempt 1's
   * write open past the point where its timeout fires and attempt 2 has
   * already started, then settle it late -- unreachable through the
   * fixture's DEFAULT behaviour, which always settles `write()` within a
   * couple of microtasks.
   *
   * MUTATION HISTORY, revised after the mechanism fix changed what this
   * guard actually protects: BEFORE the fix, the `write().catch()` handler
   * called `retryOrFail` directly, so a missing token check let a stale
   * rejection trigger an extra, premature retry -- removing
   * `entry.attemptsMade !== token` (keeping only `this.active !== entry`)
   * used to fail THIS test (the second `writesReceived` assertion, right
   * after the stale release, showed 3 instead of 2). AFTER the fix, the
   * catch handler no longer calls `retryOrFail` at all -- it only records
   * `entry.lastError` -- so that same mutation no longer fails THIS test
   * (re-verified: it now passes unchanged). What the token check still
   * guards is narrower but real: which attempt's rejection reason ends up
   * in the final failure message. See the SECOND test below, which is
   * what now catches it.
   */
  test('is ignored -- it does not disturb the attempt that superseded it', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 3 });
    await connect(manager, clock);
    bluetooth.setWriteBehavior('A', 'hold');

    const promise = queue.send({ data: Buffer.from([0x01]), description: 'test command', isStatus: () => false });
    const rejection = expect(promise).rejects.toThrow('test command: no status received after 3 attempts');
    expect(bluetooth.writesReceived).toHaveLength(1); // attempt 1's write is held open, deliberately never settled

    await clock.advance(1000); // attempt 1's own timeout fires first -> retry (attempt 2)
    expect(bluetooth.writesReceived).toHaveLength(2);

    // Attempt 1's write FINALLY (and uselessly) rejects now, well after it
    // was superseded by attempt 2.
    bluetooth.releaseWrite('A', 0, { ok: false, err: new Error('stale rejection') });
    await flushMicrotasks(); // let its .catch() handler run, if it does anything at all

    expect(bluetooth.writesReceived).toHaveLength(2); // must NOT have produced a 3rd write by itself

    await clock.advance(1000); // attempt 2's own timeout -> retry (attempt 3)
    expect(bluetooth.writesReceived).toHaveLength(3);
    await clock.advance(1000); // attempt 3 times out -> bounded gives-up, exactly 3 attempts
    await rejection;
  });

  /**
   * What the token check in the `write().catch()` handler guards AFTER the
   * mechanism fix: not control flow (the handler no longer retries at all),
   * but WHICH attempt's rejection reason survives into the final failure
   * message. `FakeBluetoothPort.setWriteBehavior('A', 'fail')` gives
   * attempt 2 its own distinct, immediate rejection ("configured to fail
   * for..."); the stale attempt-1 write (held from the start) is released
   * with a DIFFERENT message only after attempt 2's own rejection has
   * already been recorded.
   *
   * MUTATION (invented, beyond the brief): remove the
   * `entry.attemptsMade !== token` half of the guard (keep only
   * `this.active !== entry`). Verified this failed: the final rejection
   * message carried "a stale, unrelated rejection" instead of attempt 2's
   * own "configured to fail" reason -- the stale release overwrote
   * `entry.lastError` because, with no token check, `this.active === entry`
   * was all that was checked, and that was still true (same logical
   * command, just a later attempt). Restored.
   */
  test('a stale write rejection does not overwrite the current attempt\'s own failure reason', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 2 });
    await connect(manager, clock);
    bluetooth.setWriteBehavior('A', 'hold');

    const promise = queue.send({ data: Buffer.from([0x01]), description: 'test command', isStatus: () => false });
    const rejection = expect(promise).rejects.toThrow(
      'test command: no status received after 2 attempts (last attempt: FakeBluetoothPort.write: configured to fail for "A")',
    );
    expect(bluetooth.writesReceived).toHaveLength(1); // attempt 1's write, held open

    bluetooth.setWriteBehavior('A', 'fail'); // every NEW write from now on rejects immediately, with a fixed message
    await clock.advance(1000); // attempt 1 times out -> attempt 2's write rejects immediately -- its OWN, real cause
    expect(bluetooth.writesReceived).toHaveLength(2);

    // The stale attempt-1 write, held since the very start, is released
    // now -- well after attempt 2 already recorded its own cause -- and
    // must not clobber it.
    bluetooth.releaseWrite('A', 0, { ok: false, err: new Error('a stale, unrelated rejection') });
    await flushMicrotasks();

    await clock.advance(1000); // attempt 2's own timeout -> bounded, gives up
    await rejection;
  });
});
