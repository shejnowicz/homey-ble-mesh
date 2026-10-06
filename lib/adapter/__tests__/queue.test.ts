import { randomBytes } from 'node:crypto';
import { ProxyConnectionManager } from '../connection';
import { FakeBluetoothPort } from './fakeBluetooth';
import { createFakeClock, type FakeClock } from './fakeClock';
import { TrafficQueue, type QueuedCommand, type TrafficPort } from '../queue';

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
 * Every test uses ONE node, 'A', already connected, unless a test is
 * specifically about reconnection or about never having connected at all.
 */

function setUp(options?: { timeoutMs?: number; maxAttempts?: number }): {
  bluetooth: FakeBluetoothPort;
  clock: FakeClock;
  manager: ProxyConnectionManager;
  queue: TrafficQueue;
} {
  const netKey = randomBytes(16);
  const bluetooth = new FakeBluetoothPort();
  const clock = createFakeClock();
  const manager = new ProxyConnectionManager(bluetooth, clock, netKey);
  bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
  const queue = new TrafficQueue(manager, clock, options);
  return { bluetooth, clock, manager, queue };
}

async function connect(manager: ProxyConnectionManager, clock: FakeClock): Promise<void> {
  manager.start();
  await clock.advance(0);
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

  test('a command is not stuck forever once the one ahead of it settles -- the queue keeps moving', async () => {
    const { bluetooth, clock, manager, queue } = setUp();
    await connect(manager, clock);

    const pA = queue.send({ data: Buffer.from([0x01]), description: 'A', isStatus: (n) => n.equals(Buffer.from([0x11])) });
    const pB = queue.send({ data: Buffer.from([0x02]), description: 'B', isStatus: (n) => n.equals(Buffer.from([0x12])) });

    bluetooth.simulateNotification('A', Buffer.from([0x11]));
    await pA;
    bluetooth.simulateNotification('A', Buffer.from([0x12]));
    await expect(pB).resolves.toEqual(Buffer.from([0x12]));
    expect(bluetooth.writesReceived).toHaveLength(2);
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
   * MUTATION (invented, beyond the brief), two variants tried separately:
   * (1) remove `this.active = null` from `succeed()` -- this does NOT fail
   * THIS test (a single command has nothing queued behind it to get
   * stuck), but it DOES fail both "serialisation" tests above (the next
   * backlog entry can never start, because `pump()`'s own guard reads
   * `this.active` as still occupied) -- restored, and noted here so the
   * coverage for that particular mutation is attributed to the right
   * tests. (2) remove `this.clearTimer(entry)` from `succeed()` while
   * KEEPING `this.active = null` -- verified this passes every test in
   * this file unchanged: `onAttemptTimedOut`'s own `this.active !== entry`
   * guard already makes a stray, uncancelled timer harmless once `active`
   * has moved on, so the timer clear is tidiness (releasing the
   * FakeClock's reference to a timer nobody will act on) rather than
   * load-bearing correctness. Restored; recorded as a known, accepted gap
   * in the report rather than papered over with a test that would not
   * actually discriminate it.
   */
  test('a settled command leaves nothing behind that could fire a spurious retry later', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 3 });
    await connect(manager, clock);

    const status = Buffer.from([0x77]);
    const promise = queue.send({ data: Buffer.from([0x01]), description: 'test command', isStatus: (n) => n.equals(status) });
    bluetooth.simulateNotification('A', status); // resolves well before timeoutMs elapses
    await expect(promise).resolves.toEqual(status);

    await clock.advance(10_000); // far past where the original attempt's timeout would have fired
    expect(bluetooth.writesReceived).toHaveLength(1); // no retry ever happened
  });
});

describe('bounded retries', () => {
  /**
   * MUTATION (task brief): make the retry unbounded (e.g. drop the
   * `entry.attemptsMade < this.maxAttempts` check in `retryOrFail` and
   * always retry). Verified this made the queue retry forever: after
   * advancing the clock by 20 attempts' worth of timeouts, `writesReceived`
   * kept growing and the promise never settled (the `await` on the
   * rejection assertion timed out the test runner itself). Restored the
   * check.
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
   * `manager.write()` call rejects synchronously-ish with "no active
   * proxy connection", purely through promise rejection -- no clock
   * advancement is needed at all for this one to run its full course.
   */
  test('write() rejecting outright (never connected at all) is bounded the same way, and the final failure carries the underlying reason', async () => {
    const { queue } = setUp({ timeoutMs: 1000, maxAttempts: 2 });
    // Deliberately never call connect(): manager.write() always rejects.

    const promise = queue.send({ data: Buffer.from([0x01]), description: 'test command', isStatus: () => false });

    await expect(promise).rejects.toThrow(
      'test command: no status received after 2 attempts (last attempt: ProxyConnectionManager.write: no active proxy connection)',
    );
  });
});

describe('disconnection mid-command', () => {
  /**
   * This is the scenario the design names explicitly: "A disconnection
   * mid-command causes one reconnect and one retry." Driven through a
   * REAL `ProxyConnectionManager`: `simulateDisconnect` drops the link the
   * same way a node losing power would, the manager's own backoff (reset
   * to an immediate rescan after what had just been a successful
   * connection) brings it back, and the queue's ordinary bounded-retry
   * timeout is what actually re-sends the command -- see queue.ts's module
   * header for why no dedicated "disconnect" handling exists in this
   * module at all.
   *
   * MUTATION (task brief, adapted since this module has no explicit
   * reconnect/retry counter of its own to unbound): removed the
   * `entry.attemptsMade < this.maxAttempts` bound (same mutation as the
   * "bounded retries" describe block above) and reran this test -- it
   * still resolves correctly (the one retry here succeeds well within any
   * bound), which is expected: this test's OWN job is to prove the retry
   * is exactly one, not that it is bounded in general (the previous
   * describe block already pins boundedness). What this test's final
   * assertions catch instead is a hypothetical "keep retrying/reconnecting
   * after success" bug: advancing the clock far past the point of success
   * must not add any further writes or reconnects.
   */
  test('produces exactly one reconnect and exactly one retry, not an unbounded loop', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 3 });
    await connect(manager, clock);
    expect(bluetooth.connectCalls).toEqual(['A']);

    const status = Buffer.from([0x99]);
    const promise = queue.send({ data: Buffer.from([0x01]), description: 'test command', isStatus: (n) => n.equals(status) });
    expect(bluetooth.writesReceived).toHaveLength(1); // the first attempt's write went out before the disconnect

    bluetooth.simulateDisconnect('A'); // the link drops while we are waiting for a status
    expect(manager.getState().status).toBe('unavailable');

    await clock.advance(0); // the connection manager's own immediate post-disconnect rescan+reconnect
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });
    expect(bluetooth.connectCalls).toEqual(['A', 'A']); // exactly one reconnect

    await clock.advance(1000); // this command's own attempt-1 timeout fires -> retry
    expect(bluetooth.writesReceived).toHaveLength(2); // exactly one retry write

    bluetooth.simulateNotification('A', status);
    await expect(promise).resolves.toEqual(status);

    // Advancing well past this must not produce another write or reconnect.
    await clock.advance(10_000);
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
  test('is ignored rather than resolving a later command', async () => {
    const { bluetooth, clock, manager, queue } = setUp({ timeoutMs: 1000, maxAttempts: 2 });
    await connect(manager, clock);

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

    // B must still be waiting: advancing past its attempt-1 timeout
    // produces a retry write. If the late notification had wrongly
    // resolved B already, no further write would appear here.
    await clock.advance(1000);
    expect(bluetooth.writesReceived).toHaveLength(4);

    const realStatusForB = Buffer.from([0x01, 0xbb]); // same shape, genuinely different value
    bluetooth.simulateNotification('A', realStatusForB);
    await expect(b).resolves.toEqual(realStatusForB);
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
    const aRejection = expect(a).rejects.toThrow();
    await clock.advance(1000); // A's only attempt times out -> gives up
    await aRejection;

    const unrelated = Buffer.from([0xde, 0xad]); // shares no shape with anything A was ever waiting for
    bluetooth.simulateNotification('A', unrelated);

    expect(received).toHaveLength(1);
    expect(received[0]).toEqual(unrelated);
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
    const rejection = expect(promise).rejects.toThrow();
    data.fill(0xff); // mutate the caller's own buffer right after send() returns

    await clock.advance(1000); // attempt 1 times out -> retry (attempt 2)
    expect(bluetooth.writesReceived.map((w) => w.data.toString('hex'))).toEqual(['0102', '0102']);

    await clock.advance(1000); // attempt 2 times out -> final failure, not the point of this test
    await rejection;
  });
});

/**
 * A hand-rolled `TrafficPort` whose `write()` only settles when the test
 * tells it to -- unlike the real `ProxyConnectionManager`/`FakeBluetoothPort`
 * pair (which always settles `write()` within a couple of microtasks), this
 * lets a test keep an EARLIER attempt's write artificially in flight while a
 * LATER attempt (started by that earlier attempt's own timeout) is already
 * under way, to reach a race no amount of `clock.advance()` against the real
 * fakes can reach. `onNotification` is unused by the one test below but
 * still implemented, to satisfy `TrafficPort` honestly rather than casting.
 */
function controllableTransport(): {
  port: TrafficPort;
  writes: Buffer[];
  settleWrite: (index: number, outcome: { ok: true } | { ok: false; err: Error }) => void;
} {
  const writes: Buffer[] = [];
  const pending: Array<{ resolve: () => void; reject: (err: Error) => void }> = [];
  return {
    port: {
      write(data: Buffer): Promise<void> {
        writes.push(data);
        return new Promise<void>((resolve, reject) => {
          pending.push({ resolve, reject });
        });
      },
      onNotification(): () => void {
        return () => {};
      },
    },
    writes,
    settleWrite: (index, outcome) => {
      const entry = pending[index];
      if (entry === undefined) throw new Error(`controllableTransport: no write #${index} to settle`);
      if (outcome.ok) entry.resolve();
      else entry.reject(outcome.err);
    },
  };
}

describe('a write() that settles late, after its own attempt has already been superseded', () => {
  /**
   * The scenario this guards against needs a write() that can out-live its
   * OWN attempt's timeout -- unreachable through the real
   * ProxyConnectionManager/FakeBluetoothPort pair, since their `write()`
   * always settles within a couple of microtasks, well before any
   * `timeoutMs` worth advancing the clock. `controllableTransport` above
   * exists so this ONE test can hold attempt 1's write open past the point
   * where its timeout fires and attempt 2 has already started.
   *
   * MUTATION (invented, beyond the brief): remove the
   * `entry.attemptsMade !== token` half of the guard in the `write().catch()`
   * handler (keep only `this.active !== entry`). Verified this failed: the
   * stale rejection for attempt 1 went on to clear attempt 2's live timer
   * and call `retryOrFail` again, so attempt 3's write went out from the
   * REJECTION HANDLER rather than from the clock, and `writes` reached 3
   * one `clock.advance` call earlier than the assertions below expect (the
   * second assertion, checking `writes` is still 2 right after the stale
   * rejection, failed first). Restored.
   */
  test('is ignored -- it does not disturb the attempt that superseded it', async () => {
    const clock = createFakeClock();
    const { port, writes, settleWrite } = controllableTransport();
    const queue = new TrafficQueue(port, clock, { timeoutMs: 1000, maxAttempts: 3 });

    const promise = queue.send({ data: Buffer.from([0x01]), description: 'test command', isStatus: () => false });
    const rejection = expect(promise).rejects.toThrow('test command: no status received after 3 attempts');
    expect(writes).toHaveLength(1); // attempt 1's write is in flight, deliberately never settled

    await clock.advance(1000); // attempt 1's own timeout fires first -> retry (attempt 2)
    expect(writes).toHaveLength(2); // attempt 2's write went out

    // Attempt 1's write FINALLY (and uselessly) rejects now, well after it
    // was superseded by attempt 2.
    settleWrite(0, { ok: false, err: new Error('stale rejection') });
    await Promise.resolve(); // let its .catch() handler run, if it does anything at all

    expect(writes).toHaveLength(2); // must NOT have produced a 3rd write by itself

    await clock.advance(1000); // attempt 2's own timeout -> retry (attempt 3)
    expect(writes).toHaveLength(3);
    await clock.advance(1000); // attempt 3 times out -> bounded gives-up, exactly 3 attempts
    await rejection;
  });
});
