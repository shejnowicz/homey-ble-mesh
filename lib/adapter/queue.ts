import { SCAN_DURATION_MS, type ClockPort, type TimerHandle } from './connection';

/**
 * The traffic queue (docs/superpowers/specs/2026-10-06-ble-mesh-provisioner-
 * design.md, "The Homey layer" > "Commands and state"): "All mesh traffic
 * passes through one queue so commands never flood the network." And,
 * under "Error handling": "Commands use acknowledged variants and are
 * retried a bounded number of times, after which the failure is reported
 * honestly rather than retried forever. A disconnection mid-command causes
 * one reconnect and one retry."
 *
 * THERE IS NO PUBLISHED SAMPLE OF A QUEUE (task brief). Everything below is
 * this project's own design, pinned only by the behavioural tests in
 * __tests__/queue.test.ts against the SAME fakes connection.test.ts uses
 * (FakeBluetoothPort, FakeClock) driving a REAL `ProxyConnectionManager` --
 * not a second, hand-rolled mock of it (see the port shape note below).
 *
 * WHAT THIS MODULE KNOWS AND WHAT IT DOES NOT. This is lib/adapter, same as
 * connection.ts, and the SAME layering choice applies: it takes a narrow
 * port (`TrafficPort`, below -- NOT a re-declaration of `BluetoothPort`;
 * see that note too) rather than `homey` or `ProxyConnectionManager`
 * itself, so it is testable without a radio. More importantly, it is
 * PROTOCOL-AGNOSTIC: it knows nothing about opcodes, transaction
 * identifiers, source/destination addresses, or what a "Status" message
 * looks like. A `QueuedCommand` carries its own wire bytes (`data`,
 * supplied already fully encoded by the caller) and its own correlation
 * predicate (`isStatus`, which decides whether an inbound notification
 * answers THIS command). This queue only ever serialises, retries and
 * times out; it never decodes a byte of what it carries.
 *
 * THE TRANSACTION IDENTIFIER LIVES ONE LAYER UP, DELIBERATELY. The task
 * brief flags this as a decision to argue, not a detail to pick silently.
 * `lib/models/lighting.ts`'s own TID rule (transcribed there from Mesh
 * Model v1.1 Section 3.4.1.2.2/3.3.1.2.2): a retransmission of the same
 * command must carry the SAME transaction identifier; a new command gets a
 * different one; uniqueness is scoped to one (source, destination) pair
 * within a six-second window. This module could not honour that rule even
 * if it tried to: it has no notion of source or destination addresses (a
 * `QueuedCommand.data` is opaque bytes to it) and, more fundamentally, it
 * cannot tell "the caller wants to retransmit the same logical command"
 * apart from "the caller issued a brand new one" -- that distinction is
 * pure CALLER INTENT (a user tapping a switch twice is two new commands; a
 * queue giving up and trying again is one retransmission), which only
 * whoever constructs `QueuedCommand.data` can know. The allocator therefore
 * belongs in the device layer (Task 7), which calls
 * `encodeGenericOnOffSet({ tid, ... })` ONCE per logical command and hands
 * this queue the resulting bytes; every RETRY this module performs simply
 * re-sends that exact, unchanged buffer (see `attempt` below), so the "same
 * identifier for a retransmission" rule is satisfied for free, without this
 * module ever knowing a TID exists. Had the allocator lived here instead,
 * this module would have needed to grow address/opcode awareness just to
 * decide "is this a retry of the last command or a new one", which is
 * exactly the layering violation `lib/models` being protocol-pure and
 * `lib/adapter` being protocol-blind is meant to prevent.
 *
 * THE "LATE STATUS" HAZARD (the task brief's own flagged subtlety). A
 * Generic OnOff/Lightness/CTL/HSL Status message carries no transaction
 * identifier at all (it is a report of present state, not an echo of a
 * request) -- so, on the wire, nothing distinguishes "the belated answer to
 * a command this queue already gave up on" from "the answer to whatever
 * command is active now", if both happen to look alike to the caller's
 * OWN `isStatus` predicate (entirely plausible: a user toggling a light
 * twice in a row produces two commands against the very same model, and a
 * predicate written as "this decodes as a Generic OnOff Status for this
 * node" cannot and should not try to also check the requested value --
 * Status reports truth, which may legitimately differ from what was last
 * asked). Content alone cannot solve this; this module solves it with
 * state instead: when a command is abandoned (bounded retries exhausted),
 * its predicate is kept as `lastAbandoned` for EXACTLY the next inbound
 * notification -- checked and cleared before that notification is checked
 * against whatever is pending now. If it matches, it is dropped: not
 * resolving the new pending command, not forwarded to an unsolicited
 * listener either (forwarding it would reproduce the exact harm the brief
 * names -- "a user sees a lamp report a brightness they set a minute ago"
 * -- just via a different code path). The "exactly one notification" scope
 * is a deliberate, bounded cost, not an attempt at a perfect fix: a real
 * straggler is normally a single belated notification, not a stream of
 * them, so protecting against one is enough; and bounding it to one means
 * this safety net can never permanently blind the queue to a genuine
 * status that happens to share the same shape (the very next thing to
 * arrive after that is judged completely normally). See
 * queue.test.ts's "the subtle case" describe block for the behavioural
 * test and its mutation proof.
 *
 * THE PORT SHAPE, AND WHY IT IS NOT `BluetoothPort` AGAIN. `connection.ts`
 * already narrows `homey`'s Bluetooth API down to `BluetoothPort`; this
 * module narrows `ProxyConnectionManager` ITSELF down one step further, to
 * exactly the two members it actually uses: `write` and `onNotification`.
 * `TrafficPort` below is structurally satisfied by a real
 * `ProxyConnectionManager` with no adapter code in between (every
 * queue.test.ts test constructs a real one, over a real
 * FakeBluetoothPort/FakeClock pair -- see that file's module header) --
 * this is what the plan's pre-flight conflict scan means by "T5 must not
 * re-declare the port": `BluetoothPort` stays connection.ts's own, and
 * this module does not grow a second copy of it or a hand-rolled
 * replacement for `ProxyConnectionManager`.
 *
 * WHY DISCONNECTION NEEDS NO DEDICATED CODE PATH -- AND THE BUG A REVIEW
 * FOUND IN THE FIRST ATTEMPT AT THIS REASONING. `ProxyConnectionManager`
 * publishes no "you were disconnected" event this module could subscribe
 * to (only `getState()`, which nothing here polls) -- and it turns out not
 * to need one, PROVIDED a write failing outright is treated as a reason to
 * WAIT, not as a reason to try again instantly. A command's single
 * per-attempt timeout is meant to cover BOTH "the node never answered" and
 * "the link dropped while we were waiting for an answer" identically: no
 * matching notification arrives within `timeoutMs`, and the SAME retry
 * path fires. The first version of this module got this half right and
 * half wrong: `write()` rejecting (which is exactly what happens when a
 * retry is attempted while `ProxyConnectionManager` is mid-reconnect) was
 * wired to call `retryOrFail` DIRECTLY from the rejection handler, with no
 * delay. Since a rejection settles in a microtask, not a clock tick, this
 * meant that once the link was down, the ENTIRE remaining attempt budget
 * was spent inside a single microtask chain, against a radio that
 * provably was not there yet -- a review measured zero virtual
 * milliseconds between the first timeout and the final failure, i.e. "one
 * reconnect and ZERO retransmissions" against the design's own "one
 * reconnect and one retry". Worse, the ORIGINAL default `timeoutMs` (4000,
 * chosen to merely "mirror" `SCAN_DURATION_MS`) was exactly equal to one
 * scan window -- even had retries been paced correctly, a reconnect costs
 * at least one full scan PLUS connect/discover/subscribe, so the retry's
 * write would still have fired at the one moment the reconnect could not
 * yet have finished. Both defects compounded: an unpaced retry racing a
 * deadline it could not win.
 *
 * THE FIX, twofold: (1) `attempt`'s `write().catch()` handler no longer
 * calls `retryOrFail` -- it only records the rejection's message (`entry.
 * lastError`, surfaced in the eventual failure if every attempt is
 * exhausted) and otherwise does nothing, leaving the per-attempt timer
 * (armed BEFORE `write()` was even called -- see `attempt`'s own doc
 * comment) to run to completion exactly as it would for "no status ever
 * arrived". A write failing outright therefore no longer shortens the wait
 * at all; it simply means this particular attempt's wait ends in a retry
 * (or the final failure) for a known reason instead of an unknown one. (2)
 * `DEFAULT_TIMEOUT_MS` is now derived FROM `SCAN_DURATION_MS` (double it,
 * not match it) rather than coincidentally repeating the same number, so
 * the relationship that has to hold -- "comfortably longer than a scan
 * plus connect/discover/subscribe" -- is visible in the source rather than
 * two separately-chosen constants that happened to agree.
 *
 * With both fixes, "one reconnect, one retry" falls out of the ordinary
 * bounded-retry mechanism the way it was always meant to: the retry's
 * `write()` call happens only once a FULL `timeoutMs` has elapsed, by
 * which point `ProxyConnectionManager`'s own reconnect-with-backoff (which
 * resets to an immediate rescan after what had been a successful
 * connection) has had comfortably more time than it needs to finish. See
 * queue.test.ts's disconnection tests -- including one built against a
 * `FakeBluetoothPort` configured to let `scan()` actually consume its full
 * documented `durationMs` of virtual time, rather than resolving
 * instantly, which is what let the original defect hide behind a green
 * suite in the first place.
 *
 * NULLISH CONVENTION: `null` throughout (no pending command is
 * `active === null`; no stale predicate to guard against is
 * `lastAbandoned === null`; a cleared timer is `timer = null`), matching
 * connection.ts and store.ts.
 */

/**
 * One command handed to the queue: the exact bytes to write (already fully
 * encoded by the caller -- this module never looks inside them), a
 * predicate deciding whether an inbound notification is THIS command's
 * answer, and a human-readable name used only if every attempt is
 * exhausted (so a failure names what it was trying to do, not a generic
 * "timeout" -- the task brief's own requirement).
 */
export interface QueuedCommand {
  readonly data: Buffer;
  /** Called with every inbound notification while this command is the
   *  active one. Must be cheap and side-effect-free: it may be called
   *  once more than strictly necessary (see the module header's note on
   *  `lastAbandoned`). */
  isStatus(notification: Buffer): boolean;
  /** Named in the error thrown once every attempt is exhausted, e.g.
   *  "Generic OnOff Set 0x0042" -- never a bare "timeout". */
  readonly description: string;
}

/** The narrow port this module writes through and listens on -- exactly
 *  the two members of `ProxyConnectionManager` it needs (see the module
 *  header's "THE PORT SHAPE" note). A real `ProxyConnectionManager`
 *  satisfies this with no adapter code. */
export interface TrafficPort {
  write(data: Buffer): Promise<void>;
  onNotification(listener: (data: Buffer) => void): () => void;
}

export interface TrafficQueueOptions {
  /** How long one attempt waits for a matching status before retrying.
   *  Not a specification value -- an engineering choice, the same way
   *  connection.ts's backoff constants are. */
  readonly timeoutMs?: number;
  /** Total attempts for one logical command, INCLUDING the first --
   *  "bounded a number of times" per the design, never unbounded. */
  readonly maxAttempts?: number;
}

// Engineering choices, not specification values -- see TrafficQueueOptions
// above, and the module header's account of why the FIRST choice of
// DEFAULT_TIMEOUT_MS (a bare 4000, merely equal to SCAN_DURATION_MS) was
// wrong: a reconnect costs at least one full scan window PLUS connect,
// discover and subscribe, so a per-attempt timeout equal to the scan alone
// is a race the retry cannot win. Doubling SCAN_DURATION_MS -- rather than
// picking some other number that happens to be bigger -- keeps the
// relationship that actually matters ("comfortably longer than one scan")
// visible at the definition site instead of hoping two separately-chosen
// constants stay in agreement. 3 total attempts (one send, two retries) is
// a small, genuinely bounded number rather than either "never retry" or
// "retry until the heat death of the universe". Both exported so a test
// can pin the actual defaults rather than silently assuming them.
export const DEFAULT_TIMEOUT_MS = SCAN_DURATION_MS * 2;
export const DEFAULT_MAX_ATTEMPTS = 3;

interface QueueEntry {
  readonly command: QueuedCommand;
  /** An immutable snapshot taken at `send()` time -- never the caller's
   *  own buffer, so a caller mutating what it passed in after `send()`
   *  returns (while this command is still sitting in the backlog, or
   *  being retried) can never change what actually goes out on the wire. */
  readonly data: Buffer;
  readonly resolve: (data: Buffer) => void;
  readonly reject: (err: Error) => void;
}

interface ActiveEntry extends QueueEntry {
  /** Attempts made so far for this command, and -- doubling as this
   *  attempt's own token -- used to recognise a `write()` rejection or
   *  timer fire that belongs to an attempt this entry has already moved
   *  past (a retry started before the earlier attempt's own promise
   *  settled). Mirrors connection.ts's `epoch` guard, scoped to one
   *  command instead of the whole manager.
   *
   *  What the `write()`-rejection half actually guards CHANGED with the
   *  mechanism fix below: since that handler no longer calls `retryOrFail`
   *  (a stale rejection can no longer trigger an extra retry -- there is
   *  nothing left for it to trigger), the token check's remaining job is
   *  narrower but real: a stale rejection must not overwrite `lastError`
   *  with the WRONG attempt's reason, corrupting the final failure
   *  message's "last attempt: ..." detail. Independently mutation-tested
   *  (queue.test.ts's "a write() that settles late" describe block, second
   *  test, against `FakeBluetoothPort`'s own held-write support).
   *
   *  The TIMER-fire half, in `onAttemptTimedOut`, is NOT independently
   *  exercised: FakeClock's timers are one-shot and this module always
   *  cancels the previous one before arming a new one, so a stale timer
   *  fire for an entry's own earlier attempt cannot occur through any fake
   *  this project has -- kept as the same defensive, not-exercised-by-name
   *  guard connection.ts itself documents for its own epoch check. */
  attemptsMade: number;
  timer: TimerHandle | null;
  /** The most recent `write()` rejection for the CURRENT attempt, if any --
   *  reset at the start of every `attempt()` call, surfaced in the eventual
   *  failure message if every attempt is exhausted. A write failing
   *  outright no longer retries from inside the rejection handler (see the
   *  module header's account of the defect this replaced) -- it only
   *  changes what the eventual failure says caused it; the timer armed at
   *  the start of this same attempt is what actually paces the retry. */
  lastError: Error | null;
}

/** What a stale, already-abandoned command's predicate is kept as, for
 *  exactly the next inbound notification -- see the module header's
 *  "THE LATE STATUS HAZARD" note. */
interface StalePredicate {
  isStatus(notification: Buffer): boolean;
}

/**
 * Serialises every outgoing mesh command through one `TrafficPort`,
 * retrying each a bounded number of times before failing honestly. See the
 * module header for the full design and its reasoning.
 *
 * LIFECYCLE: construct once (it subscribes to the port's notifications
 * immediately) and call `send()` per command. There is no `stop()`: unlike
 * `ProxyConnectionManager`, this module owns no connection and schedules
 * no indefinite background activity of its own -- a command with no
 * attempts left simply settles and nothing further happens for it.
 */
export class TrafficQueue {
  private readonly transport: TrafficPort;
  private readonly clock: ClockPort;
  private readonly timeoutMs: number;
  private readonly maxAttempts: number;

  private readonly backlog: QueueEntry[] = [];
  private active: ActiveEntry | null = null;
  private lastAbandoned: StalePredicate | null = null;
  private readonly unsolicitedListeners = new Set<(data: Buffer) => void>();

  constructor(transport: TrafficPort, clock: ClockPort, options: TrafficQueueOptions = {}) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new Error(`TrafficQueue: timeoutMs must be a positive finite number, got ${timeoutMs}`);
    }
    const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
      throw new Error(`TrafficQueue: maxAttempts must be an integer >= 1, got ${maxAttempts}`);
    }
    this.transport = transport;
    this.clock = clock;
    this.timeoutMs = timeoutMs;
    this.maxAttempts = maxAttempts;
    this.transport.onNotification((data) => this.handleNotification(data));
  }

  /**
   * Enqueues one command. Resolves with the notification bytes that
   * satisfied its `isStatus`, or rejects once every attempt is exhausted.
   * Commands are processed strictly one at a time, in the order `send()`
   * was called -- "two commands issued at once are sent one after the
   * other, not together" (task brief).
   */
  send(command: QueuedCommand): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      this.backlog.push({ command, data: Buffer.from(command.data), resolve, reject });
      this.pump();
    });
  }

  /**
   * Registers a listener for notifications that answer no pending
   * command -- a light changed by other means, or a late status the queue
   * has decided to ignore for a different reason (see the module header).
   * Returns an unsubscribe function. Each listener gets its own fresh copy
   * of the bytes, same guarantee `ProxyConnectionManager.onNotification`
   * itself makes.
   */
  onUnsolicited(listener: (data: Buffer) => void): () => void {
    this.unsolicitedListeners.add(listener);
    return () => {
      this.unsolicitedListeners.delete(listener);
    };
  }

  /** Starts the next backlog entry, if nothing is active and there is one. */
  private pump(): void {
    if (this.active !== null) return;
    const next = this.backlog.shift();
    if (next === undefined) return;
    this.active = { ...next, attemptsMade: 0, timer: null, lastError: null };
    this.attempt(this.active);
  }

  /**
   * Makes one attempt at `entry`: writes its bytes (unchanged from the
   * first attempt -- see `QueueEntry.data`'s own doc comment, and the
   * module header's TID note), copied again here so the transport can
   * never mutate this entry's own stored snapshot (the global "never
   * retain a view into a buffer you do not own" constraint applies to what
   * this module HANDS OUT, not only to what it receives -- a port that
   * wrote into the buffer it was given would otherwise corrupt every later
   * retry of the same command), and starts this attempt's timeout. The
   * timeout is armed BEFORE `write()` settles, not after, so a slow or
   * failing write cannot itself consume time outside what `timeoutMs`
   * already bounds.
   */
  private attempt(entry: ActiveEntry): void {
    entry.attemptsMade += 1;
    entry.lastError = null;
    const token = entry.attemptsMade;
    entry.timer = this.clock.setTimeout(() => this.onAttemptTimedOut(entry, token), this.timeoutMs);
    this.transport.write(Buffer.from(entry.data)).catch((err: unknown) => {
      // A later attempt may already have started (the timeout for THIS
      // attempt fired before this rejection arrived) -- `token` no longer
      // matching means this rejection is stale and must change nothing.
      if (this.active !== entry || entry.attemptsMade !== token) return;
      // THE FIX (see the module header): a write failing outright is a
      // reason to WAIT, not a reason to retry instantly from inside this
      // handler. Only the cause is recorded, for the eventual failure
      // message if every attempt is exhausted -- the timer armed above,
      // already ticking since before this write was even attempted, is
      // what decides when the retry actually happens.
      entry.lastError = err instanceof Error ? err : new Error(String(err));
    });
  }

  private onAttemptTimedOut(entry: ActiveEntry, token: number): void {
    if (this.active !== entry || entry.attemptsMade !== token) return;
    entry.timer = null; // this timer firing IS the consumption; nothing left to clear
    this.retryOrFail(entry);
  }

  private clearTimer(entry: ActiveEntry): void {
    if (entry.timer !== null) {
      this.clock.clearTimeout(entry.timer);
      entry.timer = null;
    }
  }

  private retryOrFail(entry: ActiveEntry): void {
    if (entry.attemptsMade < this.maxAttempts) {
      this.attempt(entry);
      return;
    }
    const cause = entry.lastError;
    const detail = cause === null ? '' : ` (last attempt: ${cause.message})`;
    const attempts = entry.attemptsMade;
    const noun = attempts === 1 ? 'attempt' : 'attempts';
    this.fail(entry, new Error(`${entry.command.description}: no status received after ${attempts} ${noun}${detail}`));
  }

  private fail(entry: ActiveEntry, err: Error): void {
    this.clearTimer(entry);
    this.active = null;
    // Kept for exactly the next notification -- see the module header's
    // "THE LATE STATUS HAZARD" note.
    this.lastAbandoned = { isStatus: entry.command.isStatus };
    entry.reject(err);
    this.pump();
  }

  private succeed(entry: ActiveEntry, data: Buffer): void {
    // `clearTimer` here is NOT mere tidiness, despite `onAttemptTimedOut`'s
    // own `this.active !== entry` guard making a stray fire logically
    // harmless once `active` has moved on (review correction: an earlier
    // version of this comment claimed the opposite, and was wrong -- see
    // queue.test.ts's own corrected comment on "a settled command actually
    // cancels its own timer"). With REAL timers, an uncancelled one keeps
    // the event loop alive and keeps this `entry` (and everything it
    // closes over) reachable from the timer queue until it finally fires,
    // `timeoutMs` later, for nothing -- a genuine per-command resource
    // leak, not merely a logically-inert one. `this.active = null` below
    // is what protects the STATE MACHINE (the next backlog entry can start,
    // a stray fire is a no-op); `clearTimer` is what protects the CLOCK
    // (nothing is left pending once a command has actually settled).
    this.clearTimer(entry);
    this.active = null;
    entry.resolve(data);
    this.pump();
  }

  private handleNotification(data: Buffer): void {
    if (this.lastAbandoned !== null) {
      const stale = this.lastAbandoned;
      this.lastAbandoned = null; // one-shot: protects at most this one notification
      if (this.safeIsStatus(stale.isStatus, data)) {
        return; // the late answer to a question nobody is asking anymore -- ignored
      }
    }
    if (this.active !== null && this.safeIsStatus(this.active.command.isStatus, data)) {
      this.succeed(this.active, data);
      return;
    }
    for (const listener of this.unsolicitedListeners) {
      try {
        listener(Buffer.from(data));
      } catch {
        // One listener's own failure must not stop delivery to the rest,
        // and must not escape into ProxyConnectionManager's own
        // notification dispatch loop (which has no per-listener isolation
        // of its own -- inherited from that layer, not introduced here).
        // There is no error-reporting channel reachable from inside a
        // notification callback, so there is nothing productive to do
        // with the error beyond not letting it propagate.
      }
    }
  }

  /** Calls a caller-supplied `isStatus` predicate defensively: a predicate
   *  that throws is treated as "does not match" rather than being allowed
   *  to escape into `ProxyConnectionManager`'s own notification dispatch
   *  loop. The layer below has the same gap for its own listeners
   *  (inherited, not introduced here) -- but THIS module's predicate is
   *  caller-supplied business logic, and therefore the one most likely to
   *  actually throw. */
  private safeIsStatus(isStatus: (notification: Buffer) => boolean, data: Buffer): boolean {
    try {
      return isStatus(data);
    } catch {
      return false;
    }
  }
}
