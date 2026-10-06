import type { ClockPort, TimerHandle } from './connection';

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
 * WHY DISCONNECTION NEEDS NO DEDICATED CODE PATH. `ProxyConnectionManager`
 * publishes no "you were disconnected" event this module could subscribe
 * to (only `getState()`, which nothing here polls) -- and it turns out not
 * to need one. A command's single per-attempt timeout already covers BOTH
 * "the node never answered" and "the link dropped while we were waiting
 * for an answer": either way, no matching notification arrives within
 * `timeoutMs`, and the SAME retry path fires. By the time that retry's
 * `write()` call actually happens, `ProxyConnectionManager`'s own
 * reconnect-with-backoff (connection.ts, "on disconnect it rescans") has
 * ordinarily already restored the connection (its backoff resets to an
 * immediate rescan after a connection that had been successful -- which
 * this one was, until it dropped), so the retried write simply succeeds.
 * "One reconnect, one retry" therefore falls out of the ordinary bounded-
 * retry mechanism applied to this one scenario, not a special case bolted
 * onto it -- see queue.test.ts's disconnection test, which drives this
 * through a REAL `ProxyConnectionManager`/`FakeBluetoothPort` pair rather
 * than asserting anything about a made-up "disconnect" hook.
 *
 * A write that fails outright (e.g. `ProxyConnectionManager.write` rejects
 * immediately because nothing is connected right now -- see its own doc
 * comment) is treated exactly like a timeout for retry-accounting purposes:
 * it consumes one of the bounded attempts and, if any remain, the next
 * attempt is tried; the underlying rejection's message rides along in the
 * final failure if every attempt is exhausted (see `describeFailure`
 * below), since "the hub's own message" is more honest than reinventing
 * one.
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
// above. 4 seconds mirrors connection.ts's own SCAN_DURATION_MS as "long
// enough for a real round trip, short enough not to make a stuck command
// feel broken"; 3 total attempts (one send, two retries) is a small,
// genuinely bounded number rather than either "never retry" or "retry
// until the heat death of the universe".
const DEFAULT_TIMEOUT_MS = 4000;
const DEFAULT_MAX_ATTEMPTS = 3;

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
   *  command instead of the whole manager. The `write()`-rejection half of
   *  this is independently mutation-tested (queue.test.ts's
   *  "a write() that settles late" describe block, against a hand-rolled
   *  `TrafficPort` whose write a test can keep open past its own timeout --
   *  the real FakeBluetoothPort always settles write() within a couple of
   *  microtasks, too fast to reach this race). The TIMER-fire half, in
   *  `onAttemptTimedOut`, is NOT independently exercised: FakeClock's
   *  timers are one-shot and this module always cancels the previous one
   *  before arming a new one, so a stale timer fire for an entry's own
   *  earlier attempt cannot occur through any fake this project has --
   *  kept as the same defensive, not-exercised-by-name guard connection.ts
   *  itself documents for its own epoch check. */
  attemptsMade: number;
  timer: TimerHandle | null;
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
    this.active = { ...next, attemptsMade: 0, timer: null };
    this.attempt(this.active);
  }

  /**
   * Makes one attempt at `entry`: writes its bytes (unchanged from the
   * first attempt -- see `QueueEntry.data`'s own doc comment, and the
   * module header's TID note) and starts this attempt's timeout. The
   * timeout is armed BEFORE `write()` settles, not after, so a slow or
   * failing write cannot itself consume time outside what `timeoutMs`
   * already bounds.
   */
  private attempt(entry: ActiveEntry): void {
    entry.attemptsMade += 1;
    const token = entry.attemptsMade;
    entry.timer = this.clock.setTimeout(() => this.onAttemptTimedOut(entry, token), this.timeoutMs);
    this.transport.write(entry.data).catch((err: unknown) => {
      // A later attempt may already have started (the timeout for THIS
      // attempt fired before this rejection arrived) -- `token` no longer
      // matching means this rejection is stale and must change nothing.
      if (this.active !== entry || entry.attemptsMade !== token) return;
      this.clearTimer(entry);
      this.retryOrFail(entry, err instanceof Error ? err : new Error(String(err)));
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

  private retryOrFail(entry: ActiveEntry, cause?: Error): void {
    if (entry.attemptsMade < this.maxAttempts) {
      this.attempt(entry);
      return;
    }
    const detail = cause === undefined ? '' : ` (last attempt: ${cause.message})`;
    this.fail(entry, new Error(`${entry.command.description}: no status received after ${entry.attemptsMade} attempts${detail}`));
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
    // `clearTimer` here is tidiness (releasing the clock's reference to a
    // timer nobody will act on), not itself load-bearing: `this.active =
    // null` below is what actually protects against a stray later fire,
    // since `onAttemptTimedOut`/the write() `.catch()` handler both check
    // `this.active === entry` first. Mutation-tested separately (see
    // queue.test.ts's comment on "a settled command leaves nothing behind"):
    // dropping `this.active = null` breaks the "serialisation" tests (the
    // next backlog entry can never start); dropping `clearTimer` alone
    // breaks nothing this suite can observe.
    this.clearTimer(entry);
    this.active = null;
    entry.resolve(data);
    this.pump();
  }

  private handleNotification(data: Buffer): void {
    if (this.lastAbandoned !== null) {
      const stale = this.lastAbandoned;
      this.lastAbandoned = null; // one-shot: protects at most this one notification
      if (stale.isStatus(data)) {
        return; // the late answer to a question nobody is asking anymore -- ignored
      }
    }
    if (this.active !== null && this.active.command.isStatus(data)) {
      this.succeed(this.active, data);
      return;
    }
    for (const listener of this.unsolicitedListeners) {
      listener(Buffer.from(data));
    }
  }
}
