/**
 * A fake `ClockPort` (see ../connection.ts) for testing backoff without
 * waiting: virtual time only ever moves when a test calls `advance`, never
 * on its own. Not one of the three files the task brief names explicitly,
 * but split out from connection.test.ts anyway, for the same reason
 * fakeBluetooth.ts is its own file rather than living in the test file that
 * first needed it — the task brief's own queue (a later task) needs
 * exactly this same bounded-retry timing and should not have to duplicate
 * it or import it from a test file.
 *
 * WHY `advance` IS ASYNC. A `ClockPort.setTimeout` callback in this
 * module's real caller (ProxyConnectionManager.runAttempt) kicks off a
 * chain of awaited promises (scan, then connect, then discover, then
 * subscribe) before it settles. Firing the callback and returning
 * immediately would leave a test asserting on a state that has not
 * actually been reached yet. `advance` instead fires every timer due at or
 * before the new virtual time, in the order they were scheduled, and after
 * EACH one waits a full macrotask turn (`setImmediate`) — which Node only
 * runs once every microtask the callback queued (however many `await`s
 * deep) has already drained — before checking for more. A timer newly
 * scheduled by that drained continuation (e.g. a failed attempt scheduling
 * its own backoff) is picked up by the same loop if its delay keeps it due
 * within this same `advance` call; otherwise it is left pending for a later
 * `advance`, exactly like a real clock.
 */

import type { ClockPort, TimerHandle } from '../connection';

interface ScheduledTimer {
  readonly id: number;
  readonly dueAt: number;
  readonly callback: () => void;
  cancelled: boolean;
}

export interface FakeClock extends ClockPort {
  /** Advances virtual time by `ms` and runs every timer that falls due,
   *  waiting for each one's consequences to fully settle before looking for
   *  more. Resolves once nothing more is due at the new virtual time. */
  advance(ms: number): Promise<void>;
  /** Number of timers currently scheduled and not yet fired or cancelled —
   *  for assertions that want to know whether the manager is still
   *  "waiting on something" without inspecting any of its own fields. */
  pendingCount(): number;
}

function flushMicrotasks(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

/** A safety cap on how many timers one `advance` call will fire, purely to
 *  turn a runaway reschedule-at-the-same-due-time bug in a test (or in the
 *  code under test) into a clear thrown error instead of a hang. No
 *  legitimate use of this fixture comes anywhere close to it. */
const MAX_TIMERS_PER_ADVANCE = 10_000;

export function createFakeClock(startAt = 0): FakeClock {
  let now = startAt;
  let nextId = 1;
  const timers: ScheduledTimer[] = [];

  return {
    now(): number {
      return now;
    },

    setTimeout(callback: () => void, delayMs: number): TimerHandle {
      if (!Number.isFinite(delayMs) || delayMs < 0) {
        throw new Error(`FakeClock.setTimeout: delayMs must be a non-negative finite number, got ${delayMs}`);
      }
      const timer: ScheduledTimer = { id: nextId++, dueAt: now + delayMs, callback, cancelled: false };
      timers.push(timer);
      return timer;
    },

    clearTimeout(handle: TimerHandle): void {
      const timer = handle as ScheduledTimer;
      timer.cancelled = true;
    },

    pendingCount(): number {
      return timers.filter((t) => !t.cancelled).length;
    },

    async advance(ms: number): Promise<void> {
      if (!Number.isFinite(ms) || ms < 0) {
        throw new Error(`FakeClock.advance: ms must be a non-negative finite number, got ${ms}`);
      }
      const target = now + ms;
      let fired = 0;

      for (;;) {
        // Earliest still-pending timer due at or before target. Re-scanned
        // every iteration rather than snapshotted once, so a timer a
        // callback schedules mid-loop (e.g. the next backoff attempt) is
        // picked up if it is due within this same advance.
        let earliest: ScheduledTimer | null = null;
        for (const timer of timers) {
          if (timer.cancelled) continue;
          if (timer.dueAt > target) continue;
          if (earliest === null || timer.dueAt < earliest.dueAt || (timer.dueAt === earliest.dueAt && timer.id < earliest.id)) {
            earliest = timer;
          }
        }
        if (earliest === null) break;

        if (fired >= MAX_TIMERS_PER_ADVANCE) {
          throw new Error(
            `FakeClock.advance: fired more than ${MAX_TIMERS_PER_ADVANCE} timers in one advance() call — likely a runaway reschedule loop`,
          );
        }

        now = earliest.dueAt; // the callback observes the time it was due at, not the final target
        earliest.cancelled = true; // a one-shot timer: consumed once fired, same as a real setTimeout
        earliest.callback();
        fired += 1;
        await flushMicrotasks();
      }

      now = target;
    },
  };
}
