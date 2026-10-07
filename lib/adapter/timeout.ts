/**
 * `withTimeout` — the one bounded-wait helper in this project, and the one
 * place its semantics are written down.
 *
 * WHY IT LIVES HERE RATHER THAN IN ONE OF ITS CALLERS. It was written for
 * `drivers/light/pairing.ts` (commit f6dd4ae, "bound every GATT operation,
 * not only the reply wait") and stayed module-private there. The final
 * re-review then found the proxy path needing exactly the same thing — a
 * `BluetoothPort.write` that never settles latching
 * `ProxyConnectionManager`'s own in-flight flag forever — and a helper that
 * two modules need is a shared module, not a copy. `ClockPort` was already
 * shared (it is declared in `./connection` and consumed by both), so this
 * file adds no new concept: it moves one function to where both callers can
 * reach it.
 *
 * THE IMPORT DIRECTION. `ClockPort` is imported from `./connection` with
 * `import type`, which TypeScript erases entirely at emit, so the runtime
 * module graph has `connection.ts -> timeout.ts` and nothing back — no
 * require cycle, despite the type reference pointing the other way.
 *
 * WHAT "BOUNDED" MEANS HERE, precisely, because both callers depend on it:
 * whichever of the two outcomes happens FIRST wins, cleanly, and the
 * loser's own eventual settlement is a no-op rather than a second
 * resolve/reject. A late reply arriving after a timeout changes nothing; a
 * timer that never gets to fire because the promise settled first is
 * cancelled through the same `ClockPort` it was scheduled on, so a test's
 * fake clock sees it go away and a real `setTimeout` is not left holding
 * the event loop open.
 *
 * WHAT IT DOES NOT DO: it cannot cancel the underlying operation. A GATT
 * write that never settles is still pending inside the platform after this
 * rejects; what the timeout buys is that the CALLER stops waiting on it and
 * whatever the caller had to unwind (a `finally`, a flag, a session) gets
 * to run. Every caller's own comment says what it unwinds.
 */

import type { ClockPort } from './connection';

/**
 * Races `promise` against a `clock`-driven timer; rejects with an error
 * naming `what` if `timeoutMs` elapses first.
 *
 * `what` is the subject of the message and should name the operation and
 * its context ("provisioning: writing to the node", "ProxyConnectionManager
 * .write: segment 2 of 2"), because that string is usually all a user ever
 * sees of the failure.
 */
export function withTimeout<T>(promise: Promise<T>, clock: ClockPort, timeoutMs: number, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const timer = clock.setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error(`${what}: timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    promise.then(
      (value) => {
        if (settled) return;
        settled = true;
        clock.clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        if (settled) return;
        settled = true;
        clock.clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      },
    );
  });
}
