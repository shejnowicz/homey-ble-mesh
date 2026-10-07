/**
 * `withTimeout` was module-private inside `drivers/light/pairing.ts` until
 * the final re-review found `lib/adapter/connection.ts` needing the same
 * bound, so it moved to `lib/adapter/timeout.ts`. It was never tested
 * directly — only through pairing's own end-to-end stalls — which is fine
 * for one caller and not fine for a shared module: these are the properties
 * BOTH callers now depend on, pinned where the function itself lives.
 */

import { withTimeout } from '../timeout';
import { createFakeClock } from './fakeClock';

function neverSettles<T>(): Promise<T> {
  return new Promise<T>(() => {});
}

test('resolves with the promise value when it settles first, and cancels the timer rather than leaving it pending', async () => {
  const clock = createFakeClock();

  await expect(withTimeout(Promise.resolve('ok'), clock, 50, 'something')).resolves.toBe('ok');
  expect(clock.pendingCount()).toBe(0);
});

test("propagates the promise's own rejection unchanged, and cancels the timer", async () => {
  const clock = createFakeClock();
  const boom = new Error('the port said no');

  await expect(withTimeout(Promise.reject(boom), clock, 50, 'something')).rejects.toBe(boom);
  expect(clock.pendingCount()).toBe(0);
});

test('a non-Error rejection is wrapped in an Error rather than thrown as a bare value', async () => {
  const clock = createFakeClock();

  await expect(withTimeout(Promise.reject('a bare string'), clock, 50, 'something')).rejects.toThrow('a bare string');
});

test('rejects naming `what` and the deadline when the promise never settles', async () => {
  const clock = createFakeClock();
  const promise = withTimeout(neverSettles<void>(), clock, 50, 'provisioning: writing to the node');
  promise.catch(() => {}); // a handler must exist before advance(), or Node reports an unhandled rejection

  await clock.advance(50);

  await expect(promise).rejects.toThrow('provisioning: writing to the node: timed out after 50ms');
});

test('a late settlement after the timeout has already fired changes nothing — no second resolve, no unhandled rejection', async () => {
  const clock = createFakeClock();
  let settle: (value: string) => void = () => {};
  const inner = new Promise<string>((resolve) => {
    settle = resolve;
  });
  const promise = withTimeout(inner, clock, 50, 'late');
  promise.catch(() => {});

  await clock.advance(50);
  await expect(promise).rejects.toThrow('late: timed out after 50ms');

  settle('too late'); // the loser settling afterwards is a no-op
  await expect(promise).rejects.toThrow('late: timed out after 50ms');
});

test('the timer is driven through the injected clock, never the global one', async () => {
  const clock = createFakeClock();
  const promise = withTimeout(neverSettles<void>(), clock, 50, 'bounded');
  promise.catch(() => {});

  expect(clock.pendingCount()).toBe(1); // scheduled on OUR clock...
  await clock.advance(49);
  // ...and nothing but that clock advancing can make it fire.
  let fired = false;
  promise.catch(() => {
    fired = true;
  });
  await Promise.resolve();
  expect(fired).toBe(false);

  await clock.advance(1);
  await expect(promise).rejects.toThrow('bounded');
});
