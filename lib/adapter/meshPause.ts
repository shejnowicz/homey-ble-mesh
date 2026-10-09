/**
 * Pausing the shared proxy connection around a pairing attempt — the one
 * place this project decides when the radio is free enough for pairing to
 * use it, and the only reason `ProxyConnectionManager#whenLinkReleased()`
 * exists.
 *
 * THE HARDWARE DEFECT THIS FIXES (confirmed on the owner's three bulbs,
 * 2026-10-09). Adding a bulb to a mesh that already had paired bulbs failed
 * EVERY time with
 *
 *     could not connect to "<peripheral>" for provisioning:
 *     provisioning: connecting: timed out after 30000ms
 *
 * while the same bulb in the same place paired first time with the mesh
 * empty. It reported -54 dBm with nothing connected and -75 dBm with a
 * proxy connection live: the radio was busy, not the bulb further away. The
 * proof was a temporary patch making `app.ts#ensureMeshStarted()` return
 * immediately — the connection manager never started, the radio was
 * guaranteed free, and that exact bulb paired on the first attempt. The
 * network now holds three fully configured nodes.
 *
 * WHAT WAS ACTUALLY WRONG. `app.ts` already paused the mesh for pairing
 * (its own "PAIRING PAUSES THE SHARED CONNECTION" note) — but the pause was
 * synchronous all the way down. `driver.ts`'s `withMeshPaused` called
 * `pauseMeshForPairing()`, which called `ProxyConnectionManager#stop()`,
 * which ended with `void this.bluetooth.disconnect(connection)` — fired and
 * not awaited. `stop()` returned, the pause returned, and pairing started
 * scanning and connecting while the proxy link was still being torn down.
 * `app.ts`'s own header had predicted precisely this in writing ("maybe
 * pairing and the proxy connection contend for the radio in some OTHER way
 * this does not address … something only the owner's three bulbs can
 * confirm"). They confirmed it.
 *
 * THE SEAM. `stop()` stays synchronous — it is called from `onUninit` and
 * from this module, and its job (make the manager inert NOW) is one a
 * caller must be able to do without awaiting. The manager instead publishes
 * `whenLinkReleased()`, a promise for "the last teardown has settled", and
 * this module is the one caller that waits on it. Nothing else in the
 * project had to become async.
 *
 * WHY THE WAIT IS BOUNDED. `whenLinkReleased()` cannot make a port that
 * never settles settle — a real GATT stack can simply swallow a disconnect.
 * Pairing proceeding after a bounded wait is strictly better than pairing
 * never starting: the worst case is the contention we had before, which at
 * least produces a failed attempt the user can retry, rather than a pairing
 * wizard that hangs with no timeout of its own to rescue it. See
 * `MESH_LINK_RELEASE_TIMEOUT_MS` for the bound and why it is that number.
 *
 * WHY THIS LIVES IN lib/adapter RATHER THAN IN driver.ts. `driver.ts` and
 * `app.ts` both import `homey`, so neither can be imported by a jest test
 * and neither may carry a named runtime export at all (it would be
 * discarded by `module.exports =` — see
 * `lib/__tests__/module-export-boundary.test.ts`). Leaving the ordering
 * rule inside either of them is what let the defect ship unnoticed: the
 * whole gate passed with the disconnect unawaited. Here, both halves are
 * ordinary functions over ordinary ports, and
 * `__tests__/meshPause.test.ts` drives them against the real
 * `ProxyConnectionManager` and the real fake radio.
 */

import type { ClockPort } from './connection';
import { withTimeout } from './timeout';

/**
 * How long `pauseProxyForPairing` waits for the proxy link to finish
 * tearing down before it lets pairing have the radio anyway.
 *
 * NOT A SPECIFICATION VALUE — an engineering choice, bracketed by two
 * numbers this project already committed to. It is well above
 * `connection.ts#PROXY_WRITE_TIMEOUT_MS` (2 000 ms, one GATT write on a
 * healthy link), because a teardown is an operation on a link that may
 * already be misbehaving — that is often WHY it is being torn down. It is
 * well below `pairing.ts#DEFAULT_PAIRING_STEP_TIMEOUT_MS` (30 000 ms, one
 * pairing step), so this wait can never be mistaken for, or add
 * meaningfully to, the 30-second connect timeout that is the defect's own
 * symptom: in the pathological case the user waits five seconds longer and
 * then gets the same attempt they would have got before this fix.
 */
export const MESH_LINK_RELEASE_TIMEOUT_MS = 5000;

/**
 * The part of `ProxyConnectionManager` this module drives — declared here
 * rather than importing the class so the pause logic is testable against a
 * stub as well as against the real manager, and so nothing about pausing
 * depends on the manager's much larger surface.
 */
export interface PausableProxy {
  /** Begins scanning/connecting again. */
  start(): void;
  /** Makes the manager inert and ASKS the port to drop the active link;
   *  returns before that teardown has finished. */
  stop(): void;
  /** Settles once the teardown `stop()` asked for has finished. */
  whenLinkReleased(): Promise<void>;
}

export interface PauseOptions {
  /** Where a teardown that outran the bound is reported. Omitted, it is
   *  silent — which is wrong for the app (`app.ts` passes `this.log`) and
   *  right for a test that is asserting something else. */
  readonly log?: (message: string) => void;
  /** Overrides `MESH_LINK_RELEASE_TIMEOUT_MS` — injected so a test drives
   *  the bound without waiting on it. */
  readonly releaseTimeoutMs?: number;
}

/**
 * Stops `proxy` and waits — boundedly — for its link to actually be
 * released, so the caller can use the radio.
 *
 * Returns whether anything was running (and so was actually paused), which
 * is the contract `withMeshPaused` resumes on: `false` means the mesh had
 * never been started, and starting it here would be wrong — on the
 * FIRST-ever pairing that is `app.ts#ensureMeshStarted`'s job, once a
 * network key exists at all.
 *
 * NEVER THROWS, by design, and `withMeshPaused` depends on that: a pause
 * that threw after `stop()` had already landed would skip the `finally`
 * that resumes and leave the mesh down for every already-paired bulb until
 * the app restarted. A teardown that rejects or outruns the bound is
 * therefore logged and swallowed, and the answer is still `true` — it WAS
 * running, it HAS been stopped, and it must be started again afterwards.
 */
export async function pauseProxyForPairing(
  proxy: PausableProxy | null,
  clock: ClockPort,
  options: PauseOptions = {},
): Promise<boolean> {
  if (proxy === null) return false;
  proxy.stop();

  const log = options.log ?? ((): void => {});
  const releaseTimeoutMs = options.releaseTimeoutMs ?? MESH_LINK_RELEASE_TIMEOUT_MS;
  try {
    await withTimeout(
      proxy.whenLinkReleased(),
      clock,
      releaseTimeoutMs,
      'pausing the mesh for pairing: releasing the proxy connection',
    );
  } catch (err) {
    log(
      `${err instanceof Error ? err.message : String(err)} — starting the pairing attempt anyway; if it fails to connect, the radio was probably still busy`,
    );
  }
  return true;
}

/** What `withMeshPaused` needs from `app.ts` — the two methods `driver.ts`
 *  already called, with the pause now asynchronous. */
export interface MeshPauseHost {
  /** Stops the shared proxy connection AND waits for its link to be
   *  released; resolves to whether anything was running. */
  pauseMeshForPairing(): Promise<boolean>;
  /** The inverse — called only when that call resolved `true`. */
  resumeMeshAfterPairing(): void;
}

/**
 * Runs `run` with the shared proxy connection paused and the radio
 * released, resuming it afterwards if and only if it had been running.
 *
 * The `await` on the pause is the entire fix — see this module's header.
 * `run` must not be called until it resolves, which is what
 * `__tests__/meshPause.test.ts` pins: a mutation dropping that await
 * typechecks cleanly (`if (promise)` is a legal truthiness test on a
 * `Promise<boolean>`), so only a test can hold this line in place.
 */
export async function withMeshPaused<T>(host: MeshPauseHost, run: () => Promise<T>): Promise<T> {
  const wasRunning = await host.pauseMeshForPairing();
  try {
    return await run();
  } finally {
    if (wasRunning) host.resumeMeshAfterPairing();
  }
}
