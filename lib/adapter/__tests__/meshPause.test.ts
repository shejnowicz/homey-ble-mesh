import { randomBytes } from 'node:crypto';
import { ProxyConnectionManager } from '../connection';
import {
  MESH_LINK_RELEASE_TIMEOUT_MS,
  pauseProxyForPairing,
  withMeshPaused,
  type MeshPauseHost,
  type PausableProxy,
} from '../meshPause';
import { FakeBluetoothPort } from './fakeBluetooth';
import { createFakeClock, type FakeClock } from './fakeClock';

/**
 * The 2026-10-09 hardware defect, pinned: pairing used to start scanning
 * and connecting while the proxy link was still being torn down, because
 * `ProxyConnectionManager#stop()` ended with an unawaited
 * `bluetooth.disconnect(…)`. See `../meshPause.ts`'s module header for the
 * experiment that proved it.
 *
 * TWO LEVELS, deliberately. The first group drives the REAL
 * `ProxyConnectionManager` over the real fake radio, with a teardown the
 * test holds open — the closest this project can get, without a hub, to
 * "the radio is still busy". The rest drive `pauseProxyForPairing` and
 * `withMeshPaused` over a stub proxy, which is the only way to reach the
 * bound and the rejection paths at all (the real manager never rejects a
 * teardown outward — that is itself one of the things pinned below).
 */

/** One macrotask turn: lets every `await` chain the code under test queued
 *  run to completion before an assertion looks at it. Same device
 *  `fakeClock.advance` uses internally, for the same reason. */
function flush(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

interface Deferred {
  readonly promise: Promise<void>;
  readonly resolve: () => void;
  readonly reject: (err: Error) => void;
}

/** A promise a test settles by hand. Written as a function returning the
 *  three pieces rather than as two `let`s assigned inside an executor,
 *  because TypeScript's control-flow analysis narrows the latter to `never`
 *  (it cannot see that the executor runs synchronously). */
function deferred(): Deferred {
  let resolve: () => void = () => {};
  let reject: (err: Error) => void = () => {};
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** A `PausableProxy` whose teardown the test settles by hand, plus a
 *  record of what was called on it and when. */
function stubProxy(): {
  proxy: PausableProxy;
  calls: string[];
  releaseLink: () => void;
  failLink: (err: Error) => void;
} {
  const calls: string[] = [];
  // Nothing attaches a handler to this until `pauseProxyForPairing` awaits
  // it, and a test that never pauses never rejects it, so no unhandled
  // rejection is possible.
  const link = deferred();
  return {
    calls,
    proxy: {
      start: (): void => {
        calls.push('start');
      },
      stop: (): void => {
        calls.push('stop');
      },
      whenLinkReleased: (): Promise<void> => {
        calls.push('whenLinkReleased');
        return link.promise;
      },
    },
    releaseLink: link.resolve,
    failLink: link.reject,
  };
}

/** `pauseProxyForPairing` wired into the `MeshPauseHost` shape `app.ts`
 *  implements, so `withMeshPaused` is exercised over the real pause rather
 *  than over a second stub of it. */
function hostOver(proxy: PausableProxy | null, clock: FakeClock, log?: (message: string) => void): MeshPauseHost {
  return {
    pauseMeshForPairing: (): Promise<boolean> => pauseProxyForPairing(proxy, clock, log ? { log } : {}),
    resumeMeshAfterPairing: (): void => proxy?.start(),
  };
}

describe('the real ProxyConnectionManager, with a teardown the test holds open', () => {
  /** A manager connected to one node, with that node's `disconnect()`
   *  configured to hang until the test releases it. */
  async function connectedManager(): Promise<{
    bluetooth: FakeBluetoothPort;
    clock: FakeClock;
    manager: ProxyConnectionManager;
  }> {
    const netKey = randomBytes(16);
    const bluetooth = new FakeBluetoothPort();
    const clock = createFakeClock();
    const manager = new ProxyConnectionManager(bluetooth, clock, netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey, disconnectBehavior: 'hold' });
    manager.start();
    await clock.advance(0);
    expect(manager.getState().status).toBe('connected');
    return { bluetooth, clock, manager };
  }

  test('pairing does not begin until the disconnect has settled', async () => {
    const { bluetooth, clock, manager } = await connectedManager();
    let pairingStarted = false;

    const run = withMeshPaused(hostOver(manager, clock), async () => {
      pairingStarted = true;
      return 'paired';
    });

    // The teardown has been ASKED for — the manager is already inert — but
    // the radio has not finished with it.
    await flush();
    expect(bluetooth.heldDisconnectCount('A')).toBe(1);
    expect(pairingStarted).toBe(false);

    bluetooth.releaseDisconnect('A', 0, { ok: true });
    await flush();
    expect(pairingStarted).toBe(true);
    await expect(run).resolves.toBe('paired');
  });

  test('the bounded wait is what ends it if the disconnect never settles, and the mesh still resumes', async () => {
    const { bluetooth, clock, manager } = await connectedManager();
    let pairingStarted = false;

    const run = withMeshPaused(hostOver(manager, clock), async () => {
      pairingStarted = true;
      return 'paired';
    });

    await clock.advance(MESH_LINK_RELEASE_TIMEOUT_MS - 1);
    expect(pairingStarted).toBe(false);
    expect(bluetooth.scanCallCount()).toBe(1); // only the original connect's own scan

    await clock.advance(1);
    expect(pairingStarted).toBe(true);
    await expect(run).resolves.toBe('paired');

    // Resumed — the manager scanned again — and the teardown it is still
    // waiting on was never abandoned or repeated, which is the point: the
    // bound releases the CALLER, it cannot release the radio.
    expect(bluetooth.scanCallCount()).toBe(2);
    expect(bluetooth.heldDisconnectCount('A')).toBe(1);
  });

  test('a disconnect that rejects releases pairing immediately and leaves the manager usable', async () => {
    const { bluetooth, clock, manager } = await connectedManager();
    let pairingStarted = false;

    const run = withMeshPaused(hostOver(manager, clock), async () => {
      pairingStarted = true;
      return 'paired';
    });

    await flush();
    expect(pairingStarted).toBe(false);
    bluetooth.releaseDisconnect('A', 0, { ok: false, err: new Error('the stack refused to disconnect') });

    await flush();
    expect(pairingStarted).toBe(true);
    await expect(run).resolves.toBe('paired');

    // Not wedged: the resumed manager reconnects to the same node.
    await clock.advance(0);
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });
  });

  test('a rejected teardown is reported through the manager log rather than thrown anywhere', async () => {
    const netKey = randomBytes(16);
    const bluetooth = new FakeBluetoothPort();
    const clock = createFakeClock();
    const logged: string[] = [];
    const manager = new ProxyConnectionManager(bluetooth, clock, netKey, {
      log: (message: string): void => {
        logged.push(message);
      },
    });
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey, disconnectBehavior: 'fail' });
    manager.start();
    await clock.advance(0);

    manager.stop();
    await expect(manager.whenLinkReleased()).resolves.toBeUndefined();
    expect(logged).toContain('mesh proxy disconnect failed: FakeBluetoothPort.disconnect: configured to fail for "A"');
  });
});

describe('pauseProxyForPairing', () => {
  test('stops the proxy and waits for the link, in that order', async () => {
    const clock = createFakeClock();
    const { proxy, calls, releaseLink } = stubProxy();

    let resolved = false;
    const pausing = pauseProxyForPairing(proxy, clock).then((wasRunning) => {
      resolved = true;
      return wasRunning;
    });

    await flush();
    expect(calls).toEqual(['stop', 'whenLinkReleased']);
    expect(resolved).toBe(false);

    releaseLink();
    await expect(pausing).resolves.toBe(true);
  });

  test('a null proxy is a no-op that reports it was not running', async () => {
    const clock = createFakeClock();
    await expect(pauseProxyForPairing(null, clock)).resolves.toBe(false);
    // Nothing was scheduled: no bounded wait was ever armed for a mesh that
    // was never running.
    expect(clock.pendingCount()).toBe(0);
  });

  test('a teardown that outruns the bound still resolves true, and says so through the log', async () => {
    const clock = createFakeClock();
    const { proxy } = stubProxy(); // never released
    const logged: string[] = [];

    const pausing = pauseProxyForPairing(proxy, clock, {
      log: (message: string): void => {
        logged.push(message);
      },
    });

    await clock.advance(MESH_LINK_RELEASE_TIMEOUT_MS);
    await expect(pausing).resolves.toBe(true);
    expect(logged).toHaveLength(1);
    expect(logged[0]).toContain(
      `pausing the mesh for pairing: releasing the proxy connection: timed out after ${MESH_LINK_RELEASE_TIMEOUT_MS}ms`,
    );
  });

  test('releaseTimeoutMs overrides the default bound', async () => {
    const clock = createFakeClock();
    const { proxy } = stubProxy(); // never released
    const pausing = pauseProxyForPairing(proxy, clock, { releaseTimeoutMs: 25 });

    await clock.advance(24);
    let settled = false;
    void pausing.then(() => {
      settled = true;
    });
    await flush();
    expect(settled).toBe(false);

    await clock.advance(1);
    await expect(pausing).resolves.toBe(true);
  });

  test('a teardown that rejects resolves true rather than throwing out of the pause', async () => {
    const clock = createFakeClock();
    const { proxy, failLink } = stubProxy();
    const logged: string[] = [];
    const pausing = pauseProxyForPairing(proxy, clock, {
      log: (message: string): void => {
        logged.push(message);
      },
    });

    failLink(new Error('the stack refused to disconnect'));
    await expect(pausing).resolves.toBe(true);
    expect(logged[0]).toContain('the stack refused to disconnect');
  });

  test('the bound is disarmed once the link is released, so no stray timer is left running', async () => {
    const clock = createFakeClock();
    const { proxy, releaseLink } = stubProxy();
    const pausing = pauseProxyForPairing(proxy, clock);
    await flush();
    expect(clock.pendingCount()).toBe(1);

    releaseLink();
    await pausing;
    expect(clock.pendingCount()).toBe(0);
  });
});

describe('withMeshPaused: the "was it running" contract', () => {
  test('resumes the mesh when it had been running', async () => {
    const clock = createFakeClock();
    const { proxy, calls, releaseLink } = stubProxy();
    releaseLink();

    await expect(withMeshPaused(hostOver(proxy, clock), async () => 'paired')).resolves.toBe('paired');
    expect(calls).toEqual(['stop', 'whenLinkReleased', 'start']);
  });

  test('does not start a mesh that was never running', async () => {
    const clock = createFakeClock();
    const { proxy, calls } = stubProxy();

    // `null` is what app.ts passes before any network key exists — the
    // FIRST-ever pairing, where starting the connection is
    // `ensureMeshStarted`'s job, not this one's.
    const host: MeshPauseHost = {
      pauseMeshForPairing: (): Promise<boolean> => pauseProxyForPairing(null, clock),
      resumeMeshAfterPairing: (): void => proxy.start(),
    };

    await expect(withMeshPaused(host, async () => 'paired')).resolves.toBe('paired');
    expect(calls).toEqual([]);
  });

  test('resumes even when the pairing work throws, and propagates the failure', async () => {
    const clock = createFakeClock();
    const { proxy, calls, releaseLink } = stubProxy();
    releaseLink();

    await expect(
      withMeshPaused(hostOver(proxy, clock), async () => {
        throw new Error('pairing failed');
      }),
    ).rejects.toThrow('pairing failed');
    expect(calls).toEqual(['stop', 'whenLinkReleased', 'start']);
  });

  test('resumes only after the pairing work has finished, never alongside it', async () => {
    const clock = createFakeClock();
    const { proxy, calls, releaseLink } = stubProxy();
    releaseLink();

    const pairing = deferred();
    const run = withMeshPaused(hostOver(proxy, clock), async () => {
      await pairing.promise;
      return 'paired';
    });

    await flush();
    expect(calls).toEqual(['stop', 'whenLinkReleased']); // no 'start' yet

    pairing.resolve();
    await expect(run).resolves.toBe('paired');
    expect(calls).toEqual(['stop', 'whenLinkReleased', 'start']);
  });
});
