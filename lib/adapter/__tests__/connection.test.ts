import { randomBytes } from 'node:crypto';
import { k3 } from '../../mesh/crypto/derive';
import {
  ProxyConnectionManager,
  MESH_PROXY_SERVICE_UUID,
  MESH_PROXY_DATA_IN_UUID,
  MESH_PROXY_DATA_OUT_UUID,
  MESH_PROVISIONING_SERVICE_UUID,
  SCAN_DURATION_MS,
  findServiceData,
  type BluetoothPort,
  type ScanResult,
  type DiscoveredCharacteristic,
  type Subscription,
} from '../connection';
import { FakeBluetoothPort } from './fakeBluetooth';
import { createFakeClock } from './fakeClock';
import { NETWORK_ID_ADVERTISING_SAMPLE, hex } from './vectors';

/**
 * This task's one real anchor (task brief): everything else in this suite
 * pins THIS PROJECT's own design (selection, migration, backoff,
 * availability — none of it published anywhere), but the advertised
 * Network ID itself is a transcribed specification value with a published
 * sample. This re-derives it independently of both the manager and the
 * fake port (which also use k3, but importing it here and computing the
 * expected bytes by hand means a bug shared between this module and k3's
 * OWN caller in connection.ts cannot hide behind the fake reusing the same
 * function — see vectors.ts for the full provenance).
 */
test('the published Section 8.6.1 sample: k3(NetKey) reproduces the Network ID and the full advertising bytes', () => {
  const netKey = hex(NETWORK_ID_ADVERTISING_SAMPLE.netKey);
  const networkId = k3(netKey);

  expect(networkId.toString('hex')).toBe(NETWORK_ID_ADVERTISING_SAMPLE.expectedNetworkId);

  const advData = Buffer.concat([
    hex(NETWORK_ID_ADVERTISING_SAMPLE.advLen),
    hex(NETWORK_ID_ADVERTISING_SAMPLE.adType), // AD Type: Service Data - 16-bit UUID
    hex(NETWORK_ID_ADVERTISING_SAMPLE.meshProxyServiceUuidLe),
    hex(NETWORK_ID_ADVERTISING_SAMPLE.identificationType),
    networkId,
  ]);
  expect(advData.toString('hex')).toBe(NETWORK_ID_ADVERTISING_SAMPLE.expectedAdvData);
});

function setUp(netKey: Buffer): { bluetooth: FakeBluetoothPort; clock: ReturnType<typeof createFakeClock>; manager: ProxyConnectionManager } {
  const bluetooth = new FakeBluetoothPort();
  const clock = createFakeClock();
  const manager = new ProxyConnectionManager(bluetooth, clock, netKey);
  return { bluetooth, clock, manager };
}

describe('constructor validation', () => {
  test('rejects a netKey of the wrong length, naming the length', () => {
    const bluetooth = new FakeBluetoothPort();
    const clock = createFakeClock();
    expect(() => new ProxyConnectionManager(bluetooth, clock, randomBytes(15))).toThrow(
      'ProxyConnectionManager: netKey must be 16 bytes, got 15',
    );
  });

  /**
   * Review finding: this defensive copy is one of the plan's GLOBAL
   * constraints ("never retain a view into a buffer it does not own"),
   * not an incidental nicety -- it should not have been one of the
   * unpinned lines.
   *
   * FIRST ATTEMPT AT THIS TEST, and why it was wrong: mutating `netKey`
   * AFTER construction (then checking whether the manager still recognised
   * a node keyed off the original bytes) cannot discriminate "copied
   * before use" from "used directly" here, because `k3` consumes its input
   * SYNCHRONOUSLY during the constructor call and returns a brand-new
   * buffer; nothing ever reads `netKey` again afterwards either way. I
   * mutation-tested that version and it passed unchanged with the
   * defensive copy removed -- a false pin. This version instead spies on
   * the imported `k3` function itself and asserts the ACTUAL buffer
   * instance connection.ts hands it is not the caller's own.
   */
  test('passes k3 a copy of the netKey, never the caller-supplied buffer instance', () => {
    const deriveModule: typeof import('../../mesh/crypto/derive') = require('../../mesh/crypto/derive');
    const spy = jest.spyOn(deriveModule, 'k3');
    try {
      const netKey = randomBytes(16);
      new ProxyConnectionManager(new FakeBluetoothPort(), createFakeClock(), netKey);

      expect(spy).toHaveBeenCalledTimes(1);
      const passed = spy.mock.calls[0]?.[0] as Buffer;
      expect(passed).not.toBe(netKey); // a distinct Buffer instance...
      expect(passed.equals(netKey)).toBe(true); // ...with the same bytes
    } finally {
      spy.mockRestore();
    }
  });
});

describe('the published sample, end-to-end', () => {
  /**
   * Review finding: every other identity test in this suite generates a
   * random key and derives BOTH the advertisement (via the fake's
   * `networkKey` option) and the manager's own check with the same k3
   * call -- self-consistent, but not anchored: if k3 and this module's use
   * of it were wrong in the same way, every one of those tests would still
   * pass. This test feeds the PUBLISHED NetKey through the manager's own
   * constructor and advertises the LITERAL published bytes (string
   * constants transcribed from Section 8.6.1, not computed by calling k3
   * anywhere in this test) -- the only test in this suite where the
   * "expected" side comes from the specification text rather than from
   * this project's own code on both sides at once.
   */
  test('feeding the published NetKey through the manager accepts the literal published advertisement', async () => {
    const netKey = hex(NETWORK_ID_ADVERTISING_SAMPLE.netKey);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({
      id: 'published-sample-node',
      rssi: -50,
      serviceDataOverride: hex(
        NETWORK_ID_ADVERTISING_SAMPLE.identificationType + NETWORK_ID_ADVERTISING_SAMPLE.expectedNetworkId,
      ),
    });

    manager.start();
    await clock.advance(0);

    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'published-sample-node' });
  });
});

describe('selection', () => {
  test('the strongest of several of our nodes is chosen', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    // Three distinct, non-uniform signal strengths with the strongest in
    // the MIDDLE of insertion order -- a fixture that always picked
    // scan()[0] or scan()[last] both fail this, which a fixture with the
    // strongest first or last would not catch.
    bluetooth.addNode({ id: 'weak', rssi: -70, networkKey: netKey });
    bluetooth.addNode({ id: 'strongest', rssi: -40, networkKey: netKey });
    bluetooth.addNode({ id: 'middling', rssi: -55, networkKey: netKey });

    manager.start();
    await clock.advance(0);

    expect(bluetooth.connectCalls).toEqual(['strongest']);
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'strongest' });
  });

  test('a node advertising a foreign network identity is never connected to, even when it is the strongest', async () => {
    const ourKey = randomBytes(16);
    const foreignKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(ourKey);
    bluetooth.addNode({ id: 'foreign', rssi: -20, networkKey: foreignKey }); // strongest overall
    bluetooth.addNode({ id: 'ours-weaker', rssi: -60, networkKey: ourKey });

    manager.start();
    await clock.advance(0);

    expect(bluetooth.connectCalls).not.toContain('foreign');
    expect(bluetooth.connectCalls).toEqual(['ours-weaker']);
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'ours-weaker' });
  });

  /**
   * Beyond the brief's listed cases: Table 7.8 defines three OTHER
   * identification types besides Network ID (Node Identity, and two
   * Private variants). A node advertising one of those is not "a foreign
   * network" in the sense of the test above -- it is a perfectly ordinary
   * node of OUR OWN mesh, just not currently advertising the one
   * identification type this module can check without a connection (see
   * connection.ts's module header). It must still never be selected on the
   * strength of an identity this module cannot verify.
   *
   * REVIEW FINDING: an earlier version of this test used RANDOM bytes as
   * the identity parameters under the wrong type octet. That is no test of
   * the type check at all -- the random bytes already fail the byte
   * comparison against our real Network ID, so the node is rejected before
   * the type octet is ever consulted; deleting the type check entirely
   * still passed the whole suite. This version carries the GENUINE derived
   * identity (k3(ourKey)) under the wrong type octet, so the type check is
   * the ONLY thing that can reject it -- a byte-comparison bug could not.
   */
  test('a node advertising our genuine identity under the wrong identification type is never selected', async () => {
    const ourKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(ourKey);
    bluetooth.addNode({
      id: 'wrong-type',
      rssi: -10,
      // Type 0x01 (Node Identity), but the Identification Parameters ARE
      // our real k3(ourKey) -- only the type octet is wrong.
      serviceDataOverride: Buffer.concat([Buffer.from([0x01]), k3(ourKey)]),
    });
    bluetooth.addNode({ id: 'ours', rssi: -60, networkKey: ourKey });

    manager.start();
    await clock.advance(0);

    expect(bluetooth.connectCalls).toEqual(['ours']);
  });

  test('a node advertising no Mesh Proxy Service data at all is never selected', async () => {
    const ourKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(ourKey);
    bluetooth.addNode({ id: 'no-service-data', rssi: -10, serviceDataOverride: null });
    bluetooth.addNode({ id: 'ours', rssi: -60, networkKey: ourKey });

    manager.start();
    await clock.advance(0);

    expect(bluetooth.connectCalls).toEqual(['ours']);
  });
});

describe('migration on disconnect', () => {
  test('losing the connection causes a rescan and a connection to the next node', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -40, networkKey: netKey }); // strongest initially
    bluetooth.addNode({ id: 'B', rssi: -70, networkKey: netKey });

    manager.start();
    await clock.advance(0);
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });

    // A loses power: stops advertising AND its link drops -- exactly the
    // design's own scenario ("cutting power to the node currently serving
    // as proxy moves the connection to another node").
    bluetooth.simulateNodePoweredOff('A');
    expect(manager.getState()).toEqual({ status: 'unavailable', peripheralId: null });

    await clock.advance(0); // disconnect reschedules at 0 delay -- see connection.ts
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'B' });
    expect(bluetooth.connectCalls).toEqual(['A', 'B']);
  });
});

describe('backoff', () => {
  test('repeated connection failures back off with increasing delay, driven by the fake clock, not by waiting', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey, connectBehavior: 'fail' });

    manager.start();
    await clock.advance(0); // attempt 1 (t=0): fails
    expect(bluetooth.connectCalls).toHaveLength(1);

    // Advancing LESS than the scheduled delay must not trigger a retry --
    // this is what makes the test prove a DELAY exists at all, not just
    // that retries eventually happen.
    await clock.advance(999);
    expect(bluetooth.connectCalls).toHaveLength(1);
    await clock.advance(1); // now at t=1000 -- exactly the first backoff
    expect(bluetooth.connectCalls).toHaveLength(2); // attempt 2: fails

    await clock.advance(1999);
    expect(bluetooth.connectCalls).toHaveLength(2);
    await clock.advance(1); // t=3000 -- 1000 + 2000, the SECOND backoff, strictly longer than the first
    expect(bluetooth.connectCalls).toHaveLength(3); // attempt 3: fails

    await clock.advance(3999);
    expect(bluetooth.connectCalls).toHaveLength(3);
    await clock.advance(1); // t=7000 -- 3000 + 4000, strictly longer again
    expect(bluetooth.connectCalls).toHaveLength(4);

    expect(manager.getState()).toEqual({ status: 'unavailable', peripheralId: null });
  });

  test('backoff is capped rather than growing without bound', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey, connectBehavior: 'fail' });

    manager.start();
    // Walk the schedule this module's own constants produce (1000, 2000,
    // 4000, 8000, 16000ms) up to where it saturates at the 30s cap, then
    // confirm the NEXT delay stays at the cap rather than doubling past it.
    const delays = [0, 1000, 2000, 4000, 8000, 16000];
    for (const delay of delays) {
      await clock.advance(delay);
    }
    expect(bluetooth.connectCalls).toHaveLength(delays.length); // one attempt per scheduled delay so far

    await clock.advance(30_000 - 1);
    expect(bluetooth.connectCalls).toHaveLength(delays.length); // the cap, not 32000ms (1000*2**5), is what is due
    await clock.advance(1);
    expect(bluetooth.connectCalls).toHaveLength(delays.length + 1);

    await clock.advance(30_000 - 1);
    expect(bluetooth.connectCalls).toHaveLength(delays.length + 1); // still capped at 30s, not 60s
    await clock.advance(1);
    expect(bluetooth.connectCalls).toHaveLength(delays.length + 2);
  });

  test('backoff resets after a successful connection', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey, connectBehavior: 'fail' });

    manager.start();
    await clock.advance(0); // attempt 1 (t=0): fails -> next delay 1000ms
    await clock.advance(1000); // attempt 2 (t=1000): fails -> next delay 2000ms
    expect(bluetooth.connectCalls).toHaveLength(2);

    bluetooth.setConnectBehavior('A', 'succeed');
    await clock.advance(2000); // attempt 3 (t=3000): succeeds
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });
    expect(bluetooth.connectCalls).toHaveLength(3);

    bluetooth.simulateDisconnect('A'); // A is still advertising -- just the link drops
    bluetooth.setConnectBehavior('A', 'fail'); // force one more failure to observe ITS backoff
    await clock.advance(0); // the immediate post-disconnect rescan (t=3000): attempt 4, fails
    expect(bluetooth.connectCalls).toHaveLength(4);

    // THE actual assertion: had the earlier 1000/2000ms streak NOT been
    // reset by the successful attempt 3, this next delay would be 4000ms
    // (continuing the doubling from streak=2) and nothing would fire yet
    // at t=4000. With the reset, the streak restarts at 1 and this delay
    // is back to the base 1000ms.
    await clock.advance(1000); // t=4000
    expect(bluetooth.connectCalls).toHaveLength(5);
  });
});

describe('availability', () => {
  test('with no node answering at all, the manager reports unavailable and keeps trying', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    // No nodes registered at all -- scan() always resolves empty.

    manager.start();
    await clock.advance(0);
    expect(manager.getState()).toEqual({ status: 'unavailable', peripheralId: null });
    expect(bluetooth.scanCallCount()).toBe(1);

    await clock.advance(1000);
    expect(manager.getState()).toEqual({ status: 'unavailable', peripheralId: null });
    expect(bluetooth.scanCallCount()).toBe(2);

    await clock.advance(2000);
    expect(manager.getState()).toEqual({ status: 'unavailable', peripheralId: null });
    expect(bluetooth.scanCallCount()).toBe(3); // keeps trying, never gives up
  });

  test('a node whose GATT discovery does not expose both Mesh Proxy characteristics fails the attempt and keeps trying, rather than crashing', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'incomplete', rssi: -50, networkKey: netKey, missingCharacteristic: 'dataIn' });

    manager.start();
    await expect(clock.advance(0)).resolves.toBeUndefined();

    expect(manager.getState()).toEqual({ status: 'unavailable', peripheralId: null });
    expect(bluetooth.connectCalls).toEqual(['incomplete']); // it DID try to connect -- discovery is what failed

    await clock.advance(1000); // backoff still applies to this failure mode
    expect(bluetooth.connectCalls).toEqual(['incomplete', 'incomplete']);
  });

  /** Review finding: `discoverBehavior`/`subscribeBehavior` existed on the
   *  fixture from the start (the brief explicitly lists failing a
   *  discovery or a subscribe among the fake's required capabilities) but
   *  nothing exercised them -- the corresponding `try`/`catch` paths in
   *  `runAttempt` were live code with no test ever taking them. */
  test('a node whose GATT discovery call itself fails (not just an incomplete result) fails the attempt and keeps trying', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey, discoverBehavior: 'fail' });

    manager.start();
    await clock.advance(0);
    expect(manager.getState()).toEqual({ status: 'unavailable', peripheralId: null });
    expect(bluetooth.connectCalls).toEqual(['A']);

    await clock.advance(1000); // the backoff schedule applies to this failure mode too
    expect(bluetooth.connectCalls).toEqual(['A', 'A']);
  });

  test('a node whose subscribe() call fails fails the attempt and keeps trying', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey, subscribeBehavior: 'fail' });

    manager.start();
    await clock.advance(0);
    expect(manager.getState()).toEqual({ status: 'unavailable', peripheralId: null });
    expect(bluetooth.connectCalls).toEqual(['A']);

    await clock.advance(1000);
    expect(bluetooth.connectCalls).toEqual(['A', 'A']);
  });
});

describe('epoch guards against stale or superseded port callbacks', () => {
  /**
   * Review finding: the earlier report disclosed this guard as untested
   * but reasoned it was unreachable through the fixture's public surface.
   * That conclusion was wrong -- a hand-written stub port that captures
   * the `onDisconnect` callback (the same technique already used for the
   * buffer-retention test above) reaches it directly in about twenty-five
   * lines.
   */
  test('a stale disconnect callback from a superseded connection attempt does not disturb the current connection', async () => {
    const netKey = randomBytes(16);
    const serviceData = Buffer.concat([Buffer.from([0x00]), k3(netKey)]);
    const disconnectCallbacks: Array<() => void> = [];
    const port: BluetoothPort = {
      scan: async (): Promise<ScanResult[]> => [{ peripheralId: 'A', rssi: -50, serviceData: [{ serviceUuid: MESH_PROXY_SERVICE_UUID, data: serviceData }] }],
      connect: async (_id, onDisconnect): Promise<unknown> => {
        disconnectCallbacks.push(onDisconnect);
        return {};
      },
      discover: async (): Promise<DiscoveredCharacteristic[]> => [
        { serviceUuid: MESH_PROXY_SERVICE_UUID, characteristicUuid: MESH_PROXY_DATA_IN_UUID, handle: {} },
        { serviceUuid: MESH_PROXY_SERVICE_UUID, characteristicUuid: MESH_PROXY_DATA_OUT_UUID, handle: {} },
      ],
      read: async (): Promise<Buffer> => Buffer.alloc(0),
      write: async (): Promise<void> => {},
      subscribe: async (): Promise<Subscription> => ({ unsubscribe: (): void => {} }),
      disconnect: async (): Promise<void> => {},
    };
    const clock = createFakeClock();
    const manager = new ProxyConnectionManager(port, clock, netKey);

    manager.start();
    await clock.advance(0); // first connection: callback #0 captured
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });

    const staleCallback = disconnectCallbacks[0]!;
    staleCallback(); // a GENUINE disconnect: triggers migration
    await clock.advance(0); // reconnects: callback #1 captured, a newer generation

    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });
    expect(disconnectCallbacks).toHaveLength(2);

    staleCallback(); // the SAME, now-stale callback fires again -- a late/duplicate port event

    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' }); // unaffected
  });

  /**
   * The sibling the review found and this report did not: `stop()` bumps
   * the exact same epoch counter, and was equally unpinned. Without it, an
   * in-flight attempt that happens to complete AFTER `stop()` was called
   * would leave the manager believing it is connected.
   */
  test('stop() invalidates an in-flight attempt: completing after stop does not leave the manager believing it is connected', async () => {
    const netKey = randomBytes(16);
    const serviceData = Buffer.concat([Buffer.from([0x00]), k3(netKey)]);
    let resolveConnect: (() => void) | null = null;
    let disconnectCalls = 0;
    const port: BluetoothPort = {
      scan: async (): Promise<ScanResult[]> => [{ peripheralId: 'A', rssi: -50, serviceData: [{ serviceUuid: MESH_PROXY_SERVICE_UUID, data: serviceData }] }],
      connect: (): Promise<unknown> =>
        new Promise((resolve) => {
          resolveConnect = (): void => resolve({});
        }),
      discover: async (): Promise<DiscoveredCharacteristic[]> => [
        { serviceUuid: MESH_PROXY_SERVICE_UUID, characteristicUuid: MESH_PROXY_DATA_IN_UUID, handle: {} },
        { serviceUuid: MESH_PROXY_SERVICE_UUID, characteristicUuid: MESH_PROXY_DATA_OUT_UUID, handle: {} },
      ],
      read: async (): Promise<Buffer> => Buffer.alloc(0),
      write: async (): Promise<void> => {},
      subscribe: async (): Promise<Subscription> => ({ unsubscribe: (): void => {} }),
      disconnect: async (): Promise<void> => {
        disconnectCalls += 1;
      },
    };
    const clock = createFakeClock();
    const manager = new ProxyConnectionManager(port, clock, netKey);

    manager.start();
    await clock.advance(0); // scan completes, connect() is called and left pending

    manager.stop(); // epoch bumped while connect() is still in flight
    expect(manager.getState()).toEqual({ status: 'unavailable', peripheralId: null });

    resolveConnect!(); // let the now-stale attempt's connect() resolve
    await new Promise((resolve) => setImmediate(resolve)); // flush its discover()/subscribe() continuation

    expect(manager.getState()).toEqual({ status: 'unavailable', peripheralId: null }); // still -- not 'connected'
    expect(disconnectCalls).toBe(1); // the now-unwanted connection was cleaned up, not left open
  });
});

describe('write and notifications', () => {
  test('write() rejects, naming why, when nothing is connected', async () => {
    const { manager } = setUp(randomBytes(16));

    await expect(manager.write(Buffer.from([0x01]))).rejects.toThrow(
      'ProxyConnectionManager.write: no active proxy connection',
    );
  });

  test('write() resolves even when the port silently drops it -- Write Without Response gives no acknowledgement either way', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey, dropWrites: true });
    manager.start();
    await clock.advance(0);

    await expect(manager.write(Buffer.from([0xaa, 0xbb]))).resolves.toBeUndefined();
    expect(bluetooth.writesReceived).toEqual([]);
  });

  test('write() forwards to the port when the connection accepts it, targeting the Data In characteristic specifically', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    await manager.write(Buffer.from([0x01, 0x02, 0x03]));

    expect(bluetooth.writesReceived).toHaveLength(1);
    expect(bluetooth.writesReceived[0]?.peripheralId).toBe('A');
    expect(bluetooth.writesReceived[0]?.data.toString('hex')).toBe('010203');
    // Review finding: a prior version of this fixture/test could not tell
    // "wrote to A" apart from "wrote to the wrong characteristic on A" --
    // swapping the Data In handle for the Data Out handle in connection.ts
    // passed this test unchanged. Pinning the characteristic, not just the
    // peripheral, is what Table 7.15's Write-Without-Response/Notify split
    // actually requires: writing commands into the NOTIFY characteristic
    // does nothing on real hardware.
    expect(bluetooth.writesReceived[0]?.characteristicUuid).toBe(MESH_PROXY_DATA_IN_UUID);
  });

  test('the scan duration the module requests is actually observed by the port, not silently ignored', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    manager.start();
    await clock.advance(0);

    expect(bluetooth.scanDurationsRequested.length).toBeGreaterThan(0);
    for (const duration of bluetooth.scanDurationsRequested) {
      expect(duration).toBe(SCAN_DURATION_MS);
    }
  });

  /**
   * A minimal hand-written stub port, not the full fake -- the fake's OWN
   * `write()` already copies its `data` argument (see fakeBluetooth.ts),
   * which would launder away a missing copy in connection.ts itself (the
   * same reasoning store.test.ts's AliasingSettingsPort is built on, for
   * the same reason). This stub captures exactly the reference it was
   * given, with no copy of its own, so only connection.ts's OWN defensive
   * copy (the global "never retain a view into a buffer it does not own"
   * rule) can make the assertions below pass.
   */
  test('write() never retains a view into the caller-supplied buffer', async () => {
    const netKey = randomBytes(16);
    const serviceData = Buffer.concat([Buffer.from([0x00]), k3(netKey)]);
    let captured: Buffer | null = null;
    const stub: BluetoothPort = {
      scan: async (): Promise<ScanResult[]> => [{ peripheralId: 'A', rssi: -50, serviceData: [{ serviceUuid: MESH_PROXY_SERVICE_UUID, data: serviceData }] }],
      connect: async (): Promise<unknown> => ({}),
      discover: async (): Promise<DiscoveredCharacteristic[]> => [
        { serviceUuid: MESH_PROXY_SERVICE_UUID, characteristicUuid: MESH_PROXY_DATA_IN_UUID, handle: {} },
        { serviceUuid: MESH_PROXY_SERVICE_UUID, characteristicUuid: MESH_PROXY_DATA_OUT_UUID, handle: {} },
      ],
      read: async (): Promise<Buffer> => Buffer.alloc(0),
      write: async (_characteristic, data): Promise<void> => {
        captured = data; // deliberately no copy -- the point of this stub
      },
      subscribe: async (): Promise<Subscription> => ({ unsubscribe: (): void => {} }),
      disconnect: async (): Promise<void> => {},
    };
    const clock = createFakeClock();
    const manager = new ProxyConnectionManager(stub, clock, netKey);
    manager.start();
    await clock.advance(0);

    const original = Buffer.from([0x01, 0x02, 0x03]);
    await manager.write(original);

    expect(captured).not.toBeNull();
    expect(captured).not.toBe(original); // a distinct Buffer instance...
    expect((captured as unknown as Buffer).equals(original)).toBe(true); // ...with the same bytes

    original.fill(0xff); // mutate the CALLER's own buffer after the call returns
    expect((captured as unknown as Buffer).equals(Buffer.from([0x01, 0x02, 0x03]))).toBe(true); // unaffected
  });

  test('a Data Out notification is delivered to a registered listener', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    const received: Buffer[] = [];
    manager.onNotification((data) => received.push(data));
    bluetooth.simulateNotification('A', Buffer.from([0x05, 0x06]));

    expect(received).toHaveLength(1);
    expect(received[0]?.toString('hex')).toBe('0506');
  });

  test('unsubscribing stops further delivery to that listener', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    const received: Buffer[] = [];
    const unsubscribe = manager.onNotification((data) => received.push(data));
    bluetooth.simulateNotification('A', Buffer.from([0x01]));
    unsubscribe();
    bluetooth.simulateNotification('A', Buffer.from([0x02]));

    expect(received).toHaveLength(1);
    expect(received[0]?.toString('hex')).toBe('01');
  });

  test('a listener cannot corrupt what another listener (or a later notification) receives by mutating its own copy', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    const secondListenerReceived: Buffer[] = [];
    manager.onNotification((data) => data.fill(0)); // mutates its own copy
    manager.onNotification((data) => secondListenerReceived.push(data));
    bluetooth.simulateNotification('A', Buffer.from([0x07, 0x08]));

    expect(secondListenerReceived[0]?.toString('hex')).toBe('0708'); // unaffected by the first listener's mutation
  });
});

describe('gaps found while writing this suite, beyond the brief\'s own list', () => {
  test('write() rejects immediately after an unexpected disconnect, before the next reconnect completes', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);
    expect(manager.getState().status).toBe('connected');

    // Make the node unreachable too, so the rescan that follows the
    // disconnect does not immediately reconnect and mask a stale `active`
    // reference with a fresh, legitimate one.
    bluetooth.setAdvertising('A', false);
    bluetooth.simulateDisconnect('A');

    await expect(manager.write(Buffer.from([0x01]))).rejects.toThrow(
      'ProxyConnectionManager.write: no active proxy connection',
    );
  });

  test('a successful connection does not schedule a further scan while it stays connected', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);
    expect(bluetooth.scanCallCount()).toBe(1);

    await clock.advance(1_000_000); // far past any backoff delay this module uses
    expect(bluetooth.scanCallCount()).toBe(1); // still just the one scan that found A
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });
  });

  test('a Network ID-shaped advertisement with the right type but the wrong length is never selected', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    // Right identification type (0x00) but only 4 octets of "Network ID"
    // instead of Table 7.11's 8 -- a truncated or corrupted advertisement,
    // not a different network's identity, and still not ours to trust.
    bluetooth.addNode({ id: 'short', rssi: -10, serviceDataOverride: Buffer.concat([Buffer.from([0x00]), randomBytes(4)]) });
    bluetooth.addNode({ id: 'ours', rssi: -60, networkKey: netKey });

    manager.start();
    await clock.advance(0);

    expect(bluetooth.connectCalls).toEqual(['ours']);
  });
});

describe('stop', () => {
  /**
   * Review finding: `fakeBluetooth`'s own `disconnect()` already clears its
   * notify callbacks, which would launder away a missing explicit
   * `subscription.unsubscribe()` call in connection.ts's own `stop()` --
   * the same reasoning behind the buffer-retention stub above. This stub's
   * `disconnect()` deliberately does nothing on its own, so only
   * connection.ts's own call can make the assertion pass.
   */
  test("stop() calls the active subscription's own unsubscribe(), not just the port's disconnect()", async () => {
    const netKey = randomBytes(16);
    const serviceData = Buffer.concat([Buffer.from([0x00]), k3(netKey)]);
    let unsubscribeCalled = false;
    const port: BluetoothPort = {
      scan: async (): Promise<ScanResult[]> => [{ peripheralId: 'A', rssi: -50, serviceData: [{ serviceUuid: MESH_PROXY_SERVICE_UUID, data: serviceData }] }],
      connect: async (): Promise<unknown> => ({}),
      discover: async (): Promise<DiscoveredCharacteristic[]> => [
        { serviceUuid: MESH_PROXY_SERVICE_UUID, characteristicUuid: MESH_PROXY_DATA_IN_UUID, handle: {} },
        { serviceUuid: MESH_PROXY_SERVICE_UUID, characteristicUuid: MESH_PROXY_DATA_OUT_UUID, handle: {} },
      ],
      read: async (): Promise<Buffer> => Buffer.alloc(0),
      write: async (): Promise<void> => {},
      subscribe: async (): Promise<Subscription> => ({
        unsubscribe: (): void => {
          unsubscribeCalled = true;
        },
      }),
      disconnect: async (): Promise<void> => {}, // deliberately does nothing on its own
    };
    const clock = createFakeClock();
    const manager = new ProxyConnectionManager(port, clock, netKey);
    manager.start();
    await clock.advance(0);

    manager.stop();

    expect(unsubscribeCalled).toBe(true);
  });

  test('stop() tears down an active connection and schedules no further attempts', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);
    expect(manager.getState().status).toBe('connected');

    manager.stop();

    expect(manager.getState()).toEqual({ status: 'unavailable', peripheralId: null });
    // The port's own connection bookkeeping was torn down -- simulating a
    // disconnect on it now is a misconfigured-test error, proving `stop()`
    // actually called the port's `disconnect`, not just forgot about it
    // locally.
    expect(() => bluetooth.simulateDisconnect('A')).toThrow('"A" is not currently connected');

    await clock.advance(1_000_000);
    expect(bluetooth.scanCallCount()).toBe(1); // no further attempt was ever scheduled
  });
});

/**
 * Review finding: `FakeBluetoothPort` has configuration surface this
 * task's own manager never exercises on its own (it never calls `read`,
 * never calls `removeNode`/`setRssi` through any behaviour the manager
 * triggers). Rather than leave them live but untested, each gets a direct,
 * fixture-level smoke test here -- these are tests of the FIXTURE, not of
 * `ProxyConnectionManager`, and are expected to matter once the traffic
 * queue (reads a capability) and the pairing flow (dynamic signal
 * strength during a pairing scan) actually call them through the manager
 * or its successors.
 */
describe('fixture coverage: fakeBluetooth capabilities this task does not itself exercise through the manager', () => {
  test('removeNode: a removed node no longer appears in scan results', async () => {
    const bluetooth = new FakeBluetoothPort();
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: randomBytes(16) });
    expect(await bluetooth.scan(0)).toHaveLength(1);

    bluetooth.removeNode('A');
    expect(await bluetooth.scan(0)).toHaveLength(0);
  });

  test('setRssi: changes what subsequent scans report for that node', async () => {
    const bluetooth = new FakeBluetoothPort();
    bluetooth.addNode({ id: 'A', rssi: -70, networkKey: randomBytes(16) });
    expect((await bluetooth.scan(0))[0]?.rssi).toBe(-70);

    bluetooth.setRssi('A', -30);
    expect((await bluetooth.scan(0))[0]?.rssi).toBe(-30);
  });

  test('read()/setReadValue(): a configured value is returned to a connected reader; an unconfigured one defaults to empty', async () => {
    const bluetooth = new FakeBluetoothPort();
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: randomBytes(16) });
    const connection = await bluetooth.connect('A', () => {});
    const characteristics = await bluetooth.discover(connection);
    const dataIn = characteristics.find((c) => c.characteristicUuid === MESH_PROXY_DATA_IN_UUID)!;

    expect((await bluetooth.read(dataIn.handle)).length).toBe(0); // unconfigured: empty, not an error

    bluetooth.setReadValue('A', MESH_PROXY_DATA_IN_UUID, Buffer.from([0xaa, 0xbb]));
    expect((await bluetooth.read(dataIn.handle)).toString('hex')).toBe('aabb');
  });

  test('read() rejects once the peripheral is no longer connected', async () => {
    const bluetooth = new FakeBluetoothPort();
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: randomBytes(16) });
    const connection = await bluetooth.connect('A', () => {});
    const characteristics = await bluetooth.discover(connection);
    const dataIn = characteristics.find((c) => c.characteristicUuid === MESH_PROXY_DATA_IN_UUID)!;
    await bluetooth.disconnect(connection);

    await expect(bluetooth.read(dataIn.handle)).rejects.toThrow('is not connected');
  });
});

/**
 * `findServiceData` is new in task 6 (the SCAN RESULT SHAPE generalisation
 * — see connection.ts's own module header): every OTHER test in this file
 * only ever gives a `ScanResult` ONE service data entry, so a version that
 * ignored `serviceUuid` entirely and returned whichever entry came first
 * would still pass every one of them — measured, not assumed (see the
 * task 6 report). A result carrying TWO entries, for TWO DIFFERENT service
 * UUIDs, is the only fixture that can tell "found the right one" apart
 * from "found a thing".
 */
describe('findServiceData', () => {
  const proxyData = Buffer.from([0xaa, 0xaa]);
  const provisioningData = Buffer.from([0xbb, 0xbb]);
  const result: ScanResult = {
    peripheralId: 'A',
    rssi: -50,
    serviceData: [
      { serviceUuid: MESH_PROXY_SERVICE_UUID, data: proxyData },
      { serviceUuid: MESH_PROVISIONING_SERVICE_UUID, data: provisioningData },
    ],
  };

  test('returns the entry matching the requested service UUID, not merely the first one present', () => {
    // Asking for the SECOND-listed service first: a "return entry 0
    // regardless" bug would fail this specific call even though the proxy
    // one (entry 0) would still look right by coincidence.
    expect(findServiceData(result, MESH_PROVISIONING_SERVICE_UUID)).toEqual(provisioningData);
    expect(findServiceData(result, MESH_PROXY_SERVICE_UUID)).toEqual(proxyData);
  });

  test('returns null for a service UUID not present at all', () => {
    expect(findServiceData(result, 0x1234)).toBeNull();
  });

  test('returns null for an empty serviceData array', () => {
    expect(findServiceData({ peripheralId: 'A', rssi: -50, serviceData: [] }, MESH_PROXY_SERVICE_UUID)).toBeNull();
  });
});
