import { randomBytes } from 'node:crypto';
import { k3 } from '../../mesh/crypto/derive';
import {
  ProxyConnectionManager,
  MESH_PROXY_SERVICE_UUID,
  MESH_PROXY_DATA_IN_UUID,
  MESH_PROXY_DATA_OUT_UUID,
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
    Buffer.from([0x16]), // AD Type: Service Data - 16-bit UUID
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
   */
  test('a node advertising Node Identity (type 0x01) rather than Network ID is never selected', async () => {
    const ourKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(ourKey);
    // Same 8-octet length as a real Network ID, only the type octet
    // differs -- so a selection bug that checks length but not type would
    // still pass this unless this specific case is exercised.
    bluetooth.addNode({
      id: 'node-identity',
      rssi: -10,
      serviceDataOverride: Buffer.concat([Buffer.from([0x01]), randomBytes(8)]),
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

  test('write() forwards to the port when the connection accepts it', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    await manager.write(Buffer.from([0x01, 0x02, 0x03]));

    expect(bluetooth.writesReceived).toHaveLength(1);
    expect(bluetooth.writesReceived[0]?.peripheralId).toBe('A');
    expect(bluetooth.writesReceived[0]?.data.toString('hex')).toBe('010203');
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
      scan: async (): Promise<ScanResult[]> => [{ peripheralId: 'A', rssi: -50, proxyServiceData: serviceData }],
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
