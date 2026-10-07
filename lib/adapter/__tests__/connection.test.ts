import { randomBytes } from 'node:crypto';
import { k3 } from '../../mesh/crypto/derive';
import {
  ProxyConnectionManager,
  MESH_PROXY_SERVICE_UUID,
  MESH_PROXY_DATA_IN_UUID,
  MESH_PROXY_DATA_OUT_UUID,
  MESH_PROVISIONING_SERVICE_UUID,
  MAX_PROXY_PDU_LENGTH,
  PROXY_WRITE_TIMEOUT_MS,
  SCAN_DURATION_MS,
  findServiceData,
  type BluetoothPort,
  type ScanResult,
  type DiscoveredCharacteristic,
  type Subscription,
} from '../connection';
import { FakeBluetoothPort } from './fakeBluetooth';
import { createFakeClock } from './fakeClock';
import { PROXY_SAR_TIMEOUT_MS } from '../../mesh/packet/proxyPdu';
import { DEFAULT_TIMEOUT_MS } from '../queue';
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

  /**
   * REVIEW FINDING (final wave): the identity comparison itself was
   * weakenable three ways with the whole suite green — compare only
   * `serviceData[1]`, compare only a leading PREFIX, or relax the length
   * check to `>=` — because the one negative case above ("a foreign
   * network") uses a WHOLLY DIFFERENT key, whose derived Network ID
   * differs in essentially every byte. A test that a single-byte
   * comparison already passes cannot be the thing protecting this check.
   *
   * TWO near misses are needed, not one, because the two weakenings differ
   * in WHERE they stop looking, and each is built from our own genuine
   * Network ID with the correct identification type and the correct length:
   *   - `head-match` shares the LEADING byte and differs from the second
   *     octet onward, so a comparison that stops after one byte accepts it;
   *   - `tail-differs` is our Network ID with only its LAST byte changed, so
   *     any comparison over a prefix — of any length short of the whole —
   *     accepts it.
   * Both were MEASURED: before `tail-differs` existed, replacing the check
   * with a four-octet prefix comparison passed the entire suite.
   *
   * The length check is a different story, recorded honestly rather than
   * padded with a test that cannot fail: relaxing `!==` to `<` is
   * BEHAVIOUR-PRESERVING here, because `Buffer.equals` compares lengths
   * too, so an over-long advertisement is rejected by the byte comparison
   * whether or not the length check ran. `too-long` below is kept as the
   * case that shows that, not as a pin on the length check itself.
   *
   * This is the design's own explicit neighbour-protection clause ("checks
   * that the advertised network identity derives from *our* network key so
   * a neighbour's installation can never be mistaken for ours"), held by
   * cases that can actually discriminate.
   */
  test('near-miss identities — one sharing our leading byte, one differing only in its last — are both rejected', async () => {
    const ourKey = randomBytes(16);
    const ourNetworkId = k3(ourKey);

    const headMatch = Buffer.from(ourNetworkId);
    for (let i = 1; i < headMatch.length; i += 1) headMatch[i] = (headMatch[i] as number) ^ 0xff;
    expect(headMatch[0]).toBe(ourNetworkId[0]);
    expect(headMatch.equals(ourNetworkId)).toBe(false);

    const tailDiffers = Buffer.from(ourNetworkId);
    const last = tailDiffers.length - 1;
    tailDiffers[last] = (tailDiffers[last] as number) ^ 0xff;
    expect(tailDiffers.subarray(0, last).equals(ourNetworkId.subarray(0, last))).toBe(true);
    expect(tailDiffers.equals(ourNetworkId)).toBe(false);

    const { bluetooth, clock, manager } = setUp(ourKey);
    // Both stronger than the genuine node, so either one being accepted
    // changes which peripheral is connected to.
    bluetooth.addNode({
      id: 'head-match',
      rssi: -10,
      serviceDataOverride: Buffer.concat([Buffer.from([0x00]), headMatch]),
    });
    bluetooth.addNode({
      id: 'tail-differs',
      rssi: -12,
      serviceDataOverride: Buffer.concat([Buffer.from([0x00]), tailDiffers]),
    });
    bluetooth.addNode({
      id: 'too-long',
      rssi: -15,
      serviceDataOverride: Buffer.concat([Buffer.from([0x00]), ourNetworkId, Buffer.from([0x5a])]),
    });
    bluetooth.addNode({ id: 'ours', rssi: -60, networkKey: ourKey });

    manager.start();
    await clock.advance(0);

    expect(bluetooth.connectCalls).toEqual(['ours']);
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'ours' });
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

/**
 * THE PROXY PDU ENVELOPE, at the layer that actually drives the radio —
 * `lib/mesh/packet/__tests__/proxyPdu.test.ts` pins the bytes against the
 * transcribed tables; these pin that this module USES them, in both
 * directions, and that it does what Section 6.3.2.2 says when a peer
 * violates the protocol.
 *
 * The defect these close: every write this app made carried a BARE Network
 * PDU, and every notification was handed to listeners as if it were bare.
 * Both halves passed 889 tests, because the fake recorded whatever it was
 * given — which is why `fakeBluetooth.ts` now speaks the protocol too (see
 * its own module header).
 */
describe('the Proxy PDU envelope (Section 6.3 "Proxy PDU")', () => {
  test('a write that fits goes out as ONE Proxy PDU: SAR 0b00, MessageType 0x00 (Network PDU), then the PDU itself', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    await manager.write(Buffer.from([0xde, 0xad, 0xbe, 0xef]));

    // The literal header octet, written out rather than computed: Table 6.2
    // SAR 0b00 ("Data field contains a complete message") in the two most
    // significant bits, Table 6.3 MessageType 0x00 ("Network PDU") in the
    // remaining six.
    expect(bluetooth.rawWritesReceived.map((w) => w.data.toString('hex'))).toEqual(['00deadbeef']);
    // ...and the node reassembles it back to exactly what we asked to send.
    expect(bluetooth.writesReceived.map((w) => w.data.toString('hex'))).toEqual(['deadbeef']);
    expect(bluetooth.writesReceived[0]?.messageType).toBe(0x00);
  });

  test('a write larger than one Proxy PDU is segmented in order, filling every PDU but the last', async () => {
    const netKey = randomBytes(16);
    const bluetooth = new FakeBluetoothPort();
    const clock = createFakeClock();
    // A deliberately tiny PDU size so the segmentation is small enough to
    // write out byte for byte: 1 header octet + 3 data octets.
    const manager = new ProxyConnectionManager(bluetooth, clock, netKey, { maxProxyPduLength: 4 });
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    const message = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    await manager.write(message);

    expect(bluetooth.rawWritesReceived.map((w) => w.data.toString('hex'))).toEqual([
      '40010203', // 0b01_000000: first segment
      '80040506', // 0b10_000000: continuation segment
      'c007', //     0b11_000000: last segment, not filled
    ]);
    // Every segment went to the Data In characteristic, not the notify one.
    for (const write of bluetooth.rawWritesReceived) {
      expect(write.characteristicUuid).toBe(MESH_PROXY_DATA_IN_UUID);
    }
    // The node's own reassembly produces exactly the message we handed in —
    // one logical message, not three.
    expect(bluetooth.writesReceived.map((w) => w.data.toString('hex'))).toEqual([message.toString('hex')]);
  });

  test('a message arriving in several notifications reaches the listener ONCE, whole', async () => {
    const netKey = randomBytes(16);
    const bluetooth = new FakeBluetoothPort();
    const clock = createFakeClock();
    const manager = new ProxyConnectionManager(bluetooth, clock, netKey, { maxProxyPduLength: 4 });
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    const received: Buffer[] = [];
    manager.onNotification((data) => received.push(data));

    // Three raw PDUs on the wire, each one its own notification.
    bluetooth.simulateRawNotification('A', Buffer.from([0x40, 0x11, 0x22]));
    expect(received).toHaveLength(0); // nothing delivered mid-message
    bluetooth.simulateRawNotification('A', Buffer.from([0x80, 0x33, 0x44]));
    expect(received).toHaveLength(0);
    bluetooth.simulateRawNotification('A', Buffer.from([0xc0, 0x55]));

    expect(received.map((b) => b.toString('hex'))).toEqual(['1122334455']);
  });

  test('a notification that is not a Network PDU (a mesh beacon) is never delivered to a listener', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    const received: Buffer[] = [];
    manager.onNotification((data) => received.push(data));
    // 0b00_000001: a complete message of MessageType 0x01, "Mesh Beacon"
    // (Table 6.3) — legal on this characteristic, and consumed by nothing
    // in this app (see connection.ts's own IV INDEX note).
    bluetooth.simulateRawNotification('A', Buffer.from([0x01, 0xaa, 0xbb]));

    expect(received).toEqual([]);
    expect(manager.getState().status).toBe('connected'); // ignored, not disconnected over
  });

  test('an unexpected SAR value disconnects the link and rescans, naming why (Section 6.3.2.2)', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });

    const received: Buffer[] = [];
    manager.onNotification((data) => received.push(data));
    // 0b10_000000: a continuation segment with nothing being reassembled.
    bluetooth.simulateRawNotification('A', Buffer.from([0x80, 0x01]));

    expect(manager.getState()).toEqual({ status: 'unavailable', peripheralId: null });
    expect(manager.getLastProxyProtocolDisconnect()).toMatch(/unexpected SAR value 0b10/);
    expect(received).toEqual([]);

    // Recoverable, not terminal: the rescan brings the link back — after
    // this path's OWN backoff, which is no longer zero (final re-review,
    // finding 4: a protocol violation repeats on every reconnection, so it
    // escalates rather than looping at scan speed).
    await clock.advance(1000);
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });
  });

  test('a reassembly that simply stops arriving disconnects after the 20-second SAR timeout', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    bluetooth.simulateRawNotification('A', Buffer.from([0x40, 0x11])); // a first segment, then silence

    await clock.advance(PROXY_SAR_TIMEOUT_MS - 1);
    expect(manager.getState().status).toBe('connected'); // still waiting, correctly

    await clock.advance(1);
    expect(manager.getLastProxyProtocolDisconnect()).toMatch(/SAR transfer timed out/);
    expect(manager.getState().status).toBe('unavailable'); // the link really was dropped
    // The rescan it schedules waits out this path's own backoff first
    // (finding 4), so the second connect attempt is one delay away rather
    // than on the same tick.
    expect(bluetooth.connectCalls).toEqual(['A']);
    await clock.advance(1000);
    expect(bluetooth.connectCalls).toEqual(['A', 'A']);
  });

  test('a completed message cancels the SAR timeout rather than leaving it to fire later', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    bluetooth.simulateRawNotification('A', Buffer.from([0x40, 0x11]));
    bluetooth.simulateRawNotification('A', Buffer.from([0xc0, 0x22]));

    await clock.advance(PROXY_SAR_TIMEOUT_MS * 2);
    expect(manager.getLastProxyProtocolDisconnect()).toBeNull();
    expect(bluetooth.connectCalls).toEqual(['A']); // never dropped, never re-attempted
  });

  test('a disconnection abandons a half-arrived message rather than carrying it into the next link', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    bluetooth.simulateRawNotification('A', Buffer.from([0x40, 0x11])); // first segment, then the link drops
    bluetooth.simulateDisconnect('A');
    await clock.advance(0); // reconnects

    const received: Buffer[] = [];
    manager.onNotification((data) => received.push(data));
    // On the NEW link, a fresh complete message. If the old reassembly had
    // survived, this would be "a complete message mid-reassembly" and the
    // manager would disconnect over it instead of delivering it.
    bluetooth.simulateRawNotification('A', Buffer.from([0x00, 0x99]));

    expect(received.map((b) => b.toString('hex'))).toEqual(['99']);
    expect(manager.getLastProxyProtocolDisconnect()).toBeNull();
  });

  test('a second segmented write while one is still in flight is refused rather than interleaved', async () => {
    const netKey = randomBytes(16);
    const bluetooth = new FakeBluetoothPort();
    const clock = createFakeClock();
    const manager = new ProxyConnectionManager(bluetooth, clock, netKey, { maxProxyPduLength: 4 });
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);
    bluetooth.setWriteBehavior('A', 'hold');

    const first = manager.write(Buffer.from([0x01, 0x02, 0x03, 0x04]));
    const firstRejection = expect(first).rejects.toThrow(/held/); // settled at the end of this test
    await Promise.resolve();

    await expect(manager.write(Buffer.from([0x05, 0x06, 0x07, 0x08]))).rejects.toThrow(
      /a segmented Proxy PDU write is already in flight/,
    );
    // The held message's own first segment is the only thing on the wire —
    // no segment of the second message got in between.
    expect(bluetooth.rawWritesReceived.map((w) => w.data.toString('hex'))).toEqual(['40010203']);

    bluetooth.releaseWrite('A', 0, { ok: false, err: new Error('held write abandoned') });
    await firstRejection;
  });

  test('a single-PDU write is never refused, however many are already pending', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);
    bluetooth.setWriteBehavior('A', 'hold');

    const a = manager.write(Buffer.from([0x01]));
    const b = manager.write(Buffer.from([0x02]));
    const settled = Promise.all([
      expect(a).rejects.toThrow('abandoned a'),
      expect(b).rejects.toThrow('abandoned b'),
    ]);
    await Promise.resolve();

    expect(bluetooth.rawWritesReceived.map((w) => w.data.toString('hex'))).toEqual(['0001', '0002']);
    bluetooth.releaseWrite('A', 0, { ok: false, err: new Error('abandoned a') });
    bluetooth.releaseWrite('A', 1, { ok: false, err: new Error('abandoned b') });
    await settled;
  });

  test('rejects a maxProxyPduLength that leaves no room for Data, naming it', () => {
    const bluetooth = new FakeBluetoothPort();
    const clock = createFakeClock();
    expect(() => new ProxyConnectionManager(bluetooth, clock, randomBytes(16), { maxProxyPduLength: 1 })).toThrow(
      'ProxyConnectionManager: maxProxyPduLength must be an integer >= 2, got 1',
    );
  });

  test('MAX_PROXY_PDU_LENGTH is the documented conservative floor, and is what the manager uses by default', async () => {
    expect(MAX_PROXY_PDU_LENGTH).toBe(20);

    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    // Exactly one octet more than the default allows in a single PDU, so
    // the default itself is what decides this is two writes rather than one.
    await manager.write(Buffer.alloc(MAX_PROXY_PDU_LENGTH, 0x7e));
    expect(bluetooth.rawWritesReceived).toHaveLength(2);
    expect(bluetooth.rawWritesReceived[0]?.data).toHaveLength(MAX_PROXY_PDU_LENGTH);
  });
});

/**
 * FINAL RE-REVIEW, FINDING 1 (HIGH). `segmentedWriteInFlight` was set
 * before the segment loop and cleared in exactly one place — that loop's
 * `finally`. A single `bluetooth.write` that never settled therefore
 * latched it for the lifetime of the process: the `finally` never ran, and
 * every later segmented write was refused. "Later segmented write" means
 * EVERY later message: at `MAX_PROXY_PDU_LENGTH` = 20 the largest message
 * that fits one Proxy PDU is 19 octets, and the smallest Network PDU this
 * app builds is 20 (Table 3.10's 9 octets of header + a 7-octet
 * TransportPDU + a 4-octet NetMIC, for a Get). Nothing cleared it either —
 * not `stop()`, not a disconnect, not a reconnect.
 *
 * The fix has two halves and each is pinned separately below, because
 * either one alone leaves a real failure standing: the TIMEOUT bounds a
 * write that hangs while the link stays up, and the TEARDOWN RESET covers
 * a write still pending when the link goes away (which no timeout can
 * hurry, since the fixture — like a real stack that loses a peripheral
 * mid-write — never settles it at all).
 */
describe('a GATT write that never settles (final re-review, finding 1)', () => {
  /** A port that hangs every `write` while `hang.value` is true and
   *  records every buffer it was handed. Hand-written rather than
   *  `FakeBluetoothPort` on purpose: the fake models a real node's Proxy
   *  PDU SERVER too, so after an abandoned first segment it correctly
   *  refuses the next message's first segment (Section 6.3.2.2) — true to
   *  hardware, and it would make this test prove the fixture's behaviour
   *  rather than the manager's. What is under test here is only whether
   *  the MANAGER is still willing to write. */
  function hangingWritePort(
    netKey: Buffer,
    hang: { value: boolean },
    written: Buffer[],
  ): BluetoothPort {
    const serviceData = Buffer.concat([Buffer.from([0x00]), k3(netKey)]);
    return {
      scan: async (): Promise<ScanResult[]> => [
        { peripheralId: 'A', rssi: -50, serviceData: [{ serviceUuid: MESH_PROXY_SERVICE_UUID, data: serviceData }] },
      ],
      connect: async (): Promise<unknown> => ({}),
      discover: async (): Promise<DiscoveredCharacteristic[]> => [
        { serviceUuid: MESH_PROXY_SERVICE_UUID, characteristicUuid: MESH_PROXY_DATA_IN_UUID, handle: {} },
        { serviceUuid: MESH_PROXY_SERVICE_UUID, characteristicUuid: MESH_PROXY_DATA_OUT_UUID, handle: {} },
      ],
      read: async (): Promise<Buffer> => Buffer.alloc(0),
      write: async (_characteristic, data): Promise<void> => {
        written.push(Buffer.from(data));
        if (hang.value) await new Promise<void>(() => {}); // never settles
      },
      subscribe: async (): Promise<Subscription> => ({ unsubscribe: (): void => {} }),
      disconnect: async (): Promise<void> => {},
    };
  }

  /** One full macrotask turn, which Node only reaches once every microtask
   *  queued behind it has drained — the same technique fakeClock's own
   *  `advance` uses internally, needed here when a test must observe a
   *  multi-`await` chain reaching a particular point BEFORE virtual time
   *  moves. */
  function flushMicrotasks(): Promise<void> {
    return new Promise((resolve) => setImmediate(resolve));
  }

  test('is bounded rather than latched: the hung write rejects, and the NEXT message still goes out', async () => {
    const netKey = randomBytes(16);
    const hang = { value: true };
    const written: Buffer[] = [];
    const clock = createFakeClock();
    const manager = new ProxyConnectionManager(hangingWritePort(netKey, hang, written), clock, netKey);
    manager.start();
    await clock.advance(0);

    // 20 octets: one octet past what a single Proxy PDU can carry at the
    // default maxProxyPduLength, so this takes the segmented path — as
    // every real message does.
    const first = manager.write(Buffer.alloc(20, 0x11));
    const firstRejection = expect(first).rejects.toThrow(/timed out after/); // settled at the end of this test
    await Promise.resolve();
    expect(written).toHaveLength(1); // the first segment went out, and never came back

    await clock.advance(PROXY_WRITE_TIMEOUT_MS);
    await firstRejection;

    hang.value = false;
    await expect(manager.write(Buffer.alloc(20, 0x22))).resolves.toBeUndefined();
    // the abandoned segment, then BOTH segments of the second message
    expect(written).toHaveLength(3);
    expect(written[1]?.[0]).toBe(0x40); // 0b01_000000: first segment of the new message
    expect(written[2]?.[0]).toBe(0xc0); // 0b11_000000: its last segment
  });

  test('an unexpected disconnect clears the flag, so the reconnected link starts clean', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);
    bluetooth.setWriteBehavior('A', 'hold');

    const held = manager.write(Buffer.alloc(20, 0x11));
    held.catch(() => {}); // the fixture never settles a held write (its own documented gap)
    await Promise.resolve();

    bluetooth.simulateDisconnect('A');
    await clock.advance(0); // the ordinary rescan reconnects
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });

    // NO virtual time has passed, so the write timeout cannot be what
    // rescues this: only the teardown reset can.
    bluetooth.setWriteBehavior('A', 'succeed');
    await expect(manager.write(Buffer.alloc(20, 0x22))).resolves.toBeUndefined();
  });

  test('stop() clears the flag, so a restarted manager starts clean', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);
    bluetooth.setWriteBehavior('A', 'hold');

    const held = manager.write(Buffer.alloc(20, 0x11));
    held.catch(() => {});
    await Promise.resolve();

    manager.stop();
    manager.start();
    await clock.advance(0);
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });

    bluetooth.setWriteBehavior('A', 'succeed');
    await expect(manager.write(Buffer.alloc(20, 0x22))).resolves.toBeUndefined();
  });

  test('the specification-mandated disconnect clears the flag too', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);
    bluetooth.setWriteBehavior('A', 'hold');

    const held = manager.write(Buffer.alloc(20, 0x11));
    held.catch(() => {});
    await Promise.resolve();

    // 0b10_000000: a continuation segment with nothing being reassembled —
    // Section 6.3.2.2, "the Proxy PDU Client shall disconnect".
    bluetooth.simulateRawNotification('A', Buffer.from([0x80, 0x01]));
    expect(manager.getState().status).toBe('unavailable');
    await clock.advance(1000); // this path's own backoff, well short of the write timeout
    expect(manager.getState()).toEqual({ status: 'connected', peripheralId: 'A' });

    bluetooth.setWriteBehavior('A', 'succeed');
    await expect(manager.write(Buffer.alloc(20, 0x22))).resolves.toBeUndefined();
  });

  test('the bound names which Proxy PDU stalled, and is the injected one, not merely the default', async () => {
    const netKey = randomBytes(16);
    const hang = { value: true };
    const written: Buffer[] = [];
    const clock = createFakeClock();
    const manager = new ProxyConnectionManager(hangingWritePort(netKey, hang, written), clock, netKey, {
      proxyWriteTimeoutMs: 75,
    });
    manager.start();
    await clock.advance(0);

    const first = manager.write(Buffer.alloc(20, 0x11));
    const rejection = expect(first).rejects.toThrow(
      'ProxyConnectionManager.write: Proxy PDU 1 of 2 to the Mesh Proxy Data In characteristic: timed out after 75ms',
    );
    await Promise.resolve();

    await clock.advance(74);
    expect(written).toHaveLength(1); // still waiting, correctly
    await clock.advance(1);
    await rejection;
  });

  test('a SECOND segment that stalls names itself, not the first', async () => {
    const netKey = randomBytes(16);
    const written: Buffer[] = [];
    const hangAfterFirst = { value: false };
    const clock = createFakeClock();
    const port = hangingWritePort(netKey, hangAfterFirst, written);
    const manager = new ProxyConnectionManager(
      {
        ...port,
        write: async (characteristic, data): Promise<void> => {
          hangAfterFirst.value = written.length === 1; // hang on the second segment only
          await port.write(characteristic, data);
        },
      },
      clock,
      netKey,
      { proxyWriteTimeoutMs: 75 },
    );
    manager.start();
    await clock.advance(0);

    const first = manager.write(Buffer.alloc(20, 0x11));
    const rejection = expect(first).rejects.toThrow('Proxy PDU 2 of 2 to the Mesh Proxy Data In characteristic');
    // Both segments have to have actually reached the port before virtual
    // time moves, or the FIRST segment's own (about to be cancelled) timer
    // would still be pending when `advance` scans — a race in the test, not
    // in the module.
    await flushMicrotasks();
    expect(written).toHaveLength(2); // only the second never came back

    await clock.advance(75);
    await rejection;
  });

  test('rejects a proxyWriteTimeoutMs that is not a positive whole number of milliseconds, naming it', () => {
    const bluetooth = new FakeBluetoothPort();
    const clock = createFakeClock();
    expect(() => new ProxyConnectionManager(bluetooth, clock, randomBytes(16), { proxyWriteTimeoutMs: 0 })).toThrow(
      'ProxyConnectionManager: proxyWriteTimeoutMs must be an integer >= 1, got 0',
    );
  });

  /**
   * The relationship PROXY_WRITE_TIMEOUT_MS's own comment argues for, pinned
   * rather than left to two separately-chosen constants staying in
   * agreement. Every message is exactly two Proxy PDUs (see `write`'s own
   * comment), so one traffic-queue attempt can spend at most twice this
   * bound inside `write()`; if that ever reached the queue's own per-attempt
   * deadline, the retry would arrive while the previous attempt still held
   * the segmented-write flag and be refused — the exact failure the bound
   * exists to remove, reintroduced by arithmetic.
   */
  test('a whole two-segment message times out well inside one traffic-queue attempt', () => {
    expect(PROXY_WRITE_TIMEOUT_MS).toBe(2000);
    expect(PROXY_WRITE_TIMEOUT_MS * 2).toBeLessThan(DEFAULT_TIMEOUT_MS);
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
    // ...carrying the Proxy PDU envelope around those same bytes: SAR 0b00
    // (a complete message, Table 6.2) and MessageType 0x00 (Network PDU,
    // Table 6.3) pack to 0x00, followed by the Network PDU itself.
    expect((captured as unknown as Buffer).toString('hex')).toBe('00010203');

    original.fill(0xff); // mutate the CALLER's own buffer after the call returns
    expect((captured as unknown as Buffer).toString('hex')).toBe('00010203'); // unaffected
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

/**
 * FINAL RE-REVIEW, FINDING 4 (LOW). A disconnect this module performs
 * because the specification requires it (Section 6.3.2.2) was invisible and
 * instant: `getLastProxyProtocolDisconnect()` was read by nothing outside
 * this test file, and the reschedule used `backoffDelayMs(this.failureStreak)`
 * with a streak a successful connection had just reset to 0 — which is 0 ms.
 * A bulb whose proxy behaviour this module's (strict, defensible) reading of
 * "unexpected" rejects therefore produced an endless connect → violate →
 * disconnect → immediate rescan loop, paced only by SCAN_DURATION_MS, with
 * no growing delay and no line anywhere saying why.
 *
 * A protocol violation is not a transient. It will repeat on every
 * reconnection to the same node, which is exactly why it gets a streak of
 * its OWN rather than sharing `failureStreak`: that one is reset by a
 * successful CONNECTION, and connecting is precisely the part that keeps
 * working here. This one is reset by a message that actually completes —
 * the link demonstrably behaving — so a single odd PDU on an otherwise
 * healthy link decays, while a node that always violates escalates.
 */
describe('a specification-mandated disconnect is visible and backs off (final re-review, finding 4)', () => {
  function setUpLogging(netKey: Buffer): {
    bluetooth: FakeBluetoothPort;
    clock: ReturnType<typeof createFakeClock>;
    manager: ProxyConnectionManager;
    lines: string[];
  } {
    const bluetooth = new FakeBluetoothPort();
    const clock = createFakeClock();
    const lines: string[] = [];
    const manager = new ProxyConnectionManager(bluetooth, clock, netKey, { log: (message) => lines.push(message) });
    return { bluetooth, clock, manager, lines };
  }

  /** 0b10_000000: a continuation segment with nothing being reassembled. */
  function violate(bluetooth: FakeBluetoothPort, id: string): void {
    bluetooth.simulateRawNotification(id, Buffer.from([0x80, 0x01]));
  }

  test('is reported through the injected log, naming the node and the reason', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager, lines } = setUpLogging(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    violate(bluetooth, 'A');

    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/unexpected SAR value 0b10/);
    expect(lines[0]).toMatch(/A/);
    expect(lines[0]).toMatch(/1000/); // and when it will try again
  });

  test('nothing is logged on an ordinary, well-behaved link', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager, lines } = setUpLogging(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    bluetooth.simulateNotification('A', Buffer.from([0x11, 0x22]));
    bluetooth.simulateDisconnect('A'); // an ordinary drop is not a violation
    await clock.advance(0);

    expect(lines).toEqual([]);
  });

  test('repeated violations back off with increasing delay rather than rescanning instantly', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUpLogging(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    violate(bluetooth, 'A');
    await clock.advance(999);
    expect(manager.getState().status).toBe('unavailable'); // not yet
    await clock.advance(1);
    expect(manager.getState().status).toBe('connected');

    violate(bluetooth, 'A');
    await clock.advance(1999);
    expect(manager.getState().status).toBe('unavailable'); // the SECOND one waits twice as long
    await clock.advance(1);
    expect(manager.getState().status).toBe('connected');
  });

  test('a message that actually completes resets the escalation', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUpLogging(netKey);
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    violate(bluetooth, 'A');
    await clock.advance(1000);
    expect(manager.getState().status).toBe('connected');

    // The link works: a whole message arrives and is delivered.
    const received: Buffer[] = [];
    manager.onNotification((data) => received.push(data));
    bluetooth.simulateNotification('A', Buffer.from([0x11, 0x22]));
    expect(received).toHaveLength(1);

    violate(bluetooth, 'A');
    await clock.advance(999);
    expect(manager.getState().status).toBe('unavailable');
    await clock.advance(1);
    expect(manager.getState().status).toBe('connected'); // back to the FIRST delay, not the second
  });

  test('a manager given no log port at all works exactly the same, silently', async () => {
    const netKey = randomBytes(16);
    const { bluetooth, clock, manager } = setUp(netKey); // no `log` option
    bluetooth.addNode({ id: 'A', rssi: -50, networkKey: netKey });
    manager.start();
    await clock.advance(0);

    expect(() => violate(bluetooth, 'A')).not.toThrow();
    expect(manager.getLastProxyProtocolDisconnect()).toMatch(/unexpected SAR value 0b10/);
    await clock.advance(1000);
    expect(manager.getState().status).toBe('connected');
  });
});
