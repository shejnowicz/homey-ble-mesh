// The light driver's pairing flow (docs/superpowers/specs/2026-10-06-ble-
// mesh-provisioner-design.md, "The Homey layer" > "Pairing"): this is the
// ONE file in `drivers/light` that imports `homey` — everything it actually
// DOES (scanning, provisioning, the configuration exchange, capability
// mapping) is `./pairing.ts`'s job, pure and unit-tested without a hub (see
// `__tests__/pairing.test.ts`). This file only wires that pure logic to the
// real Homey APIs: a `BluetoothPort` over `this.homey.ble`, a `NetworkStore`
// over `this.homey.settings`, and a custom pairing view
// (`pair/list_devices.html`) talking to `onPair`'s two handlers below.
//
// THE SHARED NetworkStore, NOT A SECOND ONE (task 7 finding, fixed here as
// part of that task's own wiring responsibility). This file used to
// construct its OWN `NetworkStore` for pairing, which was harmless while
// nothing else in the app ever ran one at the same time — app.ts was a
// skeleton. Task 7 gives app.ts a LONG-LIVED `NetworkStore` that every
// device's ordinary commands allocate sequence numbers through for as long
// as the app runs. `NetworkStore`'s sequence allocator keeps its "next
// number" cursor IN MEMORY, loaded once at construction (store.ts's own
// module header) — if pairing kept constructing its own second instance
// (reading the SAME persisted ceiling independently), opening the pairing
// wizard while existing bulbs are already being controlled could hand out
// the SAME sequence number to two unrelated messages, which a receiving
// node's own replay protection would then treat as a replay and silently
// drop one of (see meshLight.ts's/device.ts's own identical note — this
// file is the other half of the same hazard). `onPair` below therefore
// reaches into `this.homey.app` for the one shared instance instead, the
// same in-process pattern device.ts uses, and tells the app to start the
// mesh connection (a no-op after the first time) the moment the FIRST
// pairing ever succeeds — see `ensureMeshStarted`'s own call site below.
//
// REAL BLUETOOTH ADAPTER, FIRST TIME IN THIS PROJECT. Every earlier task's
// `BluetoothPort` consumer (`lib/adapter/connection.ts`, `lib/adapter/
// queue.ts`) was only ever driven against `lib/adapter/__tests__/
// fakeBluetooth.ts` — nothing in this repository before this file has
// wired the port to `this.homey.ble` for real. `HomeyBluetoothPort` below
// is that wiring, built directly from `@types/homey`'s own
// `ManagerBLE`/`BleAdvertisement`/`BlePeripheral`/`BleService`/
// `BleCharacteristic` declarations. UNVERIFIED ON HARDWARE (flagged
// honestly, the same way `lib/mesh/provisioning/machine.ts` flags its own
// CMAC-only limitation):
//
// - `ManagerBLE.discover()` takes no duration — this port's own
//   `scan(durationMs)` therefore cannot honour `durationMs` exactly; it
//   simply returns whatever Homey's own discovery window already found.
// - The event name/payload Homey emits on an unexpected peripheral
//   disconnect is not documented in `@types/homey`'s own declarations.
//   `DISCONNECT_EVENT` below is this module's best-effort guess, to be
//   confirmed (and corrected if wrong) the first time a bulb is power-cycled
//   mid-connection on real hardware — until then, `onDisconnect` simply may
//   not fire for a real unexpected drop, which `pairing.ts` already handles
//   safely (an unanswered `channel.next()` leaves the pairing attempt
//   stuck rather than corrupting anything — the user can always retry).
// - Service/characteristic UUIDs are translated between this project's
//   numeric convention (`lib/adapter/connection.ts`'s own `0x1828`-style
//   constants) and Homey's own hex-string convention (`BleAdvertisement`/
//   `BleService`/`BleCharacteristic`'s `uuid: string`) via `./pairing.ts`'s
//   own `bleUuidString`/`filterKnownServiceData`/`filterKnownCharacteristics`
//   — moved there, under the typecheck/jest gate, after a review found
//   three real bugs in this file's own earlier naive `parseInt(uuid, 16)`
//   (see that module's own header for what they were and why they were
//   real, not merely untested), and later found the FILTERING LOOPS that
//   used the resulting parser were themselves outside the gate too (this
//   file imports `homey`, so neither `npm run typecheck` nor
//   `npx jest --ci` ever exercised them) — now moved alongside it, leaving
//   this file nothing but the direct Homey API calls and a reshape of
//   their results into those functions' input shape.
import Homey from 'homey';
import type { BleAdvertisement, BlePeripheral, BleCharacteristic } from 'homey';

import type { NetworkStore } from '../../lib/adapter/store';
import {
  MESH_PROVISIONING_SERVICE_UUID,
  MESH_PROXY_SERVICE_UUID,
  type BluetoothPort,
  type CharacteristicHandle,
  type ConnectionHandle,
  type DiscoveredCharacteristic,
  type ScanResult,
  type Subscription,
} from '../../lib/adapter/connection';
import {
  pairNode,
  scanForUnprovisionedNodes,
  createNodeCryptoRandomSource,
  createRealClock,
  bleUuidString,
  filterKnownServiceData,
  filterKnownCharacteristics,
  type PairingDeps,
  type PairingOutcome,
  type UnprovisionedNodeCandidate,
} from './pairing';

/** Best-effort guess — see this file's own header. */
const DISCONNECT_EVENT = 'disconnect';

/**
 * `@types/homey`'s top-level module only re-exports a fixed list of names
 * (`Driver`, `Device`, `BleAdvertisement`, etc. — see `homey.d.ts`'s own
 * closing `export { ... }` statement) which does NOT include its `Homey`
 * class (the type of `this.homey` inside a `Driver`/`Device`) or
 * `ManagerBLE` individually. Both are still fully reachable through
 * `Homey.Driver`'s own declared `homey: Homey` instance property, via
 * `InstanceType` — this is how this file names them without a deep import
 * path `@types/homey` does not support (see the module header's own note
 * on this).
 */
type DriverHomey = InstanceType<typeof Homey.Driver>['homey'];
type BleManager = DriverHomey['ble'];

/** The only two services this app ever needs to find — passed to
 *  `ManagerBLE.discover()` as its own `serviceFilter` (review finding: the
 *  earlier version of this port ignored that parameter entirely and asked
 *  Homey for every advertisement it could see). */
const SCAN_SERVICE_FILTER = [bleUuidString(MESH_PROVISIONING_SERVICE_UUID), bleUuidString(MESH_PROXY_SERVICE_UUID)];

/** Wraps one `BlePeripheral`'s discovered characteristics so `discover()`
 *  only has to flatten `BleService[]` once per connection. */
interface HomeyCharacteristicHandle {
  readonly characteristic: BleCharacteristic;
}

/** Exported for task 7's `app.ts`, which needs the identical real-Bluetooth
 *  wiring for the shared proxy connection manager — `this.homey.ble` is the
 *  same manager regardless of whether it is read from `Homey.App` or
 *  `Homey.Driver` (both type it as the same `Homey` class's own `ble`
 *  property), so one class serves both rather than a second copy of this
 *  file's own UNVERIFIED-ON-HARDWARE wiring (see this file's own header)
 *  drifting from it. */
export class HomeyBluetoothPort implements BluetoothPort {
  constructor(private readonly ble: BleManager) {}

  async scan(_durationMs: number): Promise<ScanResult[]> {
    // See this file's own header: Homey's discover() has no duration
    // parameter, so `_durationMs` cannot be honoured exactly. The service
    // filter, by contrast, WAS previously ignored despite being available —
    // see SCAN_SERVICE_FILTER's own comment. The actual UUID filtering logic
    // is `filterKnownServiceData` (pairing.ts, under the gate) — this method
    // is nothing but the Homey API call and a reshape of its result.
    const advertisements = await this.ble.discover(SCAN_SERVICE_FILTER);
    return advertisements.map((advertisement: BleAdvertisement) => ({
      peripheralId: advertisement.uuid,
      rssi: advertisement.rssi,
      serviceData: filterKnownServiceData(advertisement.serviceData),
    }));
  }

  async connect(peripheralId: string, onDisconnect: () => void): Promise<ConnectionHandle> {
    const advertisement = await this.ble.find(peripheralId);
    const peripheral = await advertisement.connect();
    peripheral.once(DISCONNECT_EVENT, onDisconnect);
    return peripheral;
  }

  async discover(connection: ConnectionHandle): Promise<DiscoveredCharacteristic[]> {
    // The actual UUID filtering logic is `filterKnownCharacteristics`
    // (pairing.ts, under the gate) — this method is nothing but the Homey
    // API call and a reshape of its result into that function's input
    // shape.
    const peripheral = connection as BlePeripheral;
    const services = await peripheral.discoverAllServicesAndCharacteristics();
    return filterKnownCharacteristics(
      services.map((service) => ({
        uuid: service.uuid,
        characteristics: service.characteristics.map((characteristic) => {
          const handle: HomeyCharacteristicHandle = { characteristic };
          return { uuid: characteristic.uuid, handle };
        }),
      })),
    );
  }

  async read(characteristic: CharacteristicHandle): Promise<Buffer> {
    return (characteristic as HomeyCharacteristicHandle).characteristic.read();
  }

  async write(characteristic: CharacteristicHandle, data: Buffer): Promise<void> {
    await (characteristic as HomeyCharacteristicHandle).characteristic.write(data);
  }

  async subscribe(characteristic: CharacteristicHandle, onNotify: (data: Buffer) => void): Promise<Subscription> {
    const ch = (characteristic as HomeyCharacteristicHandle).characteristic;
    await ch.subscribeToNotifications(onNotify);
    return {
      unsubscribe: (): void => {
        void ch.unsubscribeFromNotifications();
      },
    };
  }

  async disconnect(connection: ConnectionHandle): Promise<void> {
    await (connection as BlePeripheral).disconnect();
  }
}

/** What `app.ts`'s `BleMeshApp` exposes in-process for pairing — see this
 *  file's own module header's "THE SHARED NetworkStore" note. A narrow,
 *  driver-local interface (not shared with `device.ts`'s own
 *  `BleMeshAppHost`), same convention homey-heating's own
 *  `drivers/automation/device.ts` already uses for its own, differently-
 *  shaped `AutomationHost`: each caller declares exactly what IT needs from
 *  the app, rather than every caller sharing one grab-bag interface. */
interface MeshBootstrapHost {
  getNetworkStore(): NetworkStore;
  /** Starts the shared proxy connection manager the first time a network
   *  key exists; a no-op on every later call (including every call before
   *  the first network key exists). */
  ensureMeshStarted(): void;
  /** See app.ts's own "PAIRING PAUSES THE SHARED CONNECTION" note — stops
   *  the shared proxy connection for the duration of one pairing attempt so
   *  this app never holds two simultaneous GATT connections. Returns
   *  whether anything was actually running (and so actually paused). */
  pauseMeshForPairing(): boolean;
  /** The inverse of `pauseMeshForPairing` — call only when that call
   *  returned `true`. */
  resumeMeshAfterPairing(): void;
}

class LightDriver extends Homey.Driver {
  async onInit(): Promise<void> {
    this.log('light driver ready');
  }

  // `session`'s type is pulled from `Homey.Driver#onPair`'s own declared
  // parameter via `Parameters<...>[0]`, the same `InstanceType` trick
  // `DriverHomey`/`BleManager` use above — `@types/homey` does not export
  // `PairSession` from its top-level module for this file to name directly.
  async onPair(session: Parameters<InstanceType<typeof Homey.Driver>['onPair']>[0]): Promise<void> {
    const bluetooth = new HomeyBluetoothPort(this.homey.ble);
    const host = this.homey.app as unknown as MeshBootstrapHost;
    const deps: PairingDeps = { bluetooth, store: host.getNetworkStore(), random: createNodeCryptoRandomSource(), clock: createRealClock() };

    session.setHandler('list_devices', async (): Promise<UnprovisionedNodeCandidate[]> => {
      return scanForUnprovisionedNodes(bluetooth);
    });

    session.setHandler('pair_node', async (data: { peripheralId: string }): Promise<PairingOutcome> => {
      // See app.ts's own "PAIRING PAUSES THE SHARED CONNECTION" note: from
      // the second bulb onward this app would otherwise hold two
      // simultaneous GATT connections (the proxy, plus this attempt's own)
      // from the same Homey radio. A no-op, returning `false`, on the
      // FIRST-ever pairing (nothing running yet to pause) — `wasRunning`
      // below is what tells this handler not to call `resumeMeshAfterPairing`
      // in that case, leaving `ensureMeshStarted` as the only thing that
      // starts the connection the very first time.
      const wasRunning = host.pauseMeshForPairing();
      try {
        const outcome = await pairNode(deps, data.peripheralId);
        if (outcome.kind === 'paired') {
          // First-ever pairing is what creates the network (ensureNetworkInitialized,
          // pairing.ts) — this is the one place that tells app.ts to start the
          // shared connection manager once that has happened. A no-op on every
          // later pairing (the mesh is already running by then).
          host.ensureMeshStarted();
        }
        return outcome;
      } finally {
        if (wasRunning) host.resumeMeshAfterPairing();
      }
    });
  }
}

module.exports = LightDriver;
