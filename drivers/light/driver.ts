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
// - Service/characteristic UUIDs are translated from this project's
//   numeric convention (`lib/adapter/connection.ts`'s own `0x1828`-style
//   constants) to Homey's own hex-string convention (`BleAdvertisement`/
//   `BleService`/`BleCharacteristic`'s `uuid: string`) via plain
//   `parseInt(uuid, 16)` (`parseUuid` below) — Homey's own documentation
//   gives no other shape for these strings, but this has not been
//   exercised against a real GATT stack's exact string casing/padding.
import Homey from 'homey';
import type { BleAdvertisement, BlePeripheral, BleCharacteristic } from 'homey';

import { NetworkStore, type SettingsPort } from '../../lib/adapter/store';
import type {
  BluetoothPort,
  CharacteristicHandle,
  ConnectionHandle,
  DiscoveredCharacteristic,
  ScanResult,
  ServiceDataEntry,
  Subscription,
} from '../../lib/adapter/connection';
import {
  pairNode,
  scanForUnprovisionedNodes,
  createNodeCryptoRandomSource,
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

function parseUuid(uuid: string): number {
  return parseInt(uuid, 16);
}

/** Wraps one `BlePeripheral`'s discovered characteristics so `discover()`
 *  only has to flatten `BleService[]` once per connection. */
interface HomeyCharacteristicHandle {
  readonly characteristic: BleCharacteristic;
}

class HomeyBluetoothPort implements BluetoothPort {
  constructor(private readonly ble: BleManager) {}

  async scan(_durationMs: number): Promise<ScanResult[]> {
    // See this file's own header: Homey's discover() has no duration
    // parameter, so `_durationMs` cannot be honoured exactly.
    const advertisements = await this.ble.discover();
    return advertisements.map((advertisement: BleAdvertisement) => {
      const serviceData: ServiceDataEntry[] = advertisement.serviceData.map((entry) => ({
        serviceUuid: parseUuid(entry.uuid),
        data: entry.data,
      }));
      return { peripheralId: advertisement.uuid, rssi: advertisement.rssi, serviceData };
    });
  }

  async connect(peripheralId: string, onDisconnect: () => void): Promise<ConnectionHandle> {
    const advertisement = await this.ble.find(peripheralId);
    const peripheral = await advertisement.connect();
    peripheral.once(DISCONNECT_EVENT, onDisconnect);
    return peripheral;
  }

  async discover(connection: ConnectionHandle): Promise<DiscoveredCharacteristic[]> {
    const peripheral = connection as BlePeripheral;
    const services = await peripheral.discoverAllServicesAndCharacteristics();
    const result: DiscoveredCharacteristic[] = [];
    for (const service of services) {
      const serviceUuid = parseUuid(service.uuid);
      for (const characteristic of service.characteristics) {
        const handle: HomeyCharacteristicHandle = { characteristic };
        result.push({ serviceUuid, characteristicUuid: parseUuid(characteristic.uuid), handle });
      }
    }
    return result;
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

/** `this.homey.settings` already matches `SettingsPort`'s own
 *  `{get(key), set(key, value)}` shape structurally — no adapter class
 *  needed, same as every other `lib/adapter` module that takes a settings
 *  port. */
function settingsPort(homey: DriverHomey): SettingsPort {
  return {
    get: (key: string): unknown => homey.settings.get(key),
    set: (key: string, value: unknown): void => homey.settings.set(key, value),
  };
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
    const store = new NetworkStore(settingsPort(this.homey));
    const deps: PairingDeps = { bluetooth, store, random: createNodeCryptoRandomSource() };

    session.setHandler('list_devices', async (): Promise<UnprovisionedNodeCandidate[]> => {
      return scanForUnprovisionedNodes(bluetooth);
    });

    session.setHandler('pair_node', async (data: { peripheralId: string }): Promise<PairingOutcome> => {
      return pairNode(deps, data.peripheralId);
    });
  }
}

module.exports = LightDriver;
