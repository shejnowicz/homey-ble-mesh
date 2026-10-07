// The real-Bluetooth port, extracted from driver.ts.
//
// WHY ITS OWN FILE. A Homey driver module must end with
// `module.exports = <Driver>`, and that assignment REPLACES the module's
// exports object outright. Any `export class` in the same file therefore
// compiles to a property on an object that is then thrown away: reachable
// from TypeScript and from jest, which resolve the named export at compile
// time, but `undefined` to anything that `require()`s the driver at runtime.
// `app.ts` did exactly that and failed on the owner's own hardware with
// "driver_1.HomeyBluetoothPort is not a constructor" — after a clean scan
// that had already found all three bulbs. A plain module has no
// `module.exports =` to clobber it, so both `driver.ts` and `app.ts` can
// import this and get the same class. `lib/__tests__/module-export-boundary
// .test.ts` now enforces that rule for every driver file, so the next
// `export` added beside a `module.exports =` fails the suite instead of the
// pairing session.
//
// UNVERIFIED ON HARDWARE applies to everything below exactly as it did in
// driver.ts, whose module header describes each guess in full.
import Homey from 'homey';
import type { BleAdvertisement, BlePeripheral, BleCharacteristic } from 'homey';

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
import { bleUuidString, filterKnownServiceData, filterKnownCharacteristics } from './pairing';

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
export type DriverHomey = InstanceType<typeof Homey.Driver>['homey'];
export type BleManager = DriverHomey['ble'];

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
