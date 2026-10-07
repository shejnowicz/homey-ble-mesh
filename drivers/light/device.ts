// The light device (docs/superpowers/specs/2026-10-06-ble-mesh-provisioner-
// design.md, "The Homey layer"): the ONE file in this directory, besides
// driver.ts, that imports `homey` — see meshLight.ts's own module header for
// why the real logic cannot live here and lives there instead, and for why
// this is `meshLight.ts`/`device.ts` rather than the task brief's literal
// `device.ts`/`__tests__/device.test.ts` pairing (the task report explains
// the deviation). This file is nothing but Homey API calls and a reshape of
// `this` into `meshLight.ts`'s own narrow `DeviceCapabilityPort`, mirroring
// exactly how `driver.ts` wraps `pairing.ts`.
//
// THE SHARED SINGLETONS, AND WHY THIS FILE NEVER CONSTRUCTS ITS OWN. Every
// device reaches into `this.homey.app` (the same in-process pattern
// homey-heating's own drivers/automation/device.ts already uses — see
// `AutomationHost` there) for the SAME `NetworkStore`/`TrafficQueue`
// instances app.ts constructed once — never its own. This is not merely
// tidiness: `NetworkStore`'s sequence-number allocator keeps its "next
// number" cursor IN MEMORY, loaded once at construction (store.ts's own
// module header). If each device constructed its own `NetworkStore` over
// the same settings, every one of them would start from the SAME persisted
// ceiling and hand out OVERLAPPING sequence numbers to different nodes —
// which share ONE sequence-number space because they share one source
// address (ours; SeqAuth replay protection on the receiving end keys on
// SRC+SEQ, not on which destination we meant it for). A receiving node
// would then silently drop whichever of two colliding messages it saw
// second, as an ordinary replay — an intermittent "the command was just
// ignored" defect, not a theoretical one. The queue and connection manager
// are singletons for the identical reason the design states directly:
// "One connection serves the whole mesh... All mesh traffic passes through
// one queue."
//
// `light_mode` IS WIRED DIRECTLY HERE, NOT THROUGH THE CONTROLLER — the
// only capability handled that way; see meshLight.ts's own module header
// for why (no wire traffic, nothing to gate under the testable seam).
import Homey from 'homey';
import { MeshLightController, type DeviceCapabilityPort, type MeshTrafficPort } from './meshLight';
import type { NetworkStore } from '../../lib/adapter/store';

/** What `app.ts`'s `BleMeshApp` exposes in-process. `getMeshContext()`
 *  returning `null` is unreachable in ordinary operation (app.ts starts the
 *  mesh in its own `onInit`, which Homey always runs to completion before
 *  any driver/device `onInit` — the same ordering homey-heating's own
 *  app.ts/device.ts already rely on) — handled defensively here anyway
 *  rather than assumed away. */
export interface BleMeshAppHost {
  getMeshContext(): { readonly store: NetworkStore; readonly queue: MeshTrafficPort } | null;
  /** Registers a controller to receive `onConnectionStateChange` calls
   *  whenever the shared proxy connection's status changes. Returns an
   *  unsubscribe function — called from `onUninit` below so a removed or
   *  reloaded device is never notified again. */
  registerDeviceController(controller: MeshLightController): () => void;
}

/** `this` already satisfies `DeviceCapabilityPort` structurally for every
 *  member except `setUnavailable` (Homey's own signature accepts
 *  `string | null | undefined`; the port's accepts `string | undefined`) —
 *  trivially bridged below rather than widening the port for one caller. */
function capabilityPort(device: LightDevice): DeviceCapabilityPort {
  return {
    hasCapability: (id) => device.hasCapability(id),
    getCapabilityValue: (id) => device.getCapabilityValue(id),
    setCapabilityValue: (id, value) => device.setCapabilityValue(id, value),
    setAvailable: () => device.setAvailable(),
    setUnavailable: (message) => device.setUnavailable(message ?? null),
  };
}

class LightDevice extends Homey.Device {
  private controller: MeshLightController | null = null;
  private unregister: (() => void) | null = null;

  async onInit(): Promise<void> {
    const host = this.homey.app as unknown as BleMeshAppHost;
    const context = host.getMeshContext();
    if (context === null) {
      this.error('mesh context not available at device init (should be unreachable — see this file\'s own module header)');
      await this.setUnavailable('Mesh network not initialized');
      return;
    }

    const address = Number(this.getData().id);
    const controller = new MeshLightController({
      queue: context.queue,
      store: context.store,
      device: capabilityPort(this),
      address,
    });
    this.controller = controller;
    this.unregister = host.registerDeviceController(controller);
    controller.start();

    if (this.hasCapability('onoff')) {
      this.registerCapabilityListener('onoff', async (value: boolean) => controller.setOnOff(value));
    }
    if (this.hasCapability('dim')) {
      this.registerCapabilityListener('dim', async (value: number) => controller.setDim(value));
    }
    if (this.hasCapability('light_temperature')) {
      this.registerCapabilityListener('light_temperature', async (value: number) => controller.setLightTemperature(value));
    }
    if (this.hasCapability('light_hue') && this.hasCapability('light_saturation')) {
      // Hue and saturation travel together (Light HSL Set's own single
      // message — see meshLight.ts#setColor). Homey's own
      // `registerMultipleCapabilityListener` exists precisely for a pair
      // like this: a drag on a colour wheel typically changes both at once,
      // and this combines them into ONE call instead of two commands racing
      // each other with stale values for whichever field did not change
      // this time. The debounce window (500 ms) matches the example in
      // `@types/homey`'s own `Device#registerMultipleCapabilityListener`
      // doc comment.
      this.registerMultipleCapabilityListener(
        ['light_hue', 'light_saturation'],
        async (values: Record<string, unknown>) => {
          const hue = typeof values.light_hue === 'number' ? values.light_hue : (this.getCapabilityValue('light_hue') as number);
          const saturation =
            typeof values.light_saturation === 'number'
              ? values.light_saturation
              : (this.getCapabilityValue('light_saturation') as number);
          await controller.setColor(hue, saturation);
        },
        500,
      );
    }
    if (this.hasCapability('light_mode')) {
      this.registerCapabilityListener('light_mode', async (value: string) => {
        await this.setCapabilityValue('light_mode', value);
      });
    }
  }

  async onUninit(): Promise<void> {
    this.unregister?.();
    this.unregister = null;
    this.controller?.stop();
  }

  async onDeleted(): Promise<void> {
    if (this.controller === null) {
      this.error('device deleted with no controller ever constructed — nothing to reset');
      return;
    }
    try {
      await this.controller.remove();
    } catch (err) {
      // onDeleted cannot stop Homey from removing the device (see
      // meshLight.ts's own REMOVAL note) — this is the one place that
      // failure can still be surfaced, in the app's own log.
      this.error('failed to reset node before removing it from the mesh', err);
    }
  }
}

module.exports = LightDevice;
