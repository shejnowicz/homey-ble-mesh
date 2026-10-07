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
import {
  MeshLightController,
  type DeviceCapabilityPort,
  type MeshClockPort,
  type MeshTrafficPort,
  type ProbeRunnerPort,
} from './meshLight';
import type { NetworkStore } from '../../lib/adapter/store';
import type { HomeyCapability } from '../../lib/models/capabilities';
import { rangeFromUnknown, resolveTemperatureRange } from './temperatureRange';
import {
  COLOUR_MODES,
  COLOUR_MODE_SETTING,
  colourModeFromUnknown,
  planCapabilityChange,
  seedColourMode,
  type ColourMode,
} from './colourMode';

/** What `app.ts`'s `BleMeshApp` exposes in-process. `getMeshContext()`
 *  returning `null` is unreachable in ordinary operation (app.ts starts the
 *  mesh in its own `onInit`, which Homey always runs to completion before
 *  any driver/device `onInit` — the same ordering homey-heating's own
 *  app.ts/device.ts already rely on) — handled defensively here anyway
 *  rather than assumed away. */
export interface BleMeshAppHost {
  getMeshContext(): {
    readonly store: NetworkStore;
    readonly queue: MeshTrafficPort;
    readonly clock: MeshClockPort;
    /** The app's ONE backfill-probe runner — see
     *  `meshLight.ts#ProbeRunnerPort`. Shared for the same reason the queue
     *  is: the mesh carries one command at a time, so several devices
     *  initialising together must not probe concurrently. */
    readonly probeRunner: ProbeRunnerPort;
  } | null;
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
  /** Which capabilities already have a listener. `wireCapabilityListeners`
   *  runs again after every colour-mode change (a capability ADDED at
   *  runtime has no listener until one is registered for it), and without
   *  this set, flipping the setting back and forth would stack a second,
   *  third, fourth listener on the same capability. */
  private readonly registeredCapabilityListeners = new Set<HomeyCapability>();

  async onInit(): Promise<void> {
    const host = this.homey.app as unknown as BleMeshAppHost;
    const context = host.getMeshContext();
    if (context === null) {
      this.error('mesh context not available at device init (should be unreachable — see this file\'s own module header)');
      await this.setUnavailable('Mesh network not initialized');
      return;
    }

    const address = Number(this.getData().id);
    // THE COLOUR-TEMPERATURE RANGE, resolved here because this is the one
    // file allowed to read a Homey setting — `temperatureRange.ts` owns the
    // precedence (the user's setting, then what the node reported about
    // itself at pairing time, then the documented fallback) and
    // `meshLight.ts` only ever receives the answer, so its maths stays pure.
    const controller = new MeshLightController({
      queue: context.queue,
      store: context.store,
      // The app's own single real clock — the controller needs `now()` to
      // rate-limit its re-read retries (meshLight.ts's own "ONE UNREACHABLE
      // BULB" note), and this file is not allowed to own wall-clock time.
      clock: context.clock,
      device: capabilityPort(this),
      address,
      temperatureRange: this.resolveRange(context.store, address),
      probeRunner: context.probeRunner,
    });
    this.controller = controller;
    // ORDER MATTERS (review finding): `start()` subscribes the controller's
    // unsolicited-notification listener; `registerDeviceController` can
    // deliver an IMMEDIATE `onConnectionStateChange('connected')` call if
    // the mesh is already up (app.ts's own doc comment on that method), which
    // runs `reReadState()` and therefore sends Gets whose replies the
    // controller must already be listening for. The two previously ran in
    // the other order and only worked because `registerDeviceController`'s
    // delivery happens after an `await` inside an async call this file never
    // awaited — correct by accident of scheduling, not by this file's own
    // guarantee. `start()` first removes the accident.
    // WHAT THIS LAMP PHYSICALLY HAS, applied BEFORE anything starts asking
    // the node about it. `registerDeviceController` below can deliver an
    // immediate `onConnectionStateChange('connected')`, which runs
    // `reReadState()` — and that picks which Gets to send from
    // `hasCapability`. Applying the mode first means it never asks a
    // monocolor lamp for its colour, and never skips a slider the user has
    // just restored. This touches only Homey's own device record; it sends
    // nothing to the mesh.
    await this.applyColourMode(await this.resolveColourMode());

    controller.start();
    this.unregister = host.registerDeviceController(controller);

    this.wireCapabilityListeners(controller);

    // NOTHING HERE STARTS THE BACKFILL PROBE, deliberately. Measuring a bulb
    // that predates the probe is the controller's own job and its own
    // trigger (`meshLight.ts#startBackfillProbe`): it runs from the first
    // moment the node has actually ANSWERED, not from device init, which on
    // a cold start happens while the proxy connection is still coming up.
    // All this file supplies is the app's ONE shared probe runner, above.
  }

  async onUninit(): Promise<void> {
    this.unregister?.();
    this.unregister = null;
    this.controller?.stop();
  }

  /**
   * Registers a capability listener for every capability this device has
   * and does not already have one for. Idempotent (see
   * `registeredCapabilityListeners`), because it runs again whenever
   * `applyColourMode` adds a capability at runtime.
   */
  private wireCapabilityListeners(controller: MeshLightController): void {
    const once = (capability: HomeyCapability, register: () => void): void => {
      if (!this.hasCapability(capability)) return;
      if (this.registeredCapabilityListeners.has(capability)) return;
      this.registeredCapabilityListeners.add(capability);
      register();
    };

    once('onoff', () => {
      this.registerCapabilityListener('onoff', async (value: boolean) => controller.setOnOff(value));
    });
    once('dim', () => {
      this.registerCapabilityListener('dim', async (value: number) => controller.setDim(value));
    });
    once('light_temperature', () => {
      this.registerCapabilityListener('light_temperature', async (value: number) => controller.setLightTemperature(value));
    });
    if (this.hasCapability('light_hue') && this.hasCapability('light_saturation')) {
      // Hue and saturation travel together (Light HSL Set's own single
      // message — see meshLight.ts#setColor). Homey's own
      // `registerMultipleCapabilityListener` exists precisely for a pair
      // like this: a drag on a colour wheel typically changes both at once,
      // and this combines them into ONE call instead of two commands racing
      // each other with stale values for whichever field did not change
      // this time. The debounce window (500 ms) matches the example in
      // `@types/homey`'s own `Device#registerMultipleCapabilityListener`
      // doc comment. Keyed on `light_hue` alone because ONE registration
      // covers the pair — and the pair always arrives and leaves together
      // (`colourMode.ts`'s own nesting).
      once('light_hue', () => {
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
      });
    }
    once('light_mode', () => {
      this.registerCapabilityListener('light_mode', async (value: string) => {
        await this.setCapabilityValue('light_mode', value);
      });
    });
  }

  /**
   * This device's colour mode: the user's own stored answer, or — for a
   * bulb paired before this setting existed — one SEEDED from the
   * capabilities pairing already gave it, and written back so the dropdown
   * shows the truth rather than a blank.
   *
   * SEEDING FROM THE DEVICE'S OWN CAPABILITIES IS PROVABLY A NO-OP
   * (`__tests__/colourMode.test.ts` pins exactly that), which is what makes
   * it safe to do unprompted on a device nobody has said anything about. A
   * manifest DEFAULT would not have been: Homey would hand it back from
   * `getSetting` indistinguishably from a real answer, and applying it
   * would add or remove capabilities on the strength of a guess — which is
   * why `driver.compose.json`'s dropdown deliberately carries none.
   *
   * A failed write is logged and otherwise ignored: the mode still applies
   * this run, and the next start seeds it again.
   */
  private async resolveColourMode(): Promise<ColourMode> {
    const stored = colourModeFromUnknown(this.getSetting(COLOUR_MODE_SETTING));
    if (stored !== null) return stored;
    const seeded = seedColourMode(this.getCapabilities());
    try {
      await this.setSettings({ [COLOUR_MODE_SETTING]: seeded });
    } catch (err) {
      this.error('could not seed the colour-mode setting', err);
    }
    return seeded;
  }

  /**
   * Brings this device's capabilities into line with `mode`, adding and
   * removing them in place — no re-pairing, and no reload.
   *
   * REMOVE FIRST, THEN ADD, THEN RE-WIRE. Removing first is what keeps
   * `light_mode` from ever being visible without both pickers it switches
   * between (`colourMode.ts#planCapabilityChange` orders its own removals
   * for the same reason). Re-wiring last is not optional: a capability
   * Homey has just been given has no listener until one is registered for
   * it, so without it a user correcting `monocolor` back to `multicolor`
   * would get pickers that do nothing at all.
   *
   * Homey's own `addCapability`/`removeCapability` are documented as
   * expensive, which is why the plan is computed first and the common case
   * (nothing to change) performs no calls whatsoever.
   */
  private async applyColourMode(mode: ColourMode): Promise<void> {
    const plan = planCapabilityChange(mode, this.getCapabilities());
    for (const capability of plan.remove) await this.removeCapability(capability);
    for (const capability of plan.add) await this.addCapability(capability);
    if (this.controller !== null) this.wireCapabilityListeners(this.controller);
  }

  /** The user's own setting first, then the node's own reported range from
   *  the pairing-time probe, then the documented fallback. */
  private resolveRange(store: NetworkStore, address: number): ReturnType<typeof resolveTemperatureRange> {
    const fromSettings = rangeFromUnknown(this.getSetting('temperature_min_kelvin'), this.getSetting('temperature_max_kelvin'));
    const fromNode = store.getState().nodes.find((node) => node.address === address)?.probe?.temperatureRange ?? null;
    return resolveTemperatureRange(fromSettings, fromNode);
  }

  /**
   * Homey's own settings hook. A range the user edits takes effect on the
   * NEXT command rather than on a reload, and an unusable pair (inverted, or
   * outside the Mesh Model's own legal span) is REJECTED by throwing: Homey
   * shows the thrown message to the user and does not save the change, which
   * is the honest outcome — silently clamping a typo into something valid
   * would leave the slider mapped onto a range the user never chose and
   * cannot see.
   */
  async onSettings(event: { newSettings: Record<string, unknown>; changedKeys: string[] }): Promise<void> {
    // THE COLOUR MODE TAKES EFFECT IMMEDIATELY, which is the whole point of
    // it: the user looks at the lamp, says what it is, and the capabilities
    // follow without a re-pair. `event.newSettings`, not `getSetting`:
    // Homey has not persisted the change yet at this point, and throwing
    // below is what refuses it.
    if (event.changedKeys.includes(COLOUR_MODE_SETTING)) {
      const mode = colourModeFromUnknown(event.newSettings[COLOUR_MODE_SETTING]);
      if (mode === null) {
        throw new Error(`The colour mode must be one of: ${COLOUR_MODES.join(', ')}.`);
      }
      await this.applyColourMode(mode);
    }

    if (!event.changedKeys.includes('temperature_min_kelvin') && !event.changedKeys.includes('temperature_max_kelvin')) {
      return;
    }
    const range = rangeFromUnknown(event.newSettings.temperature_min_kelvin, event.newSettings.temperature_max_kelvin);
    if (range === null || this.controller === null || !this.controller.setTemperatureRange(range)) {
      throw new Error(
        'The lowest value must be below the highest one, and both must be between 800 K and 20000 K (Mesh Model Table 6.6).',
      );
    }
  }

  async onDeleted(): Promise<void> {
    if (this.controller === null) {
      this.error('device deleted with no controller ever constructed — nothing to reset');
      return;
    }
    // Review finding: without this, a deleted device's controller stayed
    // registered and subscribed — it kept being handed every future
    // `onConnectionStateChange` call (re-reading a node that no longer
    // exists on every reconnection) and kept listening for unsolicited
    // status from an address nothing will ever use again. Unregister/stop
    // BEFORE attempting the reset below, not after: a reset attempt can
    // take the queue's full bounded-retry time, and this cleanup does not
    // depend on its outcome either way.
    this.unregister?.();
    this.unregister = null;
    this.controller.stop();
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
