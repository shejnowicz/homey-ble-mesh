// Homey app entry point — the final wiring task (task 7). This is the one
// place in the project allowed to own randomness and wall-clock time (see
// docs/superpowers/specs/2026-10-06-ble-mesh-provisioner-design.md and this
// plan's own "Self-review notes": "The core takes both as inputs precisely
// so they could be supplied at the edge; app.ts is that edge") — lib/mesh
// and lib/adapter take both as inputs instead of reading them directly,
// specifically so they stay testable without a hub. This file is nothing
// but that wiring: it owns the ONE shared `NetworkStore`, `TrafficQueue` and
// `ProxyConnectionManager` for the whole app, and the one poll loop that
// turns the connection manager's own `getState()` into
// `MeshLightController#onConnectionStateChange` calls for every registered
// device. Everything it drives is already pure and tested
// (`drivers/light/meshLight.ts`, `lib/adapter/*`); this file itself is
// exercised via the Homey CLI, not jest — see jest.config.js's own header
// for why, and `npx tsc --noEmit -p tsconfig.json` (the whole-repo
// typecheck the project's gate also requires) for how it is still at least
// type-checked.
//
// ONE NetworkStore FOR THE WHOLE APP — SEE driver.ts's/device.ts's OWN
// IDENTICAL NOTE. `NetworkStore`'s sequence-number allocator keeps its "next
// number" cursor in memory, loaded once at construction; a second instance
// over the same settings would independently reissue sequence numbers
// another instance already used, which a receiving node's replay protection
// would then treat as a replay and silently drop. `getNetworkStore()` below
// is driver.ts's own route to this SAME instance for exactly that reason.
//
// ENSURE-MESH-STARTED IS IDEMPOTENT AND NETWORK-KEY-GATED. On an ordinary
// restart with bulbs already paired, this app's own `onInit` finds a
// network key already in the store and starts the connection manager right
// away. On a BRAND NEW install with nothing paired yet, there is no network
// key (and therefore nothing to scan for — `ProxyConnectionManager`'s own
// constructor requires one) until the FIRST pairing creates it
// (`pairing.ts#ensureNetworkInitialized`) — `driver.ts`'s `onPair` calls
// `ensureMeshStarted()` right after that first success, which is what
// actually starts the connection the very first time.
//
// PAIRING PAUSES THE SHARED CONNECTION (review finding). From the second
// bulb onward, pairing a new node happens WHILE the proxy connection to an
// already-paired bulb is held — the design's own "held permanently" — so
// provisioning a second peripheral means this app briefly needs TWO
// simultaneous GATT connections from the one Homey radio. The design's own
// accepted risk only covers coexisting with another app that mostly
// listens (SwitchBot), not two connections from THIS app at once, and nothing
// in this project has verified Homey's radio supports that. `driver.ts`'s
// `pair_node` handler therefore calls `pauseMeshForPairing()` before
// provisioning and `resumeMeshAfterPairing()` afterward (in a `finally`),
// trading a brief, whole-mesh "unavailable" for every ALREADY-paired bulb
// during the new bulb's own pairing attempt against the alternative — two
// live connections whose actual coexistence on real hardware is unverified.
// UNVERIFIED ON HARDWARE, same disclosure driver.ts's own module header
// already makes for its real-Bluetooth wiring: whether this is even
// necessary (maybe two connections work fine) or sufficient (maybe pairing
// and the proxy connection contend for the radio in some OTHER way this
// does not address) is something only the owner's three bulbs can confirm.
import Homey from 'homey';
import { NetworkStore, type SettingsPort } from './lib/adapter/store';
import { ProxyConnectionManager, type ProxyConnectionState } from './lib/adapter/connection';
import { TrafficQueue } from './lib/adapter/queue';
import { type MeshLightController, type MeshClockPort, type MeshTrafficPort } from './drivers/light/meshLight';
import { createRealClock } from './drivers/light/pairing';
import { HomeyBluetoothPort } from './drivers/light/homeyBluetooth';

type AppHomey = InstanceType<typeof Homey.App>['homey'];

/** `this.homey.settings` already matches `SettingsPort`'s own
 *  `{get(key), set(key, value)}` shape structurally — no adapter class
 *  needed, same as every other `lib/adapter` module that takes a settings
 *  port (and the same helper driver.ts used to construct, before this task
 *  moved the one `NetworkStore` instance here). */
function settingsPort(homey: AppHomey): SettingsPort {
  return {
    get: (key: string): unknown => homey.settings.get(key),
    set: (key: string, value: unknown): void => homey.settings.set(key, value),
  };
}

/**
 * How often this app polls the shared proxy connection's own `getState()`
 * and fans a CHANGE out to every registered device controller — see
 * `meshLight.ts`'s own module header, "AVAILABILITY IS CONNECTION-LEVEL":
 * `ProxyConnectionManager` publishes no change event to subscribe to
 * instead, only a value to poll, and this is the one place in the project
 * allowed to own that poll. Not a specification value — an engineering
 * choice, generous enough not to spam `onConnectionStateChange` yet short
 * enough that "unavailable" and "available again" both show up quickly on a
 * human timescale (well under `SCAN_DURATION_MS`, so it never misses a
 * transition that itself takes several seconds to happen).
 */
const CONNECTION_POLL_MS = 2000;

/** What `drivers/light/device.ts` and `drivers/light/driver.ts` each
 *  reach into `this.homey.app` for, combined here (both files declare their
 *  own narrower view of this same shape — see each one's own comment on why
 *  a shared cross-file interface is not used instead). */
class BleMeshApp extends Homey.App {
  private store: NetworkStore | null = null;
  private manager: ProxyConnectionManager | null = null;
  private queue: TrafficQueue | null = null;
  /** The ONE real clock this app owns — handed to the connection manager,
   *  the traffic queue and every device controller, so "now" means the same
   *  thing everywhere. Constructed lazily with the mesh itself. */
  private clock: MeshClockPort | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private lastConnectionStatus: ProxyConnectionState['status'] | null = null;
  private readonly controllers = new Set<MeshLightController>();

  async onInit(): Promise<void> {
    this.log('BLE mesh app init');
    this.store = new NetworkStore(settingsPort(this.homey));
    this.ensureMeshStarted();
  }

  async onUninit(): Promise<void> {
    if (this.pollTimer !== null) {
      this.homey.clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    this.manager?.stop();
  }

  /** `driver.ts#MeshBootstrapHost`'s own requirement — always returns the
   *  SAME instance (constructed once, in `onInit` above). Throwing rather
   *  than constructing one on demand if called too early is deliberate: a
   *  second instance here would be exactly the hazard this file's own
   *  module header describes, so there must never be a path that silently
   *  creates one. Unreachable in practice — Homey always runs this app's
   *  own `onInit` to completion before any driver's `onPair` can run. */
  getNetworkStore(): NetworkStore {
    if (this.store === null) {
      throw new Error('BleMeshApp.getNetworkStore: called before onInit has run');
    }
    return this.store;
  }

  /** `device.ts#BleMeshAppHost`'s own requirement. `null` only when the
   *  mesh has never been started (no network key yet) — see this file's own
   *  module header. */
  getMeshContext(): { readonly store: NetworkStore; readonly queue: MeshTrafficPort; readonly clock: MeshClockPort } | null {
    if (this.store === null || this.queue === null || this.clock === null) return null;
    return { store: this.store, queue: this.queue, clock: this.clock };
  }

  /** `device.ts#BleMeshAppHost`'s own requirement — registers `controller`
   *  to receive every future `onConnectionStateChange` call, and delivers
   *  the CURRENT status immediately if one is already known (so a device
   *  paired into an already-connected mesh does not sit unavailable for up
   *  to `CONNECTION_POLL_MS` waiting for the next poll tick to tell it what
   *  the app already knows). Returns an unsubscribe function. */
  registerDeviceController(controller: MeshLightController): () => void {
    this.controllers.add(controller);
    if (this.lastConnectionStatus !== null) {
      const status = this.lastConnectionStatus;
      controller.onConnectionStateChange(status).catch((err) => this.error('onConnectionStateChange failed', err));
    }
    return () => {
      this.controllers.delete(controller);
    };
  }

  /** `driver.ts#MeshBootstrapHost`'s own requirement — see this file's own
   *  module header's "ENSURE-MESH-STARTED" note. Idempotent: a no-op once
   *  the manager is already running, and a no-op (deliberately) when no
   *  network key exists yet. */
  ensureMeshStarted(): void {
    if (this.manager !== null) return;
    const store = this.store;
    if (store === null) return; // onInit has not run yet — see getNetworkStore's own note
    const netKey = store.getState().netKey;
    if (netKey === null) return; // nothing paired yet — nothing to connect to

    const bluetooth = new HomeyBluetoothPort(this.homey.ble);
    const clock = createRealClock();
    // The log port (final re-review, finding 4). A disconnect this app
    // performs because Section 6.3.2.2 requires it used to be recorded in a
    // field nothing on a production path ever read, so a bulb whose proxy
    // behaviour we reject presented as "the mesh keeps flapping" with the
    // actual reason invisible. It now says so, here, through the same
    // `this.log` every other event in this file uses.
    const manager = new ProxyConnectionManager(bluetooth, clock, netKey, {
      log: (message: string) => this.log(message),
    });
    const queue = new TrafficQueue(manager, clock);
    this.manager = manager;
    this.queue = queue;
    this.clock = clock;
    manager.start();
    this.pollTimer = this.homey.setInterval(() => this.pollConnectionState(), CONNECTION_POLL_MS);
    this.log('mesh connection manager started');
  }

  /**
   * `driver.ts#MeshBootstrapHost`'s own requirement — see this file's own
   * module header's "PAIRING PAUSES THE SHARED CONNECTION" note. Returns
   * whether the manager was actually running (and so actually paused), so
   * the caller knows whether to resume it afterward rather than starting
   * one that was never running (which `ensureMeshStarted` — the FIRST-ever-
   * pairing path — is already responsible for). A no-op, returning `false`,
   * when the mesh has not been started yet.
   */
  pauseMeshForPairing(): boolean {
    if (this.manager === null) return false;
    this.manager.stop();
    return true;
  }

  /** The inverse of `pauseMeshForPairing` — only ever called by
   *  `driver.ts` when THAT call's own `pauseMeshForPairing` returned `true`. */
  resumeMeshAfterPairing(): void {
    this.manager?.start();
  }

  /**
   * Fans `onConnectionStateChange` out to every registered controller on
   * EVERY tick, not only when `getState().status` changes (review finding).
   * The earlier, change-gated version left a controller whose OWN re-read
   * had failed latched unavailable forever: `meshLight.ts`'s own
   * `onConnectionStateChange('connected')` can mark itself unavailable
   * AGAIN if `reReadState()` throws (a node that does not answer even
   * though the shared connection itself is up), but the SHARED status
   * never changes again to tell it to try once more — nothing was polling
   * on ITS behalf specifically. Calling every controller on every tick
   * gives it that retry for free: `onConnectionStateChange` is idempotent
   * against a repeated identical call (a `'connected'` call while already
   * connected is a cheap no-op), so notifying a controller that has nothing
   * to do costs nothing, while one whose own `connected` flag is still
   * `false` gets a genuine new attempt every `CONNECTION_POLL_MS`.
   * `lastConnectionStatus` is kept only for `registerDeviceController`'s own
   * "deliver immediately" check and for the log line below, never to gate
   * this loop.
   */
  private pollConnectionState(): void {
    if (this.manager === null) return;
    const status = this.manager.getState().status;
    if (status !== this.lastConnectionStatus) {
      this.lastConnectionStatus = status;
      this.log('mesh connection state changed', status);
    }
    for (const controller of this.controllers) {
      controller.onConnectionStateChange(status).catch((err) => this.error('onConnectionStateChange failed', err));
    }
  }
}

module.exports = BleMeshApp;
