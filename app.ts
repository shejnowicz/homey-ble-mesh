// Homey app entry point. SKELETON for now: later tasks wire the proxy connection
// manager, the traffic queue and the pairing/device drivers in here. This is also
// the one place in the project allowed to own randomness and wall-clock time
// (see docs/superpowers/plans/2026-10-06-ble-mesh-homey-app.md, "Self-review
// notes") — lib/mesh and lib/adapter take both as inputs instead of reading them
// directly, specifically so they stay testable without a hub.
import Homey from 'homey';

class BleMeshApp extends Homey.App {
  async onInit(): Promise<void> {
    this.log('BLE mesh app init');
  }
}

module.exports = BleMeshApp;
