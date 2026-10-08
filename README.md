# BLE Mesh — a Bluetooth SIG Mesh provisioner for Homey

**Experimental.** Test channel only. This app provisions and controls Bluetooth SIG
Mesh **lighting** directly from a Homey Pro — no cloud, no vendor gateway, no bridge
app in between. As far as the public record goes it is the first SIG Mesh provisioner
for this platform; Athom's own answer to "Does Homey support BLE SIG Mesh?" has been
"No" since 2024, and every comparable implementation lives in the Home Assistant world.

## Read this before pairing anything

**Pairing is destructive to your existing installation.** A SIG Mesh node belongs to
exactly one network at a time. Provisioning a bulb here removes it from whatever
network owns it now — the manufacturer's app will simply lose it — and the only way
back is a factory reset of the bulb.

**The network keys live only in this app's settings.** There is no export and no
import; that was a deliberate decision. A Homey backup covers them. Nothing else does.
If the settings are lost, every bulb has to be factory reset and paired again.

## What is supported

- **Lighting nodes only.** One driver: *Mesh Light*.
- Mesh models: Generic OnOff (`0x1000`), Light Lightness (`0x1300`), Light CTL
  Temperature (`0x1306`, written through `Light CTL Temperature Set` `0x8264`) and
  Light HSL (`0x1307`).
- Provisioning over **PB-GATT, no-OOB**, for unprovisioned (factory-reset) nodes.
- One mesh network, owned by this app. A single GATT connection serves the whole
  network through whichever node is in range; it reconnects on its own with backoff.
- Homey capabilities: on/off, dim, colour temperature, hue, saturation, light mode.

### Verified hardware

Tuya-sold SIG Mesh bulbs (`cid 0x07D0`, `pid 768`, vendor `modelId 4`), confirmed by
decrypting live traffic on 2026-10-07. **Everything else is untested** — that is the
reason this is a test release rather than a store listing.

Those bulbs break the specification in ways the app works around, and the workarounds
may be unnecessary or insufficient on other hardware:

- the composite `Light CTL Set` (`0x825E`) never answers, so colour temperature is
  written through the dedicated `Light CTL Temperature Set` instead;
- `Light HSL Hue Set` and `Light HSL Saturation Set` never answer either, although the
  bulbs advertise those servers, so colour goes through the composite `Light HSL Set`;
- the bulbs do not treat the temperature field as Kelvin — they stretch their physical
  range across the whole legal 800–20000 span. The `temperature_min_kelvin` and
  `temperature_max_kelvin` device settings are therefore **the range of values we
  send**, not a description of the lamp;
- they keep a separate white/colour mode with no SIG switch for it, and we could not
  find a vendor opcode that changes it. Neither has anyone else; it is an open problem
  across projects, not a defect of this app.

## What is not supported

Sensors, buttons, switches and relays — they report unsolicited, which needs Model
Publication and Subscription configuration this app does not implement. Also: group
addressing and scenes, Relay/Friend/Low Power node configuration, key refresh, OTA
updates, importing an existing mesh network, and proxy filter configuration.

## Install

Not in the Homey App Store. Install from the Test link, or locally:

```
npm install
npx homey app validate --level publish
npx homey app install
```

## Develop

```
npm run typecheck     # tsc, no emit
npx jest --ci         # 36 suites / 1213 tests
```

The mesh stack under `lib/mesh/` is written against the published Bluetooth
specifications and carries no knowledge of lighting; device-specific code lives in
`lib/models/` and `drivers/light/`. An import-boundary test enforces that separation,
so adding another device class means new model encoders and a new driver, not changes
to the stack.

## Reporting a problem

Include the bulb's make and model, what you expected, what happened, and whether the
bulb had been paired with another app before. Logs from `homey app run` are the most
useful thing you can attach.
