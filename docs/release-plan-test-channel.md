# Release plan — Homey App Store **Test** channel, experimental

Status: proposed, 2026-10-08. Owner decision pending on the open items at the end.

This app would be the first Bluetooth SIG Mesh provisioner for Homey. The gap is
real and long-standing: Athom's own answer to "Does Homey support BLE SIG Mesh?"
has been a flat "No" since June 2024, the question returned in March 2026 with the
same answer, and the Jung Home thread (a commercial Bluetooth-mesh lighting line)
was still unanswered in May 2026. Every working implementation of this kind lives
in the Home Assistant world, none on Homey.

That is also the reason to ship it as **experimental, test channel only**: there is
no prior art on this platform to inherit confidence from.

## 1. What we support — the scope statement

This text is the contract with whoever installs it. It goes, in shortened form,
into the store description and the README.

**Supported**

- Bluetooth SIG Mesh **lighting nodes only**. One driver: *Mesh Light*.
- Mesh models: Generic OnOff (`0x1000`), Light Lightness (`0x1300`),
  Light CTL Temperature (`0x1306`, written through `Light CTL Temperature Set`
  `0x8264`), Light HSL (`0x1307`).
- Provisioning: **PB-GATT, no-OOB**, unprovisioned (factory-reset) nodes only.
- One mesh network, created and owned by this app. One GATT connection serves the
  whole network through whichever node is in range.
- Capabilities exposed: on/off, dim, colour temperature, hue, saturation, light mode.

**Verified on hardware**

Tuya-sold SIG Mesh bulbs (`cid 0x07D0`, `pid 768`, vendor `modelId 4`), confirmed on
the wire 2026-10-07. Everything else is untested — including other vendors' bulbs,
which is the main reason this is a test release.

**Not supported, and not planned for this release**

- Sensors, buttons, switches, relays — they report unsolicited, which needs
  Model Publication and Subscription configuration that this app does not implement.
- Group addressing, scenes.
- Relay / Friend / Low Power node configuration, key refresh, IV update initiation.
- OTA firmware updates.
- Importing an existing mesh network, or exporting ours.
- Proxy filter configuration (see risk 3 below).

## 2. Two warnings that must reach the user before anything else

**2.1 Pairing is destructive to an existing installation.** A SIG Mesh node belongs
to exactly one network at a time. Provisioning a bulb here removes it from whatever
network it was in — the vendor's app will lose it, and the only way back is a factory
reset of the bulb. Today the pairing screen says only "Select the bulbs to pair" and
"Scanning…". This warning must appear **before the scan starts**, not in a footnote.

**2.2 Losing the app's settings orphans every bulb.** The network keys live only in
this app's settings; there is no export or import (a deliberate decision, already
stated plainly on the settings page). A Homey backup covers it; nothing else does.
If the settings are lost, every bulb needs a factory reset. The store description
must repeat this in one sentence.

A third, milder note belongs in the description: the colour-temperature range in the
device settings (`temperature_min_kelvin` / `temperature_max_kelvin`, default
800–20000) is **the range of values we send**, not a physical property of the lamp.
Our verified bulbs stretch their real ~3000–6000 K across the full legal span, so
sending true Kelvin values moves the colour barely at all.

## 3. Work before publishing, in order

1. **Pairing-screen warning** (2.1). Blocking; the single most important item.
2. **README** for the repository: scope, the two warnings, verified hardware, how to
   report a problem. The repo has none today.
3. **Store description** rewritten from the current one-liner to carry the scope
   statement, the experimental status, and the warnings in short form.
4. **`.homeychangelog.json`** with the first entry. `homey app publish` prompts for
   it; writing it deliberately is better than improvising at the prompt.
5. **Multi-node portability check** (risk 3). Cheap and potentially scope-changing.
6. **Stability evidence**: all three bulbs paired, several days of normal use without
   losing the connection. This is the only item that cannot be hurried.

## 4. Publication steps

```
cd ~/projects/homey-ble-mesh
npx homey app validate --level publish     # already green as of 2026-10-08
npx homey app publish                      # prompts for version bump + changelog
```

Then, in the Homey Developer dashboard, submit the uploaded build as a **Test**
release. It becomes reachable only through the Test link from the dashboard — it is
not listed in the store and not installable by browsing. **Do not submit for Live
certification.** Homey has no separate "experimental" flag; the Test channel plus an
explicit description is the mechanism.

## 5. Risks carried into the release

1. **Only one vendor's bulbs are verified.** Other SIG Mesh lighting may behave
   differently, especially around colour. Stated in the description; this is what the
   test channel is for.
2. **The firmware we tested breaks the specification in several places** — a dead
   `Light CTL Set`, unresponsive `Light HSL Hue/Saturation Set`, models placed on the
   wrong element, a white/colour mode we could not find a switch for. Our workarounds
   are shaped around those quirks and may be unnecessary, or insufficient, elsewhere.
3. **We rely on the proxy node's default filter.** We never send proxy configuration
   messages (`0x02`), which sidesteps a known trap — the Home Assistant project
   `frekarlsen/ha-sg-smart-mesh` documents that these must be encrypted with the
   *proxy* nonce and that some vendors silently reject a wrong one. The cost is that
   reaching a node through another node depends on that node's default filter being
   permissive. Ours appear to be. Another vendor's may not, and the symptom would be
   silence rather than an error. Item 3.5 above is the check.
4. **No recovery path for lost keys**, by design.
5. ~~**Athom's publishing limit.**~~ **Resolved 2026-10-07.** Publishing had been
   returning "Too many requests" account-wide since 2026-10-02; it works again.
   Evidence: `com.shejnowicz.vasco-kermi-x` 1.0.11 and `com.shejnowicz.ecoschedule`
   0.0.3 are installed on the hub with `origin: appstore`, `channel: test`, which only
   a real publish produces. The drafted Athom support ticket is no longer needed.
   **There is now no external blocker — only our own work in section 3.**

## 6. Open for the owner

- Publish under the current `0.1.0`, or bump to `0.2.0` to mark the first public build?
- Does the app keep the name "BLE Mesh", or something that signals the narrow scope,
  such as "BLE Mesh Lights"?
- A support URL for the store listing: the GitHub repository is private. Publish it,
  or point support at an email address?
