/**
 * Sample data transcribed from the Bluetooth Mesh specification, Section
 * 8.6 "Mesh Proxy Service sample data", subsection 8.6.1 "Service data
 * using Network ID". Transcribed by hand from the official Bluetooth SIG
 * "Mesh Protocol" specification v1.1 HTML document
 * (https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/MshPRT_v1.1/out/en/index-en.html),
 * re-fetched and byte-compared (identical, same SHA-256) against the copy
 * already used by this project's earlier tasks, on 2026-10-07.
 *
 * This is the ONE published sample for what connection.ts has to recognise
 * on the air: not just k3's output (that sample is Section 8.1.5, already
 * transcribed and known-answer-tested in lib/mesh/crypto/__tests__/vectors.ts
 * as K3_SAMPLE, with a DIFFERENT NetKey) but the complete Mesh Proxy Service
 * advertising payload — Identification Type byte, Network ID bytes, and the
 * AD Length/AD Type/UUID envelope a real scan would actually see on the
 * air (Table 7.11 "Service Data for Mesh Proxy Service with Network ID",
 * Section 7.2.2.2.2).
 *
 * The section's own text, verbatim from the fetched document: "This shows
 * the advertising data used to broadcast the Network ID of a network that
 * can be accessed through a Mesh Proxy service. This would be used to
 * allow a device to connect to a specific mesh network."
 */
export const hex = (s: string): Buffer => Buffer.from(s.replace(/\s+/g, ''), 'hex');

export const NETWORK_ID_ADVERTISING_SAMPLE = {
  netKey: '7dd7364cd842ad18c17c2b820c84c3d6',
  // k3(netKey) — verified against this project's own k3 implementation
  // (lib/mesh/crypto/derive.ts) while writing this task: it reproduces
  // this exact value from this exact NetKey.
  expectedNetworkId: '3ecaff672f673370',
  advLen: '0c',
  // AD Type 0x16 = Service Data - 16-bit UUID. This IS spelled out as its
  // own hex byte in the section's table: the row labelled "Adv (Service
  // Data)" carries exactly "16", immediately above the nested "Mesh Proxy
  // UUID"/"Type"/"Network ID" breakdown rows (re-confirmed against the raw
  // HTML table cells directly, not the flattened text, after an earlier
  // version of this comment wrongly claimed the opposite).
  adType: '16',
  meshProxyServiceUuidLe: '2818', // 0x1828, little-endian on the air
  identificationType: '00', // Table 7.8: 0x00 = Network ID type
  // The complete advertising data blob the specification publishes:
  // Adv Len (0c) || AD Type (16) || UUID LE (2818) || Type (00) || Network ID.
  expectedAdvData: '0c162818003ecaff672f673370',
};
