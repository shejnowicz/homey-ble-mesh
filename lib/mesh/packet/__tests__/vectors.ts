/**
 * Nonce and Network PDU sample data transcribed from the Bluetooth SIG
 * "Mesh Protocol" specification v1.1 HTML document
 * (https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/MshPRT_v1.1/out/en/index-en.html),
 * fetched and parsed programmatically (markup stripped, tables flattened to
 * row/field text, no reading off a rendered page) on 2026-10-06.
 *
 * The layouts (Table 3.66 Network nonce format, Table 3.67 CTL and TTL field
 * format, Table 3.68 Application nonce format, Table 3.69 ASZMIC and Pad
 * field format, Table 3.70 Device nonce format, all in Section 3.9.5) and the
 * worked examples below (Section 8.3 "Mesh message sample data", messages
 * #1, #2, #6, #16, #18, #24) came from this same v1.1 document.
 *
 * A labelling quirk in the source document: the per-message sample tables in
 * Section 8.3 reuse the row label "Application nonce" for every upper
 * transport nonce row, including the ones that are actually Device nonces.
 * The DEVICE_NONCE_SAMPLE_* entries below are such rows — identified not by
 * that label but by the nonce's own first octet (0x02, the Device nonce type
 * from Table 3.65 "Nonce types") and by the row using "DevKey" rather than
 * "AppKey" as the sample's encryption key. The transcribed hex is unaffected
 * by the mislabelling; only the row's English caption is wrong in the
 * source.
 */
export const hex = (s: string): Buffer => Buffer.from(s.replace(/\s+/g, ''), 'hex');

/**
 * Section 8.3.1 "Message #1": a Friend Request (Transport Control message,
 * CTL=1) from SRC 0x1201 to the all-friends address, SEQ=0x000001,
 * IV Index=0x12345678, TTL=0x00. Network nonce published alongside the
 * Network PDU derivation.
 */
export const NETWORK_NONCE_SAMPLE_1 = {
  ctl: true,
  ttl: 0x00,
  seq: 0x000001,
  src: 0x1201,
  ivIndex: 0x12345678,
  expected: '00800000011201000012345678',
};

/**
 * Section 8.3.2 "Message #2": a Friend Offer (Transport Control message,
 * CTL=1) from SRC 0x2345, SEQ=0x014820, same IV Index as Message #1,
 * TTL=0x00.
 */
export const NETWORK_NONCE_SAMPLE_2 = {
  ctl: true,
  ttl: 0x00,
  seq: 0x014820,
  src: 0x2345,
  ivIndex: 0x12345678,
  expected: '00800148202345000012345678',
};

/**
 * Section 8.3.18 "Message #18": a Health Current Status Access message,
 * AKF=1 (AppKey), unsegmented so ASZMIC=0. SRC 0x1201, DST 0xffff (group),
 * SEQ=0x000007, IV Index=0x12345678.
 */
export const APPLICATION_NONCE_SAMPLE_1 = {
  aszmic: false,
  seq: 0x000007,
  src: 0x1201,
  dst: 0xffff,
  ivIndex: 0x12345678,
  expected: '01000000071201ffff12345678',
};

/**
 * Section 8.3.24 "Message #24": a vendor command Access message to a
 * virtual address, AKF=1 (AppKey), segmented with a 64-bit TransMIC so
 * SZMIC=1 (ASZMIC=1). SRC 0x1234, DST 0x9736, SEQ=0x07080d,
 * IV Index=0x12345677. The only sample in this task with ASZMIC set, so it
 * is the one that pins down the ASZMIC bit's position in the nonce.
 */
export const APPLICATION_NONCE_SAMPLE_2 = {
  aszmic: true,
  seq: 0x07080d,
  src: 0x1234,
  dst: 0x9736,
  ivIndex: 0x12345677,
  expected: '018007080d1234973612345677',
};

/**
 * Section 8.3.6 "Message #6": a Config AppKey Add response encrypted with
 * DevKey, AKF=0 (device key), unsegmented so ASZMIC=0. SRC 0x0003,
 * DST 0x1201, SEQ=0x3129ab, IV Index=0x12345678. Labelled "Application
 * nonce" in the source table (see the module comment); its first octet
 * (0x02) and its use of DevKey rather than AppKey make it a Device nonce.
 */
export const DEVICE_NONCE_SAMPLE_1 = {
  aszmic: false,
  seq: 0x3129ab,
  src: 0x0003,
  dst: 0x1201,
  ivIndex: 0x12345678,
  expected: '02003129ab0003120112345678',
};

/**
 * Section 8.3.16 "Message #16": a Config AppKey Status response encrypted
 * with DevKey, AFK=0 (device key; the row calls the field "AFK", a
 * transposition typo in the source for AKF), unsegmented so ASZMIC=0.
 * SRC 0x1201, DST 0x0003, SEQ=0x000006, IV Index=0x12345678. Also labelled
 * "Application nonce" in the source table; same reasoning as
 * DEVICE_NONCE_SAMPLE_1 identifies it as a Device nonce.
 */
export const DEVICE_NONCE_SAMPLE_2 = {
  aszmic: false,
  seq: 0x000006,
  src: 0x1201,
  dst: 0x0003,
  ivIndex: 0x12345678,
  expected: '02000000061201000312345678',
};

/**
 * Network PDU sample data, transcribed from the same v1.1 document and
 * fetch as the nonce samples above (same URL, same 9,945,160-byte HTML,
 * same markup-stripping method, fetched again independently on 2026-10-06
 * for this task — table/row text compared byte-for-byte against the nonce
 * task's transcription where the two overlap, e.g. the published Network
 * nonce field of each message below, and found identical).
 *
 * Each sample's "NetworkPDU" block in Section 8.3 publishes every
 * intermediate value of the network-layer procedure (Section 3.4.4
 * "Network PDU", Section 3.9.6.3.1 "NID, EncryptionKey, and PrivacyKey",
 * Section 3.9.7.2 "Network layer authentication and encryption" and
 * Section 3.9.7.3 "Network layer obfuscation"): NetKey, the derived NID /
 * EncryptionKey / PrivacyKey, the network nonce, the cleartext header
 * fields, the cleartext TransportPDU, the NetMIC size, EncDST||
 * EncTransportPDU, NetMIC, the obfuscation's Privacy Plaintext and PECB,
 * and finally the on-the-wire NetworkPDU. Only the fields `encodeNetworkPdu`
 * actually takes as input or produces as output are kept below (`expected`
 * is the final wire NetworkPDU); the intermediate values were used only to
 * hand-verify each transcription (XORing the published CTL||TTL||SEQ||SRC
 * against the published PECB's first six octets and confirming it equals
 * the published ObfuscatedData, etc.) before being discarded, and separately
 * to run the already known-answer-tested `k2`/`ccmEncrypt`/`e` primitives
 * from `lib/mesh/crypto` against this same NetKey/plaintext and confirm each
 * one reproduces the document's own intermediate hex — neither check used
 * `encodeNetworkPdu` itself, so this is a transcription check, not a test of
 * the new code.
 *
 * NID/EncryptionKey/PrivacyKey are not transcribed as separate fields here:
 * `encodeNetworkPdu` derives them itself via `k2(networkKey, 0x00)` (the
 * managed-flooding P input fixed by Section 3.9.6.3.1), already exercised by
 * `lib/mesh/crypto/__tests__/derive.test.ts` against a different sample
 * (`K2_MASTER`). All three samples below share one NetKey, so they also
 * cross-check that the derived NID/EncryptionKey/PrivacyKey triple
 * (0x68 / 0953fa93e7caac9638f58820220a398e / 8b84eedec100067d670971dd2aa700cf
 * in the document) is reused correctly across messages rather than
 * re-derived per call.
 */

/**
 * Section 8.3.1 "Message #1": the same Friend Request as
 * NETWORK_NONCE_SAMPLE_1 (Transport Control message, CTL=1 so NetMIC is
 * 64 bits per Table 3.11). NetKey, IV Index, DST and the cleartext
 * LowerTransportPDU come from the message's own "NetworkPDU" block; the
 * expected value is that block's final "NetworkPDU" row.
 */
export const NETWORK_PDU_SAMPLE_1 = {
  networkKey: '7dd7364cd842ad18c17c2b820c84c3d6',
  ivIndex: 0x12345678,
  ctl: true,
  ttl: 0x00,
  seq: 0x000001,
  src: 0x1201,
  dst: 0xfffd,
  transportPdu: '034b50057e400000010000',
  expected: '68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df',
};

/**
 * Section 8.3.2 "Message #2": the same Friend Offer as
 * NETWORK_NONCE_SAMPLE_2, a second CTL=1 sample with a different SEQ, SRC
 * and DST and a shorter (7-octet) TransportPDU — catches a length-dependent
 * bug the first sample's 11-octet TransportPDU wouldn't.
 */
export const NETWORK_PDU_SAMPLE_2 = {
  networkKey: '7dd7364cd842ad18c17c2b820c84c3d6',
  ivIndex: 0x12345678,
  ctl: true,
  ttl: 0x00,
  seq: 0x014820,
  src: 0x2345,
  dst: 0x1201,
  transportPdu: '04320308ba072f',
  expected: '68d4c826296d7979d7dbc0c9b4d43eebec129d20a620d01e',
};

/**
 * Section 8.3.18 "Message #18": a Health Current Status Access message
 * (CTL=0, so NetMIC is 32 bits per Table 3.11) — the sample that pins down
 * the shorter MIC length and the lower, non-zero TTL (0x03) the two CTL=1
 * samples above don't exercise.
 */
export const NETWORK_PDU_SAMPLE_3 = {
  networkKey: '7dd7364cd842ad18c17c2b820c84c3d6',
  ivIndex: 0x12345678,
  ctl: false,
  ttl: 0x03,
  seq: 0x000007,
  src: 0x1201,
  dst: 0xffff,
  transportPdu: '665a8bde6d9106ea078a',
  expected: '6848cba437860e5673728a627fb938535508e21a6baf57',
};
