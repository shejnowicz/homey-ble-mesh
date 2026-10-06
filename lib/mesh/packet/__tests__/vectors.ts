/**
 * Nonce sample data transcribed from the Bluetooth SIG "Mesh Protocol"
 * specification v1.1 HTML document
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
