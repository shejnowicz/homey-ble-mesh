/**
 * Nonce, Network PDU and Upper Transport PDU sample data transcribed from
 * the Bluetooth SIG "Mesh Protocol" specification v1.1 HTML document
 * (https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/MshPRT_v1.1/out/en/index-en.html),
 * fetched and parsed programmatically (markup stripped, tables flattened to
 * row/field text, no reading off a rendered page) on 2026-10-06.
 *
 * The layouts (Table 3.66 Network nonce format, Table 3.67 CTL and TTL field
 * format, Table 3.68 Application nonce format, Table 3.69 ASZMIC and Pad
 * field format, Table 3.70 Device nonce format, all in Section 3.9.5; Table
 * 3.25 Upper Transport Access PDU fields and Figure 3.17 in Section 3.6.2)
 * and the worked examples below (Section 8.3 "Mesh message sample data",
 * messages #1, #2, #6, #16, #18, #20, #22, #23, #24) came from this same
 * v1.1 document.
 *
 * UPPER TRANSPORT ADDITION (same task that added `upperTransport.ts`): no
 * new message numbers were needed for the first three upper-transport
 * samples - they reuse Messages #6, #18 and #24, already transcribed above
 * for their nonces, now also transcribing each message's AppKey/DevKey,
 * AID (where AKF=1 publishes one), Access message, EncAccessMessage,
 * TransMIC and UpperTransportPDU rows. Also fetched independently for this
 * task (same URL, same 9,945,160-byte HTML, same method) and found
 * identical to the existing transcription where they overlap (the three
 * nonces).
 *
 * REVIEW-ROUND ADDITION: a first review of this task found that Message #24
 * was the suite's only sample combining SZMIC=1 with a virtual address, so
 * nothing varied those two independently (confirmed live: making the
 * Label UUID conditional on `szmic` at both call sites in `upperTransport.ts`
 * still passed every test). Closed by transcribing two more messages, #22
 * and #23 - both already named in this file's "SECOND, UNRELATED DEFECT"
 * note below for their own NetworkPDU errata, now also mined for their
 * upper-transport rows. Both are virtual-address, SZMIC=0 (32-bit TransMIC)
 * samples: #23 reuses Message #24's own Label UUID and destination (proving
 * the AAD requirement is about the address, not something specific to one
 * message), #22 uses a different Label UUID and destination entirely.
 *
 * Message #24 ("the Low Power node sends a vendor command to a virtual
 * address using a 64-bit TransMIC") is addressed to a VIRTUAL address, and
 * its row publishes a "Label UUID" (f4a002c7fb1e4ca0a469a021de0db875) beside
 * "DST (Virtual Address)". Section 3.4.2.3 "Virtual address" states the
 * Label UUID "shall be used as the Additional Data field of the message
 * integrity check value in the upper transport layer (see Section 3.9.7.1
 * )", and Section 3.9.7.1 gives the virtual-address case its own formula,
 * distinct from the unicast/group one:
 * `EncAccessMessage, TransMIC=AES-CCM_AppKey(application nonce, Access
 * message, Label UUID)`. Checked directly, independent of this project's own
 * code, with a standalone `node:crypto` AES-CCM call: encrypting Message
 * #24's Access message under its published AppKey and application nonce
 * WITHOUT that Label UUID as additional data produces TransMIC
 * c77bf543bdb352c1 - not the document's published aa5001f31c01cea6. With the
 * Label UUID as additional data it reproduces aa5001f31c01cea6 exactly. This
 * matters because Message #24 is also Section 8.3's only sample with the
 * ASZMIC bit set (see the existing note on APPLICATION_NONCE_SAMPLE_2 below)
 * - the one sample this task must reproduce exactly to exercise the 64-bit
 * TransMIC path - and it cannot be reproduced at all without that Label
 * UUID, a field the task-2 brief's own `UpperTransportInput` interface did
 * not include. `labelUuid` was added to that interface for exactly this
 * reason; see `upperTransport.ts`'s module header for the full account.
 *
 * A labelling quirk in the source document: the per-message sample tables in
 * Section 8.3 reuse the row label "Application nonce" for every upper
 * transport nonce row, including the ones that are actually Device nonces.
 * The DEVICE_NONCE_SAMPLE_* entries below are such rows — identified not by
 * that label but by the nonce's own first octet (0x02, the Device nonce type
 * from Table 3.65 "Nonce types") and by the row using "DevKey" rather than
 * "AppKey" as the sample's encryption key. The transcribed hex is unaffected
 * by the mislabelling; only the row's English caption is wrong in the
 * source. Re-checked for this task against the same document: every row in
 * Section 8.3 captioned "Application nonce" was listed with its own first
 * octet, and exactly two of them — Message #6 (Section 8.3.6) and Message
 * #16 (Section 8.3.16) — carry 0x02 and sit beside a "DevKey" row; no row
 * anywhere in Section 8.3 is captioned "Device nonce" at all. The note above
 * still holds exactly as written.
 *
 * A SECOND, UNRELATED DEFECT in the same Section 8.3 sample data, recorded
 * here because the lower transport layer's work will read precisely the rows
 * it affects: in Message #22 (Section 8.3.22) and Message #23 (Section
 * 8.3.23) — and, checked across the whole of Section 8.3 by comparing every
 * "LowerTransportPDU" row against the other such rows in its own message, in
 * those two messages ONLY — the "NetworkPDU" block repeats the message's
 * LowerTransportPDU with a corrupted FIRST OCTET, 0x34 where it should read
 * 0x66:
 *
 *   Message #22: ...3871b904d431526316ca48a0 — the message's own
 *     LowerTransportUnsegmentedAccessPDU block and the "TransportPDU" row
 *     inside the very same NetworkPDU block both publish a leading 66; that
 *     block's own "LowerTransportPDU" row publishes 34.
 *   Message #23: ...2456db5e3100eef65daa7a38 — same disagreement, same two
 *     values.
 *
 * 0x66 is the correct octet, and this is not a judgement call. It is what
 * each message's own published lower transport Header row says (SEG=0,
 * AKF=1, AID=0x26, i.e. 0<<7 | 1<<6 | 0x26 = 0x66, whereas 0x34 would mean
 * AKF=0 and AID=0x34, contradicting the same block's published AKF and AID),
 * and it is what AES-CCM actually recovers from each message's published
 * wire "NetworkPDU" row under the published NetKey — decrypting both PDUs
 * authenticated cleanly and returned a TransportPDU beginning 66, which
 * settles it: the authentication tag covers that octet, so a value the tag
 * verifies cannot be the corrupted one. (Messages #6 and #24 also publish
 * two differing "LowerTransportPDU" values each, but those are not errata:
 * each is a two-segment message publishing one row per segment, and each
 * row agrees with its own segment's "TransportPDU".)
 *
 * TRUST, for those two messages: the lower-transport block's own
 * "LowerTransportPDU" row and the NetworkPDU block's "TransportPDU" row.
 * DISTRUST: the "LowerTransportPDU" row inside those two NetworkPDU blocks.
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
 * Section 8.3.6 "Message #6": a Config AppKey Add REQUEST (the document's
 * own words: "A Configuration Client sends a Config AppKey Add message to
 * the Low Power node" - not a response; Message #16 below is the one
 * that's a Status response) encrypted with DevKey, AKF=0 (device key),
 * unsegmented so ASZMIC=0. SRC 0x0003, DST 0x1201, SEQ=0x3129ab,
 * IV Index=0x12345678. Labelled "Application nonce" in the source table
 * (see the module comment); its first octet (0x02) and its use of DevKey
 * rather than AppKey make it a Device nonce.
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

/**
 * Section 8.3.20 "Message #20": the only sample in this file whose IV Index
 * is ODD — 0x12345677, least significant bit 1, where every sample above
 * uses 0x12345678.
 *
 * That one bit is why this sample exists. The IV Index reaches the wire in
 * three different ways, and with an EVEN IV Index all three agree with an
 * implementation that quietly drops the bit, so none of the samples above
 * can tell a correct implementation from a broken one:
 *   - IVI, the leading octet's bit 7 (Table 3.10), is that bit, sent in
 *     clear;
 *   - the full 32-bit value is folded into the network nonce (Table 3.66),
 *     so it is authenticated;
 *   - the full 32-bit value is folded into the obfuscation's Privacy
 *     Plaintext (Section 3.9.7.3), so it masks the header.
 * On the decoding side the same bit decides whether a receiver strips IVI
 * out of the leading octet before comparing NID (Section 3.9.6.3.1): a
 * comparison that forgot to would match on an even IV Index and reject
 * EVERY inbound packet on an odd one. The design follows the IV Index from
 * secure network beacons, so it does change over time, and that failure
 * would arrive later, silently, looking like foreign traffic.
 *
 * A Health Current Status Access message (CTL=0, so a 32-bit NetMIC per
 * Table 3.11) from SRC 0x1234 to the all-nodes address 0xffff, SEQ=0x070809,
 * TTL=0x03. It uses the same managed-flooding security material as the
 * samples above — the same NetKey, deriving NID 0x68 and EncryptionKey
 * 0953fa93e7caac9638f58820220a398e — and is deliberately NOT one of Section
 * 8.3's friendship-credential samples (Messages #4-#5 and #10-#15), which
 * derive NID 0x5e and EncryptionKey be635105434859f484fc798e043ce40e from a
 * different k2 input and are not what this module implements.
 *
 * Transcription verified the same way as the samples above and, again,
 * without running the code under test — a standalone AES-CMAC/k2/AES-CCM
 * script reproduced, from the transcribed inputs alone, every one of this
 * message's own published intermediate rows: NID 68, EncryptionKey
 * 0953fa93e7caac9638f58820220a398e, PrivacyKey
 * 8b84eedec100067d670971dd2aa700cf, Network nonce
 * 00030708091234000012345677, EncDST || EncTransportPDU
 * 8c3dc87344a16c787f6b08cc897c, NetMIC 941a5368, Privacy Plaintext
 * 0000000000123456778c3dc87344a16c, PECB 5fcd59ebfaad, CTL||TTL||SEQ||SRC
 * 030708091234, and finally the wire NetworkPDU below. The document's own
 * "IVI NID" row for this message reads e8 = 0x80 | 0x68, which is the
 * document itself stating that IVI is set here.
 */
export const NETWORK_PDU_SAMPLE_ODD_IV = {
  networkKey: '7dd7364cd842ad18c17c2b820c84c3d6',
  ivIndex: 0x12345677,
  ctl: false,
  ttl: 0x03,
  seq: 0x070809,
  src: 0x1234,
  dst: 0xffff,
  transportPdu: '669c9803e110fea929e9542d',
  expected: 'e85cca51e2e8998c3dc87344a16c787f6b08cc897c941a5368',
};

/**
 * Not a specification sample: a NetKey constructed for the decoder's test
 * suite, chosen (by a one-off brute-force search over `k2`, outside the
 * code under test) because it derives the SAME NID (0x68) as the NetKey
 * above, while obviously deriving a different EncryptionKey/PrivacyKey.
 *
 * This matters because NID is only 7 bits (Section 3.9.6.3.1 notes up to
 * 2^121 possible keys share any given NID), so a real receiver cannot reject
 * foreign traffic by NID alone - it has to try decryption and let
 * authentication fail. A foreign key picked at random would, 127 times out
 * of 128, already differ in its derived NID, and a decode test built on it
 * would then pass for the wrong reason: rejected by the cheap NID
 * short-circuit before AES-CCM authentication ever runs. This key is picked
 * so the "foreign key" decode test actually exercises - and can actually
 * catch a regression in - the authentication check itself.
 */
export const FOREIGN_NETWORK_KEY_SAME_NID = '00000000000000000000000000000033';

/**
 * Upper Transport Access PDU sample data (Section 3.6.2, Table 3.25;
 * encryption rule in Section 3.9.7.1). Each sample's "UpperTransportAccessPDU"
 * block in its Section 8.3 message publishes the Access message, the
 * key, the nonce (already cross-checked against the nonce samples above),
 * AID (when AKF=1 - the AppKey identifier derived by k4, published in the
 * message's LowerTransport block; not produced or consumed by
 * `upperTransport.ts`, which has no use for it, but transcribed anyway so
 * the fixture carries it), EncAccessMessage, TransMIC and the assembled
 * UpperTransportPDU. Only the fields `encryptUpperTransport`/
 * `decryptUpperTransport` actually take as input or produce as output are
 * used by the module; `expected` is the UpperTransportPDU
 * (EncAccessMessage || TransMIC).
 *
 * Transcription for all five was independently cross-checked with a
 * standalone AES-CCM call via `node:crypto` directly (not through
 * `ccmEncrypt`/`encryptUpperTransport`), reusing each message's application
 * or device nonce (the first three already known-answer-tested above as
 * `APPLICATION_NONCE_SAMPLE_1`, `DEVICE_NONCE_SAMPLE_1`,
 * `APPLICATION_NONCE_SAMPLE_2`; Messages #22/#23's nonces are new to this
 * file but built from the same published SEQ/SRC/DST/IV Index fields and
 * verified the same way): every one reproduced its message's published
 * EncAccessMessage and TransMIC exactly.
 */

/**
 * Section 8.3.18 "Message #18": the same Health Current Status message as
 * APPLICATION_NONCE_SAMPLE_1 - AppKey, unsegmented (so a 32-bit TransMIC,
 * szmic=false), unicast/group destination (DST 0xffff, no Label UUID
 * published for this message - not a virtual address). AID 0x26 (published
 * in the message's LowerTransport block).
 */
export const UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY = {
  keyKind: 'application' as const,
  key: '63964771734fbd76e3b40519d1d94a48',
  aid: 0x26,
  seq: 0x000007,
  src: 0x1201,
  dst: 0xffff,
  ivIndex: 0x12345678,
  szmic: false,
  accessPayload: '0400000000',
  expected: '5a8bde6d9106ea078a',
};

/**
 * Section 8.3.6 "Message #6": the same Config AppKey Add REQUEST (see
 * DEVICE_NONCE_SAMPLE_1's note above - the document has the Configuration
 * Client sending this, it is not a response) as DEVICE_NONCE_SAMPLE_1 -
 * DevKey, sent in two lower-transport segments but still with a 32-bit
 * TransMIC (szmic=false; see the module header on why a 64-bit TransMIC is
 * not available here). The message's LowerTransport block publishes AID
 * 0x00, but that is not a "derived" AID in the sense the other samples'
 * AID is - AKF=0 here (device key, not application key), and AID only ever
 * identifies which application key was used, so this field is not
 * transcribed as `aid` for this sample: 0x00 is a fixed placeholder for
 * "not applicable", not a value k4 produced.
 */
export const UPPER_TRANSPORT_SAMPLE_DEVICE_KEY = {
  keyKind: 'device' as const,
  key: '9d6dd0e96eb25dc19a40ed9914f8f03f',
  seq: 0x3129ab,
  src: 0x0003,
  dst: 0x1201,
  ivIndex: 0x12345678,
  szmic: false,
  accessPayload: '0056341263964771734fbd76e3b40519d1d94a48',
  expected: 'ee9dddfd2169326d23f3afdfcfdc18c52fdef772e0e17308',
};

/**
 * Section 8.3.22 "Message #22": "The Low Power node sends a vendor command
 * to a virtual address." AppKey (same AppKey as Messages #18/#24), AID
 * 0x26, unsegmented (SEG=0, so szmic=false - a 32-bit TransMIC), addressed
 * to a VIRTUAL destination (DST 0xb529, hashed from the published Label
 * UUID 0073e7e4d8b9440faf8415df4c56c0e1) - a DIFFERENT Label UUID and
 * destination than Message #24's. Exists in this file specifically to
 * exercise SZMIC=0 and a virtual address (Label UUID additional data)
 * TOGETHER: Message #24 is the only sample with SZMIC=1, and until this
 * sample was added it was also the only virtual-address sample, so nothing
 * in the suite varied those two dimensions independently (confirmed by
 * mutation - see `upperTransport.test.ts`).
 */
export const UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC = {
  keyKind: 'application' as const,
  key: '63964771734fbd76e3b40519d1d94a48',
  aid: 0x26,
  seq: 0x07080b,
  src: 0x1234,
  dst: 0xb529,
  ivIndex: 0x12345677,
  szmic: false,
  labelUuid: '0073e7e4d8b9440faf8415df4c56c0e1',
  accessPayload: 'd50a0048656c6c6f',
  expected: '3871b904d431526316ca48a0',
};

/**
 * Section 8.3.23 "Message #23": "The Low Power node sends a vendor command
 * to a different virtual address" (different from Message #22's, that is -
 * the document's own words). AppKey (same as #18/#22/#24), AID 0x26,
 * unsegmented (szmic=false, 32-bit TransMIC), addressed to the SAME
 * virtual destination and Label UUID as Message #24 (DST 0x9736, Label UUID
 * f4a002c7fb1e4ca0a469a021de0db875) but with SZMIC=0 instead of #24's
 * SZMIC=1 - the two messages differ only in SEQ, SZMIC and the TransMIC
 * length that follows from it, isolating the SZMIC dimension from the
 * Label UUID/virtual-address one even more directly than Message #22 does.
 */
export const UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL = {
  keyKind: 'application' as const,
  key: '63964771734fbd76e3b40519d1d94a48',
  aid: 0x26,
  seq: 0x07080c,
  src: 0x1234,
  dst: 0x9736,
  ivIndex: 0x12345677,
  szmic: false,
  labelUuid: 'f4a002c7fb1e4ca0a469a021de0db875',
  accessPayload: 'd50a0048656c6c6f',
  expected: '2456db5e3100eef65daa7a38',
};

/**
 * Section 8.3.24 "Message #24": the same vendor command as
 * APPLICATION_NONCE_SAMPLE_2 - AppKey, AID 0x26, segmented with SZMIC=1
 * (szmic=true, the only Section 8.3 sample with the ASZMIC bit set),
 * addressed to a VIRTUAL address (DST 0x9736, hashed from the published
 * Label UUID f4a002c7fb1e4ca0a469a021de0db875). Reproducing this sample's
 * published TransMIC requires that Label UUID as AES-CCM additional data -
 * see the module header above and `upperTransport.ts`'s own header for why
 * `labelUuid` exists on `UpperTransportInput` at all.
 */
export const UPPER_TRANSPORT_SAMPLE_SZMIC = {
  keyKind: 'application' as const,
  key: '63964771734fbd76e3b40519d1d94a48',
  aid: 0x26,
  seq: 0x07080d,
  src: 0x1234,
  dst: 0x9736,
  ivIndex: 0x12345677,
  szmic: true,
  labelUuid: 'f4a002c7fb1e4ca0a469a021de0db875',
  accessPayload: 'ea0a00576f726c64',
  expected: 'c3c51d8e476b28e3aa5001f31c01cea6',
};
