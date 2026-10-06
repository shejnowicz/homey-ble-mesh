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
 * 3.25 Upper Transport Access PDU fields and Figure 3.17 in Section 3.6.2;
 * Table 3.15 Lower Transport PDU format types, Table 3.17 Unsegmented Access
 * message format and Table 3.19 Unsegmented Control message format, all in
 * Section 3.5.2) and the worked examples below (Section 8.3 "Mesh message
 * sample data", messages #1, #2, #6, #16, #18, #20, #22, #23, #24) came from
 * this same v1.1 document.
 *
 * LOWER TRANSPORT ADDITION (same task that added `lowerTransport.ts`): no new
 * message numbers were needed - every message this task's tests use was
 * already listed above for its nonce or upper-transport row. What is new is
 * reading each message's own "LowerTransportUnsegmentedAccessPDU" or
 * "LowerTransportUnsegmentedControlPDU" block (Section 8.3), which Messages
 * #18, #20, #22 and #23 publish AKF/AID/Header directly, and Messages #1/#2
 * publish Opcode/Header directly, independent of the `transportPdu` hex
 * blobs already transcribed below - this is the "fixture data nobody read"
 * the task-3 brief warned about, now actually exercised. Fetched the same
 * 9,945,160-byte document independently for this task on 2026-10-06 and
 * confirmed, per message: Message #1 Opcode=03, Header=03; Message #2
 * Opcode=04, Header=04; Message #18 AKF=01/AID=26/Header=66; Message #20
 * AKF=01/AID=26/Header=66; Message #22 AKF=01/AID=26/Header=66,
 * LowerTransportPDU=663871b904d431526316ca48a0 (the CORRECT leading octet -
 * see the errata note above, which this same fetch re-confirmed by
 * comparing every "LowerTransportPDU" row in Section 8.3 against its
 * sibling rows); Message #23 AKF=01/AID=26/Header=66,
 * LowerTransportPDU=662456db5e3100eef65daa7a38 (same errata, same
 * resolution). Message #24's own block (SEG=01, AKF=01, AID=26, SZMIC=01,
 * SeqZero=80d, SegO=00, SegN=01, Header=e6a03401,
 * LowerTransportPDU=e6a03401c3c51d8e476b28e3aa5001f3) is a SEGMENTED
 * message (SEG=1) - transcribed anyway, as `LOWER_TRANSPORT_SAMPLE_SEGMENTED`
 * below, specifically because it is genuine specification data with the SEG
 * bit set: `lowerTransport.ts`'s decoders must return null for exactly this
 * bit, and testing that against a fabricated byte would be the same kind of
 * unfalsifiable fixture this note exists to avoid.
 *
 * LOWER TRANSPORT REVIEW ROUND: a review of this task found that every
 * access sample above has AKF=1 - so an encoder/decoder that silently
 * ignored `akf` and always treated it as 1 would still pass every test
 * (confirmed live by mutation; see `lowerTransport.test.ts`). Closed by
 * transcribing Message #16's own "LowerTransportUnsegmentedAccessPDU" block
 * (AKF=0, the DEVICE-key Config AppKey Status response already known as
 * DEVICE_NONCE_SAMPLE_2) as `LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY`
 * below - fetched the same way as everything else in this addition. The
 * review also found four fixture fields (opcode on NETWORK_PDU_SAMPLE_1/2,
 * akf/aid on NETWORK_PDU_SAMPLE_3/ODD_IV) that duplicated values already
 * live in the LOWER_TRANSPORT_SAMPLE_* fixtures below with nothing reading
 * either copy - closed not by deleting them but by cross-checking the two
 * halves against each other in `lowerTransport.test.ts` (and, where a
 * message has one, against its `UPPER_TRANSPORT_SAMPLE_*.aid` too), so a
 * future edit to either copy that silently diverges from its sibling now
 * fails a test instead of sitting unread.
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
 *
 * SEGMENTATION TASK ADDITION (`lowerTransport.ts`'s Segmented Access message
 * support): fetched the same 9,945,160-byte v1.1 document independently for
 * this task on 2026-10-06 (same URL, same markup-stripping method: `</td>`/
 * `</tr>` converted to separators before stripping tags, entities
 * unescaped). Section 3.5.2.2 "Segmented Access message", Table 3.18
 * "Segmented Access message format", gives the header layout (SEG 1 bit,
 * AKF 1, AID 6, SZMIC 1, SeqZero 13, SegO 5, SegN 5 - 32 bits/4 octets,
 * packed MSB-first, matching the bit positions `lowerTransport.test.ts`'s
 * existing per-bit block already proved against `LOWER_TRANSPORT_SAMPLE_
 * SEGMENTED.header`) and the segment-size rule: "For all segments except
 * the last segment, Segment m is octet 12*m to 12*m+11. In the last
 * segment, Segment m is octet 12*m through the end of the message." - i.e.
 * every non-last segment carries exactly 12 octets, so SegN (the zero-based
 * last segment number) is `ceil(upperTransportPduLength / 12) - 1`. Section
 * 2.3.3 "Messages" additionally states the overall ceiling this implies:
 * "The lower transport layer provides a SAR mechanism capable of
 * transporting up to 32 Access or Transport Control message segments. The
 * maximum Upper Transport Access PDU size when using a SAR is 384 octets."
 * (32 segments x 12 octets - consistent with SegO/SegN's own 5-bit width,
 * 0-31).
 *
 * This task's new fixture data (both added to the EXISTING
 * `LOWER_TRANSPORT_SAMPLE_SEGMENTED` object and the new
 * `LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY` below) reuses Messages #24
 * and #6, already transcribed above for their nonce/upper-transport rows -
 * no new message numbers were needed. What is new is each message's SECOND
 * "LowerTransportSegmentedAccessPDU" block (Section 8.3's per-message
 * tables publish one such block per segment for a two-segment message) and,
 * for Message #24, the Access-message block's own `Segment#0`/`Segment#1`
 * rows - read independently for this task; see the module-scope comments on
 * each constant for the exact rows and values found.
 *
 * SEGMENT ACKNOWLEDGMENT TASK ADDITION (`lowerTransport.ts`'s
 * `encodeSegmentAck`/`decodeSegmentAck`): fetched the same 9,945,160-byte
 * v1.1 document independently for this task on 2026-10-06 (same URL, same
 * `</td>`/`</tr>`-before-tag-stripping method). Section 3.5.2.3.1 "Segment
 * Acknowledgment message", Table 3.21 "Segment Acknowledgment message
 * format" (Figure 3.14), gives the field layout: SEG 1 bit (fixed 0),
 * Opcode 7 bits (fixed 0x00), OBO 1, SeqZero 13, RFU 2, AckedSegments 32 -
 * 56 bits/7 octets total, of which the first octet (SEG||Opcode) is the
 * SAME header octet the Unsegmented Control message format above already
 * builds/reads, and the remaining 48 bits/6 octets are this message's own
 * Parameters, packed MSB-first in that field order.
 *
 * TWO new message numbers, both from the friendship procedure's worked
 * example (Section 8.3.4 through 8.3.15) - not previously transcribed
 * anywhere in this file for any purpose. Checked directly, independent of
 * this project's own code: both messages' own "NetworkPDU" blocks publish
 * NetKey 7dd7364cd842ad18c17c2b820c84c3d6 and derive NID 0x68 - the SAME
 * NetKey/NID as every other sample in this file, NOT the friendship
 * SECURITY CREDENTIAL (NID 0x5e) `NETWORK_PDU_SAMPLE_ODD_IV`'s own comment
 * above says this project does not implement; that note is about a
 * different, unrelated set of messages (the ones whose Network PDU is
 * itself encrypted/authenticated under rotated friendship credentials), not
 * about these two, whose network-layer security is entirely ordinary. Only
 * each message's own "Transport Control message" block (its Segment
 * Acknowledgment fields) and its "LowerTransportUnsegmentedControlPDU"
 * block (Header/Parameters/LowerTransportPDU, the only rows
 * `lowerTransport.ts` itself reads) were mined for this task; the
 * surrounding friendship procedure (why a Friend node is acknowledging on
 * a Low Power node's behalf) is scene-setting, not something this module
 * implements or needs.
 *
 * Section 8.3.7 "Message #7" ("A friend of the destination acknowledges
 * only one of the segments"): Opcode=00 (Segment Acknowledgment), OBO=01,
 * SeqZero=09ab, BlockAck=00000002 - these four are the per-message
 * "Transport Control message" block's own labelled fields, already decoded
 * by hand as a cross-check before being trusted: SeqZero 0x9ab's top 7 bits
 * (0x9ab >>> 6 = 0x26) and bottom 6 bits (0x9ab & 0x3f = 0x2b) pack with
 * OBO=1 into octets a6/ac exactly as the message's own
 * "LowerTransportUnsegmentedControlPDU" block publishes them (Header=00,
 * its own "UpperTransportPDU" row - this block's name for the Segment
 * Acknowledgment message's Parameters field -
 * a6ac00000002, LowerTransportPDU=00a6ac00000002 = Header||Parameters).
 * BlockAck=00000002 (bit 1 set, bit 0 clear) is also the fixture this
 * task's known-answer test relies on to be asymmetric under a full 32-bit
 * reversal (0x00000002 reversed is 0x40000000, not itself) - recorded here,
 * not just in the test file, since it is a property of the TRANSCRIBED
 * value, not of the test.
 *
 * Section 8.3.9 "Message #9" ("The Friend node receives this last segment
 * and sends an acknowledgment of this last segment"): same OBO=01,
 * SeqZero=09ab as Message #7 (the same in-flight transfer, one message
 * later), but BlockAck=00000003 - BOTH of a 2-segment message's bits set
 * (0b11), i.e. a COMPLETE acknowledgment, not a partial one like Message
 * #7's. Header=00, Parameters=a6ac00000003,
 * LowerTransportPDU=00a6ac00000003 - verified by hand the same way as
 * Message #7's above.
 *
 * ACCESS LAYER TASK ADDITION (`access.ts`'s `encodeAccessMessage`/
 * `decodeAccessMessage`): fetched the same 9,945,160-byte v1.1 document
 * independently for this task on 2026-10-06 (same URL, same
 * `</td>`/`</tr>`-before-tag-stripping method). Adds Table 3.60 "Access
 * message fields" and Table 3.62 "Opcode formats" (both Section 3.7.2/
 * 3.7.2.1) to the layouts list above, plus Section 3.7.1 "Endianness" (the
 * access layer's own multi-octet values are little-endian, unlike the
 * big-endian network/lower/upper transport layers already transcribed
 * above - see `ACCESS_SAMPLE_CONFIG_APPKEY_STATUS`'s own comment, just
 * below this header, for the full quote and the published-sample
 * cross-check). No new message numbers were needed except Message #16
 * (Section 8.3.16, already listed above for its Device nonce and
 * encrypted Upper Transport PDU) - what is new is that message's own
 * plaintext "Access message" block, the only sample in this file with a
 * genuine 2-octet SIG opcode. Messages #6, #18, #22, #23 and #24's own
 * "Access message"/"Opcode" rows were ALSO read for the first time here
 * (their `accessPayload` fields were already transcribed for the upper
 * transport task, but nothing had read the per-message Opcode row
 * confirming that leading octet really is this layer's own field) -
 * reused as-is, not duplicated under new constants, per this file's
 * established convention.
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
 *
 * `opcode` is this same message's own "LowerTransportUnsegmentedControlPDU"
 * block, read independently for the lower transport task (Section 8.3.1:
 * SEG=00, Opcode=03, Header=03) - `transportPdu` above is Header||Parameters
 * (03 || 4b50057e400000010000), so `opcode` plus `transportPdu.slice(2)` is
 * exactly `lowerTransport.ts`'s `parameters`.
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
  opcode: 0x03,
  expected: '68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df',
};

/**
 * Section 8.3.2 "Message #2": the same Friend Offer as
 * NETWORK_NONCE_SAMPLE_2, a second CTL=1 sample with a different SEQ, SRC
 * and DST and a shorter (7-octet) TransportPDU — catches a length-dependent
 * bug the first sample's 11-octet TransportPDU wouldn't.
 *
 * `opcode` from this message's own "LowerTransportUnsegmentedControlPDU"
 * block (Section 8.3.2: SEG=00, Opcode=04, Header=04), read independently
 * for the lower transport task - a second, different opcode than Message
 * #1's, so a decoder that only happened to work for opcode 0x03 cannot pass
 * both.
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
  opcode: 0x04,
  expected: '68d4c826296d7979d7dbc0c9b4d43eebec129d20a620d01e',
};

/**
 * Section 8.3.18 "Message #18": a Health Current Status Access message
 * (CTL=0, so NetMIC is 32 bits per Table 3.11) — the sample that pins down
 * the shorter MIC length and the lower, non-zero TTL (0x03) the two CTL=1
 * samples above don't exercise.
 *
 * `akf`/`aid` from this message's own "LowerTransportUnsegmentedAccessPDU"
 * block (Section 8.3.18: SEG=00, AKF=01, AID=26, Header=66), read
 * independently for the lower transport task; `transportPdu` above is
 * Header||UpperTransportPDU (66 || 5a8bde6d9106ea078a), and that
 * UpperTransportPDU is the same value already transcribed as
 * `UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.expected` below.
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
  akf: true,
  aid: 0x26,
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
  // `akf`/`aid` from this message's own "LowerTransportUnsegmentedAccessPDU"
  // block (Section 8.3.20: SEG=00, AKF=01, AID=26, Header=66), read
  // independently for the lower transport task - the same AID as Message
  // #18 (both use the same AppKey), but a different IV Index/SEQ/TTL
  // (this is the "odd IV Index" sample, see the module note above it).
  akf: true,
  aid: 0x26,
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

/**
 * Access message sample data (Section 3.7.2 "Access message", Table 3.60
 * "Access message fields": Opcode 1/2/3 octets, Parameters 0-379 octets).
 * Fetched the same 9,945,160-byte v1.1 document independently for this task
 * on 2026-10-06 (same URL, same `</td>`/`</tr>`-before-tag-stripping
 * method).
 *
 * The opcode FORMAT rules themselves (Section 3.7.2.1 "Opcode field", Table
 * 3.62 "Opcode formats") are:
 *
 *   Opcode Format                      | Description
 *   -----------------------------------|---------------------
 *   0xxxxxxx (excluding 01111111)      | 1-octet Opcodes
 *   01111111                           | Reserved for Future Use
 *   10xxxxxx xxxxxxxx                  | 2-octet Opcodes
 *   11xxxxxx zzzzzzzz zzzzzzzz         | 3-octet Opcodes
 *
 * i.e. 1-octet opcodes are 0x00-0x7E (0x7F reserved), 2-octet opcodes have
 * their first octet in 0x80-0xBF, and 3-octet ("vendor") opcodes have their
 * first octet in 0xC0-0xFF with the company identifier in the second/third
 * octets ("z" in the table). Section 3.7.2.1's own prose: "The company
 * identifiers are 16-bit values defined by the Bluetooth SIG and are coded
 * into the second and third octets of the 3-octet opcodes ... using
 * endianness as defined in Section 3.7.1" - and Section 3.7.1 ("Endianness",
 * inside the Access layer chapter) states: "All multiple-octet numeric
 * values in this layer shall be little-endian as described in Section
 * 3.1.1.2." This is NOT the byte order used by the network/lower transport/
 * upper transport layers below it: Section 3.1.1 ("Endianness and field
 * ordering") draws the contrast explicitly - "For the network layer, lower
 * transport layer, upper transport layer, mesh beacons, and Provisioning,
 * all multiple-octet numeric values shall be sent in big-endian ... For the
 * access layer and Foundation Models, all multiple-octet numeric values
 * shall be little-endian" - i.e. every SRC/DST/SEQ/IV Index this file's
 * other sections transcribe is big-endian (as `network.ts`/`nonce.ts`
 * already encode them), while the company identifier packed into a vendor
 * opcode is little-endian: least-significant octet first. Section 3.7.2.1's
 * own worked example proves the direction, not just the general rule: "when
 * the manufacturer-specific opcode is equal to 0x23 and the company
 * identifier is equal to 0x0136 [4], then the 3-octet opcode is equal to
 * 0xE3 0x36 0x01" - company ID 0x0136's LOW byte (0x36) is written first,
 * its HIGH byte (0x01) second.
 *
 * Section 3.7.3.4 "Message error procedure" gives the receive-side rule for
 * an opcode nothing recognises (the reserved value included, since no model
 * is ever bound to it): "When receiving a message that is not understood by
 * an element, it shall ignore the message, ... [including when] the opcode
 * field of the Access message is unknown by the receiving element."
 *
 * Three of the five vendor-opcode messages already transcribed above
 * (#22, #23, #24) publish their own "Access message" block with an explicit
 * "Opcode" row, independently confirming both the company identifier VALUE
 * and its byte order straight from the primary source, not merely derived
 * from the general endianness rule: Message #22/#23 (Section 8.3.22/
 * 8.3.23): "Opcode : 15 : 000a (Vendor 15 : 000a)" - vendor sub-opcode 0x15,
 * company ID 0x000A - against wire bytes d5 0a 00 (`UPPER_TRANSPORT_SAMPLE_
 * VIRTUAL_SHORT_MIC(_SHARED_LABEL).accessPayload` below), where byte1=0x0a
 * is the company ID's LOW octet and byte2=0x00 its HIGH octet - exactly
 * what reading them little-endian (0x0a | 0x00<<8 = 0x000a) produces, and
 * NOT what reading them big-endian (0x0a00 = 2560) would. Message #24
 * (Section 8.3.24) is more explicit still, captioning the company ID by
 * name: "Company ID: 0x000A - Cambridge Silicon Radio (See Bluetooth
 * Assigned Numbers)" and "Vendor Opcode: 0x2A", with its own Access message
 * row reading "Vendor Opcode : 0x2A : 0x000A (Opcode 2a : Company ID 000a)"
 * against wire bytes ea 0a 00 (`UPPER_TRANSPORT_SAMPLE_SZMIC.accessPayload`
 * below) - same company ID, same byte pair, different vendor sub-opcode
 * (0x2A vs 0x15), so between the two messages the test suite exercises two
 * different first-octet values while the company-ID byte pair (0x0a, 0x00)
 * - asymmetric, not a palindrome like 0x0101 - stays fixed, which is what
 * actually catches a byte-order bug: swapping the two octets changes the
 * decoded company ID (0x000a vs 0x0a00) regardless of which message's
 * vendor sub-opcode is under test.
 *
 * Messages #6 and #18, transcribed above for their upper-transport rows,
 * ALSO publish their own "Access message" block with an explicit "Opcode"
 * row - read here for the first time, independent confirmation that the
 * leading octet already relied on by `lowerTransport.ts`'s AKF/AID decoding
 * is genuinely this message's OPCODE octet, not a coincidence of bit
 * position: Message #6 (Section 8.3.6): "Opcode : 00 (Config AppKey Add)"
 * against `UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.accessPayload` (leading byte
 * 0x00 - also the reused-elsewhere 1-octet form's lower boundary value).
 * Message #18 (Section 8.3.18): "Opcode : 04 (Health Current Status)"
 * against `UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.accessPayload` (leading
 * byte 0x04). Both are reused as-is below (no new constant), per this
 * file's own "reuse rather than duplicate" convention - search this file for
 * `accessPayload` to see every opcode form a published sample already
 * covers before adding another.
 *
 * Message #16's own "Access message" block (Section 8.3.16), by contrast, IS
 * new: nothing above transcribes its plaintext Access message (only its
 * ENCRYPTED ciphertext, `LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY`'s
 * `upperTransportPdu`, and its Device nonce, `DEVICE_NONCE_SAMPLE_2`, were
 * read before) - and it is the only sample anywhere in this file with a
 * genuine 2-octet SIG opcode, so it is the one new fixture this task
 * actually needs. "Opcode : 8003 (Config AppKey Status)", Status=00,
 * NetKeyIndex=456, AppKeyIndex=123, "Access message : 800300563412" - wire
 * bytes 80 03 read in the SAME order Table 3.62 displays them ("10xxxxxx
 * xxxxxxxx", first octet most significant), matching the document's own
 * "8003" caption directly: unlike the vendor opcode's embedded company ID,
 * the 2-octet opcode's own two octets are NOT byte-swapped.
 */
export const ACCESS_SAMPLE_CONFIG_APPKEY_STATUS = {
  opcode: 0x8003,
  parameters: '00563412',
  expected: '800300563412',
};

/**
 * Lower Transport PDU sample data (Section 3.5.2; Table 3.15 "Lower
 * Transport PDU format types", Table 3.17 "Unsegmented Access message
 * format", Table 3.19 "Unsegmented Control message format"). Every sample below
 * reuses a message already transcribed above for its nonce and/or
 * upper-transport row; what is new here is each message's own
 * "LowerTransportUnsegmentedAccessPDU"/"LowerTransportUnsegmentedControlPDU"
 * block, read independently for this task (see the module header's "LOWER
 * TRANSPORT ADDITION" note) - the AID/AKF fields the upper-transport task
 * transcribed as unread fixture data are, for messages #18/#20, this task's
 * first real consumer.
 *
 * `expected` is the complete on-the-wire Lower Transport PDU
 * (Header||Parameters for control, Header||UpperTransportAccessPDU for
 * access) - the same bytes `NETWORK_PDU_SAMPLE_*.transportPdu` above already
 * carries for Messages #1/#2/#18/#20, repeated here so this section is a
 * self-contained, readable record of exactly what `lowerTransport.ts`
 * encodes/decodes, without sending a reader back and forth between two
 * sections for the same four messages.
 */

/**
 * Section 8.3.1 "Message #1": the same Friend Request as
 * NETWORK_PDU_SAMPLE_1 - a Transport Control message (CTL=1), unsegmented
 * (SEG=0), Opcode 0x03 (Friend Request), Parameters the Friend Request's own
 * 10-octet body. `expected` is NETWORK_PDU_SAMPLE_1.transportPdu, Header
 * (03) || Parameters.
 */
export const LOWER_TRANSPORT_SAMPLE_CONTROL_1 = {
  opcode: 0x03,
  parameters: '4b50057e400000010000',
  expected: '034b50057e400000010000',
};

/**
 * Section 8.3.2 "Message #2": the same Friend Offer as NETWORK_PDU_SAMPLE_2
 * - Transport Control (CTL=1), unsegmented, Opcode 0x04 (Friend Offer) - a
 * different opcode and a shorter Parameters field than Message #1's, so a
 * decoder/encoder that only works for one opcode or one length cannot pass
 * both. `expected` is NETWORK_PDU_SAMPLE_2.transportPdu.
 */
export const LOWER_TRANSPORT_SAMPLE_CONTROL_2 = {
  opcode: 0x04,
  parameters: '320308ba072f',
  expected: '04320308ba072f',
};

/**
 * Section 8.3.18 "Message #18": the same Health Current Status Access
 * message as NETWORK_PDU_SAMPLE_3/UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY -
 * Access message (CTL=0), unsegmented, AKF=1, AID=0x26, a non-virtual
 * destination (0xffff). `expected` is NETWORK_PDU_SAMPLE_3.transportPdu,
 * Header (66) || UpperTransportAccessPDU.
 */
export const LOWER_TRANSPORT_SAMPLE_ACCESS_1 = {
  akf: true,
  aid: 0x26,
  upperTransportPdu: '5a8bde6d9106ea078a',
  expected: '665a8bde6d9106ea078a',
};

/**
 * Section 8.3.20 "Message #20": the same odd-IV-Index Health Current Status
 * message as NETWORK_PDU_SAMPLE_ODD_IV - same AKF/AID as Message #18 (same
 * AppKey) but a different, longer UpperTransportAccessPDU, catching a
 * length-dependent bug Message #18's shorter one wouldn't. `expected` is
 * NETWORK_PDU_SAMPLE_ODD_IV.transportPdu.
 */
export const LOWER_TRANSPORT_SAMPLE_ACCESS_2 = {
  akf: true,
  aid: 0x26,
  upperTransportPdu: '9c9803e110fea929e9542d',
  expected: '669c9803e110fea929e9542d',
};

/**
 * Section 8.3.16 "Message #16": the same Config AppKey Status response as
 * DEVICE_NONCE_SAMPLE_2 - a DEVICE-key Access message, so AKF=0 (not 1, as
 * every other access sample above has it). This is the only AKF=0
 * unsegmented access sample in this file, and without it nothing would
 * notice an encoder/decoder that silently ignored `akf` in either direction
 * (confirmed by mutation - see `lowerTransport.test.ts`): every other
 * sample's published Header has bit 6 set, so a decoder hardcoded to
 * report `akf: true` would still match every one of them.
 *
 * This message's own "LowerTransportUnsegmentedAccessPDU" block publishes
 * SEG=00, AID=00, Header=00. AID=00 is not a derived value here - Section
 * 3.6.4.1 "Transmitting an Upper Transport PDU" states the rule normatively:
 * "If the device key is used, then the AKF field shall be set to 0 and the
 * AID field shall be set to 0b000000." (the same section already cited in
 * this module's own header for how AKF/AID get set in general; see also
 * `UPPER_TRANSPORT_SAMPLE_DEVICE_KEY`'s note on the same point). The block's
 * own row for this field is labelled "AFK" in the source document - the
 * same transposition typo already noted in this file's header comment for
 * DEVICE_NONCE_SAMPLE_1/_2 (it is the AKF field; the hex value is
 * unaffected, only the row's English label is wrong).
 */
export const LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY = {
  akf: false,
  aid: 0x00,
  upperTransportPdu: '89511bf1d1a81c11dcef',
  expected: '0089511bf1d1a81c11dcef',
};

/**
 * Section 8.3.22 "Message #22": the same virtual-address vendor command as
 * UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC - unsegmented, AKF=1, AID=0x26.
 * Not one of the NETWORK_PDU_SAMPLE_* above (those don't cover this
 * message), so `expected` is transcribed fresh here: this message's own
 * "LowerTransportUnsegmentedAccessPDU" block publishes
 * LowerTransportPDU=663871b904d431526316ca48a0 - the CORRECT leading octet
 * (0x66 = SEG 0 | AKF 1 | AID 0x26); the module header's errata note is
 * about a DIFFERENT row (inside this same message's "NetworkPDU" block,
 * which repeats the LowerTransportPDU with a corrupted leading 0x34) and
 * does not apply to the value transcribed here.
 */
export const LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_1 = {
  akf: true,
  aid: 0x26,
  upperTransportPdu: '3871b904d431526316ca48a0',
  expected: '663871b904d431526316ca48a0',
};

/**
 * Section 8.3.23 "Message #23": the same virtual-address vendor command as
 * UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL - unsegmented,
 * AKF=1, AID=0x26, same errata caveat as Message #22 above (this message's
 * own LowerTransport block's 0x66 leading octet is the correct, authenticated
 * value; a different row inside its NetworkPDU block is the corrupted one).
 */
export const LOWER_TRANSPORT_SAMPLE_ACCESS_VIRTUAL_2 = {
  akf: true,
  aid: 0x26,
  upperTransportPdu: '2456db5e3100eef65daa7a38',
  expected: '662456db5e3100eef65daa7a38',
};

/**
 * Section 8.3.24 "Message #24": the same vendor command as
 * UPPER_TRANSPORT_SAMPLE_SZMIC, but SEGMENTED (SEG=1) - this message's own
 * "LowerTransportSegmentedAccessPDU" block publishes SEG=01, AKF=01, AID=26,
 * SZMIC=01, SeqZero=80d, SegO=00, SegN=01, Header=e6a03401 (4 octets, not 1
 * - a Segmented Access message's header carries more than SEG||AKF||AID,
 * which segmentation is a LATER task's job to decode), `segment0`
 * (`c3c51d8e476b28e3aa5001f3`, this message's single published segment),
 * and `pdu` (Header||segment0, the complete on-the-wire
 * LowerTransportPDU=e6a03401c3c51d8e476b28e3aa5001f3).
 *
 * An OBJECT, not a bare hex string, deliberately: the segmentation task
 * will want these other fields (seqZero/segO/segN/szmic) anyway, and a
 * later task adding them to a bare string would force a breaking shape
 * change (and a vectors.ts/test.ts merge conflict) right when it is already
 * busy implementing segmentation; recording them now, as inert data this
 * task's own code does not read, costs nothing today. `aid` is cross-
 * checked against `UPPER_TRANSPORT_SAMPLE_SZMIC.aid` and `segment0` against
 * the first 12 octets of its `expected` below, in `lowerTransport.test.ts`.
 *
 * Not decoded for its content by this task - segmentation is explicitly out
 * of scope. `pdu` exists solely so `decodeUnsegmentedAccess`/
 * `decodeUnsegmentedControl`'s "SEG=1 returns null" path is tested against
 * genuine specification bytes with the bit actually set, rather than an
 * arbitrary fabricated byte nothing published ever confirms is realistic.
 *
 * SEGMENTATION TASK ADDITION: the second segment (SegO=1) of this same
 * message, read from the SAME Section 8.3.24 block as everything above -
 * fetched independently for this task (same URL, same 9,945,160-byte HTML,
 * same markup-stripping method, 2026-10-06). The "Access message" block's
 * own `Segment#1` row reads `1c01cea6` (the complete `UpperTransportPDU` row
 * there, `c3c51d8e476b28e3aa5001f31c01cea6`, is `UPPER_TRANSPORT_SAMPLE_SZMIC
 * .expected` above with `segment0` as its first 12 octets and `segment1` as
 * the remaining 4 - cross-checked in `lowerTransport.test.ts`). The message's
 * own SECOND "LowerTransportSegmentedAccessPDU" block (distinct from the one
 * `header`/`pdu` above transcribe, which is the FIRST) publishes this
 * segment's own CTL/TTL/SEQ/SRC/DST/SEG/AKF/AID/SZMIC/SeqZero/SegO/SegN/
 * Header/Segment#1/LowerTransportPDU rows directly: SegO=01 (SegN still 01,
 * same AKF/AID/SZMIC/SeqZero as segment 0, per Table 3.18's "Every Segmented
 * Access message for the same Upper Transport Access PDU shall have the same
 * values" rule), Header=e6a03421, Segment#1=1c01cea6,
 * LowerTransportPDU=e6a034211c01cea6 - `header1`/`segment1`/`pdu1` below are
 * that row triple, not derived from `header`/`segment0` by flipping a bit:
 * `header1` is an independently transcribed wire value, cross-checked
 * against `header`'s own bit layout (Table 3.18: only SegO should differ,
 * 0->1) in `lowerTransport.test.ts`.
 */
export const LOWER_TRANSPORT_SAMPLE_SEGMENTED = {
  seg: true,
  akf: true,
  aid: 0x26,
  szmic: true,
  seqZero: 0x80d,
  segO: 0x00,
  segN: 0x01,
  header: 'e6a03401',
  segment0: 'c3c51d8e476b28e3aa5001f3',
  pdu: 'e6a03401c3c51d8e476b28e3aa5001f3',
  header1: 'e6a03421',
  segment1: '1c01cea6',
  pdu1: 'e6a034211c01cea6',
};

/**
 * Section 8.3.6 "Message #6": the same Config AppKey Add REQUEST as
 * DEVICE_NONCE_SAMPLE_1/UPPER_TRANSPORT_SAMPLE_DEVICE_KEY, but read for its
 * OWN two "LowerTransportSegmentedAccessPDU" blocks (Section 8.3.6) - fetched
 * independently for the segmentation task (same URL/HTML/method,
 * 2026-10-06). Like LOWER_TRANSPORT_SAMPLE_SEGMENTED (Message #24), both of
 * Message #6's segments publish their own complete
 * "LowerTransportSegmentedAccessPDU" block independently, each with its own
 * Header and LowerTransportPDU row (neither message's `header1` is derived
 * from its `header` by flipping a bit - see that constant's own comment
 * above). Message #6 is this task's primary multi-segment sample because
 * it is DevKey (AKF=0, AID=0, SZMIC=0), the one combination this file's
 * other segmented sample above does not cover (same AKF=0 gap already
 * closed for the unsegmented case by LOWER_TRANSPORT_SAMPLE_ACCESS_
 * DEVICE_KEY, for the same reason: every other segmented sample here has
 * AKF=1/SZMIC=1, so a decoder that silently ignored either bit would still
 * pass without this - confirmed by mutation: with this sample's three
 * encode/decode tests skipped, an AKF-blind mutation and, separately, a
 * SZMIC-blind one (both the same "hardcoded true" shape the unsegmented
 * case's own AKF mutation above uses) each leave the rest of
 * `lowerTransport.test.ts` fully green (0 failed); with those three tests
 * enabled, each mutation fails exactly those three and nothing else - this
 * sample is the only thing in the suite standing between either bug and a
 * green gate).
 *
 * Segment #0's own block: CTL=00, TTL=04, SEQ=3129ab, SRC=0003, DST=1201,
 * SEG=01, AKF=00, AID=00, SZMIC=00, SeqZero=9ab, SegO=00, SegN=01,
 * Header=8026ac01, Segment#0=ee9dddfd2169326d23f3afdf,
 * LowerTransportPDU=8026ac01ee9dddfd2169326d23f3afdf.
 *
 * Segment #1's own block: CTL=00, TTL=04, SEQ=3129ac, SRC=0003, DST=1201,
 * SEG=01, AKF=00, AID=00, SZMIC=00, SegO=01, SegN=01, Header=8026ac21,
 * Segment#1=cfdc18c52fdef772e0e17308,
 * LowerTransportPDU=8026ac21cfdc18c52fdef772e0e17308. Its own "SeqZero" row
 * reads 3129ab (24 bits) - too wide to be a 13-bit SeqZero field reading at
 * all (Table 3.18: SeqZero is 13 bits, max 0x1fff; 0x3129ab does not fit).
 * It is also NOT this segment's own SEQ (that is 3129ac, one more, per this
 * same block's own SEQ row above) - it is segment 0's SEQ, i.e. the
 * message's SeqAuth (the full, untruncated sequence number a segmented
 * message's SeqZero field is the low 13 bits of). That is not a guess:
 * 0x3129ab's own low 13 bits are 0x9ab, exactly the value Header 8026ac21
 * decodes to bit-for-bit per Table 3.18 (and the same value segment 0's own
 * row (correctly, as 0x9ab) and SeqZero column both read) - so this row
 * CORROBORATES the header rather than contradicting it, by publishing the
 * same quantity in its untruncated form instead of truncating it to 13
 * bits like the other rows do. `seqZero` below is that bit-decoded value
 * (0x9ab), common to both segments as Table 3.18 requires ("Every
 * Segmented Access message for the same Upper Transport Access PDU shall
 * have the same values for ... SeqZero ... fields").
 *
 * `upperTransportPdu` is UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.expected
 * (ee9dddfd2169326d23f3afdfcfdc18c52fdef772e0e17308, already transcribed
 * above) - cross-checked in `lowerTransport.test.ts` against
 * segment0||segment1 here.
 */
export const LOWER_TRANSPORT_SAMPLE_SEGMENTED_DEVICE_KEY = {
  akf: false,
  aid: 0x00,
  szmic: false,
  seqZero: 0x9ab,
  segN: 0x01,
  header0: '8026ac01',
  segment0: 'ee9dddfd2169326d23f3afdf',
  pdu0: '8026ac01ee9dddfd2169326d23f3afdf',
  header1: '8026ac21',
  segment1: 'cfdc18c52fdef772e0e17308',
  pdu1: '8026ac21cfdc18c52fdef772e0e17308',
};

/**
 * Section 8.3.7 "Message #7": a Segment Acknowledgment message, OBO=1
 * (a Friend node acknowledging on behalf of a Low Power node), SeqZero
 * 0x9ab, BlockAck 0x00000002 (segment 1 only, of a 2-segment message - see
 * the module header's note on why this is the fixture the known-answer
 * test relies on for mutation resistance). `parameters` is this message's
 * own "LowerTransportUnsegmentedControlPDU" block's "UpperTransportPDU" row
 * (its name, in the source, for the Segment Acknowledgment message's own
 * Parameters field - not the generic Upper Transport Control PDU this
 * field holds for every OTHER opcode `LOWER_TRANSPORT_SAMPLE_CONTROL_1`/
 * `_2` above represent); `expected` is that same block's "LowerTransportPDU"
 * row, Header (00) || Parameters.
 */
export const LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_1 = {
  obo: true,
  seqZero: 0x9ab,
  blockAck: 0x00000002,
  parameters: 'a6ac00000002',
  expected: '00a6ac00000002',
};

/**
 * Section 8.3.9 "Message #9": the next Segment Acknowledgment message in
 * the same friendship exchange as Message #7 above - same OBO/SeqZero, but
 * BlockAck 0x00000003 (both segments of the same 2-segment message, i.e. a
 * COMPLETE acknowledgment where Message #7's was partial). Same field
 * provenance as Message #7's own comment above.
 */
export const LOWER_TRANSPORT_SAMPLE_SEGMENT_ACK_2 = {
  obo: true,
  seqZero: 0x9ab,
  blockAck: 0x00000003,
  parameters: 'a6ac00000003',
  expected: '00a6ac00000003',
};
