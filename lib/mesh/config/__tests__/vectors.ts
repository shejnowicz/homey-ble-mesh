/**
 * Composition Data Page 0 sample data transcribed from the Bluetooth SIG
 * "Mesh Protocol" specification v1.1 HTML document
 * (https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/MshPRT_v1.1/out/en/index-en.html),
 * fetched fresh for this task on 2026-10-06 (HTTP 200, 9,945,160 bytes -
 * the same byte count every other fixture file in this repository records
 * for its own, independent fetch of the same document). Extracted
 * programmatically: `</td>`/`</tr>` converted to separators before
 * tag-stripping (per the task brief), entities unescaped, then located by
 * section title - table CAPTIONS in this document are not trustworthy on
 * their own (see this project's prior errata notes in
 * `provisioning/__tests__/vectors.ts`), and table numbers are separated
 * from the word "Table" by a non-breaking space (U+00A0), which an ASCII
 * grep for "Table " silently misses - confirmed by grepping the raw HTML
 * for this file's own hex sample byte-for-byte (exactly one match) before
 * transcribing anything below.
 *
 * THIS FILE'S INVENTORY:
 * - `COMPOSITION_DATA_PAGE0_SAMPLE`: the one published Composition Data
 *   Page 0 sample (Section 8.10.1 "Composition Data Page 0 sample data"),
 *   28 octets, plus the specification's own field-by-field breakdown of
 *   what those bytes decode to (CID/PID/VID/CRPL, the Features bits, one
 *   element's Loc/NumS/NumV/SIG Models/Vendor Models) - independent
 *   transcriptions of the same bytes `message` already contains, so a test
 *   can check the decoder's individual fields against the document's own
 *   breakdown, not merely against a byte string nothing separately
 *   verifies.
 * - `CONFIG_OPCODES`: the Configuration Client's eight message opcodes
 *   (Composition Data Get/Status, AppKey Add/Status, Model App Bind/Status,
 *   Node Reset/Status), transcribed from the Bluetooth SIG "Assigned
 *   Numbers" document (a SEPARATE document from the Mesh Protocol v1.1 HTML
 *   above - see `client.ts`'s own OPCODE PROVENANCE note for why that
 *   second fetch was necessary), with the two values independently
 *   cross-checked against this document's own Section 8.3 sample data.
 * - `CONFIG_APPKEY_ADD_SAMPLE` / `CONFIG_APPKEY_STATUS_SAMPLE`: Section
 *   8.3.6 "Message #6" and Section 8.3.16 "Message #16" - the two
 *   Configuration messages this document actually publishes full wire
 *   bytes for - decomposed into their NetKeyIndex/AppKeyIndex/AppKey/Status
 *   fields (Table 4.119/4.122), on top of the wire bytes themselves
 *   (already transcribed, for a different task, as
 *   `UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.accessPayload` /
 *   `ACCESS_SAMPLE_CONFIG_APPKEY_STATUS.expected` in
 *   `packet/__tests__/vectors.ts` - `client.test.ts` imports both so the
 *   two files' transcriptions of the same bytes stay bound together).
 * - `CONFIG_STATUS_CODES`: the full Table 4.308 "Summary of configuration
 *   and health messages status codes" (Section 4.3.14), every code 0x00
 *   through 0x15 with its published name.
 * - `CONFIG_KEY_INDEX_TOP_OF_RANGE_SAMPLE`: hand-computed (not
 *   document-published - see its own comment) packed bytes for the 12-bit
 *   key index domain's own top value, 0xFFF, in both the two-index
 *   (Figure 4.4) and single-index (Figure 4.5) forms.
 * - `CONFIG_MODEL_APP_BIND_SAMPLE` / `CONFIG_MODEL_APP_STATUS_SAMPLE`: also
 *   hand-computed (no Section 8.3 sample exercises either message), built
 *   from values already transcribed elsewhere in this file and in
 *   `packet/__tests__/vectors.ts` (Message #6/#16's own ElementAddress-
 *   shaped DST 0x1201 and AppKeyIndex 0x123, and this file's own published
 *   Vendor Model ID 0x003f/0x002a) rather than invented numbers, so every
 *   individual field value is still specification data even though the
 *   combination into one message is this task's own construction.
 *
 * LAYOUT SOURCE (not reproduced as fixture data, since it has no bytes of
 * its own - see `config/composition.ts`'s module header for the full
 * transcription): Section 4.2.2.1 "Composition Data Page 0", Table 4.2
 * "Composition Data Page 0 fields" (CID/PID/VID/CRPL/Features, 2 octets
 * each, then a variable-length Elements sequence), Table 4.3 "Features
 * field format" (bit 0 Relay, bit 1 Proxy, bit 2 Friend, bit 3 Low Power,
 * bits 4-15 RFU), Table 4.5 "Element description format" (Loc 2 octets,
 * NumS 1 octet, NumV 1 octet, then NumS SIG Model IDs and NumV Vendor
 * Model IDs), and Table 3.64 "Vendor Model ID format" (Section 3.8.2: a
 * 16-bit Company Identifier followed by a 16-bit Vendor Model Identifier).
 *
 * BYTE ORDER: Section 4.1.1 "Endianness" (opening "4.1. Conventions" of
 * Chapter 4, which Composition Data lives in) states plainly: "All
 * multiple-octet numeric values in this layer shall be little-endian, as
 * described in Section 3.1.1.2." The same rule is stated twice more,
 * independently, elsewhere in the document - Section 3.1.1 ("For the
 * access layer and Foundation Models, all multiple-octet numeric values
 * shall be little-endian") and Section 3.7.1 (the Access layer's own
 * chapter, same sentence) - and Section 8.10.1's own sample carries an
 * explicit inline reminder: "Note: The composition data is little-endian."
 * This is the OPPOSITE byte order from every lower layer this project
 * already built (network/lower transport/upper transport/Provisioning are
 * all big-endian, per the same Section 3.1.1).
 *
 * THE SAMPLE, HAND-VERIFIED BYTE BY BYTE AGAINST ITS OWN DECODED FIELDS
 * before being trusted as a known-answer test (every multi-octet field
 * below read low-octet-first, per the endianness rule above):
 *   - `0C00` -> CID 0x000C (published: "CID is 0x000C").
 *   - `1A00` -> PID 0x001A (published: "PID is 0x001A").
 *   - `0100` -> VID 0x0001 (published: "VID is 0x0001").
 *   - `0800` -> CRPL 0x0008 (published: "CRPL is 0x0008").
 *   - `0300` -> Features 0x0003 (published: "Features is 0x0003") - see the
 *     ERRATA NOTE below for what this decodes to.
 *   - `0001` -> Loc 0x0100 (published: "Loc is “front” – 0x0100").
 *   - `05` -> NumS 5 (published: "NumS is 5").
 *   - `01` -> NumV 1 (published: "NumV is 1").
 *   - `0000 0080 0100 0010 0310` -> SIG Models 0x0000, 0x8000, 0x0001,
 *     0x1000, 0x1003 (published: "The Bluetooth SIG Models supported are:
 *     0x0000, 0x8000, 0x0001, 0x1000, 0x1003") - each pair of octets reads
 *     low-byte-first (e.g. `0080` -> 0x8000, NOT 0x0080).
 *   - `3F002A00` -> one Vendor Model: Company Identifier octets `3F00` ->
 *     0x003F, Vendor Model Identifier octets `2A00` -> 0x002A (published:
 *     "Company Identifier 0x003F and Model Identifier 0x002A").
 * Total length: 10 header octets + (2 + 1 + 1 + 5*2 + 1*4) = 10 + 18 = 28,
 * matching the 28-octet sample exactly (confirmed by counting the published
 * hex string's own characters, 56 hex characters / 2).
 *
 * ERRATA NOTE: Section 8.10.1's own prose misdescribes its Features value -
 * "Features is 0x0003 – Relay and Friend features." - but Table 4.3
 * ("Composition Data Page 0" -> "Features field format", Section 4.2.2.1)
 * unambiguously assigns bit 0 to Relay and bit 1 to Proxy (bit 2 is
 * Friend), and 0x0003 is bits 0 and 1 set (0b0000000000000011), which is
 * Relay AND PROXY, not Relay and Friend - Friend is bit 2 (value 0x0004),
 * which is clear in 0x0003. Matched on the bit positions Table 4.3 itself
 * defines, not on the sample's own prose gloss: `features` below decodes
 * per Table 4.3 (relay=true, proxy=true, friend=false, lowPower=false),
 * exactly as `config/composition.ts` computes it from the raw 0x0003 value
 * - which is itself independently confirmed by the published wire bytes
 * (`0300` little-endian) agreeing with the published "Features is 0x0003"
 * line, so there is no ambiguity about the NUMBER, only about the one
 * mis-typed English description of what it means. Review round: confirmed
 * independently against TWO more tables elsewhere in this same document
 * that assign these identical four bits (bit 0 Relay, bit 1 Proxy, bit 2
 * Friend, bit 3 Low Power) the same way - Table 3.49 "Features field
 * format" (Section 3.6.5.10 "Heartbeat") and Table 4.39 "Heartbeat
 * Publication Feature values" (Section 4.2.18.5 "Heartbeat Publication
 * Features") - so Table 4.3's own bit assignment is not itself a
 * transcription error; the sample's prose is the sole error here.
 *
 * ELEMENT-COUNT NOTE: this is a ONE-element sample (the document gives no
 * second Loc/NumS/NumV/model-list group), so it alone cannot pin the
 * "parse elements until the buffer is exhausted" loop boundary as firmly
 * as a multi-element sample would; `composition.test.ts` compensates with
 * synthetic multi-element buffers built by concatenating two copies of
 * this sample's own element bytes (genuine wire bytes, not fabricated
 * field values) onto a single header, so the loop itself is exercised
 * against bytes that are still, in every individual field, specification
 * data.
 */

export const hex = (s: string): Buffer => Buffer.from(s.replace(/\s+/g, ''), 'hex');

/** Section 8.10.1 "Composition Data Page 0 sample data". */
export const COMPOSITION_DATA_PAGE0_SAMPLE = {
  message: '0C001A0001000800030000010501000000800100001003103F002A00',
  fields: {
    cid: 0x000c,
    pid: 0x001a,
    vid: 0x0001,
    crpl: 0x0008,
    /**
     * Raw Features value as published ("Features is 0x0003"). See this
     * file's ERRATA NOTE above for why `decodedFeatures` below, not the
     * sample's own prose, is what a correct decoder must produce.
     */
    features: 0x0003,
    decodedFeatures: {
      relay: true,
      proxy: true,
      friend: false,
      lowPower: false,
    },
    elements: [
      {
        loc: 0x0100,
        sigModels: [0x0000, 0x8000, 0x0001, 0x1000, 0x1003],
        vendorModels: [{ companyId: 0x003f, modelId: 0x002a }],
      },
    ],
  },
};

/**
 * The Configuration Client's eight message opcodes, transcribed from the
 * Bluetooth SIG "Assigned Numbers" document (fetched fresh for this task,
 * 2026-10-06, from
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Assigned_Numbers/out/en/Assigned_Numbers.pdf,
 * HTTP 200, 1,324,070 bytes, "Version Date: 2026-10-05"), Section 4.2.1
 * "Mesh Model Message Opcodes by Value" / Section 4.2.2 "Mesh Model Message
 * Opcodes by Name" (both tables agree). This is a SEPARATE document from
 * the Mesh Protocol v1.1 HTML this file's other fixtures come from - see
 * `client.ts`'s own OPCODE PROVENANCE note for why: every one of these
 * eight messages' field tables in the Mesh Protocol document itself only
 * says "defined in the Assigned Numbers document [4]," with no literal hex
 * value of its own, EXCEPT where a Section 8.3 sample happens to publish
 * one inline (AppKey Add/Status, below) - confirmed by grepping the
 * Protocol document's own extracted text for every "Opcode" occurrence
 * near each of these eight messages' field tables before trusting the
 * Assigned Numbers document as the source for the rest.
 */
export const CONFIG_OPCODES = {
  compositionDataGet: 0x8008, // "Config Composition Data Get" = `0x80 0x08`.
  compositionDataStatus: 0x02, // "Config Composition Data Status" = `0x02`.
  appKeyAdd: 0x00, // "Config AppKey Add" = `0x00` - matches Section 8.3.6's own "Opcode : 00 (Config AppKey Add)".
  appKeyStatus: 0x8003, // "Config AppKey Status" = `0x80 0x03` - matches Section 8.3.16's own "Opcode : 8003 (Config AppKey Status)".
  modelAppBind: 0x803d, // "Config Model App Bind" = `0x80 0x3D`.
  modelAppStatus: 0x803e, // "Config Model App Status" = `0x80 0x3E`.
  nodeReset: 0x8049, // "Config Node Reset" = `0x80 0x49`.
  nodeResetStatus: 0x804a, // "Config Node Reset Status" = `0x80 0x4A`.
};

/**
 * Section 8.3.6 "Message #6": "A Configuration Client sends a Config
 * AppKey Add message to the Low Power node." Published fields: "Opcode :
 * 00 (Config AppKey Add)", "NetKeyIndex : 456" (i.e. 0x456 - see
 * `provisioning/machine.ts`'s own note on this exact sample for why these
 * are hex, not decimal, confirmed by the packed bytes below), "AppKeyIndex
 * : 123" (0x123), "AppKey :
 * 63964771734fbd76e3b40519d1d94a48", and the complete "Access message :
 * 0056341263964771734fbd76e3b40519d1d94a48" - the SAME bytes already
 * transcribed as `UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.accessPayload` in
 * `packet/__tests__/vectors.ts` for a different task; `message` below is
 * repeated here (not imported) because every `__tests__/vectors.ts` file in
 * this project is self-contained, but `client.test.ts` cross-checks the two
 * literal strings for equality so they cannot silently diverge.
 *
 * Table 4.119's own field text: "These two indexes shall be encoded as
 * defined in Section 4.3.1.1 using NetKey Index as first key index and
 * AppKey Index as second key index" - confirmed by hand: packTwoKeyIndexes
 * (0x456, 0x123) = `56 34 12`, matching the published "563412" prefix of
 * this message's Parameters field exactly (see `client.ts`'s own
 * `packTwoKeyIndexes` provenance comment for the full arithmetic).
 */
export const CONFIG_APPKEY_ADD_SAMPLE = {
  netKeyIndex: 0x456,
  appKeyIndex: 0x123,
  appKey: '63964771734fbd76e3b40519d1d94a48',
  message: '0056341263964771734fbd76e3b40519d1d94a48',
};

/**
 * Section 8.3.16 "Message #16": "The Low Power node has now received the
 * complete Config AppKey Add message, so it responds to the segmented
 * message with a status message." Published fields: "Opcode : 8003 (Config
 * AppKey Status)", "Status : 00", "NetKeyIndex : 456", "AppKeyIndex : 123",
 * and the complete "Access message : 800300563412" - the SAME bytes already
 * transcribed as `ACCESS_SAMPLE_CONFIG_APPKEY_STATUS.expected` in
 * `packet/__tests__/vectors.ts` for a different task (same cross-check
 * convention as `CONFIG_APPKEY_ADD_SAMPLE` above).
 */
export const CONFIG_APPKEY_STATUS_SAMPLE = {
  status: 0x00,
  netKeyIndex: 0x456,
  appKeyIndex: 0x123,
  message: '800300563412',
};

/**
 * Table 4.308 "Summary of configuration and health messages status codes"
 * (Section 4.3.14 "Summary of status codes"): "Table 4.308 defines status
 * codes for configuration messages (see Section 4.3.2) and health messages
 * (see Section 4.3.3) that contain a Status parameter." Every code 0x00
 * through 0x15 is a distinct published row; 0x16-0xFF is one published row,
 * "RFU".
 */
export const CONFIG_STATUS_CODES: ReadonlyArray<{ code: number; name: string }> = [
  { code: 0x00, name: 'Success' },
  { code: 0x01, name: 'Invalid Address' },
  { code: 0x02, name: 'Invalid Model' },
  { code: 0x03, name: 'Invalid AppKey Index' },
  { code: 0x04, name: 'Invalid NetKey Index' },
  { code: 0x05, name: 'Insufficient Resources' },
  { code: 0x06, name: 'Key Index Already Stored' },
  { code: 0x07, name: 'Invalid Publish Parameters' },
  { code: 0x08, name: 'Not a Subscribe Model' },
  { code: 0x09, name: 'Storage Failure' },
  { code: 0x0a, name: 'Feature Not Supported' },
  { code: 0x0b, name: 'Cannot Update' },
  { code: 0x0c, name: 'Cannot Remove' },
  { code: 0x0d, name: 'Cannot Bind' },
  { code: 0x0e, name: 'Temporarily Unable to Change State' },
  { code: 0x0f, name: 'Cannot Set' },
  { code: 0x10, name: 'Unspecified Error' },
  { code: 0x11, name: 'Invalid Binding' },
  { code: 0x12, name: 'Invalid Path Entry' },
  { code: 0x13, name: 'Cannot Get' },
  { code: 0x14, name: 'Obsolete Information' },
  { code: 0x15, name: 'Invalid Bearer' },
];

/**
 * Hand-computed (NOT document-published - no Section 8.3 sample exercises
 * either packed form at the 12-bit domain's own top value) boundary data
 * for Section 4.3.1.1's Figure 4.4 (two-index) and Figure 4.5 (single-index)
 * packing, at key index 0xFFF (4095, the 12-bit domain's own maximum -
 * Section 4.3.1.1: "Global key indexes are 12 bits long"). Values derived
 * from the figures' own stated bit arithmetic, not observed from running
 * this project's encoder (`client.ts`'s own `packTwoKeyIndexes`/
 * `packSingleKeyIndex` provenance comments repeat the same by-hand
 * arithmetic independently):
 *
 * - two-index, asymmetric (0xFFF, 0x001) so a first/second swap mutation is
 *   distinguishable: octet0 = 0xfff&0xff = 0xff; octet1 =
 *   ((0xfff>>8)&0xf)|((0x001&0xf)<<4) = 0xf|0x10 = 0x1f; octet2 =
 *   (0x001>>4)&0xff = 0x00 -> `ff1f00`. Swapped (0x001, 0xFFF): octet0 =
 *   0x01; octet1 = ((0x001>>8)&0xf)|((0xfff&0xf)<<4) = 0x0|0xf0 = 0xf0;
 *   octet2 = (0xfff>>4)&0xff = 0xff -> `01f0ff` (completely different from
 *   the unswapped bytes, confirming the asymmetric choice is sensitive to a
 *   swap).
 * - single-index, 0xFFF: octet0 = 0xff; octet1 = (0xfff>>8)&0xf = 0xf (top
 *   nibble 0, as Figure 4.5 requires) -> `ff0f`.
 */
export const CONFIG_KEY_INDEX_TOP_OF_RANGE_SAMPLE = {
  twoIndex: {
    first: 0xfff,
    second: 0x001,
    packed: 'ff1f00',
    packedSwapped: '01f0ff', // first=0x001, second=0xfff - for the mutation-sensitivity check above.
  },
  singleIndex: {
    index: 0xfff,
    packed: 'ff0f',
  },
};

/**
 * Hand-computed Config Model App Bind / Config Model App Status messages
 * (no Section 8.3 sample exercises either - see this file's own header
 * INVENTORY note). Every individual field value is still specification
 * data, reused rather than invented: ElementAddress 0x1201 is Message
 * #6/#16's own DST (a real unicast address those messages addressed - see
 * `CONFIG_APPKEY_ADD_SAMPLE`/`CONFIG_APPKEY_STATUS_SAMPLE` above), AppKeyIndex
 * 0x123 is the same AppKeyIndex Message #6/#16 use (now Figure-4.5-packed
 * instead of Figure-4.4-packed, so the WIRE BYTES differ even though the
 * logical value doesn't - `2301`, not `563412`'s own `..34 12` tail),
 * ModelIdentifier (SIG) 0x1000 and ModelIdentifier (Vendor)
 * {0x003f,0x002a} are both drawn from `COMPOSITION_DATA_PAGE0_SAMPLE`
 * above (Section 8.10.1's own published model list/vendor model), and
 * Status 0x0d ("Cannot Bind") is Table 4.308's own published row for the
 * one status code this exact message is most likely to return in practice
 * - deliberately NOT 0x00 "Success" (this task's own dispatch instructions
 * warned against exactly this gap: "any status code whose published sample
 * value happens to be success" - that sentence is from the dispatch
 * message, not from `task-5-brief.md`, which is why it won't turn up in a
 * grep of the file tree).
 *
 * Byte-by-byte (Table 3.64 Company-Identifier-first; Section 3.1.1/3.7.1
 * little-endian throughout):
 * - ElementAddress 0x1201 LE -> `0112`.
 * - AppKeyIndex 0x123 single-packed (Figure 4.5) -> `2301` (octet0 =
 *   0x123&0xff = 0x23; octet1 = (0x123>>8)&0xf = 0x01).
 * - SIG ModelIdentifier 0x1000 LE -> `0010`.
 * - Vendor ModelIdentifier {companyId:0x003f, modelId:0x002a} LE -> `3f002a00`.
 */
export const CONFIG_MODEL_APP_BIND_SAMPLE = {
  elementAddress: 0x1201,
  appKeyIndex: 0x123,
  sigModelIdentifier: 0x1000,
  vendorModelIdentifier: { companyId: 0x003f, modelId: 0x002a },
  // Opcode (803d) || ElementAddress (0112) || AppKeyIndex (2301) || SIG ModelIdentifier (0010).
  messageSig: '803d011223010010',
  // Opcode (803d) || ElementAddress (0112) || AppKeyIndex (2301) || Vendor ModelIdentifier (3f002a00).
  messageVendor: '803d011223013f002a00',
};

export const CONFIG_MODEL_APP_STATUS_SAMPLE = {
  statusSuccess: 0x00,
  statusCannotBind: 0x0d,
  elementAddress: 0x1201,
  appKeyIndex: 0x123,
  sigModelIdentifier: 0x1000,
  vendorModelIdentifier: { companyId: 0x003f, modelId: 0x002a },
  // Opcode (803e) || Status (00) || ElementAddress (0112) || AppKeyIndex (2301) || SIG ModelIdentifier (0010).
  messageSigSuccess: '803e00011223010010',
  // Same fields, Status 0x0d ("Cannot Bind") instead of Success.
  messageSigCannotBind: '803e0d011223010010',
  // Opcode (803e) || Status (00) || ElementAddress (0112) || AppKeyIndex (2301) || Vendor ModelIdentifier (3f002a00).
  messageVendorSuccess: '803e00011223013f002a00',
};

/**
 * Hand-assembled Config Composition Data Get/Status and Config Node
 * Reset/Status wire bytes - no Section 8.3 sample exercises any of these
 * four messages, so each is just its own opcode (`CONFIG_OPCODES`, above)
 * encoded per Table 3.62 (2-octet SIG opcodes MSB-first, 1-octet opcodes
 * verbatim - already established and tested in `packet/access.ts`) with
 * its (if any) published-sample parameters appended.
 */
export const CONFIG_COMPOSITION_DATA_GET_SAMPLE = {
  page: 0x00,
  message: '800800', // Opcode (8008, 2-octet MSB-first) || Page (00).
};

export const CONFIG_COMPOSITION_DATA_STATUS_SAMPLE = {
  page: 0x00,
  // Opcode (02, 1-octet) || Page (00) || Data (COMPOSITION_DATA_PAGE0_SAMPLE.message, Section 8.10.1).
  message: '0200' + COMPOSITION_DATA_PAGE0_SAMPLE.message,
};

export const CONFIG_NODE_RESET_SAMPLE = {
  message: '8049', // Opcode (8049, 2-octet MSB-first) only - no parameters (Table 4.135).
};

export const CONFIG_NODE_RESET_STATUS_SAMPLE = {
  message: '804a', // Opcode (804a, 2-octet MSB-first) only - no parameters (Table 4.136).
};
