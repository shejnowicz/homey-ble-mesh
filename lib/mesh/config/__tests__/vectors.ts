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
 *   - `0001` -> Loc 0x0100 (published: "Loc is “front” - 0x0100").
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
 * mis-typed English description of what it means.
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
