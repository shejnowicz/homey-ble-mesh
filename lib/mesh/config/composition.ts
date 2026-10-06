/**
 * Composition Data Page 0 (Mesh Protocol v1.1, Section 4.2.2.1 "Composition
 * Data Page 0"): the page every node publishes describing its own
 * identity, feature support, and the elements/models it implements. This
 * is the message the Configuration Client reads first after provisioning
 * (Section 4.3.2.4/4.3.2.5, Config Composition Data Get/Status) - and
 * because a real node's model list routinely exceeds one Access message
 * (Table 3.61's "maximum useful Access message size"), it is also the
 * message that arrives through this project's segmentation/reassembly
 * layer (`packet/reassembly.ts`) rather than a single unsegmented PDU; this
 * module only parses the fully-reassembled page bytes and has no opinion
 * on how they arrived.
 *
 * LAYOUT (Table 4.2 "Composition Data Page 0 fields"):
 *
 *   Field     | Size (octets) | Description
 *   ----------|---------------|---------------------------------------------
 *   CID       | 2             | 16-bit company identifier (Bluetooth SIG)
 *   PID       | 2             | 16-bit vendor-assigned product identifier
 *   VID       | 2             | 16-bit vendor-assigned product version id
 *   CRPL      | 2             | 16-bit replay protection list size
 *   Features  | 2             | bit field, Table 4.3
 *   Elements  | variable      | a sequence of element descriptions
 *
 * Ten fixed header octets, then the Elements sequence - no explicit "number
 * of elements" count field; how many element records follow is determined
 * only by parsing them one after another until the buffer is exhausted
 * (each element's own NumS/NumV say how many model IDs belong to THAT
 * element - see below), which is exactly the brief's "how the model counts
 * determine the lists that follow."
 *
 * FEATURES (Table 4.3 "Features field format" + Table 4.4 "Features field
 * bit values"): bit 0 Relay, bit 1 Proxy, bit 2 Friend, bit 3 Low Power,
 * bits 4-15 RFU (Reserved for Future Use - deliberately not surfaced as a
 * field below, and deliberately not allowed to leak into any of the four
 * named flags); a bit value of 1 means "supported", 0 means "not
 * supported" (Table 4.4).
 *
 * ELEMENT DESCRIPTION (Table 4.5 "Element description format"):
 *
 *   Field          | Size (octets)       | Description
 *   ---------------|---------------------|-----------------------------------
 *   Loc            | 2                   | location descriptor
 *   NumS           | 1                   | count of SIG Model IDs
 *   NumV           | 1                   | count of Vendor Model IDs
 *   SIG Models     | variable (NumS * 2) | NumS SIG Model IDs
 *   Vendor Models  | variable (NumV * 4) | NumV Vendor Model IDs
 *
 * Per Section 3.8.2 "Model identifier": a SIG Model ID is 16 bits; a Vendor
 * Model ID is 32 bits, composed of a 16-bit Company Identifier followed by
 * a 16-bit Vendor Model Identifier (Table 3.64 "Vendor Model ID format" -
 * Company Identifier listed first, Vendor Model Identifier second).
 *
 * BYTE ORDER - THE TRAP. This is access-layer/Foundation-Model data, and
 * that is the ONE place in this whole specification that is little-endian
 * while every lower layer (network/lower transport/upper transport/
 * Provisioning, all already built in this project) is big-endian. Stated
 * three times, independently: Section 3.1.1 ("For the access layer and
 * Foundation Models, all multiple-octet numeric values shall be
 * little-endian"), Section 3.7.1 (the Access layer's own chapter, same
 * sentence), and - most directly on point, since Composition Data lives in
 * Chapter 4 - Section 4.1.1 "Endianness" (opening "4.1. Conventions" of
 * Chapter 4 itself): "All multiple-octet numeric values in this layer shall
 * be little-endian, as described in Section 3.1.1.2." Section 8.10.1's own
 * published sample carries a fourth, inline confirmation: "Note: The
 * composition data is little-endian." Every multi-octet field below (CID,
 * PID, VID, CRPL, Features, Loc, each SIG Model ID, and each half of a
 * Vendor Model ID) is read least-significant-octet first accordingly - see
 * `config/__tests__/vectors.ts` for the published sample decoded by hand,
 * octet by octet, confirming the direction (e.g. wire octets `0080` decode
 * to SIG Model ID 0x8000, which only reads correctly low-octet-first - the
 * opposite reading would give 0x0080, which is not in the document's own
 * published model list).
 *
 * ERRATA: Section 8.10.1's own prose describing its sample misstates what
 * its Features value means - "Features is 0x0003 - Relay and Friend
 * features" - but Table 4.3 assigns bit 0 to Relay and bit 1 to Proxy (bit
 * 2 is Friend), so 0x0003 (bits 0 and 1 set) decodes to Relay AND PROXY,
 * not Relay and Friend. The NUMBER 0x0003 itself is not in question (the
 * sample's raw wire octets `0300` agree with the sample's own "Features is
 * 0x0003" line); only the one mis-typed English gloss is wrong. This module
 * decodes strictly per Table 4.3's bit positions, matching the actual value
 * rather than the prose describing it - see `__tests__/vectors.ts` for the
 * full accounting.
 *
 * MINIMUM ONE ELEMENT. Section 2.3.4 "Elements": "An element is an
 * addressable entity on a node. Each node has at least one element, the
 * primary element, and may have up to 254 additional secondary elements."
 * A buffer that parses as a syntactically well-formed 10-octet header
 * followed by zero element records is therefore not a valid Composition
 * Data Page 0 - no real node can report zero elements - so
 * `parseCompositionData` returns `null` for it rather than reporting an
 * empty `elements` array. This is also the exact boundary the brief's
 * truncation sweep depends on: without this check, a 10-octet prefix of
 * any longer sample would be silently accepted as a "valid" zero-element
 * page instead of rejected as the truncated data it actually is.
 *
 * `null` VS THROW. This module has exactly one exported function and no
 * encoder (the brief's own interface: `parseCompositionData(buffer)`, no
 * round trip). There is no caller-supplied parameter this module could
 * reject as "out of range" the way `access.ts#encodeOpcode` rejects an
 * invalid in-memory opcode number - the only input is the wire buffer
 * itself, and "I cannot parse this buffer" is not a caller mistake, it is
 * the ordinary outcome of a corrupt or truncated page (the same stance
 * `access.ts#decodeAccessMessage` and `packet/reassembly.ts` already take).
 * So this module never throws; every rejection is `null`. There is no
 * other nullish state for this module to be consistent with (no
 * caller-held "previous state" is threaded through a function here, unlike
 * `packet/reassembly.ts`'s `ReassemblyState` or
 * `provisioning/machine.ts`'s `ProvisioningState`), so the "a module's
 * nullish convention must be consistent" rule applies trivially: `null`
 * in, `null` out, with nothing to round-trip.
 *
 * NO BUFFER ALIASING. Every field below is read with `Buffer#readUInt8`/
 * `Buffer#readUInt16LE`, which copy the octets into a plain JS `number`
 * immediately - `parseCompositionData` never keeps a `Buffer#subarray`
 * view into its input, so there is no view for a caller's later mutation
 * of `buffer` to corrupt (the exact hazard a prior task in this project
 * left in three places - see `provisioning/machine.ts`'s review addendum).
 */

const HEADER_LENGTH = 10; // Table 4.2: CID+PID+VID+CRPL+Features, 2 octets each.
const ELEMENT_HEADER_LENGTH = 4; // Table 4.5: Loc (2) + NumS (1) + NumV (1).
const SIG_MODEL_ID_LENGTH = 2; // Section 3.8.2: a SIG Model ID is 16 bits.
const VENDOR_MODEL_ID_LENGTH = 4; // Table 3.64: 16-bit Company Identifier + 16-bit Vendor Model Identifier.

// Table 4.3 "Features field format".
const FEATURE_BIT_RELAY = 0x0001;
const FEATURE_BIT_PROXY = 0x0002;
const FEATURE_BIT_FRIEND = 0x0004;
const FEATURE_BIT_LOW_POWER = 0x0008;

/** Table 3.64 "Vendor Model ID format": Company Identifier, then Vendor Model Identifier. */
export interface VendorModelId {
  readonly companyId: number;
  readonly modelId: number;
}

/** Table 4.3/4.4: the four named feature bits; bits 4-15 are RFU and carry no meaning here. */
export interface CompositionFeatures {
  readonly relay: boolean;
  readonly proxy: boolean;
  readonly friend: boolean;
  readonly lowPower: boolean;
}

/** Table 4.5 "Element description format", fully decoded (Loc plus both model lists). */
export interface ElementDescription {
  readonly loc: number;
  readonly sigModels: ReadonlyArray<number>;
  readonly vendorModels: ReadonlyArray<VendorModelId>;
}

/** Table 4.2 "Composition Data Page 0 fields", fully decoded. */
export interface CompositionData {
  readonly cid: number;
  readonly pid: number;
  readonly vid: number;
  readonly crpl: number;
  readonly features: CompositionFeatures;
  readonly elements: ReadonlyArray<ElementDescription>;
}

/**
 * Parses one Composition Data Page 0 buffer (Table 4.2). Returns `null` for
 * anything this function cannot decode as a complete, well-formed page -
 * too short for the fixed header, a header whose Elements sequence is
 * truncated partway through an element's fixed fields or either model
 * list, or a syntactically complete header followed by zero elements
 * (Section 2.3.4: impossible for a real node - see the module header's
 * MINIMUM ONE ELEMENT note). Trailing bytes that do not form another
 * complete element record are likewise truncation, not a second page
 * appended; this function never throws.
 */
export function parseCompositionData(buffer: Buffer): CompositionData | null {
  if (buffer.length < HEADER_LENGTH) {
    return null;
  }

  const cid = buffer.readUInt16LE(0);
  const pid = buffer.readUInt16LE(2);
  const vid = buffer.readUInt16LE(4);
  const crpl = buffer.readUInt16LE(6);
  const rawFeatures = buffer.readUInt16LE(8);
  const features: CompositionFeatures = {
    relay: (rawFeatures & FEATURE_BIT_RELAY) !== 0,
    proxy: (rawFeatures & FEATURE_BIT_PROXY) !== 0,
    friend: (rawFeatures & FEATURE_BIT_FRIEND) !== 0,
    lowPower: (rawFeatures & FEATURE_BIT_LOW_POWER) !== 0,
  };

  const elements: ElementDescription[] = [];
  let offset = HEADER_LENGTH;

  while (offset < buffer.length) {
    if (offset + ELEMENT_HEADER_LENGTH > buffer.length) {
      return null; // Truncated partway through Loc/NumS/NumV (Table 4.5).
    }
    const loc = buffer.readUInt16LE(offset);
    const numS = buffer.readUInt8(offset + 2);
    const numV = buffer.readUInt8(offset + 3);
    offset += ELEMENT_HEADER_LENGTH;

    const modelsLength = numS * SIG_MODEL_ID_LENGTH + numV * VENDOR_MODEL_ID_LENGTH;
    if (offset + modelsLength > buffer.length) {
      return null; // Truncated partway through the SIG/Vendor model lists.
    }

    const sigModels: number[] = [];
    for (let i = 0; i < numS; i++) {
      sigModels.push(buffer.readUInt16LE(offset));
      offset += SIG_MODEL_ID_LENGTH;
    }

    const vendorModels: VendorModelId[] = [];
    for (let i = 0; i < numV; i++) {
      // Table 3.64: Company Identifier first, Vendor Model Identifier second.
      const companyId = buffer.readUInt16LE(offset);
      const modelId = buffer.readUInt16LE(offset + 2);
      vendorModels.push({ companyId, modelId });
      offset += VENDOR_MODEL_ID_LENGTH;
    }

    elements.push({ loc, sigModels, vendorModels });
  }

  if (elements.length === 0) {
    return null; // Section 2.3.4: every node has at least one (primary) element.
  }

  return { cid, pid, vid, crpl, features, elements };
}
