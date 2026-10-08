import { assertRange } from '../packet/ranges';
import { encodeAccessMessage, decodeAccessMessage } from '../packet/access';
import { parseCompositionData, CompositionData, VendorModelId } from './composition';

/**
 * The Configuration Client's own messages (Mesh Protocol v1.1, Section
 * 4.3.2 "Configuration messages"): the four messages this project's
 * Configuration Client sends after provisioning a node - Config
 * Composition Data Get, Config AppKey Add, Config Model App Bind, Config
 * Node Reset - and the four status messages it reads back - Config
 * Composition Data Status, Config AppKey Status, Config Model App Status,
 * Config Node Reset Status. Every message here is built on
 * `packet/access.ts`'s `encodeAccessMessage`/`decodeAccessMessage` (the
 * Opcode||Parameters envelope) and, for Composition Data Status, on
 * `./composition.ts`'s `parseCompositionData` for the Data field itself.
 *
 * DESIGN: one encode function per OUTGOING message (the caller always
 * knows which message it is building, so each gets its own typed
 * parameter list and its own function), and ONE decode function,
 * `decodeConfigStatus`, for every INCOMING status message (the caller does
 * NOT know ahead of time which status arrived over the wire - that is
 * exactly what decoding is for) that dispatches on the recovered opcode
 * and returns a tagged union, `null` for an opcode this module does not
 * recognise. This mirrors `provisioning/pdu.ts`'s own split exactly
 * (`encodeProvisioningPdu`'s per-`type` switch vs. the single
 * `decodeProvisioningPdu` dispatcher) for the same reason: a caller
 * sending a message picks its shape, a caller receiving one has to
 * discover it.
 *
 * OPCODE PROVENANCE - READ THIS BEFORE TOUCHING THE EIGHT CONSTANTS BELOW.
 * Every one of this module's eight messages' field tables in the Mesh
 * Protocol v1.1 document says the identical thing and nothing more: "The
 * Opcode field shall contain the opcode value for the Config <Message>
 * message defined in the Assigned Numbers document [4]." (verbatim,
 * repeated per message at Sections 4.3.2.4/4.3.2.5/4.3.2.37/4.3.2.40/
 * 4.3.2.46/4.3.2.48/4.3.2.53/4.3.2.54) - reference [4] resolves, in this
 * same document's own reference list, to "Bluetooth SIG Assigned Numbers,
 * http://www.bluetooth.com/specifications/assigned-numbers" (confirmed by
 * grepping the fetched document for every other appearance of "Opcode"
 * near a Config message's field table: none of the eight carries a literal
 * hex value in THIS document's body text). So the actual numeric opcodes
 * are transcribed from that separate, externally and normatively cited
 * Bluetooth SIG "Assigned Numbers" document (fetched fresh for this task,
 * 2026-10-06, from
 * https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Assigned_Numbers/out/en/Assigned_Numbers.pdf,
 * HTTP 200, 1,324,070 bytes, "Version Date: 2026-10-05"), Section 4.2.1
 * "Mesh Model Message Opcodes by Value" (filename
 * `assigned_numbers/mesh/mmdl_opcodes.yaml`) and Section 4.2.2 "Mesh Model
 * Message Opcodes by Name" - both tables list the identical
 * opcode/name pairs, by two different sort orders, and agree with each
 * other for all eight values below.
 *
 * This is independently corroborated, not merely asserted: TWO of these
 * eight values are ALSO published directly inline in the Mesh Protocol
 * document's own Section 8.3 sample data, outside any field table - "Opcode
 * : 00 (Config AppKey Add)" (Section 8.3.6, "Message #6") and "Opcode :
 * 8003 (Config AppKey Status)" (Section 8.3.16, "Message #16") - and the
 * Assigned Numbers document's two entries for exactly those two messages
 * read 0x00 and 0x80 0x03, matching Message #6/#16 exactly. The other six
 * opcodes (Composition Data Get/Status, Model App Bind/Status, Node
 * Reset/Status) are not exercised by any Section 8.3 sample in the Mesh
 * Protocol document, so they carry only the Assigned Numbers document's own
 * citation below, not a second, independent Mesh-Protocol-side check - but
 * they come from the exact same table, fetched the exact same way, as the
 * two values that DO cross-check.
 */

// ===========================================================================
// Opcodes (see the module header's OPCODE PROVENANCE note).
// ===========================================================================

// Assigned Numbers, Section 4.2.1/4.2.2: "Config Composition Data Get" =
// `0x80 0x08`; Table 4.86 (Mesh Protocol, Section 4.3.2.4): Opcode field is
// 2 octets, so this is this module's own in-memory 2-octet opcode `number`
// convention (`packet/access.ts`'s own "IN-MEMORY opcode ENCODING" table) -
// `(0x80 << 8) | 0x08`.
const OPCODE_COMPOSITION_DATA_GET = 0x8008;

// Assigned Numbers: "Config Composition Data Status" = `0x02`; Table 4.87
// (Section 4.3.2.5) states directly: "This message uses a single-octet
// opcode to maximize the size of a payload."
const OPCODE_COMPOSITION_DATA_STATUS = 0x02;

// Assigned Numbers: "Config AppKey Add" = `0x00`; Table 4.119 (Section
// 4.3.2.37): Opcode field is 1 octet. Independently confirmed inline by
// Section 8.3.6 "Message #6": "Opcode : 00 (Config AppKey Add)".
const OPCODE_APPKEY_ADD = 0x00;

// Assigned Numbers: "Config AppKey Status" = `0x80 0x03`; Table 4.122
// (Section 4.3.2.40): Opcode field is 2 octets. Independently confirmed
// inline by Section 8.3.16 "Message #16": "Opcode : 8003 (Config AppKey
// Status)".
const OPCODE_APPKEY_STATUS = 0x8003;

// Assigned Numbers: "Config Model App Bind" = `0x80 0x3D`; Table 4.128
// (Section 4.3.2.46): Opcode field is 2 octets.
const OPCODE_MODEL_APP_BIND = 0x803d;

// Assigned Numbers: "Config Model App Status" = `0x80 0x3E`; Table 4.130
// (Section 4.3.2.48): Opcode field is 2 octets.
const OPCODE_MODEL_APP_STATUS = 0x803e;

// Assigned Numbers: "Config Node Reset" = `0x80 0x49`; Table 4.135
// (Section 4.3.2.53): Opcode field is 2 octets.
const OPCODE_NODE_RESET = 0x8049;

// Assigned Numbers: "Config Node Reset Status" = `0x80 0x4A`; Table 4.136
// (Section 4.3.2.54): Opcode field is 2 octets.
const OPCODE_NODE_RESET_STATUS = 0x804a;

// ===========================================================================
// WHICH STATUS ANSWERS WHICH REQUEST - the one place that mapping exists.
//
// WHY THIS TABLE EXISTS AT ALL (hardware round, 2026-10-08). A Configuration
// Client that writes a request and then accepts the first thing that decodes
// is not matching a reply to a request, it is guessing. Three bulbs were
// lost to that guess: every notification was being delivered more than once
// (a leaked GATT subscription, fixed in `drivers/light/pairing.ts`), so the
// DUPLICATE of the previous request's Config AppKey Status was consumed as
// the answer to Config Model App Bind, which then "did not answer" while its
// real Model App Status was still in flight. Duplicates were this project's
// own bug, but the guess was wrong independently of them: a mesh model may
// publish a status message nobody asked for, and a node may retransmit one
// it has already sent, so an unsolicited or repeated status is ORDINARY mesh
// traffic rather than a malfunction. A client must be able to say "this is
// not the message I am waiting for" and keep waiting.
//
// WHAT THE KEY IS, AND WHY. The opcode, and only the opcode. Each of this
// module's four requests is answered by exactly one of its four status
// messages - the four pairs this module's own header already names, each
// with the field table it is defined by: Config Composition Data Get
// (Section 4.3.2.4) -> Config Composition Data Status (4.3.2.5); Config
// AppKey Add (4.3.2.37) -> Config AppKey Status (4.3.2.40); Config Model App
// Bind (4.3.2.46) -> Config Model App Status (4.3.2.48); Config Node Reset
// (4.3.2.53) -> Config Node Reset Status (4.3.2.54). The pairing exchange is
// point-to-point over its own GATT link to the one node being configured,
// and `packet/message.ts`'s own receive context already rejects anything not
// sourced from that node and not secured under its device key - so opcode
// equality is what remains to check.
//
// WHAT IT DELIBERATELY DOES NOT CHECK, so a reader does not assume it does.
// The status messages echo fields of their request (Table 4.130's Model App
// Status carries the ElementAddress and ModelIdentifier that were bound;
// Table 4.122's AppKey Status carries the two key indexes), and this table
// does NOT compare them. So a RETRANSMITTED Config Model App Status for
// element 0 would still satisfy a pending bind for element 1 on a
// multi-element node. Comparing the echoed fields would close that, and is
// the obvious next step if it is ever observed - it is left out here only
// because it would make this project reject a reply from any node that does
// not echo faithfully, and nothing in this project has ever been run against
// hardware that would prove it does. Config Composition Data Status's own
// Page field is not compared either, and that one is not a judgement call at
// all: a node that does not have the page it was asked for answers with a
// page it does have, and says which in the Page field - which is precisely
// why `ConfigCompositionDataStatus` reports `page` back to its caller rather
// than asserting it. A Page that differs from the request is a correct
// answer, so matching on it would reject correct answers.
// ===========================================================================

/** Every opcode this module knows, by its specification name - for messages
 *  that name what actually arrived rather than a bare hex number. */
const CONFIG_OPCODE_NAMES: ReadonlyMap<number, string> = new Map([
  [OPCODE_COMPOSITION_DATA_GET, 'Config Composition Data Get'],
  [OPCODE_COMPOSITION_DATA_STATUS, 'Config Composition Data Status'],
  [OPCODE_APPKEY_ADD, 'Config AppKey Add'],
  [OPCODE_APPKEY_STATUS, 'Config AppKey Status'],
  [OPCODE_MODEL_APP_BIND, 'Config Model App Bind'],
  [OPCODE_MODEL_APP_STATUS, 'Config Model App Status'],
  [OPCODE_NODE_RESET, 'Config Node Reset'],
  [OPCODE_NODE_RESET_STATUS, 'Config Node Reset Status'],
]);

/** The specification's own name for `opcode`, or `null` for an opcode this
 *  module does not implement (a perfectly ordinary thing to be handed - a
 *  node may send any message its models define). */
export function describeConfigOpcode(opcode: number): string | null {
  return CONFIG_OPCODE_NAMES.get(opcode) ?? null;
}

const STATUS_OPCODE_BY_REQUEST: ReadonlyMap<number, number> = new Map([
  [OPCODE_COMPOSITION_DATA_GET, OPCODE_COMPOSITION_DATA_STATUS],
  [OPCODE_APPKEY_ADD, OPCODE_APPKEY_STATUS],
  [OPCODE_MODEL_APP_BIND, OPCODE_MODEL_APP_STATUS],
  [OPCODE_NODE_RESET, OPCODE_NODE_RESET_STATUS],
]);

/** One request and the status message that answers it, both named - what a
 *  caller needs to recognise its own reply and to say, in words, what it was
 *  waiting for. */
export interface ConfigExchangeDescription {
  readonly requestOpcode: number;
  readonly requestName: string;
  readonly statusOpcode: number;
  readonly statusName: string;
}

/**
 * Describes the exchange a complete, encoded Config REQUEST PDU
 * (Opcode||Parameters, as every `encodeConfig*` above returns) starts:
 * which status opcode answers it, and both messages' names.
 *
 * `null` for anything that is not one of this module's four requests -
 * including a status message passed in by mistake, which is the shape of
 * caller error worth catching loudly rather than matching against itself.
 * Only the opcode is read; the Parameters field is not inspected at all
 * (see this section's own header for what is deliberately not compared).
 */
export function describeConfigExchange(requestPdu: Buffer): ConfigExchangeDescription | null {
  const message = decodeAccessMessage(requestPdu);
  if (message === null) {
    return null;
  }
  const statusOpcode = STATUS_OPCODE_BY_REQUEST.get(message.opcode);
  if (statusOpcode === undefined) {
    return null;
  }
  return {
    requestOpcode: message.opcode,
    requestName: CONFIG_OPCODE_NAMES.get(message.opcode) as string,
    statusOpcode,
    statusName: CONFIG_OPCODE_NAMES.get(statusOpcode) as string,
  };
}

// ===========================================================================
// Field widths and protocol-constant values.
// ===========================================================================

const MAX_OCTET = 0xff; // Page (Table 4.86/4.87), Status (Table 4.308), 8 bits.
const MAX_2_OCTET = 0xffff; // 16 bits - SIG Model ID, Company Identifier, Vendor Model Identifier.
const APP_KEY_LENGTH = 16; // Table 4.119's AppKey row: 16 octets, "AppKey value".

// Section 4.3.1.1 "Key indexes": "Global key indexes are 12 bits long."
const MAX_KEY_INDEX = 0x0fff;

/**
 * Table 3.5 "16-bit address allocations": `0b0xxxxxxxxxxxxxxx (excluding
 * 0b0000000000000000)` is Unicast Address, 0x0001-0x7fff. Table 4.128's own
 * ElementAddress row is explicit that only this form is legal here: "The
 * ElementAddress field is the unicast address of the element, all other
 * address types are Prohibited." This bound is enforced only on the
 * ENCODE side (`encodeConfigModelAppBind`, below) - it is this module's own
 * caller's mistake to build a request with a non-unicast ElementAddress;
 * decoding a node's own Config Model App Status reply never rejects
 * whatever ElementAddress value the node actually reports back (the same
 * "caller mistake on encode, not malformed on decode" split
 * `packet/access.ts#encodeOpcode`/`decodeAccessMessage` already draw).
 */
const MIN_UNICAST_ADDRESS = 0x0001;
const MAX_UNICAST_ADDRESS = 0x7fff;

// Table 3.64 "Vendor Model ID format" / Section 3.8.2 "Model identifier":
// a SIG Model ID is 16 bits (2 octets); a Vendor Model ID is a 16-bit
// Company Identifier followed by a 16-bit Vendor Model Identifier (4
// octets) - the same two widths `composition.ts` already uses to decode
// Composition Data Page 0's own model lists.
const SIG_MODEL_ID_LENGTH = 2;
const VENDOR_MODEL_ID_LENGTH = 4;

/** Keeps this module's error messages prefixed consistently with the rest of the package. */
function assertConfigField(field: string, value: number, max: number): void {
  assertRange(`config field "${field}"`, value, max);
}

// ===========================================================================
// Key index packing (Section 4.3.1.1 "Key indexes", Figure 4.4/Figure 4.5).
//
// "Global key indexes are 12 bits long. Some messages include one, two or
// multiple key indexes. To enable efficient packing, two key indexes are
// packed into three octets. Where an odd number of key indexes need to be
// packed, all but the last key index are packed into sequences of three
// octets (see Figure 4.4), and the last key index is packed into two
// octets (see Figure 4.5)."
//
// Figure 4.4 "Packing of two 12-bit key Indexes into three octets": "To
// pack two key indexes into three octets, 8 LSbs of first key index value
// are packed into the first octet, placing the remaining 4 MSbs into 4
// LSbs of the second octet. The first 4 LSbs of the second 12-bit key
// index are packed into the 4 MSbs of the second octet with the remaining
// 8 MSbs into the third octet."
//
// Figure 4.5 "Encoding of one 12-bit key index into two octets": "To pack
// one key index into two octets, 8 LSbs of first key index value are
// packed into the first octet, placing the remaining 4 MSbs into 4 LSbs of
// the second octet, and the 4 MSbs of the second octet shall be set to 0."
//
// This is the access layer's OWN little-endian representation of a 12-bit
// value, not a separate packing convention layered on top of endianness
// (`provisioning/machine.ts`'s module header works through why in detail,
// for the same figures cited from Provisioning's side) - which is why
// every message below uses it (Table 4.119/4.122's own field text: "These
// two indexes shall be encoded as defined in Section 4.3.1.1 using NetKey
// Index as first key index and AppKey Index as second key index" - the
// clause that fixes which index goes in which half; Table 4.128/4.130's
// own field text: "The AppKeyIndex field shall be encoded as defined in
// Section 4.3.1.1").
// ===========================================================================

/**
 * Packs two 12-bit global key indexes into three octets (Figure 4.4).
 * VERIFIED against Section 8.3.6 "Message #6" (a Config AppKey Add):
 * NetKeyIndex=0x456, AppKeyIndex=0x123 (Table 4.119's own field text:
 * "These two indexes shall be encoded as defined in Section 4.3.1.1 using
 * NetKey Index as first key index and AppKey Index as second key index" -
 * the clause that fixes which argument below is `first`)
 * publishes as `56 34 12` - exactly what this formula produces by hand:
 * octet0 = 0x456 & 0xff = 0x56; octet1 = ((0x456>>8)&0xf) | ((0x123&0xf)<<4)
 * = 0x4 | 0x30 = 0x34; octet2 = (0x123>>4)&0xff = 0x12.
 *
 * Callers must range-check `first`/`second` against `MAX_KEY_INDEX`
 * themselves before calling this (the same "validate once at the public
 * entry point, not again in an internal helper" split
 * `packet/access.ts#encodeOpcode` already uses).
 */
function packTwoKeyIndexes(first: number, second: number): Buffer {
  const octet0 = first & 0xff;
  const octet1 = ((first >>> 8) & 0x0f) | ((second & 0x0f) << 4);
  const octet2 = (second >>> 4) & 0xff;
  return Buffer.from([octet0, octet1, octet2]);
}

/**
 * Inverts `packTwoKeyIndexes`, reading three octets starting at `offset`.
 * Caller must ensure `buffer` has at least `offset + 3` octets.
 */
function unpackTwoKeyIndexes(buffer: Buffer, offset: number): { first: number; second: number } {
  const octet0 = buffer[offset] as number;
  const octet1 = buffer[offset + 1] as number;
  const octet2 = buffer[offset + 2] as number;
  const first = octet0 | ((octet1 & 0x0f) << 8);
  const second = ((octet1 >>> 4) & 0x0f) | (octet2 << 4);
  return { first, second };
}

/**
 * Packs one 12-bit global key index into two octets (Figure 4.5). No
 * message in the Mesh Protocol document's Section 8.3 sample data
 * exercises this single-index form with a published byte string (the
 * NetKeyIndex/AppKeyIndex pair in Sections 8.3.6/8.3.16 both use Figure
 * 4.4's two-index form instead) - the arithmetic below is this module's own
 * hand computation from the figure's stated procedure, verified against
 * the 12-bit domain's own top value, 0xFFF (`client.test.ts`'s own
 * boundary test uses this same value, derived here, not observed from
 * running the encoder): octet0 = 0xfff & 0xff = 0xff; octet1 =
 * (0xfff>>8)&0xf = 0xf (the second octet's top nibble is 0, exactly as
 * Figure 4.5 requires).
 */
function packSingleKeyIndex(index: number): Buffer {
  const octet0 = index & 0xff;
  const octet1 = (index >>> 8) & 0x0f;
  return Buffer.from([octet0, octet1]);
}

/**
 * Inverts `packSingleKeyIndex`, reading two octets starting at `offset`.
 * The second octet's top nibble is MASKED OFF, not checked and rejected:
 * Figure 4.5's "shall be set to 0" is a constraint on what a conformant
 * ENCODER produces (enforced here by `packSingleKeyIndex` always zeroing
 * it), not a promise this module can rely on for a buffer it only reads -
 * the same "decode leniently, encode strictly" split `composition.ts`'s own
 * "RESERVED BITS: MASK, NEVER REJECT" note already draws for Composition
 * Data Page 0's RFU Features bits, grounded in the same general rule
 * (Section 1.3.2 "Reserved for Future Use": "Implementations that receive a
 * message that contains a Reserved for Future Use bit that is set to 1
 * shall process the message as if that bit was set to 0, except where
 * specified otherwise in this specification" - process, not reject).
 * Caller must ensure `buffer` has at least `offset + 2` octets.
 */
function unpackSingleKeyIndex(buffer: Buffer, offset: number): number {
  const octet0 = buffer[offset] as number;
  const octet1 = buffer[offset + 1] as number;
  return octet0 | ((octet1 & 0x0f) << 8);
}

// ===========================================================================
// Model identifiers (Table 3.64 "Vendor Model ID format"; Table 4.128/4.130's
// own "2 or 4" ModelIdentifier size column).
// ===========================================================================

/**
 * A Model Identifier is either a 16-bit SIG Model ID (a plain `number`,
 * the same representation `composition.ts#ElementDescription.sigModels`
 * already uses) or a 32-bit Vendor Model ID (`composition.ts`'s own
 * `VendorModelId`, imported rather than redefined here, per the "Type
 * consistency" global constraint) - which one a given value is, is
 * determined purely by its JS `typeof` (`"number"` vs `"object"`), exactly
 * mirroring how the wire form is determined purely by the Parameters
 * field's own remaining length (2 octets vs 4) once the fixed-size fields
 * ahead of it are accounted for - there is no separate discriminant tag on
 * either side.
 */
export type ModelIdentifier = number | VendorModelId;

function isVendorModelId(id: ModelIdentifier): id is VendorModelId {
  return typeof id === 'object' && id !== null;
}

function encodeModelIdentifier(id: ModelIdentifier): Buffer {
  if (isVendorModelId(id)) {
    assertConfigField('modelIdentifier.companyId', id.companyId, MAX_2_OCTET);
    assertConfigField('modelIdentifier.modelId', id.modelId, MAX_2_OCTET);
    const buffer = Buffer.alloc(VENDOR_MODEL_ID_LENGTH);
    buffer.writeUInt16LE(id.companyId, 0); // Table 3.64: Company Identifier first, Vendor Model Identifier second.
    buffer.writeUInt16LE(id.modelId, 2);
    return buffer;
  }
  assertConfigField('modelIdentifier', id, MAX_2_OCTET);
  const buffer = Buffer.alloc(SIG_MODEL_ID_LENGTH);
  buffer.writeUInt16LE(id, 0);
  return buffer;
}

/** `parameters` must be exactly `SIG_MODEL_ID_LENGTH` or `VENDOR_MODEL_ID_LENGTH` octets; any other length is `null`, not a throw (this is the decode side). */
function decodeModelIdentifier(parameters: Buffer): ModelIdentifier | null {
  if (parameters.length === SIG_MODEL_ID_LENGTH) {
    return parameters.readUInt16LE(0);
  }
  if (parameters.length === VENDOR_MODEL_ID_LENGTH) {
    return { companyId: parameters.readUInt16LE(0), modelId: parameters.readUInt16LE(2) };
  }
  return null;
}

// ===========================================================================
// Status codes (Section 4.3.14 "Summary of status codes", Table 4.308
// "Summary of configuration and health messages status codes"). Of this
// module's eight messages, only Config AppKey Status (Table 4.122) and
// Config Model App Status (Table 4.130) carry a Status field at all -
// Config Composition Data Status (Table 4.87) and Config Node Reset Status
// (Table 4.136) have none.
// ===========================================================================

const CONFIG_STATUS_NAMES: ReadonlyMap<number, string> = new Map([
  [0x00, 'Success'],
  [0x01, 'Invalid Address'],
  [0x02, 'Invalid Model'],
  [0x03, 'Invalid AppKey Index'],
  [0x04, 'Invalid NetKey Index'],
  [0x05, 'Insufficient Resources'],
  [0x06, 'Key Index Already Stored'],
  [0x07, 'Invalid Publish Parameters'],
  [0x08, 'Not a Subscribe Model'],
  [0x09, 'Storage Failure'],
  [0x0a, 'Feature Not Supported'],
  [0x0b, 'Cannot Update'],
  [0x0c, 'Cannot Remove'],
  [0x0d, 'Cannot Bind'],
  [0x0e, 'Temporarily Unable to Change State'],
  [0x0f, 'Cannot Set'],
  [0x10, 'Unspecified Error'],
  [0x11, 'Invalid Binding'],
  [0x12, 'Invalid Path Entry'],
  [0x13, 'Cannot Get'],
  [0x14, 'Obsolete Information'],
  [0x15, 'Invalid Bearer'],
  // 0x16-0xFF: "RFU" (Table 4.308) - deliberately absent from this map, so
  // `describeConfigStatus` falls through to its own `null` for them.
]);

/**
 * Names a Config status code (Table 4.308); `null` for 0x16-0xFF ("RFU",
 * per the table's own last row) or any value outside the single-octet
 * Status field's domain. Exported because this task's own brief states the
 * reason this table matters beyond this module: "a failure shows the hub's
 * own message rather than a generic one; a status code we cannot name is
 * useless to a user."
 */
export function describeConfigStatus(status: number): string | null {
  return CONFIG_STATUS_NAMES.get(status) ?? null;
}

// ===========================================================================
// Outgoing messages: one encoder per message, each returning the complete
// wire PDU (`encodeAccessMessage`'s own Buffer output - Opcode||Parameters).
// ===========================================================================

/** Table 4.86 "Config Composition Data Get message structure": Opcode (2) || Page (1). */
export function encodeConfigCompositionDataGet(page: number): Buffer {
  assertConfigField('page', page, MAX_OCTET);
  return encodeAccessMessage({ opcode: OPCODE_COMPOSITION_DATA_GET, parameters: Buffer.from([page]) });
}

/** Table 4.119 "Config AppKey Add message structure" fields, Figure 4.4-packed. */
export interface ConfigAppKeyAddParams {
  /** Global NetKey Index, 12 bits (Section 4.3.1.1). */
  netKeyIndex: number;
  /** Global AppKey Index, 12 bits (Section 4.3.1.1). */
  appKeyIndex: number;
  /** The 16-octet AppKey value (Table 4.119: "AppKey value"). */
  appKey: Buffer;
}

/**
 * Table 4.119 "Config AppKey Add message structure": Opcode (1) ||
 * NetKeyIndexAndAppKeyIndex (3, Figure 4.4, NetKey Index first per the
 * table's own field text) || AppKey (16).
 */
export function encodeConfigAppKeyAdd(params: ConfigAppKeyAddParams): Buffer {
  assertConfigField('netKeyIndex', params.netKeyIndex, MAX_KEY_INDEX);
  assertConfigField('appKeyIndex', params.appKeyIndex, MAX_KEY_INDEX);
  if (params.appKey.length !== APP_KEY_LENGTH) {
    throw new Error(`config field "appKey" must be ${APP_KEY_LENGTH} bytes (Table 4.119), got ${params.appKey.length}`);
  }
  const indexes = packTwoKeyIndexes(params.netKeyIndex, params.appKeyIndex);
  // BELT AND BRACES, NOT LOAD-BEARING - do not read this `Buffer.from` as
  // the thing that keeps the caller's `appKey` out of the returned PDU.
  // `Buffer.concat` already allocates a fresh buffer and copies its inputs
  // into it, so the result never aliases `params.appKey` whether or not
  // this copy is here; measured, not assumed (filling `appKey` with a
  // different byte after the call leaves the returned PDU unchanged with
  // the inner `Buffer.from` removed). It is kept because it makes the
  // no-aliasing property local and obvious at the one site that handles
  // caller-supplied key material, rather than resting on a reader knowing
  // `Buffer.concat`'s copying semantics - but the genuine aliasing hazard
  // this project documents elsewhere (`composition.ts`'s NO BUFFER
  // ALIASING note, `provisioning/machine.ts`'s INPUT OWNERSHIP note) is a
  // RETAINED reference across calls, and nothing is retained here at all.
  const parameters = Buffer.concat([indexes, Buffer.from(params.appKey)]);
  return encodeAccessMessage({ opcode: OPCODE_APPKEY_ADD, parameters });
}

/** Table 4.128 "Config Model App Bind message structure" fields. */
export interface ConfigModelAppBindParams {
  /** The unicast address of the element (Table 4.128: "all other address types are Prohibited"). */
  elementAddress: number;
  /** Global AppKey Index, 12 bits (Section 4.3.1.1, Figure 4.5 single-index packing). */
  appKeyIndex: number;
  /** SIG Model ID (`number`) or Vendor Model ID (`{ companyId, modelId }`). */
  modelIdentifier: ModelIdentifier;
}

/**
 * Table 4.128 "Config Model App Bind message structure": Opcode (2) ||
 * ElementAddress (2) || AppKeyIndex (2, Figure 4.5) || ModelIdentifier (2
 * or 4).
 */
export function encodeConfigModelAppBind(params: ConfigModelAppBindParams): Buffer {
  if (
    !Number.isInteger(params.elementAddress) ||
    params.elementAddress < MIN_UNICAST_ADDRESS ||
    params.elementAddress > MAX_UNICAST_ADDRESS
  ) {
    throw new Error(
      `config field "elementAddress" must be a unicast address in [0x${MIN_UNICAST_ADDRESS.toString(16)}, 0x${MAX_UNICAST_ADDRESS.toString(16)}] (Table 4.128: "all other address types are Prohibited"), got ${params.elementAddress}`,
    );
  }
  assertConfigField('appKeyIndex', params.appKeyIndex, MAX_KEY_INDEX);

  const elementAddress = Buffer.alloc(2);
  elementAddress.writeUInt16LE(params.elementAddress, 0);
  const appKeyIndex = packSingleKeyIndex(params.appKeyIndex);
  const modelIdentifier = encodeModelIdentifier(params.modelIdentifier);

  const parameters = Buffer.concat([elementAddress, appKeyIndex, modelIdentifier]);
  return encodeAccessMessage({ opcode: OPCODE_MODEL_APP_BIND, parameters });
}

/** Table 4.135 "Config Node Reset message structure": Opcode (2) only - no parameters. */
export function encodeConfigNodeReset(): Buffer {
  return encodeAccessMessage({ opcode: OPCODE_NODE_RESET, parameters: Buffer.alloc(0) });
}

// ===========================================================================
// Incoming status messages: one dispatching decoder (see the module
// header's DESIGN note). Every Buffer field returned is read into plain
// numbers immediately (`readUInt16LE` et al.) or, for
// `ConfigCompositionDataStatus.composition`, produced by
// `parseCompositionData` - which itself never retains a view into its
// input (`composition.ts`'s own NO BUFFER ALIASING note) - so nothing
// returned here is a view into the caller-supplied `pdu`.
// ===========================================================================

/** Table 4.87 "Config Composition Data Status message structure": Page || Data (one Composition Data page). */
export interface ConfigCompositionDataStatus {
  type: 'compositionData';
  page: number;
  /**
   * `null` exactly when `parseCompositionData` itself returns `null` for
   * the Data field (malformed/truncated page) - this module's own nullish
   * convention here is to CONSUME that module's `null` as this field's
   * own state, unchanged, rather than collapsing the whole status message
   * to `null`: the envelope (Page present, Data field identified) is
   * still perfectly well-formed even when the Data it carries is not.
   */
  composition: CompositionData | null;
}

/** Table 4.122 "Config AppKey Status message structure": Status || NetKeyIndexAndAppKeyIndex. */
export interface ConfigAppKeyStatus {
  type: 'appKey';
  /** Raw Status Code (Table 4.308). */
  status: number;
  /** `describeConfigStatus(status)` - `null` for an unnamed ("RFU") code. */
  statusName: string | null;
  netKeyIndex: number;
  appKeyIndex: number;
}

/** Table 4.130 "Config Model App Status message structure": Status || ElementAddress || AppKeyIndex || ModelIdentifier. */
export interface ConfigModelAppStatus {
  type: 'modelApp';
  status: number;
  statusName: string | null;
  elementAddress: number;
  appKeyIndex: number;
  modelIdentifier: ModelIdentifier;
}

/** Table 4.136 "Config Node Reset Status message structure": Opcode only - no parameters to report. */
export interface ConfigNodeResetStatus {
  type: 'nodeReset';
}

export type ConfigStatus =
  | ConfigCompositionDataStatus
  | ConfigAppKeyStatus
  | ConfigModelAppStatus
  | ConfigNodeResetStatus;

/**
 * Decodes any one of this module's four status messages from a complete
 * wire PDU (Opcode||Parameters). Returns `null` for anything this function
 * cannot resolve to one specific, well-formed status message:
 * `decodeAccessMessage` itself returning `null` (malformed/too-short
 * envelope, or the 0x7F reserved opcode), an opcode this module does not
 * recognise as one of its four status opcodes ("a status whose opcode we
 * do not recognise decodes to `null`" - the brief's own words), or a
 * recognised opcode whose Parameters field is the wrong length for that
 * message's fixed layout (the same "message size is wrong for what it
 * claims to carry, therefore not understood" stance
 * `composition.ts`/`packet/access.ts` already take, applied one layer up).
 */
export function decodeConfigStatus(pdu: Buffer): ConfigStatus | null {
  const message = decodeAccessMessage(pdu);
  if (message === null) {
    return null;
  }
  const { opcode, parameters } = message;

  switch (opcode) {
    case OPCODE_COMPOSITION_DATA_STATUS: {
      if (parameters.length < 1) {
        return null;
      }
      const page = parameters[0] as number;
      const data = parameters.subarray(1);
      return { type: 'compositionData', page, composition: parseCompositionData(data) };
    }

    case OPCODE_APPKEY_STATUS: {
      if (parameters.length !== 4) {
        return null;
      }
      const status = parameters[0] as number;
      const { first: netKeyIndex, second: appKeyIndex } = unpackTwoKeyIndexes(parameters, 1);
      return { type: 'appKey', status, statusName: describeConfigStatus(status), netKeyIndex, appKeyIndex };
    }

    case OPCODE_MODEL_APP_STATUS: {
      // MOSTLY BELT AND BRACES. Table 4.130's Parameters are Status (1) ||
      // ElementAddress (2) || AppKeyIndex (2) || ModelIdentifier (2 or 4),
      // so 7 and 9 are the only legal lengths - but `decodeModelIdentifier`
      // below already rejects every other length on its own, because what
      // it is handed is exactly `parameters.length - 5` octets and it
      // accepts only 2 or 4. Measured: deleting this guard outright passes
      // the whole suite. It is NOT quite dead, and that is the only reason
      // it survives review as code rather than as a comment: for a
      // Parameters field shorter than 3 octets, `readUInt16LE(1)` on the
      // next line throws before `decodeModelIdentifier` is ever reached
      // (measured - a `80 3E` PDU with 0, 1 or 2 Parameters octets throws a
      // RangeError without this guard and returns `null` with it), and this
      // module's whole decode stance is `null`, never a throw. So read this
      // as "keep the short-buffer cases out of the field reads below", not
      // as the check that decides which lengths are legal.
      if (parameters.length !== 7 && parameters.length !== 9) {
        return null;
      }
      const status = parameters[0] as number;
      const elementAddress = parameters.readUInt16LE(1);
      const appKeyIndex = unpackSingleKeyIndex(parameters, 3);
      const modelIdentifier = decodeModelIdentifier(parameters.subarray(5));
      if (modelIdentifier === null) {
        return null;
      }
      return {
        type: 'modelApp',
        status,
        statusName: describeConfigStatus(status),
        elementAddress,
        appKeyIndex,
        modelIdentifier,
      };
    }

    case OPCODE_NODE_RESET_STATUS: {
      if (parameters.length !== 0) {
        return null;
      }
      return { type: 'nodeReset' };
    }

    default:
      return null;
  }
}
