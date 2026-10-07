/**
 * The Proxy PDU envelope (Mesh Protocol v1.1, Section 6.3 "Proxy PDU") —
 * the one-octet header that every byte written to, or notified from, a
 * Mesh Proxy / Mesh Provisioning characteristic carries, and the
 * segmentation and reassembly that header drives.
 *
 * WHY THIS MODULE EXISTS AT ALL, written plainly because it was missing
 * until the final review of this project found it: every GATT write this
 * app made carried a BARE Network PDU (or a bare Provisioning PDU), and
 * every notification was parsed as if it were bare. Not one byte of that
 * can be understood by a node. Section 3.3.2 "GATT bearer": "The GATT
 * bearer uses the Proxy protocol (see Section 6) to transmit and receive
 * Proxy PDUs between two devices over a GATT connection." Section 7.2.3.1
 * "Mesh Proxy Data In characteristic": "The characteristic value has the
 * same format as the Proxy PDU." — and the same sentence appears for the
 * Data Out characteristic (Section 7.2.3.2). The provisioning side says it
 * just as explicitly, Section 5.2.2 "PB-GATT": "The Mesh Provisioning Data
 * In and Mesh Provisioning Data Out characteristic formats use the Proxy
 * PDU format defined in Section 6.3.1." Worse than merely being ignored, a
 * bare Network PDU's first octet is not a valid envelope, and Section
 * 6.3.2.2 "Reassembly" says what a node does about that: "Upon receiving a
 * message with an unexpected value of the SAR field, the Proxy PDU Server
 * shall disconnect."
 *
 * THIS IS lib/mesh, NOT lib/adapter, for exactly the reasons `message.ts`'s
 * own header gives for itself: pure byte work over buffers, no I/O, no
 * clock of its own, importing nothing. The adapter layer
 * (`lib/adapter/connection.ts` for the proxy characteristics,
 * `drivers/light/pairing.ts` for the provisioning ones) owns the radio and
 * the clock and calls into this module; this module never calls out.
 *
 * THE LAYOUT, Table 6.1 "Proxy PDU format" (Section 6.3.1 "PDU format"),
 * transcribed row by row — field name, size in bits, description:
 *
 *   SAR         | 2        | Message segmentation and reassembly information
 *   MessageType | 6        | Type of message contained in the PDU
 *   Data        | variable | Full message or message segment
 *
 * WHICH BITS. Section 3.1.1 "Endianness and field ordering": "Where network
 * data structures are made of multiple fields, the fields are listed in the
 * tables from top to bottom and they appear in the corresponding figures
 * from left to right (i.e., the top row of the table corresponds to the
 * left of the figure)." and Section 3.1.1.1 "Big-endian" gives the
 * procedure: "The most significant bits (MSbs) of the number are set to the
 * value of Field 0 (first row of the table), then the number's unassigned
 * MSbs are set to the value of Field 1." SAR is Table 6.1's first row, so
 * SAR occupies the TWO MOST SIGNIFICANT bits of the header octet and
 * MessageType the remaining six — `PROXY_SAR_SHIFT`/`PROXY_MESSAGE_TYPE_MASK`
 * below. (The single-octet header makes multi-octet endianness itself moot;
 * only the within-octet field order matters, and that is what the two
 * sentences above settle.)
 *
 * THE SAR VALUES, Table 6.2 "SAR field values", transcribed in full:
 *
 *   0b00 | Data field contains a complete message
 *   0b01 | Data field contains the first segment of a message
 *   0b10 | Data field contains a continuation segment of a message
 *   0b11 | Data field contains the last segment of a message
 *
 * THE MESSAGE TYPES, Table 6.3 "MessageType values", transcribed in full
 * (type, name, description):
 *
 *   0x00      | Network PDU       | The message is a Network PDU as defined in Section 3.4.4.
 *   0x01      | Mesh Beacon       | The message is a mesh beacon as defined in Section 3.10.
 *   0x02      | Proxy Configuration | The message is a proxy configuration message as defined in Section 6.6.
 *   0x03      | Provisioning PDU  | The message is a Provisioning PDU as defined in Section 5.4.1.
 *   0x04–0x3F | RFU               | Reserved for Future Use.
 *
 * The proxy service and the provisioning service use DIFFERENT ones of
 * those, and each says so about itself: Section 7.2.3.1.1 "Characteristic
 * behavior" — "The Mesh Proxy Data In characteristic shall support Proxy
 * PDU messages containing Network PDUs, mesh beacons, and proxy
 * configuration messages and shall not support other Proxy PDU type
 * messages."; Section 7.1.3.1.1 "Characteristic behavior" — "The Mesh
 * Provisioning Data In characteristic shall support Proxy PDU messages
 * containing Provisioning PDUs and shall not support other Proxy PDU type
 * messages."
 *
 * SEGMENTATION, Section 6.3.2.1 "Segmentation": "When sending a message
 * that is less than or equal to the maximum size of a Proxy PDU, the SAR
 * field shall be set to 0b00 and the Data field shall contain the complete
 * message." and "When sending a message that is greater than the maximum
 * size of a Proxy PDU, the message is divided into segments that will fill
 * each Proxy PDU except for the last Proxy PDU that may or may not be
 * filled. These segments shall be sent in order and the SAR field of the
 * first segment shall be set to 0b01, the SAR field of the last segment
 * shall be set to 0b11, and all other segments shall have the SAR field
 * set to 0b10." Note "will FILL each Proxy PDU except for the last": the
 * segments are maximal, not evenly divided — `encodeProxyPdus` below fills
 * greedily, which is what that sentence requires.
 *
 * REASSEMBLY, Section 6.3.2.2 "Reassembly", which is written as a list of
 * conditions under which the receiver SHALL DISCONNECT rather than as a
 * state machine: "Upon receiving a message with an unexpected value of the
 * SAR field, the Proxy PDU Client shall disconnect." and "The timeout for
 * the SAR transfer is 20 seconds. When the timeout expires, the Proxy PDU
 * Client shall disconnect." (both sentences appear twice in that section,
 * once for the Server role and once, identically, for the Client role —
 * this app is the Client). `acceptProxyPdu` below therefore has a
 * `'disconnect'` result variant: this module cannot disconnect anything
 * itself (it owns no radio), so it NAMES the condition and the adapter
 * acts on it. What counts as "unexpected" is the one judgement this module
 * has to make, because the specification does not enumerate it; the
 * reading taken here, and the reason for each:
 *   - a continuation or last segment with NO reassembly in progress: there
 *     is nothing for it to continue, so it cannot be anything but
 *     unexpected;
 *   - a complete message, or a first segment, WHILE a reassembly is in
 *     progress: the sender is required to send segments "in order" (above),
 *     so a non-continuation arriving mid-message means the two sides
 *     disagree about the state of the transfer — the exact situation the
 *     disconnect rule exists to end;
 *   - a continuation/last segment whose MessageType differs from the one
 *     the first segment established: the Data field is defined as "a
 *     message defined by the MessageType field", singular, so one
 *     reassembly cannot carry two of them.
 * THE LENGTH CONDITIONS, the rest of Section 6.3.2.2's list, transcribed in
 * full (the module used to quote only the unexpected-SAR sentence above and
 * then claim the list was complete, which is how a reassembly here grew to
 * 95 019 octets in a reviewer's measurement — the maximal Network PDU is
 * 29). The section states the list twice, once per role, identically; this
 * is the Client copy, verbatim:
 *
 *   "Upon receiving a Proxy PDU matching one of the following conditions,
 *   the Proxy PDU Client shall disconnect:
 *     The MessageType field equal to a Network PDU and the Data field
 *     longer than the maximal size of a Network PDU (see Section 3.4.4)
 *     The MessageType field equal to a Mesh Beacon and the Data field
 *     longer than the maximal size of a Mesh Beacon (see Section 3.10)
 *     The MessageType field equal to a Proxy Configuration and the Data
 *     field longer than the maximal size of a proxy configuration message
 *     (see Section 6.6)
 *     The MessageType field equal to a Provisioning PDU and the Data field
 *     longer than the maximal size of a supported Provisioning PDU (see
 *     Section 5.4.1)"
 *
 * TWO OF THE FOUR ARE UNREACHABLE HERE, and that is not an omission: Mesh
 * Beacon (0x01) and Proxy Configuration (0x02) are not supported by this
 * app, so Section 6.3.2 "Behavior"'s own "shall ignore this message" —
 * checked BEFORE any of this, see `messageTypeIsSupported` — has already
 * disposed of them. The two that remain are implemented, with their maxima
 * below.
 *
 * "THE DATA FIELD", DURING A REASSEMBLY, IS THE WHOLE MESSAGE, which is the
 * one reading these conditions can have inside a section titled
 * "Reassembly": for a complete (0b00) PDU the Data field already IS the
 * message, and for a segmented transfer "the Data field" of the message
 * being assembled is the concatenation Section 6.3.2.1 defines the segments
 * as dividing. So the limit is checked against the RUNNING TOTAL, which
 * subsumes the per-PDU check (a single complete PDU's total is its own Data
 * length) and is the only reading under which a reassembly is bounded at
 * all. The alternative — comparing each segment's own Data field, which can
 * never exceed one Proxy PDU — would make the condition unreachable by
 * construction for every segmented message, which cannot be what a
 * disconnect rule in the reassembly section means.
 *
 * Everything NOT on that list is treated conservatively as `'ignored'`
 * (keeping any reassembly in progress intact), because the specification's
 * own disconnect list is explicit and a disconnect is the expensive
 * outcome: an empty PDU, a header with no Data at all, and — per Section
 * 6.3.2 "Behavior", quoted in `messageTypeIsSupported` below — any
 * message type this app does not support.
 *
 * STATELESS BY DESIGN, exactly like `reassembly.ts` and `message.ts` next
 * to it: `ProxyReassemblyState` is an immutable value the CALLER owns and
 * hands back; this module keeps no map, no timer and no clock. The 20-second
 * SAR timeout needs a clock, so it is expressed two ways, both pure: the
 * `nowMs` argument `acceptProxyPdu` already takes (so an arriving segment
 * that is too late is caught on arrival), and `proxySarTransferExpired`
 * (so an adapter with a timer can catch a transfer that simply stops, which
 * arrival alone never can).
 *
 * NULLISH CONVENTION: `undefined` for "no reassembly in progress",
 * matching `reassembly.ts`/`message.ts` rather than the `null` of the
 * adapter modules — for the same reason `reassembly.ts` gives: the caller's
 * natural storage is a field or a `Map`, whose "nothing yet" is already
 * `undefined`.
 */

// Table 6.1: SAR is the first row (2 bits), MessageType the second (6 bits);
// see the module header's WHICH BITS note for why that puts SAR in the two
// most significant bits of the header octet.
export const PROXY_SAR_SHIFT = 6;
export const PROXY_MESSAGE_TYPE_MASK = 0x3f;

/** Table 6.2 "SAR field values" — see the module header for each row's own
 *  transcribed description. */
export const PROXY_SAR_COMPLETE = 0b00;
export const PROXY_SAR_FIRST = 0b01;
export const PROXY_SAR_CONTINUATION = 0b10;
export const PROXY_SAR_LAST = 0b11;

/** Table 6.3 "MessageType values" — see the module header for the full
 *  transcription including each row's name and description. */
export const PROXY_MESSAGE_TYPE_NETWORK_PDU = 0x00;
export const PROXY_MESSAGE_TYPE_MESH_BEACON = 0x01;
export const PROXY_MESSAGE_TYPE_PROXY_CONFIGURATION = 0x02;
export const PROXY_MESSAGE_TYPE_PROVISIONING_PDU = 0x03;
/** Table 6.3's last row: 0x04–0x3F | RFU | "Reserved for Future Use." */
export const PROXY_MESSAGE_TYPE_RFU_FIRST = 0x04;

/** Section 6.3.2.2 "Reassembly": "The timeout for the SAR transfer is 20
 *  seconds. When the timeout expires, the Proxy PDU Client shall
 *  disconnect." */
export const PROXY_SAR_TIMEOUT_MS = 20_000;

/**
 * "the maximal size of a Network PDU (see Section 3.4.4)" — Section 6.3.2.2.
 * The document publishes no number; Section 3.4.4 publishes the field
 * widths, and these are what they add up to.
 *
 * Table 3.10 "Network PDU field definitions": IVI 1 bit, NID 7, CTL 1, TTL
 * 7, SEQ 24, SRC 16, DST 16 — 72 bits, so 9 octets before the payload. The
 * remaining two rows are "TransportPDU | 8 to 128" and "NetMIC | 32 or 64",
 * which read alone would allow 9 + 16 + 8 = 33; but the two are not
 * independent. Section 3.4.4.3 "CTL": "If the CTL field is set to 0, the
 * NetMIC is a 32-bit field and the Lower Transport PDU contains an Access
 * message. If the CTL field is set to 1, the NetMIC is a 64-bit field and
 * the Lower Transport PDU contains a Transport Control message." So:
 *   - CTL = 0, a 4-octet NetMIC over an Access message, whose own maximum
 *     is 16 octets either form — Table 3.17 "Unsegmented Access message
 *     format" (SEG+AKF+AID = 1 octet, Upper Transport Access PDU "40 to
 *     120" bits = 15) and Table 3.18 "Segmented Access message format"
 *     (4 octets of header, "Segment m | 8 to 96" = 12). 9 + 16 + 4 = 29.
 *   - CTL = 1, an 8-octet NetMIC over a Control message, whose maximum is
 *     12 octets either form — Table 3.19 "Unsegmented Control message
 *     format" (1 octet, "Parameters | 0 to 88" = 11) and Table 3.22
 *     "Segmented Control message format" (4 octets, "Segment m | 8 to 64"
 *     = 8). 9 + 12 + 8 = 29.
 * Both branches land on the same number, which is also the number Section
 * 7.2.2.2.7 "ATT_MTU" implies from the other direction: "The server should
 * support an ATT_MTU size equal to or larger than 33 octets to be able to
 * pass the content of a full Proxy PDU (see Section 6.5)." — 33 less the
 * 3 octets of ATT overhead is 30, one Proxy PDU header octet plus 29.
 */
export const MAX_NETWORK_PDU_LENGTH = 29;

/**
 * "the maximal size of a SUPPORTED Provisioning PDU (see Section 5.4.1)" —
 * Section 6.3.2.2, and the emphasis is the specification's own: the bound
 * is over the PDU types the implementation supports, not over everything
 * Section 5.4.1 defines. This project supports Types 0x00-0x09 (see
 * `lib/mesh/provisioning/pdu.ts`), and the largest of those is the
 * Provisioning Public Key PDU.
 *
 * Table 5.17 "Provisioning PDU format" gives a 1-octet header (Padding 2
 * bits, Type 6 bits) followed by "Parameters | variable". Table 5.36
 * "Provisioning Public Key PDU Parameters Format": "Public Key X | 32" and
 * "Public Key Y | 32" octets. 1 + 64 = 65. Nothing else this project
 * supports comes close — the next largest is Provisioning Data at 1 + 25 +
 * 8 = 34 (Table 5.39), then Confirmation/Random at 1 + 32 (Tables 5.37 and
 * 5.38, whose field is "16 or 32" octets).
 *
 * The deliberately per-app part of this is the word "supported": a project
 * that later implements Provisioning Record Response (Type 0x0B) would have
 * to raise this, and `pdu.ts`'s own type list is where that would be
 * noticed.
 */
export const MAX_SUPPORTED_PROVISIONING_PDU_LENGTH = 65;

/** The maximal message size for one of the two MessageTypes this app
 *  supports — see the two constants above, and `messageTypeIsSupported`
 *  for why no other type ever reaches this. */
function maxMessageLengthFor(messageType: number): number {
  return messageType === PROXY_MESSAGE_TYPE_NETWORK_PDU
    ? MAX_NETWORK_PDU_LENGTH
    : MAX_SUPPORTED_PROVISIONING_PDU_LENGTH;
}

/** Section 6.3.2.2's length conditions, as one check over the message
 *  length assembled so far — see the module header. `null` when the message
 *  is within its maximum. */
function tooLongReason(messageType: number, length: number): string | null {
  const max = maxMessageLengthFor(messageType);
  if (length <= max) return null;
  const what =
    messageType === PROXY_MESSAGE_TYPE_NETWORK_PDU
      ? `the maximal size of a Network PDU (${max} octets, Section 3.4.4)`
      : `the maximal size of a supported Provisioning PDU (${max} octets, Section 5.4.1)`;
  return `MessageType 0x${messageType.toString(16).padStart(2, '0')} with a Data field of ${length} octets, longer than ${what} — Section 6.3.2.2`;
}

/**
 * Section 6.3.2 "Behavior": "Upon receiving a message with the Message Type
 * field set to a value that is Reserved for Future Use or a value that is
 * not supported by the Proxy PDU Client, the Proxy PDU Client shall ignore
 * this message." Both halves of that sentence matter here: RFU is settled
 * by Table 6.3, and "not supported by" is settled by THIS app, which
 * consumes only Network PDUs and Provisioning PDUs. Mesh beacons (0x01) and
 * proxy configuration messages (0x02) are defined but unsupported here —
 * see `lib/adapter/connection.ts`'s own IV INDEX disclosure for the one
 * design clause that rests on 0x01 and is deliberately not implemented.
 */
function messageTypeIsSupported(messageType: number): boolean {
  return messageType === PROXY_MESSAGE_TYPE_NETWORK_PDU || messageType === PROXY_MESSAGE_TYPE_PROVISIONING_PDU;
}

function sarOf(header: number): number {
  return (header >> PROXY_SAR_SHIFT) & 0b11;
}

function messageTypeOf(header: number): number {
  return header & PROXY_MESSAGE_TYPE_MASK;
}

/** The header octet for one Proxy PDU — exported for the known-answer tests
 *  to build expected values from the transcribed tables rather than from
 *  this module's own encoder. */
export function proxyPduHeader(sar: number, messageType: number): number {
  if (!Number.isInteger(sar) || sar < 0 || sar > 0b11) {
    throw new Error(`proxyPduHeader: SAR must be a 2-bit value (Table 6.1), got ${sar}`);
  }
  if (!Number.isInteger(messageType) || messageType < 0 || messageType > PROXY_MESSAGE_TYPE_MASK) {
    throw new Error(`proxyPduHeader: MessageType must be a 6-bit value (Table 6.1), got ${messageType}`);
  }
  return (sar << PROXY_SAR_SHIFT) | messageType;
}

/**
 * Wraps one complete message in the Proxy PDU envelope, segmenting it
 * across as many PDUs as `maxPduLength` requires — Section 6.3.2.1
 * "Segmentation", transcribed in the module header.
 *
 * `maxPduLength` is the maximum size of ONE Proxy PDU in octets, header
 * INCLUDED ("The size of the Proxy PDU is determined by the user of the
 * Proxy protocol. For example, the GATT bearer defines the size of the
 * Proxy PDU based on the ATT_MTU." — Section 6.3). It must leave room for
 * at least one octet of Data.
 *
 * Returns the PDUs in the order they must be written; a message that fits
 * returns exactly one PDU with SAR = 0b00.
 */
export function encodeProxyPdus(messageType: number, message: Buffer, maxPduLength: number): Buffer[] {
  if (!Number.isInteger(messageType) || messageType < 0 || messageType > PROXY_MESSAGE_TYPE_MASK) {
    throw new Error(`encodeProxyPdus: MessageType must be a 6-bit value (Table 6.1), got ${messageType}`);
  }
  if (!Number.isInteger(maxPduLength) || maxPduLength < 2) {
    throw new Error(
      `encodeProxyPdus: maxPduLength must be an integer >= 2 (one header octet plus at least one Data octet), got ${maxPduLength}`,
    );
  }
  if (message.length === 0) {
    throw new Error('encodeProxyPdus: message is empty — Table 6.1 makes the Data field mandatory');
  }

  const maxDataLength = maxPduLength - 1;
  if (message.length <= maxDataLength) {
    return [Buffer.concat([Buffer.from([proxyPduHeader(PROXY_SAR_COMPLETE, messageType)]), Buffer.from(message)])];
  }

  const pdus: Buffer[] = [];
  // "the message is divided into segments that will fill each Proxy PDU
  // except for the last Proxy PDU that may or may not be filled" — greedy,
  // maximal segments, not an even division.
  for (let offset = 0; offset < message.length; offset += maxDataLength) {
    const chunk = message.subarray(offset, Math.min(offset + maxDataLength, message.length));
    const isFirst = offset === 0;
    const isLast = offset + maxDataLength >= message.length;
    const sar = isFirst ? PROXY_SAR_FIRST : isLast ? PROXY_SAR_LAST : PROXY_SAR_CONTINUATION;
    pdus.push(Buffer.concat([Buffer.from([proxyPduHeader(sar, messageType)]), Buffer.from(chunk)]));
  }
  return pdus;
}

/** One in-flight reassembly. Immutable; the caller owns it — see the module
 *  header's STATELESS BY DESIGN note. */
export interface ProxyReassemblyState {
  /** The MessageType the FIRST segment established; every later segment of
   *  the same message must repeat it. */
  readonly messageType: number;
  readonly segments: ReadonlyArray<Buffer>;
  /** `nowMs` as it was when the first segment arrived — the start of the
   *  "SAR transfer" whose timeout Section 6.3.2.2 fixes at 20 seconds. */
  readonly startedAtMs: number;
}

export type ProxyReassemblyResult =
  | { readonly kind: 'complete'; readonly state: undefined; readonly messageType: number; readonly message: Buffer }
  | { readonly kind: 'incomplete'; readonly state: ProxyReassemblyState }
  /** Not an error: the specification says to ignore this one and carry on
   *  (Section 6.3.2 "Behavior"), so any reassembly in progress survives. */
  | { readonly kind: 'ignored'; readonly state: ProxyReassemblyState | undefined; readonly reason: string }
  /** Section 6.3.2.2: the caller SHALL DISCONNECT. This module owns no
   *  radio, so it names the condition and the adapter acts. */
  | { readonly kind: 'disconnect'; readonly state: undefined; readonly reason: string };

/** Section 6.3.2.2's 20-second SAR transfer timeout, as a pure predicate an
 *  adapter's own timer can use — arrival alone can never catch a transfer
 *  that simply stops. */
export function proxySarTransferExpired(state: ProxyReassemblyState, nowMs: number): boolean {
  return nowMs - state.startedAtMs >= PROXY_SAR_TIMEOUT_MS;
}

/**
 * Feeds one received Proxy PDU into a reassembly in progress (or starts
 * one), mirroring `reassembly.ts#acceptSegment`/`message.ts#acceptIncomingPdu`
 * in shape and nullish convention. `state` is `undefined` when nothing is
 * in progress. See the module header for every rule below and where each
 * comes from.
 */
export function acceptProxyPdu(state: ProxyReassemblyState | undefined, pdu: Buffer, nowMs: number): ProxyReassemblyResult {
  if (pdu.length === 0) {
    return { kind: 'ignored', state, reason: 'empty Proxy PDU (no header octet at all)' };
  }
  const header = pdu[0] as number;
  const sar = sarOf(header);
  const messageType = messageTypeOf(header);
  const data = pdu.subarray(1);

  if (data.length === 0) {
    return {
      kind: 'ignored',
      state,
      reason: `Proxy PDU carries a header but no Data field (Table 6.1 makes Data mandatory), SAR=0b${sar.toString(2).padStart(2, '0')}`,
    };
  }
  if (!messageTypeIsSupported(messageType)) {
    return {
      kind: 'ignored',
      state,
      reason: `MessageType 0x${messageType.toString(16).padStart(2, '0')} is Reserved for Future Use or unsupported (Table 6.3, Section 6.3.2)`,
    };
  }

  // Checked before any SAR handling: a transfer that has already run past
  // its 20 seconds is over regardless of what the arriving segment says.
  if (state !== undefined && proxySarTransferExpired(state, nowMs)) {
    return {
      kind: 'disconnect',
      state: undefined,
      reason: `SAR transfer timed out after ${nowMs - state.startedAtMs} ms (Section 6.3.2.2: the timeout for the SAR transfer is 20 seconds)`,
    };
  }

  switch (sar) {
    case PROXY_SAR_COMPLETE:
      if (state !== undefined) {
        return {
          kind: 'disconnect',
          state: undefined,
          reason: 'unexpected SAR value 0b00 (a complete message) while a segmented message was still being reassembled',
        };
      }
      {
        const tooLong = tooLongReason(messageType, data.length);
        if (tooLong !== null) return { kind: 'disconnect', state: undefined, reason: tooLong };
      }
      return { kind: 'complete', state: undefined, messageType, message: Buffer.from(data) };

    case PROXY_SAR_FIRST: {
      if (state !== undefined) {
        return {
          kind: 'disconnect',
          state: undefined,
          reason: 'unexpected SAR value 0b01 (a first segment) while a segmented message was still being reassembled',
        };
      }
      const tooLong = tooLongReason(messageType, data.length);
      if (tooLong !== null) return { kind: 'disconnect', state: undefined, reason: tooLong };
      return { kind: 'incomplete', state: { messageType, segments: [Buffer.from(data)], startedAtMs: nowMs } };
    }

    case PROXY_SAR_CONTINUATION:
    case PROXY_SAR_LAST: {
      if (state === undefined) {
        return {
          kind: 'disconnect',
          state: undefined,
          reason: `unexpected SAR value 0b${sar.toString(2).padStart(2, '0')} with no segmented message being reassembled`,
        };
      }
      if (messageType !== state.messageType) {
        return {
          kind: 'disconnect',
          state: undefined,
          reason: `segment MessageType 0x${messageType.toString(16).padStart(2, '0')} does not match 0x${state.messageType
            .toString(16)
            .padStart(2, '0')} established by the first segment of this message`,
        };
      }
      // The running total, not this segment alone — see the module header's
      // "THE DATA FIELD, DURING A REASSEMBLY, IS THE WHOLE MESSAGE" note.
      // Summing the segments rather than carrying a length in the state
      // keeps `ProxyReassemblyState` the three published fields it already
      // is, and costs nothing: the sum is now bounded by the very limit it
      // is checking.
      const assembledLength = state.segments.reduce((total, segment) => total + segment.length, 0) + data.length;
      const tooLong = tooLongReason(state.messageType, assembledLength);
      if (tooLong !== null) return { kind: 'disconnect', state: undefined, reason: tooLong };
      const segments = [...state.segments, Buffer.from(data)];
      if (sar === PROXY_SAR_CONTINUATION) {
        return { kind: 'incomplete', state: { ...state, segments } };
      }
      return { kind: 'complete', state: undefined, messageType, message: Buffer.concat(segments) };
    }

    /* istanbul ignore next — `sar` is two bits, so the four cases above are
       exhaustive; this exists only so the function has no implicit return. */
    default:
      return { kind: 'ignored', state, reason: `unreachable SAR value ${sar}` };
  }
}
