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
 * Everything NOT on that list is treated conservatively as `'ignored'`
 * (keeping any reassembly in progress intact), because the specification's
 * own disconnect list is explicit and a disconnect is the expensive
 * outcome: an empty PDU, a header with no Data at all, and — per Section
 * 6.3.2 "Behavior", quoted in `MESSAGE_TYPE_IS_SUPPORTED` below — any
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
      return { kind: 'complete', state: undefined, messageType, message: Buffer.from(data) };

    case PROXY_SAR_FIRST:
      if (state !== undefined) {
        return {
          kind: 'disconnect',
          state: undefined,
          reason: 'unexpected SAR value 0b01 (a first segment) while a segmented message was still being reassembled',
        };
      }
      return { kind: 'incomplete', state: { messageType, segments: [Buffer.from(data)], startedAtMs: nowMs } };

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
