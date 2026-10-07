import {
  acceptProxyPdu,
  encodeProxyPdus,
  proxyPduHeader,
  proxySarTransferExpired,
  PROXY_MESSAGE_TYPE_MASK,
  PROXY_MESSAGE_TYPE_MESH_BEACON,
  PROXY_MESSAGE_TYPE_NETWORK_PDU,
  PROXY_MESSAGE_TYPE_PROVISIONING_PDU,
  PROXY_MESSAGE_TYPE_PROXY_CONFIGURATION,
  PROXY_MESSAGE_TYPE_RFU_FIRST,
  PROXY_SAR_COMPLETE,
  PROXY_SAR_CONTINUATION,
  PROXY_SAR_FIRST,
  PROXY_SAR_LAST,
  PROXY_SAR_SHIFT,
  PROXY_SAR_TIMEOUT_MS,
  type ProxyReassemblyResult,
  type ProxyReassemblyState,
} from '../proxyPdu';

/**
 * Known answers built from the transcribed tables, NOT from the module's own
 * encoder — Mesh Protocol v1.1 publishes no worked Proxy PDU sample
 * (searched: Section 8 "Sample data" has sample data for the proxy SERVICE
 * — Section 8.6 "Mesh Proxy Service sample data", already a known-answer
 * test in `lib/adapter/__tests__/connection.test.ts` — but none for the
 * Proxy PDU envelope itself), so every expected byte below is composed here
 * from Table 6.1's field widths, Table 6.2's four SAR values and Table 6.3's
 * four defined MessageType values, each written out as a literal rather than
 * computed with `proxyPduHeader`.
 *
 * FIXTURE VALUES ARE DELIBERATELY ASYMMETRIC, per this project's own
 * repeatedly-paid-for lesson (a palindromic value cannot distinguish byte
 * order; a value shared between two fields cannot distinguish field order):
 * the four SAR values and the four MessageType values are all different from
 * one another, the header bytes below are therefore all different, and every
 * payload is a run of distinct, non-palindromic octets whose FIRST and LAST
 * bytes differ — so a segmenter that reversed its segments, or an assembler
 * that concatenated them in the wrong order, cannot produce the expected
 * answer by accident.
 */

// ===========================================================================
// The header octet: Table 6.1 (SAR 2 bits first, MessageType 6 bits second)
// packed per Section 3.1.1/3.1.1.1 — the first row of the table takes the
// most significant bits. Every expected value below is written as an
// explicit binary literal, independent of the module's own shift constant.
// ===========================================================================

describe('the header octet (Table 6.1 "Proxy PDU format")', () => {
  test.each([
    // [sar, messageType, expected header octet]
    [PROXY_SAR_COMPLETE, PROXY_MESSAGE_TYPE_NETWORK_PDU, 0b00_000000],
    [PROXY_SAR_COMPLETE, PROXY_MESSAGE_TYPE_MESH_BEACON, 0b00_000001],
    [PROXY_SAR_COMPLETE, PROXY_MESSAGE_TYPE_PROXY_CONFIGURATION, 0b00_000010],
    [PROXY_SAR_COMPLETE, PROXY_MESSAGE_TYPE_PROVISIONING_PDU, 0b00_000011],
    [PROXY_SAR_FIRST, PROXY_MESSAGE_TYPE_NETWORK_PDU, 0b01_000000],
    [PROXY_SAR_CONTINUATION, PROXY_MESSAGE_TYPE_NETWORK_PDU, 0b10_000000],
    [PROXY_SAR_LAST, PROXY_MESSAGE_TYPE_NETWORK_PDU, 0b11_000000],
    [PROXY_SAR_FIRST, PROXY_MESSAGE_TYPE_PROVISIONING_PDU, 0b01_000011],
    [PROXY_SAR_CONTINUATION, PROXY_MESSAGE_TYPE_PROVISIONING_PDU, 0b10_000011],
    [PROXY_SAR_LAST, PROXY_MESSAGE_TYPE_PROVISIONING_PDU, 0b11_000011],
    // The last RFU-free value of the 6-bit field, so the mask itself is pinned.
    [PROXY_SAR_LAST, PROXY_MESSAGE_TYPE_MASK, 0b11_111111],
  ])('SAR 0b%s with MessageType %i packs to %i', (sar, messageType, expected) => {
    expect(proxyPduHeader(sar, messageType)).toBe(expected);
  });

  /**
   * The literal values of the four SAR rows of Table 6.2 and the four
   * defined rows of Table 6.3, asserted against the table rather than
   * against each other. Without this, renumbering any of them (e.g.
   * swapping "first segment" and "last segment", which is exactly the kind
   * of mistake a transcription makes) leaves every other test in this file
   * passing, because they all go through these same constants.
   */
  test('the transcribed SAR and MessageType values are the literal ones the tables publish', () => {
    expect(PROXY_SAR_COMPLETE).toBe(0b00);
    expect(PROXY_SAR_FIRST).toBe(0b01);
    expect(PROXY_SAR_CONTINUATION).toBe(0b10);
    expect(PROXY_SAR_LAST).toBe(0b11);
    expect(PROXY_MESSAGE_TYPE_NETWORK_PDU).toBe(0x00);
    expect(PROXY_MESSAGE_TYPE_MESH_BEACON).toBe(0x01);
    expect(PROXY_MESSAGE_TYPE_PROXY_CONFIGURATION).toBe(0x02);
    expect(PROXY_MESSAGE_TYPE_PROVISIONING_PDU).toBe(0x03);
    expect(PROXY_MESSAGE_TYPE_RFU_FIRST).toBe(0x04);
    expect(PROXY_MESSAGE_TYPE_MASK).toBe(0x3f);
    expect(PROXY_SAR_SHIFT).toBe(6);
    // Section 6.3.2.2: "The timeout for the SAR transfer is 20 seconds."
    expect(PROXY_SAR_TIMEOUT_MS).toBe(20_000);
  });

  test.each([-1, 4, 1.5])('rejects a SAR value outside the 2-bit field (%p)', (sar) => {
    expect(() => proxyPduHeader(sar, PROXY_MESSAGE_TYPE_NETWORK_PDU)).toThrow(/SAR must be a 2-bit value/);
  });

  test.each([-1, 0x40, 2.5])('rejects a MessageType outside the 6-bit field (%p)', (messageType) => {
    expect(() => proxyPduHeader(PROXY_SAR_COMPLETE, messageType)).toThrow(/MessageType must be a 6-bit value/);
  });
});

// ===========================================================================
// Segmentation — Section 6.3.2.1.
// ===========================================================================

describe('encodeProxyPdus (Section 6.3.2.1 "Segmentation")', () => {
  test('a message that fits goes out as ONE PDU with SAR 0b00 and the complete message as Data', () => {
    const message = Buffer.from([0x11, 0x22, 0x33, 0x44]);
    const pdus = encodeProxyPdus(PROXY_MESSAGE_TYPE_NETWORK_PDU, message, 20);
    expect(pdus.map((p) => p.toString('hex'))).toEqual(['0011223344']);
  });

  test('a message exactly filling one PDU is still ONE PDU (the boundary is "less than or equal to")', () => {
    const message = Buffer.from([0xa1, 0xb2, 0xc3]);
    const pdus = encodeProxyPdus(PROXY_MESSAGE_TYPE_PROVISIONING_PDU, message, 4); // 1 header + 3 data
    expect(pdus.map((p) => p.toString('hex'))).toEqual(['03a1b2c3']);
  });

  test('one octet more than fits becomes a FIRST and a LAST segment, the first one filled', () => {
    const message = Buffer.from([0xa1, 0xb2, 0xc3, 0xd4]);
    const pdus = encodeProxyPdus(PROXY_MESSAGE_TYPE_PROVISIONING_PDU, message, 4); // 3 data octets per PDU
    expect(pdus.map((p) => p.toString('hex'))).toEqual([
      '43a1b2c3', // 0b01_000011 = first segment, Provisioning PDU
      'c3d4', //     0b11_000011 = last segment,  Provisioning PDU
    ]);
  });

  test('a message needing three PDUs uses first / continuation / last, in that order', () => {
    const message = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    const pdus = encodeProxyPdus(PROXY_MESSAGE_TYPE_NETWORK_PDU, message, 4); // 3 data octets per PDU
    expect(pdus.map((p) => p.toString('hex'))).toEqual([
      '40010203', // 0b01_000000 first
      '80040506', // 0b10_000000 continuation
      'c007', //     0b11_000000 last, not filled
    ]);
  });

  test('a message needing four PDUs uses exactly TWO continuation segments', () => {
    const message = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a]);
    const pdus = encodeProxyPdus(PROXY_MESSAGE_TYPE_NETWORK_PDU, message, 4);
    expect(pdus.map((p) => p[0])).toEqual([0b01_000000, 0b10_000000, 0b10_000000, 0b11_000000]);
    expect(Buffer.concat(pdus.map((p) => p.subarray(1)))).toEqual(message);
  });

  test('every PDU except the last is filled to the maximum ("will fill each Proxy PDU except for the last")', () => {
    const message = Buffer.alloc(100, 0x5a);
    message[0] = 0x01; // not a palindrome, and the ends differ
    message[99] = 0xfe;
    const maxPduLength = 20;
    const pdus = encodeProxyPdus(PROXY_MESSAGE_TYPE_NETWORK_PDU, message, maxPduLength);
    for (const pdu of pdus.slice(0, -1)) {
      expect(pdu).toHaveLength(maxPduLength);
    }
    expect(pdus.at(-1)!.length).toBeLessThanOrEqual(maxPduLength);
    expect(Buffer.concat(pdus.map((p) => p.subarray(1)))).toEqual(message);
  });

  test('the caller\'s buffer is never retained — mutating it afterwards does not change the PDUs', () => {
    const message = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const pdus = encodeProxyPdus(PROXY_MESSAGE_TYPE_NETWORK_PDU, message, 4);
    message.fill(0xff);
    expect(pdus.map((p) => p.toString('hex'))).toEqual(['40010203', 'c004']);
  });

  test.each([1, 0, -5, 2.5])('rejects a maxPduLength that leaves no room for Data (%p)', (maxPduLength) => {
    expect(() => encodeProxyPdus(PROXY_MESSAGE_TYPE_NETWORK_PDU, Buffer.from([0x01]), maxPduLength)).toThrow(
      /maxPduLength must be an integer >= 2/,
    );
  });

  test('rejects an empty message (Table 6.1 makes the Data field mandatory)', () => {
    expect(() => encodeProxyPdus(PROXY_MESSAGE_TYPE_NETWORK_PDU, Buffer.alloc(0), 20)).toThrow(/message is empty/);
  });

  test('rejects a MessageType that does not fit the 6-bit field', () => {
    expect(() => encodeProxyPdus(0x40, Buffer.from([0x01]), 20)).toThrow(/MessageType must be a 6-bit value/);
  });
});

// ===========================================================================
// Reassembly — Section 6.3.2.2.
// ===========================================================================

/** Drives a whole sequence of PDUs through `acceptProxyPdu`, carrying the
 *  state forward exactly as a real caller does, and returns the final
 *  result — so a test asserts on an OUTCOME rather than on intermediate
 *  bookkeeping. */
function feed(pdus: Buffer[], nowMs = 0): ProxyReassemblyResult {
  let state: ProxyReassemblyState | undefined;
  let result: ProxyReassemblyResult | null = null;
  for (const pdu of pdus) {
    result = acceptProxyPdu(state, pdu, nowMs);
    state = result.kind === 'incomplete' || result.kind === 'ignored' ? result.state : undefined;
  }
  if (result === null) throw new Error('feed: called with no PDUs');
  return result;
}

describe('acceptProxyPdu (Section 6.3.2.2 "Reassembly")', () => {
  test('a complete message is delivered whole, with its MessageType', () => {
    const result = acceptProxyPdu(undefined, Buffer.from([0x00, 0x11, 0x22, 0x33]), 0);
    expect(result).toEqual({
      kind: 'complete',
      state: undefined,
      messageType: PROXY_MESSAGE_TYPE_NETWORK_PDU,
      message: Buffer.from([0x11, 0x22, 0x33]),
    });
  });

  test('first + last reassembles to the original message, in order', () => {
    const result = feed([Buffer.from([0x43, 0xa1, 0xb2, 0xc3]), Buffer.from([0xc3, 0xd4])]);
    expect(result).toEqual({
      kind: 'complete',
      state: undefined,
      messageType: PROXY_MESSAGE_TYPE_PROVISIONING_PDU,
      message: Buffer.from([0xa1, 0xb2, 0xc3, 0xd4]),
    });
  });

  test('first + continuation + last reassembles in order (a reversed assembler fails this)', () => {
    const message = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    const result = feed(encodeProxyPdus(PROXY_MESSAGE_TYPE_NETWORK_PDU, message, 4));
    expect(result.kind).toBe('complete');
    expect(result.kind === 'complete' && result.message).toEqual(message);
  });

  test('round-trips every message length across a segment boundary', () => {
    for (let length = 1; length <= 40; length += 1) {
      // Distinct, non-palindromic contents: byte i is i+1, so reversal and
      // mis-ordering are both detectable at every length.
      const message = Buffer.from(Array.from({ length }, (_, i) => (i + 1) & 0xff));
      const result = feed(encodeProxyPdus(PROXY_MESSAGE_TYPE_NETWORK_PDU, message, 8));
      expect(result.kind).toBe('complete');
      expect(result.kind === 'complete' && result.message).toEqual(message);
    }
  });

  test('an incomplete reassembly reports what it has so far and asks for more', () => {
    const result = acceptProxyPdu(undefined, Buffer.from([0x40, 0x01, 0x02]), 123);
    expect(result.kind).toBe('incomplete');
    expect(result.kind === 'incomplete' && result.state).toEqual({
      messageType: PROXY_MESSAGE_TYPE_NETWORK_PDU,
      segments: [Buffer.from([0x01, 0x02])],
      startedAtMs: 123,
    });
  });
});

describe('the conditions Section 6.3.2.2 says shall end in a disconnect', () => {
  test('a continuation segment with nothing being reassembled', () => {
    const result = acceptProxyPdu(undefined, Buffer.from([0x80, 0x01]), 0);
    expect(result.kind).toBe('disconnect');
    expect(result.kind === 'disconnect' && result.reason).toMatch(/unexpected SAR value 0b10 with no segmented message/);
  });

  test('a last segment with nothing being reassembled', () => {
    const result = acceptProxyPdu(undefined, Buffer.from([0xc0, 0x01]), 0);
    expect(result.kind).toBe('disconnect');
    expect(result.kind === 'disconnect' && result.reason).toMatch(/unexpected SAR value 0b11 with no segmented message/);
  });

  test('a complete message arriving mid-reassembly', () => {
    const result = feed([Buffer.from([0x40, 0x01, 0x02]), Buffer.from([0x00, 0x09])]);
    expect(result.kind).toBe('disconnect');
    expect(result.kind === 'disconnect' && result.reason).toMatch(/unexpected SAR value 0b00/);
  });

  test('a second first-segment arriving mid-reassembly', () => {
    const result = feed([Buffer.from([0x40, 0x01, 0x02]), Buffer.from([0x40, 0x09])]);
    expect(result.kind).toBe('disconnect');
    expect(result.kind === 'disconnect' && result.reason).toMatch(/unexpected SAR value 0b01/);
  });

  test('a continuation whose MessageType disagrees with the first segment\'s', () => {
    // 0x40 = first, Network PDU; 0x83 = continuation, Provisioning PDU.
    const result = feed([Buffer.from([0x40, 0x01, 0x02]), Buffer.from([0x83, 0x09])]);
    expect(result.kind).toBe('disconnect');
    expect(result.kind === 'disconnect' && result.reason).toMatch(/does not match 0x00 established by the first segment/);
  });

  /**
   * THE DEFECT THIS WHOLE MODULE EXISTS TO FIX, expressed as the node's own
   * reaction: a BARE Network PDU written with no envelope at all. Its first
   * octet is IVI(1)||NID(7) (Table 3.10), which a Proxy PDU Server reads as
   * SAR||MessageType — here NID = 0x6a, so the octet is 0x6a: SAR 0b01 (a
   * first segment) and MessageType 0x2a (Reserved for Future Use). The two
   * failure modes the specification prescribes for that are exactly the two
   * this module reports: an ignored message, or — once a reassembly really
   * is in progress — a disconnect.
   */
  test('a bare Network PDU, written with no envelope, is never read as a complete message', () => {
    const bareNetworkPdu = Buffer.from([0x6a, 0x7f, 0x9e, 0x51, 0x26, 0x2e, 0x47, 0x51, 0x12, 0x5f]);
    const first = acceptProxyPdu(undefined, bareNetworkPdu, 0);
    expect(first.kind).not.toBe('complete');

    const midTransfer = acceptProxyPdu(
      { messageType: PROXY_MESSAGE_TYPE_NETWORK_PDU, segments: [Buffer.from([0x01])], startedAtMs: 0 },
      Buffer.from([0x40, 0x01]), // a first segment, mid-reassembly
      0,
    );
    expect(midTransfer.kind).toBe('disconnect');
  });

  test('a segment arriving after the 20-second SAR transfer timeout', () => {
    const state: ProxyReassemblyState = {
      messageType: PROXY_MESSAGE_TYPE_NETWORK_PDU,
      segments: [Buffer.from([0x01])],
      startedAtMs: 1000,
    };
    const result = acceptProxyPdu(state, Buffer.from([0xc0, 0x02]), 1000 + PROXY_SAR_TIMEOUT_MS);
    expect(result.kind).toBe('disconnect');
    expect(result.kind === 'disconnect' && result.reason).toMatch(/SAR transfer timed out after 20000 ms/);
  });

  test('one millisecond before the timeout the same segment still completes the message', () => {
    const state: ProxyReassemblyState = {
      messageType: PROXY_MESSAGE_TYPE_NETWORK_PDU,
      segments: [Buffer.from([0x01])],
      startedAtMs: 1000,
    };
    const result = acceptProxyPdu(state, Buffer.from([0xc0, 0x02]), 1000 + PROXY_SAR_TIMEOUT_MS - 1);
    expect(result.kind).toBe('complete');
    expect(result.kind === 'complete' && result.message).toEqual(Buffer.from([0x01, 0x02]));
  });

  test('proxySarTransferExpired is exactly the same boundary', () => {
    const state: ProxyReassemblyState = { messageType: 0, segments: [], startedAtMs: 500 };
    expect(proxySarTransferExpired(state, 500 + PROXY_SAR_TIMEOUT_MS - 1)).toBe(false);
    expect(proxySarTransferExpired(state, 500 + PROXY_SAR_TIMEOUT_MS)).toBe(true);
  });
});

describe('the conditions Section 6.3.2 says shall merely be ignored', () => {
  test.each([
    ['Mesh Beacon (0x01) — defined but not consumed by this app', 0x01],
    ['Proxy Configuration (0x02) — defined but not consumed by this app', 0x02],
    ['the first RFU value (0x04)', 0x04],
    ['the last RFU value (0x3F)', 0x3f],
  ])('%s is ignored, not disconnected over', (_name, messageType) => {
    const result = acceptProxyPdu(undefined, Buffer.from([messageType, 0x01, 0x02]), 0);
    expect(result.kind).toBe('ignored');
  });

  test('an ignored message leaves a reassembly in progress untouched', () => {
    const inProgress: ProxyReassemblyState = {
      messageType: PROXY_MESSAGE_TYPE_NETWORK_PDU,
      segments: [Buffer.from([0x01])],
      startedAtMs: 0,
    };
    const ignored = acceptProxyPdu(inProgress, Buffer.from([0x01, 0xaa]), 0); // a mesh beacon
    expect(ignored.kind).toBe('ignored');
    expect(ignored.kind === 'ignored' && ignored.state).toBe(inProgress);

    // ...and the real last segment still completes the original message.
    const completed = acceptProxyPdu(inProgress, Buffer.from([0xc0, 0x02]), 0);
    expect(completed.kind === 'complete' && completed.message).toEqual(Buffer.from([0x01, 0x02]));
  });

  test('an empty PDU, and a header with no Data, are ignored rather than disconnected over', () => {
    expect(acceptProxyPdu(undefined, Buffer.alloc(0), 0).kind).toBe('ignored');
    expect(acceptProxyPdu(undefined, Buffer.from([0x00]), 0).kind).toBe('ignored');
  });
});

describe('defensive copying', () => {
  test('a completed message does not alias the PDU buffer it came from', () => {
    const pdu = Buffer.from([0x00, 0x11, 0x22]);
    const result = acceptProxyPdu(undefined, pdu, 0);
    pdu.fill(0xff);
    expect(result.kind === 'complete' && result.message).toEqual(Buffer.from([0x11, 0x22]));
  });

  test('a stored segment does not alias the PDU buffer it came from', () => {
    const firstPdu = Buffer.from([0x40, 0x11, 0x22]);
    const incomplete = acceptProxyPdu(undefined, firstPdu, 0);
    firstPdu.fill(0xff);
    const completed = acceptProxyPdu(
      incomplete.kind === 'incomplete' ? incomplete.state : undefined,
      Buffer.from([0xc0, 0x33]),
      0,
    );
    expect(completed.kind === 'complete' && completed.message).toEqual(Buffer.from([0x11, 0x22, 0x33]));
  });
});
