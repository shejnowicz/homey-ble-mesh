import { randomBytes } from 'node:crypto';
import {
  encodeMeshMessage,
  acceptIncomingPdu,
  POINT_TO_POINT_TTL,
  RELAYED_TTL,
  type MeshReceiveState,
  type MeshReceiveContext,
} from '../message';
import { decodeNetworkPdu, encodeNetworkPdu } from '../network';
import { decodeUnsegmentedAccess, decodeSegmentedAccess } from '../lowerTransport';

/**
 * `message.ts` has no published sample (it is this project's own composition
 * of already-individually-tested layers — see its own module header) and,
 * until this file, had NO dedicated test at all: every assertion it got was
 * incidental, through `drivers/light/__tests__/pairing.test.ts`'s own
 * integration tests. A review found this left real gaps, the worst being a
 * SURVIVING MUTATION with a genuine replay consequence: making the segment
 * loop call `allocateSeq()` only for the first segment (deriving the rest by
 * plain arithmetic, `firstSeq + segO`) passed every existing test, because
 * nothing checked `allocateSeq` was actually CALLED per segment — only that
 * the resulting wire values were arithmetically consistent. That mutation
 * leaves the store's own sequence counter behind what was actually
 * transmitted, which is exactly the replay hazard `lib/adapter/store.ts`'s
 * own module header exists to prevent. The dedicated test below pins the
 * CALL COUNT, not just the wire values.
 */

// Distinct, non-palindromic, never-published — this project's own fixture lesson.
const NET_KEY = Buffer.from('4b1e7f9a02c6d835719e0a4f2b8d3c67', 'hex');
const DEVICE_KEY = Buffer.from('9d2a6c4e81f037b5a9c1e4068d2f71a3', 'hex');
const APP_KEY = Buffer.from('e710b3458c02d9f61a7b4e0239d6c581', 'hex');
const OUR_ADDRESS = 1;
const NODE_ADDRESS = 2;
const FOREIGN_ADDRESS = 3;

function makeSeqAllocator(start = 0): { allocateSeq: () => number; calls: number[] } {
  let next = start;
  const calls: number[] = [];
  return {
    allocateSeq: (): number => {
      calls.push(next);
      return next++;
    },
    calls,
  };
}

describe('encodeMeshMessage', () => {
  test('a short access payload fits in one Network PDU (unsegmented)', () => {
    const { allocateSeq } = makeSeqAllocator(10);
    const pdus = encodeMeshMessage({
      accessPayload: Buffer.from([0x80, 0x08, 0x00]), // Config Composition Data Get, page 0
      key: DEVICE_KEY,
      keyKind: 'device',
      src: OUR_ADDRESS,
      dst: NODE_ADDRESS,
      netKey: NET_KEY,
      ivIndex: 0,
      ttl: POINT_TO_POINT_TTL,
      allocateSeq,
    });
    expect(pdus).toHaveLength(1);
    const net = decodeNetworkPdu({ networkKey: NET_KEY, ivIndex: 0, pdu: pdus[0] as Buffer });
    expect(net).not.toBeNull();
    expect(net?.src).toBe(OUR_ADDRESS);
    expect(net?.dst).toBe(NODE_ADDRESS);
    expect(net?.ttl).toBe(0); // POINT_TO_POINT_TTL, asserted as the literal value
    expect(decodeUnsegmentedAccess(net?.transportPdu as Buffer)).not.toBeNull();
  });

  /**
   * REVIEW FINDING (final wave): the TTL this encoder put on the wire used
   * to be asserted as `expect(net?.ttl).toBe(DEFAULT_CONFIG_TTL)` — the
   * constant against itself, a tautology that passes for ANY value the
   * constant happens to hold and therefore could not tell 0 from anything
   * else. It passed while every lighting command and every node reset went
   * out at TTL 0, which Table 3.12 defines as "Network PDU has not been
   * relayed and will not be relayed": unreachable for any bulb but the one
   * holding the connection. These assert the LITERAL values the two
   * constants must have, and that the encoder puts exactly those on the
   * wire.
   */
  test('the two TTL constants are the literal values Table 3.12 publishes for their two meanings', () => {
    expect(POINT_TO_POINT_TTL).toBe(0); // "has not been relayed and will not be relayed"
    expect(RELAYED_TTL).toBe(127); // "has not been relayed and can be relayed" — 0x7F
  });

  test.each([
    ['the point-to-point value', POINT_TO_POINT_TTL, 0],
    ['the relayed value', RELAYED_TTL, 127],
    ['an arbitrary in-range value, so the field is carried rather than pinned', 5, 5],
  ])('%s reaches the wire exactly as asked', (_name, ttl, expected) => {
    const { allocateSeq } = makeSeqAllocator();
    const pdus = encodeMeshMessage({
      accessPayload: Buffer.from([0x80, 0x08, 0x00]),
      key: DEVICE_KEY,
      keyKind: 'device',
      src: OUR_ADDRESS,
      dst: NODE_ADDRESS,
      netKey: NET_KEY,
      ivIndex: 0,
      ttl,
      allocateSeq,
    });
    const net = decodeNetworkPdu({ networkKey: NET_KEY, ivIndex: 0, pdu: pdus[0] as Buffer });
    expect(net?.ttl).toBe(expected);
  });

  /**
   * The application-key path's AKF flag and AID identifier had ZERO
   * coverage (review finding, final wave): both could be zeroed and the
   * whole suite stayed green, because this project's own receive path
   * ignores them symmetrically — it already knows which key to try. A real
   * node does not: Section 3.5.2.1 "Unsegmented Access message", Table 3.17
   * "Unsegmented Access message format" defines AKF ("Application Key
   * Flag") and AID ("Application key identifier"), and Section 3.6.4.2
   * "Receiving an Upper Transport PDU" says what a receiver does with
   * them — "the TransMIC field shall be authenticated against the device
   * key or the Device Key Candidate (see Section 3.11.8.1) or the known
   * application keys for which the AKF and AID fields match". A wrong AKF
   * or AID therefore means the bulb never tries our key at all and the
   * command is silently dropped. Asserted here on the LITERAL bits of the
   * Lower Transport PDU's first octet, decoded rather than recomputed.
   */
  test('an application-key message carries AKF=1 and the literal AID bits; a device-key one carries AKF=0 and AID=0', () => {
    const aid = 0x2b; // 6 bits, not 0 and not all-ones, so neither a cleared nor a saturated field passes
    const app = encodeMeshMessage({
      accessPayload: Buffer.from([0x82, 0x02, 0x01, 0x07]),
      key: APP_KEY,
      keyKind: 'application',
      aid,
      src: OUR_ADDRESS,
      dst: NODE_ADDRESS,
      netKey: NET_KEY,
      ivIndex: 0,
      ttl: RELAYED_TTL,
      allocateSeq: makeSeqAllocator().allocateSeq,
    });
    const appNet = decodeNetworkPdu({ networkKey: NET_KEY, ivIndex: 0, pdu: app[0] as Buffer });
    const appHeader = (appNet as { transportPdu: Buffer }).transportPdu[0] as number;
    // Table 3.17: SEG(1) || AKF(1) || AID(6), the first row taking the most
    // significant bit (Section 3.1.1). Written as literal bits, not as a
    // recomputation of what the encoder did.
    expect(appHeader & 0b1000_0000).toBe(0b0000_0000); // SEG = 0, unsegmented
    expect(appHeader & 0b0100_0000).toBe(0b0100_0000); // AKF = 1, application key
    expect(appHeader & 0b0011_1111).toBe(0x2b); // AID, verbatim
    expect(appHeader).toBe(0b0110_1011);

    const device = encodeMeshMessage({
      accessPayload: Buffer.from([0x80, 0x08, 0x00]),
      key: DEVICE_KEY,
      keyKind: 'device',
      // Deliberately supplied and deliberately ignored: a device-key
      // message's AKF is 0, so there is no identifier to carry.
      aid,
      src: OUR_ADDRESS,
      dst: NODE_ADDRESS,
      netKey: NET_KEY,
      ivIndex: 0,
      ttl: POINT_TO_POINT_TTL,
      allocateSeq: makeSeqAllocator().allocateSeq,
    });
    const deviceNet = decodeNetworkPdu({ networkKey: NET_KEY, ivIndex: 0, pdu: device[0] as Buffer });
    expect((deviceNet as { transportPdu: Buffer }).transportPdu[0]).toBe(0b0000_0000);
  });

  test('a long access payload segments, and calls allocateSeq EXACTLY ONCE PER NETWORK PDU SENT — the regression this task was rejected over', () => {
    // 30-byte access payload -> +4-octet MIC = 34-byte Upper Transport PDU,
    // outside the 5-15 octet unsegmented bound -> 3 segments (12+12+10).
    const accessPayload = Buffer.alloc(30, 0xab);
    const { allocateSeq, calls } = makeSeqAllocator(100);
    const pdus = encodeMeshMessage({
      accessPayload,
      key: DEVICE_KEY,
      keyKind: 'device',
      src: OUR_ADDRESS,
      dst: NODE_ADDRESS,
      netKey: NET_KEY,
      ivIndex: 0,
      ttl: POINT_TO_POINT_TTL,
      allocateSeq,
    });
    expect(pdus).toHaveLength(3);
    // THE DISCRIMINATING ASSERTION: a mutation that computes `firstSeq +
    // segO` for segments 1 and 2 WITHOUT calling `allocateSeq` for them
    // would still produce wire-correct SEQ values (the arithmetic is the
    // same), so `pdus` alone cannot catch it — only the call count can.
    expect(calls).toEqual([100, 101, 102]);
    // And each segment's own Network PDU seq really does match what was
    // allocated for it, confirming the wire values are ALSO right, not just
    // the call count.
    pdus.forEach((pdu, index) => {
      const net = decodeNetworkPdu({ networkKey: NET_KEY, ivIndex: 0, pdu });
      expect(net?.seq).toBe(100 + index);
      const segment = decodeSegmentedAccess(net?.transportPdu as Buffer);
      expect(segment?.segO).toBe(index);
      expect(segment?.segN).toBe(2);
    });
  });

  test('throws if allocateSeq ever returns a non-contiguous value (defensive internal consistency check)', () => {
    let call = 0;
    const brokenAllocateSeq = (): number => {
      call += 1;
      return call === 1 ? 100 : 999; // segment 0 gets 100, segment 1 gets an unrelated jump
    };
    expect(() =>
      encodeMeshMessage({
        accessPayload: Buffer.alloc(30, 0xab),
        key: DEVICE_KEY,
        keyKind: 'device',
        src: OUR_ADDRESS,
        dst: NODE_ADDRESS,
        netKey: NET_KEY,
        ivIndex: 0,
        ttl: POINT_TO_POINT_TTL,
        allocateSeq: brokenAllocateSeq,
      }),
    ).toThrow('SeqAuth contiguity broken');
  });

  test('an application-key message sets AKF and round-trips through acceptIncomingPdu with the application key', () => {
    const { allocateSeq } = makeSeqAllocator(200);
    const pdus = encodeMeshMessage({
      accessPayload: Buffer.from([0x82, 0x01, 0x02]), // arbitrary 2-octet SIG opcode + 1 param byte
      key: APP_KEY,
      keyKind: 'application',
      aid: 0x05,
      src: OUR_ADDRESS,
      dst: NODE_ADDRESS,
      netKey: NET_KEY,
      ivIndex: 0,
      ttl: POINT_TO_POINT_TTL,
      allocateSeq,
    });
    expect(pdus).toHaveLength(1);

    const context: MeshReceiveContext = {
      key: APP_KEY,
      keyKind: 'application',
      netKey: NET_KEY,
      ivIndex: 0,
      expectedSrc: OUR_ADDRESS,
    };
    const result = acceptIncomingPdu(undefined, context, pdus[0] as Buffer);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;
    expect(result.message).toEqual({ opcode: 0x8201, parameters: Buffer.from([0x02]) });
  });
});

describe('acceptIncomingPdu', () => {
  function encodeFrom(src: number, accessPayload: Buffer, allocateSeq: () => number, key: Buffer = DEVICE_KEY): Buffer[] {
    return encodeMeshMessage({
      accessPayload,
      key,
      keyKind: 'device',
      src,
      dst: OUR_ADDRESS,
      netKey: NET_KEY,
      ivIndex: 0,
      ttl: POINT_TO_POINT_TTL,
      allocateSeq,
    });
  }

  test('a complete unsegmented message decrypts and decodes to the original access payload', () => {
    const { allocateSeq } = makeSeqAllocator();
    const accessPayload = Buffer.from([0x02, 0x00, 0xaa, 0xbb]);
    const pdus = encodeFrom(NODE_ADDRESS, accessPayload, allocateSeq);
    const context: MeshReceiveContext = { key: DEVICE_KEY, keyKind: 'device', netKey: NET_KEY, ivIndex: 0, expectedSrc: NODE_ADDRESS };

    const result = acceptIncomingPdu(undefined, context, pdus[0] as Buffer);
    expect(result.kind).toBe('complete');
    if (result.kind !== 'complete') return;
    expect(result.message).toEqual({ opcode: 0x02, parameters: Buffer.from([0x00, 0xaa, 0xbb]) });
  });

  test('a segmented message reassembles across all its segments and decrypts to the original access payload', () => {
    const { allocateSeq } = makeSeqAllocator(50);
    const accessPayload = Buffer.from('a real composition data page would be this long, well past fifteen octets', 'utf8').subarray(0, 40);
    const pdus = encodeFrom(NODE_ADDRESS, Buffer.from(accessPayload), allocateSeq);
    expect(pdus.length).toBeGreaterThan(1); // confirms this case really exercises segmentation
    const context: MeshReceiveContext = { key: DEVICE_KEY, keyKind: 'device', netKey: NET_KEY, ivIndex: 0, expectedSrc: NODE_ADDRESS };

    let state: MeshReceiveState | undefined;
    let finalMessage: { opcode: number; parameters: Buffer } | undefined;
    for (const pdu of pdus) {
      const result = acceptIncomingPdu(state, context, pdu);
      if (result.kind === 'complete') {
        finalMessage = result.message;
      } else {
        state = result.state;
      }
    }
    expect(finalMessage).toBeDefined();
    expect(Buffer.concat([Buffer.from([finalMessage?.opcode as number]), finalMessage?.parameters as Buffer])).toEqual(
      Buffer.from(accessPayload),
    );
  });

  test('ignores a Network PDU that does not authenticate under our NetKey (foreign traffic)', () => {
    const { allocateSeq } = makeSeqAllocator();
    const foreignNetKey = randomBytes(16);
    const pdus = encodeMeshMessage({
      accessPayload: Buffer.from([0x02, 0x00]),
      key: DEVICE_KEY,
      keyKind: 'device',
      src: NODE_ADDRESS,
      dst: OUR_ADDRESS,
      netKey: foreignNetKey,
      ivIndex: 0,
      ttl: POINT_TO_POINT_TTL,
      allocateSeq,
    });
    const context: MeshReceiveContext = { key: DEVICE_KEY, keyKind: 'device', netKey: NET_KEY, ivIndex: 0, expectedSrc: NODE_ADDRESS };

    const result = acceptIncomingPdu(undefined, context, pdus[0] as Buffer);
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') return;
    expect(result.reason).toContain('did not authenticate under our NetKey');
  });

  test('rejects a Network PDU from an unexpected source — DISCRIMINATING: a genuine message from a DIFFERENT node, same NetKey and device key, which WOULD authenticate if the source check were removed', () => {
    const { allocateSeq } = makeSeqAllocator();
    const pdus = encodeFrom(FOREIGN_ADDRESS, Buffer.from([0x02, 0x00]), allocateSeq);
    const context: MeshReceiveContext = { key: DEVICE_KEY, keyKind: 'device', netKey: NET_KEY, ivIndex: 0, expectedSrc: NODE_ADDRESS };

    const result = acceptIncomingPdu(undefined, context, pdus[0] as Buffer);
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') return;
    expect(result.reason).toContain('unexpected source');

    // Control: the exact same bytes, with expectedSrc corrected, DO authenticate —
    // proving the rejection above was the source check, not a broken fixture.
    const matching = acceptIncomingPdu(undefined, { ...context, expectedSrc: FOREIGN_ADDRESS }, pdus[0] as Buffer);
    expect(matching.kind).toBe('complete');
  });

  test('ignores a Transport Control message (CTL=1)', () => {
    // message.ts's own encodeMeshMessage never sets CTL, so a CTL=1 Network
    // PDU is built directly via network.ts's own encoder instead (it takes
    // ctl as a plain input) — the only way to exercise this branch without
    // a published CTL=1 sample.
    const pdu = encodeNetworkPdu({
      networkKey: NET_KEY,
      ivIndex: 0,
      ctl: true,
      ttl: 0,
      seq: 1,
      src: NODE_ADDRESS,
      dst: OUR_ADDRESS,
      transportPdu: Buffer.from([0x00, 0x01, 0x02]), // arbitrary Transport Control PDU bytes
    });
    const context: MeshReceiveContext = { key: DEVICE_KEY, keyKind: 'device', netKey: NET_KEY, ivIndex: 0, expectedSrc: NODE_ADDRESS };

    const result = acceptIncomingPdu(undefined, context, pdu);
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') return;
    expect(result.reason).toContain('Transport Control message');
  });

  test('ignores a transport PDU that is neither a valid Unsegmented nor Segmented Access message', () => {
    const pdu = encodeNetworkPdu({
      networkKey: NET_KEY,
      ivIndex: 0,
      ctl: false,
      ttl: 0,
      seq: 1,
      src: NODE_ADDRESS,
      dst: OUR_ADDRESS,
      // SEG bit clear (Unsegmented) but shorter than the 5-octet minimum
      // Table 3.17 requires -> decodeUnsegmentedAccess returns null;
      // SEG bit clear also means decodeSegmentedAccess returns null (SEG
      // bit is clear there too) -> both decoders reject it.
      transportPdu: Buffer.from([0x00]),
    });
    const context: MeshReceiveContext = { key: DEVICE_KEY, keyKind: 'device', netKey: NET_KEY, ivIndex: 0, expectedSrc: NODE_ADDRESS };

    const result = acceptIncomingPdu(undefined, context, pdu);
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') return;
    expect(result.reason).toContain('neither a valid Unsegmented nor Segmented');
  });

  test('ignores (does not throw) a message whose Upper Transport MIC does not authenticate under the given key', () => {
    const { allocateSeq } = makeSeqAllocator();
    const pdus = encodeFrom(NODE_ADDRESS, Buffer.from([0x02, 0x00]), allocateSeq);
    const wrongDeviceKey = randomBytes(16);
    const context: MeshReceiveContext = { key: wrongDeviceKey, keyKind: 'device', netKey: NET_KEY, ivIndex: 0, expectedSrc: NODE_ADDRESS };

    const result = acceptIncomingPdu(undefined, context, pdus[0] as Buffer);
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') return;
    expect(result.reason).toContain('Upper Transport MIC did not authenticate');
  });

  test('ignores a reassembly whose first-seen segment is not SegO=0', () => {
    const { allocateSeq } = makeSeqAllocator(70);
    const pdus = encodeFrom(NODE_ADDRESS, Buffer.alloc(30, 0xcd), allocateSeq);
    expect(pdus.length).toBeGreaterThan(1);
    const context: MeshReceiveContext = { key: DEVICE_KEY, keyKind: 'device', netKey: NET_KEY, ivIndex: 0, expectedSrc: NODE_ADDRESS };

    // Feed the SECOND segment first.
    const result = acceptIncomingPdu(undefined, context, pdus[1] as Buffer);
    expect(result.kind).toBe('ignored');
    if (result.kind !== 'ignored') return;
    expect(result.reason).toContain('SegO=1, not 0');
    expect(result.state).toBeUndefined();
  });
});
