import { ccmEncrypt } from '../../crypto/ccm';
import { s1, aesCmac } from '../../crypto/cmac';
import { applicationNonce } from '../nonce';
import { encryptUpperTransport, decryptUpperTransport } from '../upperTransport';
import {
  hex,
  UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY,
  UPPER_TRANSPORT_SAMPLE_DEVICE_KEY,
  UPPER_TRANSPORT_SAMPLE_SZMIC,
  UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC,
  UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL,
} from './vectors';

// 8.3.18 "Message #18": an unsegmented Access message encrypted with an
// application key (32-bit TransMIC, szmic=false), to a non-virtual
// destination (DST 0xffff) - no additional data involved.
test('encryptUpperTransport matches the published Message #18 sample (AppKey, 32-bit TransMIC)', () => {
  const pdu = encryptUpperTransport({
    accessPayload: hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.accessPayload),
    key: hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.key),
    keyKind: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.seq,
    src: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.src,
    dst: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.szmic,
  });
  expect(pdu.toString('hex')).toBe(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.expected);
  expect(pdu).toEqual(hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.expected));
});

// Decode tested against the PUBLISHED PDU, not against encryptUpperTransport's
// own output - a round trip through our own encoder would only prove the two
// functions agree with each other, not with the specification.
test('decryptUpperTransport recovers the published Message #18 access payload', () => {
  const payload = decryptUpperTransport({
    upperTransportPdu: hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.expected),
    key: hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.key),
    keyKind: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.seq,
    src: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.src,
    dst: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.szmic,
  });
  expect(payload).toEqual(hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.accessPayload));
});

// 8.3.6 "Message #6": a device-key Access message - still a 32-bit TransMIC
// even though it is sent as two lower-transport segments (see the module's
// own header on why the 64-bit TransMIC is unavailable to an unsegmented
// message but not every segmented one).
test('encryptUpperTransport matches the published Message #6 sample (DevKey)', () => {
  const pdu = encryptUpperTransport({
    accessPayload: hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.accessPayload),
    key: hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.key),
    keyKind: UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.seq,
    src: UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.src,
    dst: UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.szmic,
  });
  expect(pdu.toString('hex')).toBe(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.expected);
  expect(pdu).toEqual(hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.expected));
});

test('decryptUpperTransport recovers the published Message #6 access payload (DevKey)', () => {
  const payload = decryptUpperTransport({
    upperTransportPdu: hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.expected),
    key: hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.key),
    keyKind: UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.seq,
    src: UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.src,
    dst: UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.szmic,
  });
  expect(payload).toEqual(hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.accessPayload));
});

// 8.3.24 "Message #24": the only Section 8.3 sample with SZMIC set (64-bit
// TransMIC) - also the only sample addressed to a virtual address, which is
// why its Label UUID must be supplied as additional data (see vectors.ts
// and the module header) to reproduce the published TransMIC at all.
test('encryptUpperTransport matches the published Message #24 sample (SZMIC=1, virtual address)', () => {
  const pdu = encryptUpperTransport({
    accessPayload: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.accessPayload),
    key: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.key),
    keyKind: UPPER_TRANSPORT_SAMPLE_SZMIC.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_SZMIC.seq,
    src: UPPER_TRANSPORT_SAMPLE_SZMIC.src,
    dst: UPPER_TRANSPORT_SAMPLE_SZMIC.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_SZMIC.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_SZMIC.szmic,
    labelUuid: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.labelUuid),
  });
  expect(pdu.toString('hex')).toBe(UPPER_TRANSPORT_SAMPLE_SZMIC.expected);
  expect(pdu).toEqual(hex(UPPER_TRANSPORT_SAMPLE_SZMIC.expected));
  // Table 3.25: TransMIC is the last 8 octets here (64 bits), not 4 - the
  // length itself pins down the long-MIC branch, independent of the hex
  // comparison above.
  expect(pdu).toHaveLength(hex(UPPER_TRANSPORT_SAMPLE_SZMIC.accessPayload).length + 8);
});

test('decryptUpperTransport recovers the published Message #24 access payload (SZMIC=1, virtual address)', () => {
  const payload = decryptUpperTransport({
    upperTransportPdu: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.expected),
    key: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.key),
    keyKind: UPPER_TRANSPORT_SAMPLE_SZMIC.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_SZMIC.seq,
    src: UPPER_TRANSPORT_SAMPLE_SZMIC.src,
    dst: UPPER_TRANSPORT_SAMPLE_SZMIC.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_SZMIC.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_SZMIC.szmic,
    labelUuid: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.labelUuid),
  });
  expect(payload).toEqual(hex(UPPER_TRANSPORT_SAMPLE_SZMIC.accessPayload));
});

// The Label UUID is required (not merely useful) whenever `dst` is a virtual
// address - Finding 2 of this task's review: omitting it used to return the
// WRONG bytes silently (a PDU authenticating against no additional data,
// which nothing on the real network could ever verify), rather than being
// rejected as the caller mistake it is. Asserts the module's own message,
// not a bare `toThrow()` - see the equivalent encrypt-side test below.
test('decryptUpperTransport rejects the published Message #24 virtual destination with no Label UUID', () => {
  expect(() =>
    decryptUpperTransport({
      upperTransportPdu: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.expected),
      key: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.key),
      keyKind: UPPER_TRANSPORT_SAMPLE_SZMIC.keyKind,
      seq: UPPER_TRANSPORT_SAMPLE_SZMIC.seq,
      src: UPPER_TRANSPORT_SAMPLE_SZMIC.src,
      dst: UPPER_TRANSPORT_SAMPLE_SZMIC.dst,
      ivIndex: UPPER_TRANSPORT_SAMPLE_SZMIC.ivIndex,
      szmic: UPPER_TRANSPORT_SAMPLE_SZMIC.szmic,
    }),
  ).toThrow(/upper transport field "labelUuid" is required when "dst" is a virtual address/);
});

// 8.3.22 "Message #22": SZMIC=0 (32-bit TransMIC) AND a virtual address
// together, with a Label UUID/destination pair that is NOT shared with
// Message #24 - closes the gap a first review found: until this sample
// existed, Message #24 was simultaneously the suite's only SZMIC=1 sample
// and its only virtual-address sample, so the two dimensions never moved
// independently (confirmed live: making the Label UUID conditional on
// `szmic` at both call sites left all 124 tests passing). See the mutation
// re-run below.
test('encryptUpperTransport matches the published Message #22 sample (virtual address, 32-bit TransMIC)', () => {
  const pdu = encryptUpperTransport({
    accessPayload: hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.accessPayload),
    key: hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.key),
    keyKind: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.seq,
    src: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.src,
    dst: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.szmic,
    labelUuid: hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.labelUuid),
  });
  expect(pdu.toString('hex')).toBe(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.expected);
  expect(pdu).toEqual(hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.expected));
});

test('decryptUpperTransport recovers the published Message #22 access payload (virtual address, 32-bit TransMIC)', () => {
  const payload = decryptUpperTransport({
    upperTransportPdu: hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.expected),
    key: hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.key),
    keyKind: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.seq,
    src: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.src,
    dst: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.szmic,
    labelUuid: hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.labelUuid),
  });
  expect(payload).toEqual(hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.accessPayload));
});

// 8.3.23 "Message #23": SZMIC=0, but the SAME Label UUID/destination as
// Message #24 (SZMIC=1) - the most direct isolation of the SZMIC dimension
// from the virtual-address one, since everything but SEQ/SZMIC/TransMIC
// length is identical between the two messages.
test('encryptUpperTransport matches the published Message #23 sample (same virtual address as #24, 32-bit TransMIC)', () => {
  const pdu = encryptUpperTransport({
    accessPayload: hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.accessPayload),
    key: hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.key),
    keyKind: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.seq,
    src: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.src,
    dst: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.szmic,
    labelUuid: hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.labelUuid),
  });
  expect(pdu.toString('hex')).toBe(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.expected);
  expect(pdu).toEqual(hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.expected));
});

test('decryptUpperTransport recovers the published Message #23 access payload (same virtual address as #24, 32-bit TransMIC)', () => {
  const payload = decryptUpperTransport({
    upperTransportPdu: hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.expected),
    key: hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.key),
    keyKind: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.seq,
    src: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.src,
    dst: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.szmic,
    labelUuid: hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.labelUuid),
  });
  expect(payload).toEqual(hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.accessPayload));
});

// Section 3.4.2.3's own formula - SALT=s1("vtad"), hash=AES-CMAC_SALT(Label
// UUID) mod 2^14, virtual address = 0x8000 | hash - run here with this
// project's own (already known-answer-tested) `s1`/`aesCmac`, to derive
// Message #24's published destination (0x9736) from its published Label
// UUID. This makes the fixture prove its own provenance: a fabricated or
// transposed Label UUID would not hash to the published destination.
test("Message #24's published Label UUID hashes to its own published virtual destination (Section 3.4.2.3)", () => {
  const salt = s1(Buffer.from('vtad', 'ascii'));
  const hash = aesCmac(salt, hex(UPPER_TRANSPORT_SAMPLE_SZMIC.labelUuid));
  // "mod 2^14" of a big-endian integer depends only on its low 14 bits,
  // which live entirely within the last two octets of the 16-octet CMAC
  // output - so reading those two octets and masking to 14 bits is exactly
  // "mod 2^14", not an approximation of it.
  const low14 = (hash.readUInt16BE(14) as number) & 0x3fff;
  const virtualAddress = 0x8000 | low14; // bit 15 set, bit 14 clear (Figure 3.7).
  expect(virtualAddress).toBe(UPPER_TRANSPORT_SAMPLE_SZMIC.dst);
});

describe('caller mistakes throw rather than being treated as a verification failure', () => {
  const valid = {
    accessPayload: hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.accessPayload),
    key: hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.key),
    keyKind: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.seq,
    src: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.src,
    dst: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.szmic,
  };

  test('encryptUpperTransport rejects a key that is not 128 bits', () => {
    expect(() => encryptUpperTransport({ ...valid, key: Buffer.alloc(15) })).toThrow(
      /upper transport field "key"/,
    );
    expect(() => encryptUpperTransport({ ...valid, key: Buffer.alloc(32) })).toThrow(
      /upper transport field "key"/,
    );
  });

  test('decryptUpperTransport rejects a key that is not 128 bits', () => {
    expect(() =>
      decryptUpperTransport({
        ...valid,
        key: Buffer.alloc(15),
        upperTransportPdu: hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.expected),
      }),
    ).toThrow(/upper transport field "key"/);
  });

  // One case per range guard, each at the first value outside the width the
  // specification gives that field: SEQ is 24 bits, SRC/DST 16, IV Index 32
  // (the same widths `ranges.ts` already enforces for the network and
  // nonce layers).
  test.each([
    ['seq', { seq: 0x1000000 }],
    ['src', { src: 0x10000 }],
    ['dst', { dst: 0x10000 }],
    ['ivIndex', { ivIndex: 0x100000000 }],
  ])('encryptUpperTransport rejects an out-of-range %s', (field, override) => {
    expect(() => encryptUpperTransport({ ...valid, ...override })).toThrow(
      new RegExp(`upper transport field "${field}"`),
    );
  });

  test.each([
    ['seq', { seq: -1 }],
    ['src', { src: 0x10000 }],
    ['dst', { dst: -1 }],
    ['ivIndex', { ivIndex: 0x100000000 }],
  ])('decryptUpperTransport rejects an out-of-range %s', (field, override) => {
    expect(() =>
      decryptUpperTransport({
        ...valid,
        ...override,
        upperTransportPdu: hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.expected),
      }),
    ).toThrow(new RegExp(`upper transport field "${field}"`));
  });

  // Section 3.9.7.1 defines only the unicast case for a device key - a
  // virtual address (and therefore a Label UUID) never applies to one.
  test('encryptUpperTransport rejects a labelUuid on a device-key message', () => {
    expect(() =>
      encryptUpperTransport({
        ...valid,
        keyKind: 'device',
        key: hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.key),
        labelUuid: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.labelUuid),
      }),
    ).toThrow(/upper transport field "labelUuid"/);
  });

  // dst is overridden to a virtual address here so this actually exercises
  // the LENGTH check - against `valid`'s own non-virtual dst (0xffff), a
  // wrong-length labelUuid would instead be rejected for being set on a
  // non-virtual destination at all, which is a different guard (covered by
  // its own test below) and would prove nothing about length specifically.
  test('encryptUpperTransport rejects a labelUuid that is not 128 bits', () => {
    expect(() =>
      encryptUpperTransport({
        ...valid,
        dst: UPPER_TRANSPORT_SAMPLE_SZMIC.dst,
        labelUuid: Buffer.alloc(15),
      }),
    ).toThrow(/upper transport field "labelUuid" must be 16 bytes/);
  });

  // Finding 2 (review): a virtual destination with no Label UUID used to be
  // accepted silently and produce a PDU authenticating against nothing - now
  // rejected as the caller mistake it is, for an application-key message.
  test('encryptUpperTransport rejects a virtual destination with no labelUuid', () => {
    expect(() =>
      encryptUpperTransport({ ...valid, dst: UPPER_TRANSPORT_SAMPLE_SZMIC.dst }),
    ).toThrow(/upper transport field "labelUuid" is required when "dst" is a virtual address/);
  });

  // The other direction: a labelUuid supplied for a destination OUTSIDE the
  // virtual address range (0x8000-0xBFFF, Section 3.4.2.3) is also rejected,
  // not silently accepted as extra, unused additional data.
  test('encryptUpperTransport rejects a labelUuid for a non-virtual destination', () => {
    expect(() =>
      encryptUpperTransport({ ...valid, labelUuid: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.labelUuid) }),
    ).toThrow(/upper transport field "labelUuid" must not be set when "dst" is not a virtual address/);
  });

  // A device-key message never uses a virtual address at all (Section
  // 3.9.7.1 defines only the unicast case for DevKey) - this is the same
  // rule as "rejects a labelUuid on a device-key message" above, but caught
  // one step earlier: here the caller never supplied a labelUuid, so a
  // weaker guard that checked only "labelUuid present" would miss it.
  test('encryptUpperTransport rejects a virtual destination on a device-key message even with no labelUuid', () => {
    expect(() =>
      encryptUpperTransport({
        ...valid,
        keyKind: 'device',
        key: hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.key),
        dst: UPPER_TRANSPORT_SAMPLE_SZMIC.dst,
      }),
    ).toThrow(/upper transport field "dst" must not be a virtual address/);
  });

  // Fix wave (Important 2): the virtual address range's own edges were
  // undefended. Every published virtual-address sample sits well INSIDE the
  // range and every non-virtual test well OUTSIDE it, so moving either
  // bound by one left all 296 tests green - and a misclassified edge is not
  // cosmetic: an application-key message whose virtual destination is
  // wrongly judged non-virtual is accepted with NO Label UUID and encrypted
  // with NO additional data, producing exactly the unauthenticatable PDU
  // the previous round added `assertLabelUuidRules` to prevent.
  //
  // Range transcribed afresh for this round from Section 3.4.2.3 "Virtual
  // address", last sentence before Figure 3.7: "A virtual address can have
  // any value from 0x8000 to 0xBFFF as shown in Figure 3.7 below." Table
  // 3.5 "16-bit address allocations" corroborates it independently, giving
  // the Virtual Address row as the bit pattern 0b10xxxxxxxxxxxxxx - the
  // same span written as bit 15 set and bit 14 clear.
  //
  // Each case asserts what the RANGE implies about behaviour, never the
  // text of the error - those messages print the bounds themselves, so a
  // test matching on them could not falsify a moved bound.
  describe('the virtual address range edges (Section 3.4.2.3: 0x8000 to 0xBFFF)', () => {
    const insideTheRange: Array<[string, number]> = [
      ['0x8000, the first virtual address', 0x8000],
      ['0xbfff, the last virtual address', 0xbfff],
    ];
    const outsideTheRange: Array<[string, number]> = [
      ['0x7fff, the address immediately below the range', 0x7fff],
      ['0xc000, the address immediately above the range', 0xc000],
    ];

    test.each(insideTheRange)('%s is virtual: a labelUuid is required, and supplying one is accepted', (_name, dst) => {
      expect(() => encryptUpperTransport({ ...valid, dst })).toThrow(
        /upper transport field "labelUuid" is required/,
      );
      expect(() =>
        encryptUpperTransport({ ...valid, dst, labelUuid: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.labelUuid) }),
      ).not.toThrow();
    });

    test.each(outsideTheRange)(
      '%s is NOT virtual: no labelUuid is required, and supplying one is rejected',
      (_name, dst) => {
        expect(() => encryptUpperTransport({ ...valid, dst })).not.toThrow();
        expect(() =>
          encryptUpperTransport({ ...valid, dst, labelUuid: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.labelUuid) }),
        ).toThrow(/upper transport field "labelUuid" must not be set/);
      },
    );

    // The device-key guard reads the same two bounds, so it needs its own
    // edge cases or half the range could move undetected on that path.
    test.each(insideTheRange)('%s is refused outright for a device-key message', (_name, dst) => {
      expect(() =>
        encryptUpperTransport({ ...valid, keyKind: 'device', key: hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.key), dst }),
      ).toThrow(/upper transport field "dst" must not be a virtual address/);
    });

    test.each(outsideTheRange)('%s is accepted for a device-key message', (_name, dst) => {
      expect(() =>
        encryptUpperTransport({ ...valid, keyKind: 'device', key: hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.key), dst }),
      ).not.toThrow();
    });
  });

  // Section 3.6.2.1: an Access message paired with a 64-bit TransMIC is
  // bounded at 376 octets, four less than the 380-octet bound for a 32-bit
  // one - both share one 384-octet ceiling on the whole Upper Transport
  // Access PDU (Section 3.7.2, Table 3.61).
  test('encryptUpperTransport rejects an access payload longer than 376 octets when szmic is set', () => {
    expect(() =>
      encryptUpperTransport({ ...valid, szmic: true, accessPayload: Buffer.alloc(377) }),
    ).toThrow(/upper transport field "accessPayload"/);
    expect(() =>
      encryptUpperTransport({ ...valid, szmic: true, accessPayload: Buffer.alloc(376) }),
    ).not.toThrow();
  });

  test('encryptUpperTransport rejects an access payload longer than 380 octets when szmic is clear', () => {
    expect(() => encryptUpperTransport({ ...valid, accessPayload: Buffer.alloc(381) })).toThrow(
      /upper transport field "accessPayload"/,
    );
    expect(() => encryptUpperTransport({ ...valid, accessPayload: Buffer.alloc(380) })).not.toThrow();
  });

  test('encryptUpperTransport rejects an empty access payload', () => {
    expect(() => encryptUpperTransport({ ...valid, accessPayload: Buffer.alloc(0) })).toThrow(
      /upper transport field "accessPayload"/,
    );
  });
});

// The design's stated contract: a MIC that fails to verify is ordinary
// (traffic for another key), not a caller mistake, so it returns null
// rather than throwing - mirrored from decodeNetworkPdu's own tests.
test('decryptUpperTransport returns null (not an exception) for a PDU encrypted under another key', () => {
  const payload = decryptUpperTransport({
    upperTransportPdu: hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.expected),
    key: hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.key), // the wrong key for this PDU, but still 128 bits.
    keyKind: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.seq,
    src: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.src,
    dst: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.szmic,
  });
  expect(payload).toBeNull();
});

// A lower transport layer handing up a truncated/corrupted reassembly must
// be dropped quietly, not thrown on - the same "truncated foreign packet"
// case `ccmDecrypt`'s own MESH_MIC_LENGTHS check already documents.
//
// Three rows, because a short PDU takes one of THREE different paths
// through the ciphertext/tag split (fix wave, Minor finding): `subarray(0,
// length - micLength)` does not clamp a negative end to zero - it takes it
// relative to the buffer's own length, and only that result is clamped.
//
//   2 octets, 32-bit MIC: end = 2-4 = -2 -> 2 + (-2) = 0, so an EMPTY
//     ciphertext and a 2-octet tag; dropped by MESH_MIC_LENGTHS.
//   3 octets, 32-bit MIC: end = -1 -> 3 + (-1) = 2, so a NON-EMPTY 2-octet
//     ciphertext and a 1-octet tag; also dropped by MESH_MIC_LENGTHS, but
//     only this row makes the non-empty split observable at all.
//   4 octets, 64-bit MIC: end = -4 -> 0, so an empty ciphertext and a
//     4-octet tag - which IS a mesh MIC length, so this one PASSES the
//     length gate and is rejected by AES-CCM itself instead. The sole
//     short-PDU case that reaches any crypto; see the function's comment.
test.each([
  ['2 octets with a 32-bit MIC (ciphertext empty, dropped on tag length)', 2, false],
  ['3 octets with a 32-bit MIC (ciphertext NON-empty, dropped on tag length)', 3, false],
  ['4 octets with a 64-bit MIC (tag length is legal, rejected by AES-CCM itself)', 4, true],
])('decryptUpperTransport rejects a truncated PDU of %s rather than throwing', (_name, length, szmic) => {
  const truncated = hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.expected).subarray(0, length);
  const decode = (): unknown =>
    decryptUpperTransport({
      upperTransportPdu: truncated,
      key: hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.key),
      keyKind: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.keyKind,
      seq: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.seq,
      src: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.src,
      dst: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.dst,
      ivIndex: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.ivIndex,
      szmic,
    });
  expect(decode).not.toThrow();
  expect(decode()).toBeNull();
});

// `encryptUpperTransport` refuses a zero-octet access payload (Section
// 3.6.2.1's "a single octet"), but `decryptUpperTransport` does not re-apply
// that minimum to what it recovers - a receiver's job is to accept whatever
// authenticates, not re-validate a sender's choices (see the function's own
// JSDoc). This builds a genuinely authenticated zero-length Upper Transport
// Access PDU directly over `ccmEncrypt`/`applicationNonce` - both already
// known-answer-tested elsewhere - deliberately bypassing
// `encryptUpperTransport`'s own guard, the same way `network.test.ts`'s
// `buildAuthenticatedPdu` bypasses `encodeNetworkPdu`'s length guard to
// reach a case the guarded function cannot produce itself.
test('decryptUpperTransport returns an empty buffer (not null) for an authenticated zero-length payload', () => {
  const sample = UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY;
  const nonce = applicationNonce({
    aszmic: sample.szmic,
    seq: sample.seq,
    src: sample.src,
    dst: sample.dst,
    ivIndex: sample.ivIndex,
  });
  const { ciphertext, tag } = ccmEncrypt(hex(sample.key), nonce, Buffer.alloc(0), 4);
  expect(ciphertext).toHaveLength(0);

  const payload = decryptUpperTransport({
    upperTransportPdu: Buffer.concat([ciphertext, tag]),
    key: hex(sample.key),
    keyKind: sample.keyKind,
    seq: sample.seq,
    src: sample.src,
    dst: sample.dst,
    ivIndex: sample.ivIndex,
    szmic: sample.szmic,
  });
  expect(payload).not.toBeNull();
  expect(payload).toHaveLength(0);
});
