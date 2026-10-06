import { encryptUpperTransport, decryptUpperTransport } from '../upperTransport';
import {
  hex,
  UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY,
  UPPER_TRANSPORT_SAMPLE_DEVICE_KEY,
  UPPER_TRANSPORT_SAMPLE_SZMIC,
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

// The Label UUID is not part of the plaintext, only additional data - so
// omitting it must not merely produce a WRONG tag, it must fail to verify
// at all against the published PDU, and decrypting without it must not
// accidentally recover the correct plaintext either.
test('decryptUpperTransport fails the published Message #24 PDU without the Label UUID', () => {
  const payload = decryptUpperTransport({
    upperTransportPdu: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.expected),
    key: hex(UPPER_TRANSPORT_SAMPLE_SZMIC.key),
    keyKind: UPPER_TRANSPORT_SAMPLE_SZMIC.keyKind,
    seq: UPPER_TRANSPORT_SAMPLE_SZMIC.seq,
    src: UPPER_TRANSPORT_SAMPLE_SZMIC.src,
    dst: UPPER_TRANSPORT_SAMPLE_SZMIC.dst,
    ivIndex: UPPER_TRANSPORT_SAMPLE_SZMIC.ivIndex,
    szmic: UPPER_TRANSPORT_SAMPLE_SZMIC.szmic,
  });
  expect(payload).toBeNull();
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

  test('encryptUpperTransport rejects a labelUuid that is not 128 bits', () => {
    expect(() => encryptUpperTransport({ ...valid, labelUuid: Buffer.alloc(15) })).toThrow(
      /upper transport field "labelUuid"/,
    );
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
test('decryptUpperTransport rejects a truncated PDU rather than throwing', () => {
  const truncated = hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.expected).subarray(0, 2);
  const decode = (): unknown =>
    decryptUpperTransport({
      upperTransportPdu: truncated,
      key: hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.key),
      keyKind: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.keyKind,
      seq: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.seq,
      src: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.src,
      dst: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.dst,
      ivIndex: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.ivIndex,
      szmic: UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.szmic,
    });
  expect(decode).not.toThrow();
  expect(decode()).toBeNull();
});
