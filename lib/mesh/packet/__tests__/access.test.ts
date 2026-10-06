import {
  encodeAccessMessage,
  decodeAccessMessage,
  makeVendorOpcode,
  decomposeVendorOpcode,
  MAX_VENDOR_SUB_OPCODE,
  MAX_COMPANY_ID,
} from '../access';
import { decryptUpperTransport } from '../upperTransport';
import {
  hex,
  ACCESS_SAMPLE_CONFIG_APPKEY_STATUS,
  UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY,
  UPPER_TRANSPORT_SAMPLE_DEVICE_KEY,
  UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC,
  UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL,
  UPPER_TRANSPORT_SAMPLE_SZMIC,
  DEVICE_NONCE_SAMPLE_2,
  LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY,
} from './vectors';

// ===========================================================================
// 1-octet opcodes (Table 3.62: "0xxxxxxx (excluding 01111111)"), reusing
// Messages #18 and #6's own plaintext Access message - already transcribed
// in `vectors.ts` as `UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.accessPayload`/
// `UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.accessPayload` for the upper transport
// task (see `vectors.ts`'s own header on why these are reused rather than
// duplicated under a new constant).
// ===========================================================================

describe('1-octet opcode (Section 3.7.2.1, Table 3.62)', () => {
  // Message #18 (Section 8.3.18): "Opcode : 04 (Health Current Status)".
  test('decodeAccessMessage recovers Message #18 (opcode 0x04, Health Current Status)', () => {
    const decoded = decodeAccessMessage(hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.accessPayload));
    expect(decoded).toEqual({
      opcode: 0x04,
      parameters: hex('00000000'),
    });
  });

  test('encodeAccessMessage reproduces Message #18 exactly', () => {
    const pdu = encodeAccessMessage({ opcode: 0x04, parameters: hex('00000000') });
    expect(pdu).toEqual(hex(UPPER_TRANSPORT_SAMPLE_APPLICATION_KEY.accessPayload));
  });

  // Message #6 (Section 8.3.6): "Opcode : 00 (Config AppKey Add)" - a
  // DIFFERENT 1-octet opcode (0x00, the form's own lower boundary) with a
  // longer, 19-octet Parameters field, so this is not just Message #18 with
  // its header byte relabelled.
  test('decodeAccessMessage recovers Message #6 (opcode 0x00, Config AppKey Add)', () => {
    const decoded = decodeAccessMessage(hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.accessPayload));
    expect(decoded).toEqual({
      opcode: 0x00,
      parameters: hex('56341263964771734fbd76e3b40519d1d94a48'),
    });
  });

  test('encodeAccessMessage reproduces Message #6 exactly', () => {
    const pdu = encodeAccessMessage({
      opcode: 0x00,
      parameters: hex('56341263964771734fbd76e3b40519d1d94a48'),
    });
    expect(pdu).toEqual(hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.accessPayload));
  });
});

// ===========================================================================
// 2-octet opcodes (Table 3.62: "10xxxxxx xxxxxxxx"). No published sample's
// plaintext Access message already in `vectors.ts` carries one (every
// 1-octet/vendor sample reused above was already there for a different
// task) - `ACCESS_SAMPLE_CONFIG_APPKEY_STATUS` (Message #16, Section 8.3.16)
// is this task's one genuinely new fixture; see its own provenance comment
// in `vectors.ts`.
// ===========================================================================

describe('2-octet opcode (Section 3.7.2.1, Table 3.62)', () => {
  // Message #16: "Opcode : 8003 (Config AppKey Status)" - wire bytes 80 03
  // read MSB-first, exactly as Table 3.62 displays "10xxxxxx xxxxxxxx" and
  // as the document's own "8003" caption states directly.
  test('decodeAccessMessage recovers Message #16 (opcode 0x8003, Config AppKey Status)', () => {
    const decoded = decodeAccessMessage(hex(ACCESS_SAMPLE_CONFIG_APPKEY_STATUS.expected));
    expect(decoded).toEqual({
      opcode: ACCESS_SAMPLE_CONFIG_APPKEY_STATUS.opcode,
      parameters: hex(ACCESS_SAMPLE_CONFIG_APPKEY_STATUS.parameters),
    });
    expect(decoded?.opcode).toBe(0x8003);
  });

  test('encodeAccessMessage reproduces Message #16 exactly', () => {
    const pdu = encodeAccessMessage({
      opcode: ACCESS_SAMPLE_CONFIG_APPKEY_STATUS.opcode,
      parameters: hex(ACCESS_SAMPLE_CONFIG_APPKEY_STATUS.parameters),
    });
    expect(pdu).toEqual(hex(ACCESS_SAMPLE_CONFIG_APPKEY_STATUS.expected));
  });
});

// ===========================================================================
// Binding ACCESS_SAMPLE_CONFIG_APPKEY_STATUS to its OWN message's already-
// transcribed ciphertext (review item 4): `vectors.ts`'s own stated
// convention is that a new transcription gets bound to its siblings so a
// future edit that silently diverges fails a test instead of sitting
// unread. Message #16's DevKey, Device nonce fields and encrypted
// UpperTransportPdu were all already in this file (for a different task);
// this decrypts them with `upperTransport.ts` (already built, already
// gated) and checks the plaintext is exactly this task's new access
// payload - everything needed was already in the file, nothing new was
// transcribed to write this test.
// ===========================================================================

describe('ACCESS_SAMPLE_CONFIG_APPKEY_STATUS cross-checked against Message #16\'s own ciphertext', () => {
  test('decrypting Message #16\'s Upper Transport PDU under its DevKey yields the new access payload', () => {
    const plaintext = decryptUpperTransport({
      key: hex(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.key), // Message #16's own "DevKey" row - the SAME DevKey as Message #6 (Section 8.3.16).
      keyKind: 'device',
      seq: DEVICE_NONCE_SAMPLE_2.seq,
      src: DEVICE_NONCE_SAMPLE_2.src,
      dst: DEVICE_NONCE_SAMPLE_2.dst,
      ivIndex: DEVICE_NONCE_SAMPLE_2.ivIndex,
      szmic: false, // unsegmented (Section 8.3.16), so the 32-bit TransMIC.
      upperTransportPdu: hex(LOWER_TRANSPORT_SAMPLE_ACCESS_DEVICE_KEY.upperTransportPdu),
    });
    expect(plaintext).toEqual(hex(ACCESS_SAMPLE_CONFIG_APPKEY_STATUS.expected));
  });
});

// ===========================================================================
// 3-octet vendor opcodes (Table 3.62: "11xxxxxx zzzzzzzz zzzzzzzz"), reusing
// Messages #22/#23/#24's own plaintext Access message, already transcribed
// for the upper transport task. These are also the suite's company-
// identifier byte-order tests - see the `describe` block further down for
// the dedicated round-trip/asymmetry checks.
// ===========================================================================

describe('3-octet vendor opcode (Section 3.7.2.1, Table 3.62)', () => {
  // Messages #22/#23 (Section 8.3.22/8.3.23): "Opcode : 15 : 000a (Vendor
  // 15 : 000a)" - vendor sub-opcode 0x15, company ID 0x000A. Both messages
  // share the identical Access message bytes (they differ only in SEQ/DST/
  // Label UUID, none of which this layer touches), so one known-answer
  // test covers both published messages' own Opcode row.
  test('decodeAccessMessage recovers Messages #22/#23 (vendor opcode 0x15, company 0x000A)', () => {
    const decoded = decodeAccessMessage(hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.accessPayload));
    // 0xd5000a: top byte 0xd5 (0b11 010101 - vendor marker + sub-opcode
    // 0x15), low 16 bits 0x000a (the company identifier, decoded
    // little-endian - see the module header and the dedicated byte-order
    // tests below).
    expect(decoded).toEqual({
      opcode: 0xd5000a,
      parameters: hex('48656c6c6f'), // "Hello" (Params row, Section 8.3.22/8.3.23).
    });
    expect(decoded?.parameters.toString('ascii')).toBe('Hello');

    // Message #23 publishes the identical Access message bytes.
    expect(decodeAccessMessage(hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.accessPayload))).toEqual(
      decoded,
    );
  });

  test('encodeAccessMessage reproduces Messages #22/#23 exactly', () => {
    const pdu = encodeAccessMessage({ opcode: 0xd5000a, parameters: hex('48656c6c6f') });
    expect(pdu).toEqual(hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.accessPayload));
    expect(pdu).toEqual(hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC_SHARED_LABEL.accessPayload));
  });

  // Message #24 (Section 8.3.24): "Company ID: 0x000A - Cambridge Silicon
  // Radio", "Vendor Opcode: 0x2A" - the SAME company ID as #22/#23 but a
  // DIFFERENT vendor sub-opcode (0x2A vs 0x15), so between this test and the
  // one above, the suite varies the first octet's low 6 bits while the
  // company-ID byte pair stays fixed.
  test('decodeAccessMessage recovers Message #24 (vendor opcode 0x2A, company 0x000A)', () => {
    const decoded = decodeAccessMessage(hex(UPPER_TRANSPORT_SAMPLE_SZMIC.accessPayload));
    expect(decoded).toEqual({
      opcode: 0xea000a, // 0xea = 0b11 101010 (vendor marker + sub-opcode 0x2A); company 0x000a.
      parameters: hex('576f726c64'), // "World" (Params row, Section 8.3.24).
    });
    expect(decoded?.parameters.toString('ascii')).toBe('World');
  });

  test('encodeAccessMessage reproduces Message #24 exactly', () => {
    const pdu = encodeAccessMessage({ opcode: 0xea000a, parameters: hex('576f726c64') });
    expect(pdu).toEqual(hex(UPPER_TRANSPORT_SAMPLE_SZMIC.accessPayload));
  });
});

// ===========================================================================
// Company identifier byte order (Section 3.7.1/3.7.2.1) - the module
// header's own "BYTE ORDER - THE PART THAT NEEDS CARE" section.
// ===========================================================================

describe('vendor opcode company identifier byte order (Section 3.7.1, Section 3.7.2.1)', () => {
  // The two company-ID octets this suite's only published vendor samples
  // carry are 0x0a and 0x00 - NOT equal to each other, so this fixture is
  // asymmetric and a byte-order bug is actually observable (a palindrome
  // like 0x0101 would read the same value either way and "prove nothing",
  // per the brief). Documented here as a fact about the TRANSCRIBED value,
  // not just asserted implicitly by the known-answer tests above.
  test('the published company-ID octets are not a palindrome', () => {
    const wire = hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.accessPayload);
    const companyLowOctet = wire[1];
    const companyHighOctet = wire[2];
    expect(companyLowOctet).toBe(0x0a);
    expect(companyHighOctet).toBe(0x00);
    expect(companyLowOctet).not.toBe(companyHighOctet);
  });

  // Decoding little-endian (the specified order) gives 0x000a - the EXACT
  // value Messages #22/#23/#24 publish in their own "Opcode"/"Vendor Opcode"
  // rows (Message #24's row even names it: "Company ID: 0x000A - Cambridge
  // Silicon Radio"). Decoding big-endian instead - the order used
  // elsewhere in these PDUs for every other multi-octet field (SRC, DST,
  // SEQ, IV Index) - would instead give 0x0a00 (2560), which is NOT what
  // the specification publishes. This test pins the correct value directly
  // against the spec's own stated company identifier, so a decoder that
  // silently swapped the two octets fails it (see this file's own mutation
  // step further down, which confirms this live).
  test('the company identifier decodes little-endian (0x000a), not big-endian (0x0a00)', () => {
    const decoded = decodeAccessMessage(hex(UPPER_TRANSPORT_SAMPLE_VIRTUAL_SHORT_MIC.accessPayload));
    const companyId = (decoded?.opcode as number) & 0xffff;
    expect(companyId).toBe(0x000a);
    expect(companyId).not.toBe(0x0a00);
  });

  // Round-trip through this module's own encode/decode pair, confirmed
  // against the PUBLISHED wire bytes on both sides (not decode-then-encode
  // compared only to itself, which a consistently-swapped implementation
  // would also pass - see the module header's note on why this alone is
  // not sufficient and the known-answer tests above are what actually
  // catches the swap).
  test('a vendor opcode round-trips with its company identifier intact', () => {
    const wire = hex(UPPER_TRANSPORT_SAMPLE_SZMIC.accessPayload);
    const decoded = decodeAccessMessage(wire);
    expect(decoded).not.toBeNull();
    const reencoded = encodeAccessMessage(decoded!);
    expect(reencoded).toEqual(wire);
    // The company identifier specifically, not just the whole-buffer
    // equality above: Section 8.3.24's own published value.
    expect(decoded!.opcode & 0xffff).toBe(0x000a);
  });
});

// ===========================================================================
// makeVendorOpcode/decomposeVendorOpcode (exported constructor/destructor
// for the vendor form's packed `opcode` number) - review item 3: these are
// the one supported way to build/read a vendor opcode from its two logical
// parts, so a later model layer does not have to re-derive the shift
// amounts in the module header's comments by hand.
// ===========================================================================

describe('makeVendorOpcode/decomposeVendorOpcode', () => {
  // Round-trips against the same published samples as the known-answer
  // tests above, so this is checked against real sub-opcode/company pairs,
  // not just arbitrary numbers.
  test.each([
    { label: 'Messages #22/#23', subOpcode: 0x15, companyId: 0x000a, opcode: 0xd5000a },
    { label: 'Message #24', subOpcode: 0x2a, companyId: 0x000a, opcode: 0xea000a },
  ])('$label: makeVendorOpcode/decomposeVendorOpcode are inverses', ({ subOpcode, companyId, opcode }) => {
    expect(makeVendorOpcode(subOpcode, companyId)).toBe(opcode);
    expect(decomposeVendorOpcode(opcode)).toEqual({ subOpcode, companyId });
  });

  test('decodeAccessMessage/encodeAccessMessage agree with makeVendorOpcode/decomposeVendorOpcode', () => {
    const decoded = decodeAccessMessage(hex(UPPER_TRANSPORT_SAMPLE_SZMIC.accessPayload));
    expect(decomposeVendorOpcode(decoded!.opcode)).toEqual({ subOpcode: 0x2a, companyId: 0x000a });
    expect(encodeAccessMessage({ opcode: makeVendorOpcode(0x2a, 0x000a), parameters: decoded!.parameters })).toEqual(
      hex(UPPER_TRANSPORT_SAMPLE_SZMIC.accessPayload),
    );
  });

  test('makeVendorOpcode rejects an out-of-range sub-opcode or company identifier', () => {
    expect(() => makeVendorOpcode(MAX_VENDOR_SUB_OPCODE + 1, 0)).toThrow(/access field "subOpcode"/);
    expect(() => makeVendorOpcode(0, MAX_COMPANY_ID + 1)).toThrow(/access field "companyId"/);
    expect(() => makeVendorOpcode(-1, 0)).toThrow(/access field "subOpcode"/);
  });

  test('makeVendorOpcode accepts the sub-opcode/company-ID extremes', () => {
    expect(makeVendorOpcode(0, 0)).toBe(0xc00000);
    expect(makeVendorOpcode(MAX_VENDOR_SUB_OPCODE, MAX_COMPANY_ID)).toBe(0xffffff);
  });

  test('decomposeVendorOpcode rejects an opcode outside the vendor form\'s range', () => {
    expect(() => decomposeVendorOpcode(0x04)).toThrow(/access field "opcode" must be a vendor opcode/);
    expect(() => decomposeVendorOpcode(0x8003)).toThrow(/access field "opcode" must be a vendor opcode/);
  });
});

// ===========================================================================
// Reserved opcode (Table 3.62: "01111111 | Reserved for Future Use"),
// Section 3.7.3.4 "Message error procedure": an unrecognised opcode is
// ignored by a receiver, never treated as a throw-worthy malformed PDU.
// ===========================================================================

describe('reserved opcode 0x7F (Table 3.62)', () => {
  test('decodeAccessMessage returns null for the reserved opcode, regardless of trailing bytes', () => {
    expect(decodeAccessMessage(hex('7f'))).toBeNull();
    expect(decodeAccessMessage(hex('7f00'))).toBeNull();
    expect(decodeAccessMessage(hex('7fffffffff'))).toBeNull();
  });

  test('encodeAccessMessage refuses to encode the reserved opcode', () => {
    expect(() => encodeAccessMessage({ opcode: 0x7f, parameters: Buffer.alloc(0) })).toThrow(
      /access field "opcode" 0x7F is Reserved for Future Use/,
    );
  });
});

// ===========================================================================
// Form boundaries (Table 3.62's own ranges) - first and last value of each
// form, derived from the transcribed ranges rather than from running the
// code under test.
//
// NOTE on the two EXACT form boundaries specifically: 0xC00000 and
// 0xFFFFFF carry company-ID octet pairs (0x00/0x00 and 0xFF/0xFF) that are
// THEMSELVES palindromes, so neither of those two rows alone can tell a
// correct little-endian decode apart from an accidentally big-endian one -
// confirmed live by the byte-swap mutation in the task report, which left
// both of those two rows passing while failing the asymmetric known-answer
// tests elsewhere in this file (Messages #22/#23/#24, company 0x000a).
// Rather than leave that gap resting only on fixtures that could be moved
// or replaced by a future refactor without anyone noticing the byte-order
// coverage went with them, the THIRD vendor row below is constructed - not
// transcribed, same as the other two - one step inside the lower boundary
// (company 0x0001, i.e. octets 0x01/0x00: asymmetric) specifically so a
// byte-order bug is caught by the boundary table itself, not only by the
// published samples. Confirmed this row passes against the real code and
// fails under the same byte-swap mutation while the other two rows stay
// blind to it (see the task report's "item 1" entry for the exact numbers).
// ===========================================================================

describe('opcode form boundaries (Table 3.62)', () => {
  test.each([
    { label: '1-octet lower boundary', opcode: 0x00, wire: '00' },
    { label: '1-octet upper boundary (0x7E, just below the reserved value)', opcode: 0x7e, wire: '7e' },
    { label: '2-octet lower boundary', opcode: 0x8000, wire: '8000' },
    { label: '2-octet upper boundary', opcode: 0xbfff, wire: 'bfff' },
    { label: 'vendor lower boundary (sub-opcode 0, company 0)', opcode: 0xc00000, wire: 'c00000' },
    {
      label: 'vendor just inside the lower boundary (company 0x0001, asymmetric octets)',
      opcode: 0xc00001,
      wire: 'c00100',
    },
    { label: 'vendor upper boundary (sub-opcode 0x3F, company 0xFFFF)', opcode: 0xffffff, wire: 'ffffff' },
  ])('encodeAccessMessage: $label', ({ opcode, wire }) => {
    expect(encodeAccessMessage({ opcode, parameters: Buffer.alloc(0) })).toEqual(hex(wire));
  });

  test.each([
    { label: '1-octet lower boundary', opcode: 0x00, wire: '00' },
    { label: '1-octet upper boundary (0x7E, just below the reserved value)', opcode: 0x7e, wire: '7e' },
    { label: '2-octet lower boundary', opcode: 0x8000, wire: '8000' },
    { label: '2-octet upper boundary', opcode: 0xbfff, wire: 'bfff' },
    { label: 'vendor lower boundary (sub-opcode 0, company 0)', opcode: 0xc00000, wire: 'c00000' },
    {
      label: 'vendor just inside the lower boundary (company 0x0001, asymmetric octets)',
      opcode: 0xc00001,
      wire: 'c00100',
    },
    { label: 'vendor upper boundary (sub-opcode 0x3F, company 0xFFFF)', opcode: 0xffffff, wire: 'ffffff' },
  ])('decodeAccessMessage: $label', ({ opcode, wire }) => {
    expect(decodeAccessMessage(hex(wire))).toEqual({ opcode, parameters: Buffer.alloc(0) });
  });

  // The two gaps immediately adjacent to the reserved value and to the
  // vendor form's lower boundary - values Table 3.62 assigns to no form at
  // all once 0x7F is excluded from the 1-octet row.
  test('encodeAccessMessage rejects opcodes that fall in no form\'s range', () => {
    expect(() => encodeAccessMessage({ opcode: 0x7fff, parameters: Buffer.alloc(0) })).toThrow(
      /access field "opcode" must be a valid 1-, 2- or 3-octet opcode \(Table 3\.62\), got 0x7fff/,
    );
    expect(() => encodeAccessMessage({ opcode: 0xc000, parameters: Buffer.alloc(0) })).toThrow(
      /access field "opcode" must be a valid 1-, 2- or 3-octet opcode \(Table 3\.62\), got 0xc000/,
    );
  });

  test('encodeAccessMessage rejects a negative or out-of-range opcode', () => {
    expect(() => encodeAccessMessage({ opcode: -1, parameters: Buffer.alloc(0) })).toThrow(
      /access field "opcode" must be an integer in \[0, 16777215\], got -1/,
    );
    expect(() => encodeAccessMessage({ opcode: 0x1000000, parameters: Buffer.alloc(0) })).toThrow(
      /access field "opcode" must be an integer in \[0, 16777215\], got 16777216/,
    );
  });
});

// ===========================================================================
// Truncated PDUs - not malformed, just "not decodable here" (Section
// 3.7.3.4), same stance as this package's other decoders.
// ===========================================================================

describe('truncated PDUs', () => {
  test('decodeAccessMessage returns null for an empty buffer', () => {
    expect(decodeAccessMessage(Buffer.alloc(0))).toBeNull();
  });

  test('decodeAccessMessage returns null for a 2-octet opcode with no second octet', () => {
    expect(decodeAccessMessage(hex('80'))).toBeNull();
  });

  test('decodeAccessMessage returns null for a vendor opcode missing its company-ID octets', () => {
    expect(decodeAccessMessage(hex('c0'))).toBeNull();
    expect(decodeAccessMessage(hex('c000'))).toBeNull();
  });
});

// ===========================================================================
// Zero-length Parameters (Table 3.60: "Parameters | 0 to 379 ... Req. M" -
// 0 octets is explicitly in range; Section 3.7.2.2 confirms: "The Parameters
// field can be zero octets in length.").
// ===========================================================================

describe('zero-length Parameters (Section 3.7.2.2)', () => {
  test('round-trips a 1-octet opcode with no parameters', () => {
    const pdu = encodeAccessMessage({ opcode: 0x10, parameters: Buffer.alloc(0) });
    expect(pdu).toEqual(hex('10'));
    expect(decodeAccessMessage(pdu)).toEqual({ opcode: 0x10, parameters: Buffer.alloc(0) });
  });
});

// ===========================================================================
// Buffer aliasing - decodeAccessMessage must not hand back a view onto the
// caller's own `pdu` (same reused-receive-buffer reasoning as
// `decodeUnsegmentedAccess` in `lowerTransport.ts`).
// ===========================================================================

describe('decoded parameters do not alias the input buffer', () => {
  test('mutating the source PDU after decoding leaves the decoded parameters unchanged', () => {
    const pdu = hex(ACCESS_SAMPLE_CONFIG_APPKEY_STATUS.expected);
    const decoded = decodeAccessMessage(pdu);
    const before = decoded?.parameters.toString('hex');
    pdu.fill(0xff);
    expect(decoded?.parameters.toString('hex')).toBe(before);
  });
});

// ===========================================================================
// MUTATION STEP (per the task brief): make the decoder treat every opcode
// as the shortest (1-octet) form and confirm a test using a longer form
// fails. Performed manually against a temporarily edited `access.ts` (not
// committed) - see the task report for the exact command and failing test
// names. This describe block documents what SHOULD fail, as a standing
// record, rather than re-applying the mutation at test time.
// ===========================================================================
