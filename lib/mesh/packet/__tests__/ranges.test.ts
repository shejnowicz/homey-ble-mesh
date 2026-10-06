import { assertRange, MAX_TTL, MAX_SEQ, MAX_ADDRESS, MAX_IV_INDEX } from '../ranges';

// Each bound below is transcribed from the field width the specification
// gives that field, as 2**bits - 1, rather than copied as a hex literal out
// of the modules this guard used to be duplicated in — copying the existing
// numbers would only prove the test agrees with the implementation, not
// that either of them agrees with the spec.
//
// TTL: Table 3.10 "Network PDU field definitions" gives TTL 7 bits, and
// Table 3.67 "CTL and TTL field format" repeats it. SEQ: Table 3.10 gives
// SEQ 24 bits; Section 3.4.4.5 states it directly ("The SEQ field is a
// 24-bit integer"); Table 3.66 "Network nonce format" gives SEQ 3 octets
// (24 bits). SRC/DST address: Table 3.10 gives both 16 bits, and Table 3.5
// is titled "16-bit address allocations". IV Index: Section 3.9.4 "IV
// Index" states "The IV Index is a 32-bit value"; Table 3.66 gives it 4
// octets (32 bits).
describe('exported bounds match the specification field widths', () => {
  test('MAX_TTL is a 7-bit field', () => {
    expect(MAX_TTL).toBe(2 ** 7 - 1);
  });

  test('MAX_SEQ is a 24-bit field', () => {
    expect(MAX_SEQ).toBe(2 ** 24 - 1);
  });

  test('MAX_ADDRESS is a 16-bit field', () => {
    expect(MAX_ADDRESS).toBe(2 ** 16 - 1);
  });

  test('MAX_IV_INDEX is a 32-bit field', () => {
    expect(MAX_IV_INDEX).toBe(2 ** 32 - 1);
  });
});

describe('assertRange', () => {
  test('accepts the bound itself', () => {
    expect(() => assertRange('field', 0x7f, 0x7f)).not.toThrow();
    expect(() => assertRange('field', 0, 0x7f)).not.toThrow();
  });

  test('rejects the value one above the bound', () => {
    expect(() => assertRange('field', 0x80, 0x7f)).toThrow();
  });

  test('rejects a negative value', () => {
    expect(() => assertRange('field', -1, 0x7f)).toThrow();
  });

  test('rejects a fractional value', () => {
    expect(() => assertRange('field', 1.5, 0x7f)).toThrow();
  });

  test('the thrown message names the field, carrying the caller-supplied prefix as-is', () => {
    expect(() => assertRange('nonce field "ttl"', 0x80, 0x7f)).toThrow(
      'nonce field "ttl" must be an integer in [0, 127], got 128',
    );
  });

  test('the thrown message reports the bound and the offending value for any caller-supplied name', () => {
    expect(() => assertRange('network PDU field "seq"', -1, 0xffffff)).toThrow(
      'network PDU field "seq" must be an integer in [0, 16777215], got -1',
    );
  });
});
