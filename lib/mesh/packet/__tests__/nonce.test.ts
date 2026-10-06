import { networkNonce, applicationNonce, deviceNonce } from '../nonce';
import {
  hex,
  NETWORK_NONCE_SAMPLE_1,
  NETWORK_NONCE_SAMPLE_2,
  APPLICATION_NONCE_SAMPLE_1,
  APPLICATION_NONCE_SAMPLE_2,
  DEVICE_NONCE_SAMPLE_1,
  DEVICE_NONCE_SAMPLE_2,
} from './vectors';

// 8.3.1 "Message #1": TTL=0, SEQ=0x000001, SRC=0x1201, CTL=1 (Transport
// Control message).
test('networkNonce matches the published Message #1 sample', () => {
  const nonce = networkNonce(NETWORK_NONCE_SAMPLE_1);
  expect(nonce.toString('hex')).toBe(NETWORK_NONCE_SAMPLE_1.expected);
  expect(nonce).toEqual(hex(NETWORK_NONCE_SAMPLE_1.expected));
});

// 8.3.2 "Message #2": a second network nonce with a different SEQ and SRC,
// still CTL=1/TTL=0 — catches a builder that only happens to work for one
// set of field widths.
test('networkNonce matches the published Message #2 sample', () => {
  const nonce = networkNonce(NETWORK_NONCE_SAMPLE_2);
  expect(nonce.toString('hex')).toBe(NETWORK_NONCE_SAMPLE_2.expected);
  expect(nonce).toEqual(hex(NETWORK_NONCE_SAMPLE_2.expected));
});

test('networkNonce is always 13 bytes', () => {
  expect(networkNonce(NETWORK_NONCE_SAMPLE_1)).toHaveLength(13);
});

// 8.3.18 "Message #18": an AppKey-encrypted, unsegmented Access message
// (ASZMIC=0).
test('applicationNonce matches the published Message #18 sample', () => {
  const nonce = applicationNonce(APPLICATION_NONCE_SAMPLE_1);
  expect(nonce.toString('hex')).toBe(APPLICATION_NONCE_SAMPLE_1.expected);
  expect(nonce).toEqual(hex(APPLICATION_NONCE_SAMPLE_1.expected));
});

// 8.3.24 "Message #24": an AppKey-encrypted, segmented Access message with a
// 64-bit TransMIC (ASZMIC=1) — the sample that pins down the ASZMIC bit.
test('applicationNonce matches the published Message #24 sample (ASZMIC=1)', () => {
  const nonce = applicationNonce(APPLICATION_NONCE_SAMPLE_2);
  expect(nonce.toString('hex')).toBe(APPLICATION_NONCE_SAMPLE_2.expected);
  expect(nonce).toEqual(hex(APPLICATION_NONCE_SAMPLE_2.expected));
});

test('applicationNonce is always 13 bytes', () => {
  expect(applicationNonce(APPLICATION_NONCE_SAMPLE_1)).toHaveLength(13);
});

// 8.3.6 "Message #6": a DevKey-encrypted, unsegmented Access message. Labelled
// "Application nonce" in the source table, but its own first octet (0x02)
// and its use of DevKey identify it as a Device nonce — see vectors.ts.
test('deviceNonce matches the published Message #6 sample', () => {
  const nonce = deviceNonce(DEVICE_NONCE_SAMPLE_1);
  expect(nonce.toString('hex')).toBe(DEVICE_NONCE_SAMPLE_1.expected);
  expect(nonce).toEqual(hex(DEVICE_NONCE_SAMPLE_1.expected));
});

// 8.3.16 "Message #16": a second DevKey-encrypted Access message, with SRC
// and DST swapped relative to Message #6 — catches a builder that
// transposes those two fields.
test('deviceNonce matches the published Message #16 sample', () => {
  const nonce = deviceNonce(DEVICE_NONCE_SAMPLE_2);
  expect(nonce.toString('hex')).toBe(DEVICE_NONCE_SAMPLE_2.expected);
  expect(nonce).toEqual(hex(DEVICE_NONCE_SAMPLE_2.expected));
});

test('deviceNonce is always 13 bytes', () => {
  expect(deviceNonce(DEVICE_NONCE_SAMPLE_1)).toHaveLength(13);
});

describe('field range validation', () => {
  test('networkNonce rejects a sequence number that does not fit 24 bits', () => {
    expect(() => networkNonce({ ...NETWORK_NONCE_SAMPLE_1, seq: 0x1000000 })).toThrow(/seq/);
  });

  test('networkNonce rejects a source address outside 16 bits', () => {
    expect(() => networkNonce({ ...NETWORK_NONCE_SAMPLE_1, src: 0x10000 })).toThrow(/src/);
  });

  test('networkNonce rejects a TTL outside 7 bits', () => {
    expect(() => networkNonce({ ...NETWORK_NONCE_SAMPLE_1, ttl: 0x80 })).toThrow(/ttl/);
  });

  test('networkNonce rejects an IV Index outside 32 bits', () => {
    expect(() => networkNonce({ ...NETWORK_NONCE_SAMPLE_1, ivIndex: 0x100000000 })).toThrow(/ivIndex/);
  });

  test('applicationNonce rejects a destination address outside 16 bits', () => {
    expect(() => applicationNonce({ ...APPLICATION_NONCE_SAMPLE_1, dst: -1 })).toThrow(/dst/);
  });

  test('deviceNonce rejects a sequence number that does not fit 24 bits', () => {
    expect(() => deviceNonce({ ...DEVICE_NONCE_SAMPLE_1, seq: -1 })).toThrow(/seq/);
  });
});
