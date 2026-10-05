import { k1, k2, k3, k4 } from '../derive';
import {
  hex,
  K1_SAMPLE,
  K2_MASTER,
  K2_FRIENDSHIP,
  K3_SAMPLE,
  K4_SAMPLE,
} from './vectors';

test('k2 derives the network identifier and both keys (managed flooding)', () => {
  const result = k2(hex(K2_MASTER.n), hex(K2_MASTER.p));
  expect(result.nid).toBe(K2_MASTER.expectedNid);
  expect(result.encryptionKey.toString('hex')).toBe(K2_MASTER.expectedEncryptionKey);
  expect(result.privacyKey.toString('hex')).toBe(K2_MASTER.expectedPrivacyKey);
});

// 8.1.4: the only sample exercising a multi-byte P (LPNAddress ‖ FriendAddress
// ‖ LPNCounter ‖ FriendCounter), which is exactly where a wrong concatenation
// order would show up.
test('k2 derives the network identifier and both keys (friendship)', () => {
  const result = k2(hex(K2_FRIENDSHIP.n), hex(K2_FRIENDSHIP.p));
  expect(result.nid).toBe(K2_FRIENDSHIP.expectedNid);
  expect(result.encryptionKey.toString('hex')).toBe(K2_FRIENDSHIP.expectedEncryptionKey);
  expect(result.privacyKey.toString('hex')).toBe(K2_FRIENDSHIP.expectedPrivacyKey);
});

test('k3 returns the low eight bytes', () => {
  expect(k3(hex(K3_SAMPLE.n)).toString('hex')).toBe(K3_SAMPLE.expected);
});

test('k4 returns six bits', () => {
  expect(k4(hex(K4_SAMPLE.n))).toBe(K4_SAMPLE.expected);
});

// 8.1.2: the standalone k1 known-answer sample (no provisioning data
// involved) — this is the real assertion; determinism is a secondary check.
test('k1 matches the published standalone sample', () => {
  const n = hex(K1_SAMPLE.n);
  const salt = hex(K1_SAMPLE.salt);
  const p = hex(K1_SAMPLE.p);
  const result = k1(n, salt, p);
  expect(result.toString('hex')).toBe(K1_SAMPLE.expected);
  // Same call, same inputs, same output.
  expect(k1(n, salt, p).toString('hex')).toBe(result.toString('hex'));
});

test('k2 rejects a NetKey shorter than 128 bits rather than deriving a plausible wrong answer', () => {
  const shortN = hex(K2_MASTER.n).subarray(0, 15);
  expect(() => k2(shortN, hex(K2_MASTER.p))).toThrow(/16 bytes/);
});

test('k3 rejects a NetKey shorter than 128 bits rather than deriving a plausible wrong answer', () => {
  const shortN = hex(K3_SAMPLE.n).subarray(0, 15);
  expect(() => k3(shortN)).toThrow(/16 bytes/);
});

test('k4 rejects an AppKey shorter than 128 bits rather than deriving a plausible wrong answer', () => {
  const shortN = hex(K4_SAMPLE.n).subarray(0, 15);
  expect(() => k4(shortN)).toThrow(/16 bytes/);
});
