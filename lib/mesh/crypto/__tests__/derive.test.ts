import { k1, k2, k3, k4 } from '../derive';
import { hex, K2_MASTER, K3_SAMPLE, K4_SAMPLE } from './vectors';

test('k2 derives the network identifier and both keys', () => {
  const result = k2(hex(K2_MASTER.n), hex(K2_MASTER.p));
  expect(result.nid).toBe(K2_MASTER.expectedNid);
  expect(result.encryptionKey.toString('hex')).toBe(K2_MASTER.expectedEncryptionKey);
  expect(result.privacyKey.toString('hex')).toBe(K2_MASTER.expectedPrivacyKey);
});

test('k3 returns the low eight bytes', () => {
  expect(k3(hex(K3_SAMPLE.n)).toString('hex')).toBe(K3_SAMPLE.expected);
});

test('k4 returns six bits', () => {
  expect(k4(hex(K4_SAMPLE.n))).toBe(K4_SAMPLE.expected);
});

test('k1 is deterministic and sixteen bytes wide', () => {
  const n = hex('3216d1509884b533248541792b877f98');
  const salt = hex('2ba14ca2c4ded5ddfdcb3b5f1b1b0bdd');
  const p = hex('5a09d60797eeb4478aada59db3352a0d');
  const first = k1(n, salt, p);
  expect(first).toHaveLength(16);
  expect(k1(n, salt, p).toString('hex')).toBe(first.toString('hex'));
});
