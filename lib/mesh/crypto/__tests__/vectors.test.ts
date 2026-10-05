import { hex, S1_TEST, K2_MASTER, K3_SAMPLE, K4_SAMPLE } from './vectors';

test('every fixture has the byte length its field implies', () => {
  expect(hex(S1_TEST.expected)).toHaveLength(16);
  expect(hex(K2_MASTER.n)).toHaveLength(16);
  expect(hex(K2_MASTER.expectedEncryptionKey)).toHaveLength(16);
  expect(hex(K2_MASTER.expectedPrivacyKey)).toHaveLength(16);
  expect(hex(K3_SAMPLE.n)).toHaveLength(16);
  expect(hex(K3_SAMPLE.expected)).toHaveLength(8);
  expect(K2_MASTER.expectedNid).toBeLessThanOrEqual(0x7f);
  expect(K4_SAMPLE.expected).toBeLessThanOrEqual(0x3f);
});
