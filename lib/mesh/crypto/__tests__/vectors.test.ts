import {
  hex,
  S1_TEST,
  K1_SAMPLE,
  K2_MASTER,
  K2_FRIENDSHIP,
  K3_SAMPLE,
  K4_SAMPLE,
  PROVISIONING_SAMPLE,
} from './vectors';

test('every fixture has the byte length its field implies', () => {
  expect(hex(S1_TEST.expected)).toHaveLength(16);
  expect(hex(K1_SAMPLE.n)).toHaveLength(16);
  expect(hex(K1_SAMPLE.salt)).toHaveLength(16);
  expect(hex(K1_SAMPLE.p)).toHaveLength(16);
  expect(hex(K1_SAMPLE.t)).toHaveLength(16);
  expect(hex(K1_SAMPLE.expected)).toHaveLength(16);
  expect(hex(K2_MASTER.n)).toHaveLength(16);
  expect(hex(K2_MASTER.expectedEncryptionKey)).toHaveLength(16);
  expect(hex(K2_MASTER.expectedPrivacyKey)).toHaveLength(16);
  expect(hex(K2_FRIENDSHIP.n)).toHaveLength(16);
  expect(hex(K2_FRIENDSHIP.p)).toHaveLength(9);
  expect(hex(K2_FRIENDSHIP.expectedEncryptionKey)).toHaveLength(16);
  expect(hex(K2_FRIENDSHIP.expectedPrivacyKey)).toHaveLength(16);
  expect(hex(K3_SAMPLE.n)).toHaveLength(16);
  expect(hex(K3_SAMPLE.expected)).toHaveLength(8);
  expect(K2_MASTER.expectedNid).toBeLessThanOrEqual(0x7f);
  expect(K2_FRIENDSHIP.expectedNid).toBeLessThanOrEqual(0x7f);
  expect(K4_SAMPLE.expected).toBeLessThanOrEqual(0x3f);
  expect(hex(PROVISIONING_SAMPLE.provisionerPublicKeyX)).toHaveLength(32);
  expect(hex(PROVISIONING_SAMPLE.provisionerPublicKeyY)).toHaveLength(32);
  expect(hex(PROVISIONING_SAMPLE.provisionerPrivateKey)).toHaveLength(32);
  expect(hex(PROVISIONING_SAMPLE.devicePublicKeyX)).toHaveLength(32);
  expect(hex(PROVISIONING_SAMPLE.devicePublicKeyY)).toHaveLength(32);
  expect(hex(PROVISIONING_SAMPLE.devicePrivateKey)).toHaveLength(32);
  expect(hex(PROVISIONING_SAMPLE.expectedSharedSecret)).toHaveLength(32);
  expect(hex(PROVISIONING_SAMPLE.sessionKey)).toHaveLength(16);
  expect(hex(PROVISIONING_SAMPLE.sessionNonce)).toHaveLength(13);
  expect(hex(PROVISIONING_SAMPLE.plaintext)).toHaveLength(25);
  expect(hex(PROVISIONING_SAMPLE.expectedCiphertext)).toHaveLength(25);
  expect(hex(PROVISIONING_SAMPLE.expectedTag)).toHaveLength(8);
});
