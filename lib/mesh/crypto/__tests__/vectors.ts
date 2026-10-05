/**
 * Sample data transcribed from the Bluetooth Mesh specification, section 8
 * "Sample data" (subsections 8.1.1 s1, 8.1.2 k1, 8.1.3 k2 (managed flooding),
 * 8.1.4 k2 (friendship), 8.1.5 k3, 8.1.6 k4, 8.17.1
 * BTM_ECDH_P256_CMAC_AES128_AES_CCM). Transcribed by hand from the official
 * Bluetooth SIG "Mesh Protocol" specification v1.1 HTML document
 * (https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/MshPRT_v1.1/out/en/index-en.html),
 * fetched and parsed on 2026-10-06. This section carries forward unchanged
 * from Mesh Profile 1.0.1 (same section/subsection numbers, same keys, same
 * expected outputs).
 */
export const hex = (s: string): Buffer => Buffer.from(s.replace(/\s+/g, ''), 'hex');

export const S1_TEST = {
  input: Buffer.from('test', 'ascii'),
  expected: 'b73cefbd641ef2ea598c2b6efb62f79c',
};

/** 8.1.2: the standalone k1 sample — no provisioning data involved. */
export const K1_SAMPLE = {
  n: '3216d1509884b533248541792b877f98',
  salt: '2ba14ffa0df84a2831938d57d276cab4',
  p: '5a09d60797eeb4478aada59db3352a0d',
  // Intermediate T = AES-CMAC_SALT(N), published alongside the final output.
  t: 'c764bea25cf9738b08956ea3c712d5af',
  expected: 'f6ed15a8934afbe7d83e8dcb57fcf5d7',
};

export const K2_MASTER = {
  n: 'f7a2a44f8e8a8029064f173ddc1e2b00',
  p: '00',
  expectedNid: 0x7f,
  expectedEncryptionKey: '9f589181a0f50de73c8070c7a6d27f46',
  expectedPrivacyKey: '4c715bd4a64b938f99b453351653124f',
};

/**
 * 8.1.4: the friendship k2 sample. P is built from four fields
 * (LPNAddress ‖ FriendAddress ‖ LPNCounter ‖ FriendCounter), the only sample
 * where P is more than the single 0x00/0x01 byte the other k2/k3/k4 samples
 * use.
 */
export const K2_FRIENDSHIP = {
  n: 'f7a2a44f8e8a8029064f173ddc1e2b00',
  lpnAddress: '0203',
  friendAddress: '0405',
  lpnCounter: '0607',
  friendCounter: '0809',
  p: '010203040506070809',
  expectedNid: 0x73,
  expectedEncryptionKey: '11efec0642774992510fb5929646df49',
  expectedPrivacyKey: 'd4d7cc0dfa772d836a8df9df5510d7a7',
};

export const K3_SAMPLE = {
  n: 'f7a2a44f8e8a8029064f173ddc1e2b00',
  expected: 'ff046958233db014',
};

export const K4_SAMPLE = {
  n: '3216d1509884b533248541792b877f98',
  expected: 0x38,
};

/**
 * 8.17.1 BTM_ECDH_P256_CMAC_AES128_AES_CCM algorithm sample data: a
 * provisioner/device key-pair exchange with its published shared secret, and
 * the session key/nonce used to AES-CCM encrypt the provisioning data with
 * an 8-byte MIC. Public keys are raw X‖Y (no 0x04 prefix), matching this
 * codebase's wire format. There is no additional authenticated data — the
 * spec defines provisioning data encryption as
 * `AES-CCM_SessionKey(SessionNonce, Provisioning Data)` with no AAD term.
 */
export const PROVISIONING_SAMPLE = {
  provisionerPublicKeyX: '2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd',
  provisionerPublicKeyY: '919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4f',
  provisionerPrivateKey: '06a516693c9aa31a6084545d0c5db641b48572b97203ddffb7ac73f7d0457663',
  devicePublicKeyX: 'f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc',
  devicePublicKeyY: '0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279',
  devicePrivateKey: '529aa0670d72cd6497502ed473502b037e8803b5c60829a5a3caa219505530ba',
  expectedSharedSecret: 'ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69',
  sessionKey: 'c80253af86b33dfa450bbdb2a191fea3',
  sessionNonce: 'da7ddbe78b5f62b81d6847487e',
  plaintext: 'efb2255e6422d330088e09bb015ed707056700010203040b0c',
  expectedCiphertext: 'd0bd7f4a89a2ff6222af59a90a60ad58acfe3123356f5cec29',
  expectedTag: '73e0ec50783b10c7',
};
