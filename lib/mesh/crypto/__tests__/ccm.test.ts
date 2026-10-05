import { ccmEncrypt, ccmDecrypt } from '../ccm';
import { hex, PROVISIONING_SAMPLE } from './vectors';

const KEY = Buffer.alloc(16, 0x11);
const NONCE = Buffer.alloc(13, 0x22);

test('decrypting what we encrypted returns the original bytes', () => {
  const plaintext = Buffer.from('mesh access payload', 'ascii');
  const { ciphertext, tag } = ccmEncrypt(KEY, NONCE, plaintext, 4);
  expect(ciphertext).toHaveLength(plaintext.length);
  expect(tag).toHaveLength(4);
  expect(ccmDecrypt(KEY, NONCE, ciphertext, tag)?.toString('ascii')).toBe('mesh access payload');
});

test('a tampered tag is rejected rather than returning rubbish', () => {
  const { ciphertext, tag } = ccmEncrypt(KEY, NONCE, Buffer.from('abc', 'ascii'), 4);
  const broken = Buffer.from(tag);
  const byte = broken[0];
  if (byte !== undefined) {
    broken[0] = byte ^ 0xff;
  }
  expect(ccmDecrypt(KEY, NONCE, ciphertext, broken)).toBeNull();
});

test('additional authenticated data is covered by the tag', () => {
  const aad = Buffer.from([0x01, 0x02]);
  const { ciphertext, tag } = ccmEncrypt(KEY, NONCE, Buffer.from('abc', 'ascii'), 8, aad);
  expect(ccmDecrypt(KEY, NONCE, ciphertext, tag, aad)?.toString('ascii')).toBe('abc');
  expect(ccmDecrypt(KEY, NONCE, ciphertext, tag, Buffer.from([0x09, 0x09]))).toBeNull();
});

test('a wrong key length throws ERR_CRYPTO_INVALID_KEYLEN rather than returning null', () => {
  const wrongKey = Buffer.alloc(32, 0xff);
  const plaintext = Buffer.from('abc', 'ascii');
  const { ciphertext, tag } = ccmEncrypt(KEY, NONCE, plaintext, 4);
  expect(() => {
    ccmDecrypt(wrongKey, NONCE, ciphertext, tag);
  }).toThrow(expect.objectContaining({ code: 'ERR_CRYPTO_INVALID_KEYLEN' }));
});

test('a wrong nonce length throws ERR_CRYPTO_INVALID_IV rather than returning null', () => {
  const wrongNonce = Buffer.alloc(6, 0x22);
  const plaintext = Buffer.from('abc', 'ascii');
  const { ciphertext, tag } = ccmEncrypt(KEY, NONCE, plaintext, 4);
  expect(() => {
    ccmDecrypt(KEY, wrongNonce, ciphertext, tag);
  }).toThrow(expect.objectContaining({ code: 'ERR_CRYPTO_INVALID_IV' }));
});

// Mesh MIC lengths are 4 and 8 bytes only. A parser slicing a MIC off a
// truncated foreign packet can reach any other length (Buffer.subarray
// clamps instead of erroring on a short buffer) — that must be dropped
// quietly, not thrown, because it is malformed traffic, not a caller bug.
test.each([0, 1, 2, 3, 5, 6, 7])(
  'a truncated %i-byte tag is dropped, not thrown (not a legal mesh MIC length)',
  (len) => {
    const plaintext = Buffer.from('abc', 'ascii');
    const { ciphertext, tag } = ccmEncrypt(KEY, NONCE, plaintext, 8);
    const truncated = tag.subarray(0, len);
    expect(truncated).toHaveLength(len);
    expect(ccmDecrypt(KEY, NONCE, ciphertext, truncated)).toBeNull();
  },
);

// 8.17.1 BTM_ECDH_P256_CMAC_AES128_AES_CCM sample: known-answer data for the
// session key, session nonce, provisioning data, resulting encrypted data
// and 8-byte MIC — proves the implementation against the specification
// rather than only against itself.
describe('known-answer: section 8.17.1 provisioning sample', () => {
  const key = hex(PROVISIONING_SAMPLE.sessionKey);
  const nonce = hex(PROVISIONING_SAMPLE.sessionNonce);
  const plaintext = hex(PROVISIONING_SAMPLE.plaintext);

  test('ccmEncrypt with an 8-byte tag reproduces the published encrypted data and MIC', () => {
    const { ciphertext, tag } = ccmEncrypt(key, nonce, plaintext, 8);
    expect(ciphertext.toString('hex')).toBe(PROVISIONING_SAMPLE.expectedCiphertext);
    expect(tag.toString('hex')).toBe(PROVISIONING_SAMPLE.expectedTag);
  });

  test('ccmDecrypt recovers the published plaintext from the published encrypted data and MIC', () => {
    const ciphertext = hex(PROVISIONING_SAMPLE.expectedCiphertext);
    const tag = hex(PROVISIONING_SAMPLE.expectedTag);
    const recovered = ccmDecrypt(key, nonce, ciphertext, tag);
    expect(recovered?.toString('hex')).toBe(PROVISIONING_SAMPLE.plaintext);
  });
});
