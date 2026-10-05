import { ccmEncrypt, ccmDecrypt } from '../ccm';

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
