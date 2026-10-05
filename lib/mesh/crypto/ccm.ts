import { createCipheriv, createDecipheriv } from 'node:crypto';

/**
 * AES-CCM with a 128-bit key. `tagLength` is in bytes: mesh uses 4 for most
 * messages and 8 where a longer tag is specified.
 */
export function ccmEncrypt(
  key: Buffer,
  nonce: Buffer,
  plaintext: Buffer,
  tagLength: number,
  additionalData?: Buffer,
): { ciphertext: Buffer; tag: Buffer } {
  const cipher = createCipheriv('aes-128-ccm', key, nonce, { authTagLength: tagLength });
  if (additionalData && additionalData.length > 0) {
    cipher.setAAD(additionalData, { plaintextLength: plaintext.length });
  }
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, tag: cipher.getAuthTag() };
}

/** Returns the plaintext, or null when the tag does not verify. */
export function ccmDecrypt(
  key: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
  tag: Buffer,
  additionalData?: Buffer,
): Buffer | null {
  try {
    const decipher = createDecipheriv('aes-128-ccm', key, nonce, { authTagLength: tag.length });
    decipher.setAuthTag(tag);
    if (additionalData && additionalData.length > 0) {
      decipher.setAAD(additionalData, { plaintextLength: ciphertext.length });
    }
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    // Genuine tag mismatch (foreign traffic from other networks) returns null.
    // This is ordinary: mesh traffic from other networks reaches us constantly
    // and must be dropped quietly. Programming errors — wrong key/nonce/tag
    // length — are not attacker-controlled (those are protocol constants or
    // locally derived), so they are bugs in the caller and must not be masked
    // as ordinary authentication failure.
    const error = err as NodeJS.ErrnoException;
    if (
      error.code === 'ERR_CRYPTO_INVALID_KEYLEN' ||
      error.code === 'ERR_CRYPTO_INVALID_IV' ||
      error.code === 'ERR_CRYPTO_INVALID_AUTH_TAG'
    ) {
      throw err;
    }
    return null;
  }
}
