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
  } catch {
    // A failed tag is an ordinary outcome here: mesh traffic from other
    // networks reaches us constantly and must be dropped quietly.
    return null;
  }
}
