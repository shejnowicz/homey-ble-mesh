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

/** The only MIC lengths mesh ever produces: 4 bytes for most messages, 8 where a longer tag is specified. */
const MESH_MIC_LENGTHS = new Set([4, 8]);

/** Returns the plaintext, or null when the tag does not verify. */
export function ccmDecrypt(
  key: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
  tag: Buffer,
  additionalData?: Buffer,
): Buffer | null {
  if (!MESH_MIC_LENGTHS.has(tag.length)) {
    // Not a length mesh ever produces. This is not a programming error: a
    // parser slicing a MIC off a truncated foreign packet reaches exactly
    // this, because `subarray` does not clamp a negative end index to zero
    // - it takes a negative end relative to the buffer's own length
    // (`length + end`, and only THAT result is clamped at 0 if it is still
    // negative; measured directly, see the same measurement spelled out in
    // `upperTransport.ts`'s `decryptUpperTransport`), so a short or
    // malformed packet yields a tag of some other, non-mesh length rather
    // than erroring. Node itself would throw ERR_CRYPTO_INVALID_AUTH_TAG for
    // most illegal lengths here, which would be indistinguishable from the
    // genuine caller bugs below — so this is checked explicitly, before any
    // of that is reached, and dropped quietly like any other foreign
    // traffic.
    return null;
  }
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
    // and must be dropped quietly. Programming errors — wrong key or nonce
    // length — are not attacker-controlled (those are protocol constants or
    // locally derived), so they are bugs in the caller and must not be masked
    // as ordinary authentication failure.
    const error = err as NodeJS.ErrnoException;
    if (
      error.code === 'ERR_CRYPTO_INVALID_KEYLEN' ||
      error.code === 'ERR_CRYPTO_INVALID_IV'
    ) {
      throw err;
    }
    return null;
  }
}
