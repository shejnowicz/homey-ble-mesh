import { createECDH } from 'node:crypto';

const CURVE = 'prime256v1';

/**
 * `createECDH().getPrivateKey()` returns a big-endian integer with no leading
 * zeros, so about one key in 256 is shorter than 32 bytes. The scalar must be
 * padded on the LEFT: padding it on the right multiplies it by 256 and yields
 * a different key, which is invisible to a round-trip test because both sides
 * would use the same wrong value.
 */
export function padPrivateKey(raw: Buffer): Buffer {
  if (raw.length >= 32) return raw;
  const padded = Buffer.alloc(32);
  raw.copy(padded, 32 - raw.length);
  return padded;
}

/**
 * Provisioning exchanges raw X‖Y public keys, with no leading format byte,
 * so both directions strip and restore the 0x04 prefix Node expects.
 */
export function generateKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
  const ecdh = createECDH(CURVE);
  ecdh.generateKeys();
  const privateKey = padPrivateKey(ecdh.getPrivateKey());
  return {
    publicKey: ecdh.getPublicKey().subarray(1),
    privateKey,
  };
}

export function sharedSecret(privateKey: Buffer, peerPublicKey: Buffer): Buffer {
  if (privateKey.length !== 32) {
    throw new Error(`sharedSecret: privateKey must be 32 bytes, got ${privateKey.length}`);
  }
  if (peerPublicKey.length !== 64) {
    throw new Error(`sharedSecret: peerPublicKey must be 64 bytes (raw X‖Y, no 0x04 prefix), got ${peerPublicKey.length}`);
  }
  const ecdh = createECDH(CURVE);
  ecdh.setPrivateKey(privateKey);
  const uncompressed = Buffer.concat([Buffer.from([0x04]), peerPublicKey]);
  return ecdh.computeSecret(uncompressed);
}
