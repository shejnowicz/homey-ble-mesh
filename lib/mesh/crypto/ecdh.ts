import { createECDH } from 'node:crypto';

const CURVE = 'prime256v1';

const PRIVATE_KEY_LENGTH = 32;

/**
 * Provisioning exchanges raw X‖Y public keys, with no leading format byte,
 * so both directions strip and restore the 0x04 prefix Node expects.
 */
export function generateKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
  const ecdh = createECDH(CURVE);
  ecdh.generateKeys();
  // Node's getPrivateKey() returns a big-endian integer with no leading zero
  // byte, so roughly 1 in 256 scalars is naturally 31 bytes (and rarer
  // shorter still). Left-pad to the 32 bytes this function promises.
  const rawPrivateKey = ecdh.getPrivateKey();
  const privateKey = Buffer.alloc(PRIVATE_KEY_LENGTH);
  rawPrivateKey.copy(privateKey, PRIVATE_KEY_LENGTH - rawPrivateKey.length);
  return {
    publicKey: ecdh.getPublicKey().subarray(1),
    privateKey,
  };
}

export function sharedSecret(privateKey: Buffer, peerPublicKey: Buffer): Buffer {
  const ecdh = createECDH(CURVE);
  ecdh.setPrivateKey(privateKey);
  const uncompressed = Buffer.concat([Buffer.from([0x04]), peerPublicKey]);
  return ecdh.computeSecret(uncompressed);
}
