import { createECDH } from 'node:crypto';

const CURVE = 'prime256v1';

/**
 * Provisioning exchanges raw X‖Y public keys, with no leading format byte,
 * so both directions strip and restore the 0x04 prefix Node expects.
 */
export function generateKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
  const ecdh = createECDH(CURVE);
  ecdh.generateKeys();
  return {
    publicKey: ecdh.getPublicKey().subarray(1),
    privateKey: ecdh.getPrivateKey(),
  };
}

export function sharedSecret(privateKey: Buffer, peerPublicKey: Buffer): Buffer {
  const ecdh = createECDH(CURVE);
  ecdh.setPrivateKey(privateKey);
  const uncompressed = Buffer.concat([Buffer.from([0x04]), peerPublicKey]);
  return ecdh.computeSecret(uncompressed);
}
