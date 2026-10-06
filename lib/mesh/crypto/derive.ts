import { aesCmac, s1 } from './cmac';

/** k1(N, SALT, P) = CMAC(CMAC(SALT, N), P). */
export function k1(n: Buffer, salt: Buffer, p: Buffer): Buffer {
  return aesCmac(aesCmac(salt, n), p);
}

/**
 * k2 derives the three values the network layer needs from a network key:
 * the 7-bit identifier carried in every packet, the encryption key and the
 * key that obfuscates the header.
 */
export function k2(n: Buffer, p: Buffer): { nid: number; encryptionKey: Buffer; privacyKey: Buffer } {
  if (n.length !== 16) {
    throw new Error(`k2: N must be 16 bytes (128-bit NetKey), got ${n.length}`);
  }
  if (p.length < 1) {
    throw new Error(`k2: P must be at least 1 octet, got ${p.length}`);
  }
  const salt = s1(Buffer.from('smk2', 'ascii'));
  const t = aesCmac(salt, n);
  const t1 = aesCmac(t, Buffer.concat([p, Buffer.from([0x01])]));
  const t2 = aesCmac(t, Buffer.concat([t1, p, Buffer.from([0x02])]));
  const t3 = aesCmac(t, Buffer.concat([t2, p, Buffer.from([0x03])]));
  return {
    nid: (t1[15] as number) & 0x7f,
    encryptionKey: t2,
    privacyKey: t3,
  };
}

/** k3 produces the eight-byte network identifier used in beacons. */
export function k3(n: Buffer): Buffer {
  if (n.length !== 16) {
    throw new Error(`k3: N must be 16 bytes (128-bit NetKey), got ${n.length}`);
  }
  const salt = s1(Buffer.from('smk3', 'ascii'));
  const t = aesCmac(salt, n);
  const result = aesCmac(t, Buffer.concat([Buffer.from('id64', 'ascii'), Buffer.from([0x01])]));
  return result.subarray(8);
}

/** k4 produces the six-bit application key identifier. */
export function k4(n: Buffer): number {
  if (n.length !== 16) {
    throw new Error(`k4: N must be 16 bytes (128-bit AppKey), got ${n.length}`);
  }
  const salt = s1(Buffer.from('smk4', 'ascii'));
  const t = aesCmac(salt, n);
  const result = aesCmac(t, Buffer.concat([Buffer.from('id6', 'ascii'), Buffer.from([0x01])]));
  return (result[15] as number) & 0x3f;
}
