import { createCipheriv } from 'node:crypto';

const BLOCK = 16;
/** The constant RFC 4493 folds in when a left shift overflows. */
const RB = 0x87;

/**
 * The single AES-128 ECB block cipher primitive, exported as `e` because
 * that is the Mesh specification's own name for it (Security Toolbox,
 * "Encryption function": "ciphertext = e(key, plaintext)" — section 3.8.2.1
 * in Mesh Profile 1.0.1, renumbered 3.9.2.1 in Mesh Protocol v1.1). RFC 4493
 * never names this primitive `e`; it calls it AES-128(K,M). Exported because
 * the provisioning plan's header obfuscation needs exactly this primitive,
 * not a re-derivation of it.
 */
export function e(key: Buffer, block: Buffer): Buffer {
  const cipher = createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

function shiftLeft(input: Buffer): Buffer {
  const out = Buffer.alloc(input.length);
  let carry = 0;
  for (let i = input.length - 1; i >= 0; i -= 1) {
    const value = input[i] as number;
    out[i] = ((value << 1) & 0xff) | carry;
    carry = (value & 0x80) ? 1 : 0;
  }
  return out;
}

// RFC 4493's own subkeys, named subkey1/subkey2 here to avoid colliding with
// the unrelated exported k1/k2 key-derivation functions in derive.ts.
function subkeys(key: Buffer): { subkey1: Buffer; subkey2: Buffer } {
  const l = e(key, Buffer.alloc(BLOCK));
  const subkey1 = shiftLeft(l);
  if ((l[0] as number) & 0x80) subkey1[BLOCK - 1] = ((subkey1[BLOCK - 1] as number) ^ RB) as number;
  const subkey2 = shiftLeft(subkey1);
  if ((subkey1[0] as number) & 0x80) subkey2[BLOCK - 1] = ((subkey2[BLOCK - 1] as number) ^ RB) as number;
  return { subkey1, subkey2 };
}

function xor(a: Buffer, b: Buffer): Buffer {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i += 1) out[i] = (a[i] as number) ^ (b[i] as number);
  return out;
}

/** AES-CMAC as defined by RFC 4493, with a 128-bit key. Returns 16 bytes. */
export function aesCmac(key: Buffer, message: Buffer): Buffer {
  const { subkey1, subkey2 } = subkeys(key);
  const complete = message.length > 0 && message.length % BLOCK === 0;
  const blockCount = complete ? message.length / BLOCK : Math.floor(message.length / BLOCK) + 1;

  let last: Buffer;
  if (complete) {
    last = xor(message.subarray((blockCount - 1) * BLOCK), subkey1);
  } else {
    const tail = message.subarray((blockCount - 1) * BLOCK);
    const padded = Buffer.alloc(BLOCK);
    tail.copy(padded);
    padded[tail.length] = 0x80;
    last = xor(padded, subkey2);
  }

  let x: Buffer = Buffer.alloc(BLOCK);
  for (let i = 0; i < blockCount - 1; i += 1) {
    x = e(key, xor(x, message.subarray(i * BLOCK, (i + 1) * BLOCK))) as Buffer;
  }
  return e(key, xor(x, last));
}

/** s1(M) = AES-CMAC with an all-zero key. The mesh salt function. */
export function s1(message: Buffer): Buffer {
  return aesCmac(Buffer.alloc(BLOCK), message);
}
