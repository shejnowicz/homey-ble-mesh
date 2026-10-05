import { createCipheriv } from 'node:crypto';

const BLOCK = 16;
/** The constant RFC 4493 folds in when a left shift overflows. */
const RB = 0x87;

function aesEcbBlock(key: Buffer, block: Buffer): Buffer {
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

function subkeys(key: Buffer): { k1: Buffer; k2: Buffer } {
  const l = aesEcbBlock(key, Buffer.alloc(BLOCK));
  const k1 = shiftLeft(l);
  if ((l[0] as number) & 0x80) k1[BLOCK - 1] = ((k1[BLOCK - 1] as number) ^ RB) as number;
  const k2 = shiftLeft(k1);
  if ((k1[0] as number) & 0x80) k2[BLOCK - 1] = ((k2[BLOCK - 1] as number) ^ RB) as number;
  return { k1, k2 };
}

function xor(a: Buffer, b: Buffer): Buffer {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i += 1) out[i] = (a[i] as number) ^ (b[i] as number);
  return out;
}

/** AES-CMAC as defined by RFC 4493, with a 128-bit key. Returns 16 bytes. */
export function aesCmac(key: Buffer, message: Buffer): Buffer {
  const { k1, k2 } = subkeys(key);
  const complete = message.length > 0 && message.length % BLOCK === 0;
  const blockCount = complete ? message.length / BLOCK : Math.floor(message.length / BLOCK) + 1;

  let last: Buffer;
  if (complete) {
    last = xor(message.subarray((blockCount - 1) * BLOCK), k1);
  } else {
    const tail = message.subarray((blockCount - 1) * BLOCK);
    const padded = Buffer.alloc(BLOCK);
    tail.copy(padded);
    padded[tail.length] = 0x80;
    last = xor(padded, k2);
  }

  let x: Buffer = Buffer.alloc(BLOCK);
  for (let i = 0; i < blockCount - 1; i += 1) {
    x = aesEcbBlock(key, xor(x, message.subarray(i * BLOCK, (i + 1) * BLOCK))) as Buffer;
  }
  return aesEcbBlock(key, xor(x, last));
}

/** s1(M) = AES-CMAC with an all-zero key. The mesh salt function. */
export function s1(message: Buffer): Buffer {
  return aesCmac(Buffer.alloc(BLOCK), message);
}
