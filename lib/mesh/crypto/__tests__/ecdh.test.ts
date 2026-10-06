import { createECDH } from 'node:crypto';
import { generateKeyPair, sharedSecret } from '../ecdh';
import { hex, PROVISIONING_SAMPLE } from './vectors';

const CURVE = 'prime256v1';

test('a generated public key is the 64-byte X and Y pair', () => {
  const pair = generateKeyPair();
  expect(pair.publicKey).toHaveLength(64);
  expect(pair.privateKey).toHaveLength(32);
});

// Node's getPrivateKey() omits a leading zero byte, so roughly 1 call in 200
// returns a scalar shorter than 32 bytes before padding. Enough iterations
// make sure this exercises that path, not just the common 32-byte case.
test('generateKeyPair always left-pads the private key to 32 bytes', () => {
  for (let i = 0; i < 500; i += 1) {
    expect(generateKeyPair().privateKey).toHaveLength(32);
  }
});

test('both sides agree on the same secret', () => {
  const ours = generateKeyPair();
  const theirs = generateKeyPair();
  const a = sharedSecret(ours.privateKey, theirs.publicKey);
  const b = sharedSecret(theirs.privateKey, ours.publicKey);
  expect(a).toHaveLength(32);
  expect(a.toString('hex')).toBe(b.toString('hex'));
});

// Confirms setPrivateKey genuinely accepts the left-padded 32-byte form and
// yields the identical shared secret Node computes from the raw, unpadded
// scalar — not just that both of OUR wrapper's calls agree with each other.
test('a left-padded private key reproduces the same secret Node computes from the unpadded scalar', () => {
  const peer = generateKeyPair();
  let shortScalar: Buffer | null = null;
  for (let i = 0; i < 5000 && !shortScalar; i += 1) {
    const candidate = createECDH(CURVE);
    candidate.generateKeys();
    const raw = candidate.getPrivateKey();
    if (raw.length === 31) {
      shortScalar = raw;
    }
  }
  expect(shortScalar).not.toBeNull();
  const raw = shortScalar as Buffer;

  const rawEcdh = createECDH(CURVE);
  rawEcdh.setPrivateKey(raw);
  const directSecret = rawEcdh.computeSecret(Buffer.concat([Buffer.from([0x04]), peer.publicKey]));

  const padded = Buffer.alloc(32);
  raw.copy(padded, 32 - raw.length);
  const paddedSecret = sharedSecret(padded, peer.publicKey);

  expect(paddedSecret.toString('hex')).toBe(directSecret.toString('hex'));
});

// 8.17.1 BTM_ECDH_P256_CMAC_AES128_AES_CCM sample: a known-answer test that
// needs no packet layer and no radio, unlike the self-consistency checks
// above (which two consistently wrong implementations would also satisfy).
describe('known-answer: section 8.17.1 provisioning sample', () => {
  const provisionerPrivateKey = hex(PROVISIONING_SAMPLE.provisionerPrivateKey);
  const provisionerPublicKey = Buffer.concat([
    hex(PROVISIONING_SAMPLE.provisionerPublicKeyX),
    hex(PROVISIONING_SAMPLE.provisionerPublicKeyY),
  ]);
  const devicePrivateKey = hex(PROVISIONING_SAMPLE.devicePrivateKey);
  const devicePublicKey = Buffer.concat([
    hex(PROVISIONING_SAMPLE.devicePublicKeyX),
    hex(PROVISIONING_SAMPLE.devicePublicKeyY),
  ]);

  test('provisioner private key + device public key reproduces the published shared secret', () => {
    const secret = sharedSecret(provisionerPrivateKey, devicePublicKey);
    expect(secret.toString('hex')).toBe(PROVISIONING_SAMPLE.expectedSharedSecret);
  });

  test('device private key + provisioner public key reproduces the published shared secret', () => {
    const secret = sharedSecret(devicePrivateKey, provisionerPublicKey);
    expect(secret.toString('hex')).toBe(PROVISIONING_SAMPLE.expectedSharedSecret);
  });
});

import { padPrivateKey } from '../ecdh';

test('a short scalar is padded on the LEFT, preserving its value', () => {
  const short = Buffer.alloc(31, 0xab);
  const padded = padPrivateKey(short);
  expect(padded).toHaveLength(32);
  expect(padded[0]).toBe(0x00);
  expect(padded.subarray(1).equals(short)).toBe(true);
});

test('a full-length scalar is returned unchanged', () => {
  const full = Buffer.alloc(32, 0xcd);
  expect(padPrivateKey(full).equals(full)).toBe(true);
});

test('sharedSecret rejects a private key that is not 32 bytes rather than deriving a plausible wrong answer', () => {
  const peer = generateKeyPair();
  expect(() => sharedSecret(Buffer.alloc(31, 0x01), peer.publicKey)).toThrow(/32 bytes/);
});

test('sharedSecret rejects a peer public key that is not 64 bytes rather than deriving a plausible wrong answer', () => {
  const ours = generateKeyPair();
  expect(() => sharedSecret(ours.privateKey, Buffer.alloc(63, 0x02))).toThrow(/64 bytes/);
});
