import { generateKeyPair, sharedSecret } from '../ecdh';

test('a generated public key is the 64-byte X and Y pair', () => {
  const pair = generateKeyPair();
  expect(pair.publicKey).toHaveLength(64);
  expect(pair.privateKey).toHaveLength(32);
});

test('both sides agree on the same secret', () => {
  const ours = generateKeyPair();
  const theirs = generateKeyPair();
  const a = sharedSecret(ours.privateKey, theirs.publicKey);
  const b = sharedSecret(theirs.privateKey, ours.publicKey);
  expect(a).toHaveLength(32);
  expect(a.toString('hex')).toBe(b.toString('hex'));
});
