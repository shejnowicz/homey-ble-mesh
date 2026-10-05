import { aesCmac, s1 } from '../cmac';
import { hex, S1_TEST } from './vectors';

// RFC 4493 example key, used by every CMAC implementation as a smoke test.
const RFC_KEY = hex('2b7e151628aed2a6abf7158809cf4f3c');

test('CMAC of an empty message matches RFC 4493', () => {
  expect(aesCmac(RFC_KEY, Buffer.alloc(0)).toString('hex'))
    .toBe('bb1d6929e95937287fa37d129b756746');
});

test('CMAC of a 16-byte message matches RFC 4493', () => {
  const message = hex('6bc1bee22e409f96e93d7e117393172a');
  expect(aesCmac(RFC_KEY, message).toString('hex'))
    .toBe('070a16b46b4d4144f79bdd9dd04a287c');
});

test('CMAC of a 40-byte message matches RFC 4493', () => {
  const message = hex(
    '6bc1bee22e409f96e93d7e117393172a'
    + 'ae2d8a571e03ac9c9eb76fac45af8e51'
    + '30c81c46a35ce411',
  );
  expect(aesCmac(RFC_KEY, message).toString('hex'))
    .toBe('dfa66747de9ae63030ca32611497c827');
});

test('s1 matches the mesh sample data', () => {
  expect(s1(S1_TEST.input).toString('hex')).toBe(S1_TEST.expected);
});
