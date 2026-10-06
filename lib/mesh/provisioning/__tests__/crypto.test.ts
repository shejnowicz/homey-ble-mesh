import {
  confirmationSalt,
  confirmationKey,
  confirmationValue,
  provisioningSalt,
  sessionKey,
  sessionNonce,
  deviceKey,
} from '../crypto';
import {
  hex,
  PDU_TYPE_SAMPLE_RANDOM_PROVISIONER,
  PDU_TYPE_SAMPLE_RANDOM_DEVICE,
  PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER,
  PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE,
  PROVISIONING_CRYPTO_SAMPLE,
} from './vectors';
import { PROVISIONING_SAMPLE } from '../../crypto/__tests__/vectors';

// ===========================================================================
// Section 8.17.1 known-answer tests: one per derivation, each asserting the
// PUBLISHED intermediate directly - never a value computed by an earlier
// step of this same suite. A single end-to-end "does the device key come
// out right" assertion would still pass if two derivations here were wrong
// in a compensating way (e.g. a reversed concatenation that is undone by a
// second, matching reversal); pinning every intermediate against the
// specification's own sample closes that gap.
// ===========================================================================

const ecdhSecret = hex(PROVISIONING_SAMPLE.expectedSharedSecret);
const publicKeyProvisioner = Buffer.concat([
  hex(PROVISIONING_SAMPLE.provisionerPublicKeyX),
  hex(PROVISIONING_SAMPLE.provisionerPublicKeyY),
]);
const publicKeyDevice = Buffer.concat([
  hex(PROVISIONING_SAMPLE.devicePublicKeyX),
  hex(PROVISIONING_SAMPLE.devicePublicKeyY),
]);
const randomProvisioner = hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.fields.random);
const randomDevice = hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.fields.random);
const authValue = hex(PROVISIONING_CRYPTO_SAMPLE.authValue);

describe('confirmationSalt (Section 5.4.2.4.1: s1(ConfirmationInputs))', () => {
  test('matches the published sample, built from the Invite/Capabilities/Start PDU values and both public keys in order', () => {
    const result = confirmationSalt(
      hex(PROVISIONING_CRYPTO_SAMPLE.provisioningInvite),
      hex(PROVISIONING_CRYPTO_SAMPLE.provisioningCapabilities),
      hex(PROVISIONING_CRYPTO_SAMPLE.provisioningStart),
      publicKeyProvisioner,
      publicKeyDevice,
    );
    expect(result.toString('hex')).toBe(PROVISIONING_CRYPTO_SAMPLE.confirmationSalt);
  });

  test('rejects a public key that is not the 64-byte X‖Y pair rather than deriving a plausible wrong answer', () => {
    expect(() =>
      confirmationSalt(
        hex(PROVISIONING_CRYPTO_SAMPLE.provisioningInvite),
        hex(PROVISIONING_CRYPTO_SAMPLE.provisioningCapabilities),
        hex(PROVISIONING_CRYPTO_SAMPLE.provisioningStart),
        publicKeyProvisioner.subarray(0, 63),
        publicKeyDevice,
      ),
    ).toThrow('provisioning crypto "publicKeyProvisioner" must be 64 bytes, got 63');
  });
});

describe('confirmationKey (Section 5.4.2.4.1: k1(ECDHSecret, ConfirmationSalt, "prck"))', () => {
  test('matches the published sample, from the published ECDHSecret and ConfirmationSalt directly (not the salt computed above)', () => {
    const result = confirmationKey(ecdhSecret, hex(PROVISIONING_CRYPTO_SAMPLE.confirmationSalt));
    expect(result.toString('hex')).toBe(PROVISIONING_CRYPTO_SAMPLE.confirmationKey);
  });

  test('rejects an ECDHSecret that is not 32 bytes rather than deriving a plausible wrong answer', () => {
    expect(() => confirmationKey(ecdhSecret.subarray(0, 31), hex(PROVISIONING_CRYPTO_SAMPLE.confirmationSalt))).toThrow(
      'provisioning crypto "ecdhSecret" must be 32 bytes, got 31',
    );
  });
});

describe('confirmationValue (Section 5.4.2.4.1: AES-CMAC_ConfirmationKey(Random || AuthValue))', () => {
  test('reproduces ConfirmationProvisioner from the published ConfirmationKey and RandomProvisioner', () => {
    const result = confirmationValue(hex(PROVISIONING_CRYPTO_SAMPLE.confirmationKey), randomProvisioner, authValue);
    expect(result.toString('hex')).toBe(PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.fields.confirmation);
  });

  test('reproduces ConfirmationDevice from the published ConfirmationKey and RandomDevice - the same function, a different Random', () => {
    const result = confirmationValue(hex(PROVISIONING_CRYPTO_SAMPLE.confirmationKey), randomDevice, authValue);
    expect(result.toString('hex')).toBe(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.fields.confirmation);
  });

  test('rejects a Random that is not 16 bytes rather than deriving a plausible wrong answer', () => {
    expect(() =>
      confirmationValue(hex(PROVISIONING_CRYPTO_SAMPLE.confirmationKey), randomProvisioner.subarray(0, 15), authValue),
    ).toThrow('provisioning crypto "random" must be 16 bytes, got 15');
  });
});

describe('provisioningSalt (Section 5.4.2.5: s1(ConfirmationSalt || RandomProvisioner || RandomDevice))', () => {
  test('matches the published sample, from the published ConfirmationSalt and both Randoms directly', () => {
    const result = provisioningSalt(hex(PROVISIONING_CRYPTO_SAMPLE.confirmationSalt), randomProvisioner, randomDevice);
    expect(result.toString('hex')).toBe(PROVISIONING_CRYPTO_SAMPLE.provisioningSalt);
  });

  test('rejects a ConfirmationSalt that is not 16 bytes rather than deriving a plausible wrong answer', () => {
    expect(() =>
      provisioningSalt(hex(PROVISIONING_CRYPTO_SAMPLE.confirmationSalt).subarray(0, 15), randomProvisioner, randomDevice),
    ).toThrow('provisioning crypto "confirmationSaltValue" must be 16 bytes, got 15');
  });
});

describe('sessionKey (Section 5.4.2.5: k1(ECDHSecret, ProvisioningSalt, "prsk"))', () => {
  test('matches the published sample, from the published ECDHSecret and ProvisioningSalt directly', () => {
    const result = sessionKey(ecdhSecret, hex(PROVISIONING_CRYPTO_SAMPLE.provisioningSalt));
    expect(result.toString('hex')).toBe(PROVISIONING_SAMPLE.sessionKey);
  });
});

describe('sessionNonce (Section 5.4.2.5: the 13 least significant octets of k1(ECDHSecret, ProvisioningSalt, "prsn"))', () => {
  test('matches the published sample', () => {
    const result = sessionNonce(ecdhSecret, hex(PROVISIONING_CRYPTO_SAMPLE.provisioningSalt));
    expect(result.toString('hex')).toBe(PROVISIONING_SAMPLE.sessionNonce);
  });

  // The published SessionNonceFull (the pre-truncation 16-byte k1 output) is
  // published alongside SessionNonce specifically so the TRUNCATION DIRECTION
  // can be pinned, not just its length: "13 least significant octets" means
  // the last 13 bytes, not the first 13 - an easy direction to get backwards
  // the way the module header explains. This fails if `sessionNonce` ever
  // returns the FIRST 13 bytes of the k1 output instead.
  test('keeps the LAST 13 octets of the full k1 output, not the first 13 (truncation direction)', () => {
    const full = hex(PROVISIONING_CRYPTO_SAMPLE.sessionNonceFull);
    expect(full.toString('hex')).toBe(PROVISIONING_CRYPTO_SAMPLE.sessionNonceFull);
    const lastThirteen = full.subarray(full.length - 13).toString('hex');
    const firstThirteen = full.subarray(0, 13).toString('hex');
    expect(lastThirteen).toBe(PROVISIONING_SAMPLE.sessionNonce);
    expect(firstThirteen).not.toBe(PROVISIONING_SAMPLE.sessionNonce);

    const result = sessionNonce(ecdhSecret, hex(PROVISIONING_CRYPTO_SAMPLE.provisioningSalt));
    expect(result.toString('hex')).toBe(lastThirteen);
    expect(result.toString('hex')).not.toBe(firstThirteen);
  });

  test('rejects a ProvisioningSalt that is not 16 bytes rather than deriving a plausible wrong answer', () => {
    expect(() => sessionNonce(ecdhSecret, hex(PROVISIONING_CRYPTO_SAMPLE.provisioningSalt).subarray(0, 15))).toThrow(
      'provisioning crypto "provisioningSaltValue" must be 16 bytes, got 15',
    );
  });
});

describe('deviceKey (Section 3.9.6.1, Figure 3.52: k1(ECDHSecret, ProvisioningSalt, "prdk"))', () => {
  test('matches the published sample, from the published ECDHSecret and ProvisioningSalt directly - not the chain computed above', () => {
    const result = deviceKey(ecdhSecret, hex(PROVISIONING_CRYPTO_SAMPLE.provisioningSalt));
    expect(result.toString('hex')).toBe(PROVISIONING_CRYPTO_SAMPLE.deviceKey);
  });

  test('rejects an ECDHSecret that is not 32 bytes rather than deriving a plausible wrong answer', () => {
    expect(() => deviceKey(ecdhSecret.subarray(0, 31), hex(PROVISIONING_CRYPTO_SAMPLE.provisioningSalt))).toThrow(
      'provisioning crypto "ecdhSecret" must be 32 bytes, got 31',
    );
  });
});

// ===========================================================================
// End-to-end: chaining every function from the raw PDU values through to the
// device key reproduces the published DevKey. This is in ADDITION to, never
// instead of, the per-derivation tests above - it would also pass with two
// compensating mistakes, which is exactly why it is not the only test here.
// ===========================================================================

test('end-to-end: the full chain from PDU values to DevKey matches the published sample', () => {
  const salt = confirmationSalt(
    hex(PROVISIONING_CRYPTO_SAMPLE.provisioningInvite),
    hex(PROVISIONING_CRYPTO_SAMPLE.provisioningCapabilities),
    hex(PROVISIONING_CRYPTO_SAMPLE.provisioningStart),
    publicKeyProvisioner,
    publicKeyDevice,
  );
  const key = confirmationKey(ecdhSecret, salt);
  const provisionerConfirmation = confirmationValue(key, randomProvisioner, authValue);
  const deviceConfirmation = confirmationValue(key, randomDevice, authValue);
  expect(provisionerConfirmation.toString('hex')).toBe(PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.fields.confirmation);
  expect(deviceConfirmation.toString('hex')).toBe(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.fields.confirmation);

  const salt2 = provisioningSalt(salt, randomProvisioner, randomDevice);
  expect(salt2.toString('hex')).toBe(PROVISIONING_CRYPTO_SAMPLE.provisioningSalt);

  expect(sessionKey(ecdhSecret, salt2).toString('hex')).toBe(PROVISIONING_SAMPLE.sessionKey);
  expect(sessionNonce(ecdhSecret, salt2).toString('hex')).toBe(PROVISIONING_SAMPLE.sessionNonce);
  expect(deviceKey(ecdhSecret, salt2).toString('hex')).toBe(PROVISIONING_CRYPTO_SAMPLE.deviceKey);
});
