import {
  beginProvisioning,
  step,
  provisioningErrorName,
  ProvisioningState,
  ProvisioningDataInput,
  EphemeralKeyPair,
} from '../machine';
import {
  encodeProvisioningPdu,
  decodeProvisioningPdu,
  ProvisioningCapabilities,
  ProvisioningPublicKey,
  ProvisioningConfirmation,
  ProvisioningRandom,
  ProvisioningData,
  ProvisioningFailed,
} from '../pdu';
import { ccmDecrypt } from '../../crypto/ccm';
import {
  hex,
  PDU_TYPE_SAMPLE_INVITE,
  PDU_TYPE_SAMPLE_CAPABILITIES,
  PDU_TYPE_SAMPLE_START,
  PDU_TYPE_SAMPLE_PUBLIC_KEY_PROVISIONER,
  PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE,
  PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER,
  PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE,
  PDU_TYPE_SAMPLE_RANDOM_PROVISIONER,
  PDU_TYPE_SAMPLE_RANDOM_DEVICE,
  PDU_TYPE_SAMPLE_DATA,
  PDU_TYPE_SAMPLE_COMPLETE,
  PROVISIONING_CRYPTO_SAMPLE,
} from './vectors';
import { PROVISIONING_SAMPLE } from '../../crypto/__tests__/vectors';

// ===========================================================================
// Shared fixture inputs for the published Section 8.7/8.17.1 exchange.
// `provisioningData` is DERIVED by slicing the already-published, already
// KAT-verified `PROVISIONING_SAMPLE.plaintext` (used elsewhere in this repo
// by `crypto/__tests__/ccm.test.ts`) according to Table 5.47's own field
// order and sizes (NetKey 16, Key Index 2, Flags 1, IV Index 4, Unicast
// Address 2) - arithmetic slicing of an already-verified byte string, not a
// hand-transcribed new value. See `machine.ts`'s own module header for why
// Key Index/IV Index/Unicast Address are read as plain big-endian integers
// here rather than Section 4.3.1.1's packed-key-index format.
// ===========================================================================

const ephemeralKeyPair: EphemeralKeyPair = {
  publicKey: Buffer.concat([
    hex(PROVISIONING_SAMPLE.provisionerPublicKeyX),
    hex(PROVISIONING_SAMPLE.provisionerPublicKeyY),
  ]),
  privateKey: hex(PROVISIONING_SAMPLE.provisionerPrivateKey),
};
const randomProvisioner = hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.fields.random);
const fullPlaintext = hex(PROVISIONING_SAMPLE.plaintext);
const provisioningData: ProvisioningDataInput = {
  netKey: fullPlaintext.subarray(0, 16),
  netKeyIndex: fullPlaintext.readUInt16BE(16),
  flags: fullPlaintext.readUInt8(18),
  ivIndex: fullPlaintext.readUInt32BE(19),
  unicastAddress: fullPlaintext.readUInt16BE(23),
};

function begin() {
  return beginProvisioning({
    attentionDuration: PDU_TYPE_SAMPLE_INVITE.fields.attentionDuration,
    ephemeralKeyPair,
    randomProvisioner,
    provisioningData,
  });
}

// ===========================================================================
// The complete published exchange, driven step by step over a loopback.
// ===========================================================================

describe('the complete published Section 8.7/8.17.1 exchange, driven step by step', () => {
  test('reproduces every published PDU in order and the published device key at the end', () => {
    let result = begin();
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_INVITE.message)]);
    expect(result.state.phase).toBe('awaitingCapabilities');

    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_START.message), hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_PROVISIONER.message)]);
    expect(result.state.phase).toBe('awaitingPublicKeyDevice');

    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.message)]);
    expect(result.state.phase).toBe('awaitingConfirmationDevice');

    result = step(result.state, hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message));
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.message)]);
    expect(result.state.phase).toBe('awaitingRandomDevice');

    result = step(result.state, hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_DATA.message)]);
    expect(result.state.phase).toBe('awaitingComplete');

    result = step(result.state, hex(PDU_TYPE_SAMPLE_COMPLETE.message));
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'provisioned',
      deviceKey: hex(PROVISIONING_CRYPTO_SAMPLE.deviceKey),
    });
  });
});

// ===========================================================================
// A node whose capabilities demand an out-of-band method we do not
// implement.
// ===========================================================================

describe('a device whose Capabilities cannot be satisfied by this project', () => {
  test('OOB-only (Table 5.23 bit 1 set) stops as "unsupported", having sent nothing further', () => {
    const begun = begin();
    const oobOnlyCapabilities: ProvisioningCapabilities = {
      ...PDU_TYPE_SAMPLE_CAPABILITIES.fields,
      type: 'capabilities',
      oobType: 0x02,
    };
    const result = step(begun.state, encodeProvisioningPdu(oobOnlyCapabilities));
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'unsupported',
      reason:
        'device Capabilities requires OOB-authenticated provisioning (Table 5.23 bit 1 set); this design implements the no-OOB path only and decides later whether to add an OOB path (docs/superpowers/specs/2026-10-06-ble-mesh-provisioner-design.md)',
    });
  });

  test('is not silently treated as the no-OOB case: a plain (non-OOB-only) Capabilities PDU is accepted instead', () => {
    // Sanity check for the test above: the UNMODIFIED sample (oobType=0x00)
    // must proceed normally, so the 'unsupported' result above is really
    // caused by the OOB bit, not by anything else differing in the
    // modified fixture.
    const begun = begin();
    const result = step(begun.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    expect(result.state.phase).toBe('awaitingPublicKeyDevice');
    expect(result.send).toHaveLength(2);
  });

  test('an algorithm set that never offers BTM_ECDH_P256_CMAC_AES128_AES_CCM also stops as "unsupported"', () => {
    const begun = begin();
    const noCmacCapabilities: ProvisioningCapabilities = {
      ...PDU_TYPE_SAMPLE_CAPABILITIES.fields,
      type: 'capabilities',
      algorithms: 0x0002, // bit 1 only: BTM_ECDH_P256_HMAC_SHA256_AES_CCM, which this project does not implement.
    };
    const result = step(begun.state, encodeProvisioningPdu(noCmacCapabilities));
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'unsupported',
      reason:
        'device Capabilities does not offer BTM_ECDH_P256_CMAC_AES128_AES_CCM (Table 5.21 bit 0) - the only algorithm this project implements (algorithms=0x0002)',
    });
  });
});

// ===========================================================================
// A PDU arriving out of order.
// ===========================================================================

describe('a PDU arriving out of order', () => {
  test('is rejected as a protocol failure (Table 5.41 0x03), without corrupting the state', () => {
    const begun = begin();
    // awaitingCapabilities expects a Capabilities PDU; feed a Random PDU instead.
    const result = step(begun.state, hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.message));
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x03,
      errorName: 'Unexpected PDU',
      reason: 'expected a Capabilities PDU but received a random PDU',
    });
  });

  test('a Public Key PDU arriving before Capabilities is also rejected, leaving a clean failed state', () => {
    const begun = begin();
    const result = step(begun.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x03,
      errorName: 'Unexpected PDU',
      reason: 'expected a Capabilities PDU but received a publicKey PDU',
    });
  });

  test('once failed, the machine is a no-op - it never resumes mid-exchange', () => {
    const begun = begin();
    const failedResult = step(begun.state, hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.message));
    const resumed = step(failedResult.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    expect(resumed).toEqual({ state: failedResult.state, send: [] });
  });

  // The three tests above only ever misorder a PDU at the FIRST phase
  // (awaitingCapabilities). A review found this leaves every later phase's
  // own type check untested: weakening just ONE of them (e.g. letting a
  // Confirmation PDU fall through at the Random step) still passed the
  // full suite, because nothing exercised that phase with a wrong type.
  // One case per remaining phase closes that, each asserting the whole
  // resulting `'failed'` state, not only that something failed.

  test('at awaitingPublicKeyDevice: a Confirmation PDU instead of Public Key is rejected', () => {
    let result = begin();
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    expect(result.state.phase).toBe('awaitingPublicKeyDevice');

    result = step(result.state, hex(PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.message));
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x03,
      errorName: 'Unexpected PDU',
      reason: 'expected a Public Key PDU but received a confirmation PDU',
    });
  });

  test('at awaitingConfirmationDevice: a Random PDU instead of Confirmation is rejected', () => {
    let result = begin();
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    expect(result.state.phase).toBe('awaitingConfirmationDevice');

    result = step(result.state, hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x03,
      errorName: 'Unexpected PDU',
      reason: 'expected a Confirmation PDU but received a random PDU',
    });
  });

  // This is the exact scenario a review's mutation targeted: weakening
  // the type check at the Random step so a Confirmation PDU fell through
  // and was treated as Random, reaching `awaitingComplete` with a zero
  // device key. With the type check intact, this must fail cleanly here
  // instead.
  test('at awaitingRandomDevice: a Confirmation PDU instead of Random is rejected, not silently advanced', () => {
    let result = begin();
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message));
    expect(result.state.phase).toBe('awaitingRandomDevice');

    result = step(result.state, hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message));
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x03,
      errorName: 'Unexpected PDU',
      reason: 'expected a Random PDU but received a confirmation PDU',
    });
  });

  test('at awaitingComplete: a Random PDU instead of Complete is rejected', () => {
    let result = begin();
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
    expect(result.state.phase).toBe('awaitingComplete');

    result = step(result.state, hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x03,
      errorName: 'Unexpected PDU',
      reason: 'expected a Complete PDU but received a random PDU',
    });
  });
});

// ===========================================================================
// A confirmation value that does not match.
// ===========================================================================

describe('a confirmation value that does not match', () => {
  function driveToAwaitingRandomDevice() {
    let result = begin();
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message));
    expect(result.state.phase).toBe('awaitingRandomDevice');
    return result;
  }

  test('a RandomDevice that does not reproduce the earlier ConfirmationDevice fails with Confirmation Failed (Table 5.41 0x04)', () => {
    const atRandomDevice = driveToAwaitingRandomDevice();
    const corruptRandomDevice = Buffer.from(hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
    const lastIndex = corruptRandomDevice.length - 1;
    corruptRandomDevice[lastIndex] = (corruptRandomDevice[lastIndex] as number) ^ 0xff;

    const result = step(atRandomDevice.state, corruptRandomDevice);
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x04,
      errorName: 'Confirmation Failed',
      reason:
        'ConfirmationDevice recomputed from the received RandomDevice does not match the value received earlier (Section 5.4.2.4.2: the Provisionee is not authenticated)',
    });
  });

  test('the genuine published RandomDevice is still accepted (control for the mutation above)', () => {
    const atRandomDevice = driveToAwaitingRandomDevice();
    const result = step(atRandomDevice.state, hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
    expect(result.state.phase).toBe('awaitingComplete');
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_DATA.message)]);
  });

  // A review found that the mutation test above does not actually prove
  // the comparison checks all 16 bytes: it corrupts a byte of RANDOM, not
  // of the stored confirmation, so the recomputed value differs from the
  // stored one starting at byte 0 - a comparison truncated to the first 8
  // bytes, or even the first 1 byte, would still catch it. This test
  // instead corrupts only the LAST byte of the device's confirmation
  // value (derived by flipping one bit of the published, verified value -
  // not a value taken on trust), then completes the exchange with the
  // GENUINE published RandomDevice. The recomputed ConfirmationDevice
  // therefore matches the published value everywhere EXCEPT that last
  // byte - the one shape of mismatch a prefix-only comparison would miss.
  test('a device confirmation differing from the published value ONLY in its last byte still fails (closes a truncated-comparison gap)', () => {
    const genuineConfirmationDevice = hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.fields.confirmation);
    const almostGenuineConfirmationDevice = Buffer.from(genuineConfirmationDevice);
    const lastIndex = almostGenuineConfirmationDevice.length - 1;
    almostGenuineConfirmationDevice[lastIndex] = (almostGenuineConfirmationDevice[lastIndex] as number) ^ 0x01;
    // Sanity check on the fixture itself: everything BUT the last byte is
    // still identical to the genuine value - otherwise this would not be
    // testing what it claims to.
    expect(almostGenuineConfirmationDevice.subarray(0, lastIndex)).toEqual(genuineConfirmationDevice.subarray(0, lastIndex));
    expect(almostGenuineConfirmationDevice.subarray(lastIndex)).not.toEqual(genuineConfirmationDevice.subarray(lastIndex));

    let result = begin();
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    const almostGenuineConfirmationPdu: ProvisioningConfirmation = {
      type: 'confirmation',
      confirmation: almostGenuineConfirmationDevice,
    };
    result = step(result.state, encodeProvisioningPdu(almostGenuineConfirmationPdu));
    expect(result.state.phase).toBe('awaitingRandomDevice');

    // The genuine RandomDevice - recomputing ConfirmationDevice from it
    // reproduces the GENUINE value, which now disagrees with the altered
    // one stored above by exactly one byte, at the end.
    result = step(result.state, hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x04,
      errorName: 'Confirmation Failed',
      reason:
        'ConfirmationDevice recomputed from the received RandomDevice does not match the value received earlier (Section 5.4.2.4.2: the Provisionee is not authenticated)',
    });
  });

  test('a 32-byte device Confirmation (wrong algorithm length) is rejected as Invalid Format, not fed into the comparison', () => {
    let result = begin();
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    const longConfirmationPdu: ProvisioningConfirmation = { type: 'confirmation', confirmation: Buffer.alloc(32, 0x01) };
    result = step(result.state, encodeProvisioningPdu(longConfirmationPdu));
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x02,
      errorName: 'Invalid Format',
      reason: 'device Confirmation is 32 bytes, expected 16 under BTM_ECDH_P256_CMAC_AES128_AES_CCM',
    });
  });

  test('a 32-byte device Random (wrong algorithm length) is rejected as Invalid Format', () => {
    const atRandomDevice = driveToAwaitingRandomDevice();
    const longRandomPdu: ProvisioningRandom = { type: 'random', random: Buffer.alloc(32, 0x02) };
    const result = step(atRandomDevice.state, encodeProvisioningPdu(longRandomPdu));
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x02,
      errorName: 'Invalid Format',
      reason: 'device Random is 32 bytes, expected 16 under BTM_ECDH_P256_CMAC_AES128_AES_CCM',
    });
  });

  test('a device confirmation identical to our own fails immediately (Section 5.4.2.4.2 sanity check), before any random is sent', () => {
    let result = begin();
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    const ownConfirmationBytes = result.send[0] as Buffer; // the Confirmation(Provisioner) PDU we just sent.

    result = step(result.state, ownConfirmationBytes); // played back as if it were the device's own.
    expect(result.send).toEqual([]);
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x04,
      errorName: 'Confirmation Failed',
      reason: "device's ConfirmationDevice equals the provisioner's own ConfirmationProvisioner (Section 5.4.2.4.2)",
    });
  });
});

// ===========================================================================
// Public key validation (Section 5.4.2.3).
// ===========================================================================

describe('device public key validation', () => {
  function driveToAwaitingPublicKeyDevice() {
    const begun = begin();
    return step(begun.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
  }

  test("a device public key identical to the provisioner's own ephemeral key fails as Invalid Format", () => {
    const atPublicKeyDevice = driveToAwaitingPublicKeyDevice();
    const samePublicKey: ProvisioningPublicKey = {
      type: 'publicKey',
      publicKeyX: Buffer.from(ephemeralKeyPair.publicKey.subarray(0, 32)),
      publicKeyY: Buffer.from(ephemeralKeyPair.publicKey.subarray(32, 64)),
    };
    const result = step(atPublicKeyDevice.state, encodeProvisioningPdu(samePublicKey));
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x02,
      errorName: 'Invalid Format',
      reason: "device's Public Key is identical to the provisioner's own ephemeral public key (Section 5.4.2.3)",
    });
  });

  test('a device public key that is not a valid point on P-256 fails as Invalid Format', () => {
    const atPublicKeyDevice = driveToAwaitingPublicKeyDevice();
    const invalidPublicKey: ProvisioningPublicKey = {
      type: 'publicKey',
      publicKeyX: Buffer.alloc(32, 0x01),
      publicKeyY: Buffer.alloc(32, 0x01),
    };
    const result = step(atPublicKeyDevice.state, encodeProvisioningPdu(invalidPublicKey));
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x02,
      errorName: 'Invalid Format',
      reason: "device's Public Key is not a valid point on P-256 (Section 5.4.2.3)",
    });
  });
});

// ===========================================================================
// Decode failures and device-reported Failed PDUs.
// ===========================================================================

describe('malformed or foreign bytes', () => {
  test('bytes that do not decode as any Provisioning PDU fail as Invalid PDU (0x01)', () => {
    const begun = begin();
    // Table 5.17: Padding (top 2 bits) must be 0b00 - 0xff sets them, so
    // this can never decode as any recognised Provisioning PDU.
    const result = step(begun.state, Buffer.from([0xff]));
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x01,
      errorName: 'Invalid PDU',
      reason:
        'received bytes do not decode as a recognised Provisioning PDU (wrong length, non-zero Padding bits, or an unimplemented/unassigned Type)',
    });
  });

  test("a Provisioning Failed PDU from the device is reported verbatim with its OWN error code, not as Unexpected PDU", () => {
    const begun = begin();
    const failedPdu: ProvisioningFailed = { type: 'failed', errorCode: 0x05 };
    const result = step(begun.state, encodeProvisioningPdu(failedPdu));
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x05,
      errorName: 'Out of Resources',
      reason: 'device reported provisioning failure: Out of Resources (0x05)',
    });
  });

  test('a Failed PDU is accepted at any phase, not only the first', () => {
    let result = begin();
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    const failedPdu: ProvisioningFailed = { type: 'failed', errorCode: 0x09 };
    result = step(result.state, encodeProvisioningPdu(failedPdu));
    expect(result.state).toEqual({
      phase: 'failed',
      errorCode: 0x09,
      errorName: 'Invalid Data',
      reason: 'device reported provisioning failure: Invalid Data (0x09)',
    });
  });
});

// ===========================================================================
// Terminal states are no-ops, never throws (the "one nullish convention"
// requirement: whatever this module returns as state, it must be able to
// consume).
// ===========================================================================

describe('terminal states', () => {
  test.each<[string, ProvisioningState]>([
    ['provisioned', { phase: 'provisioned', deviceKey: Buffer.alloc(16, 0x01) }],
    ['unsupported', { phase: 'unsupported', reason: 'test fixture' }],
    ['failed', { phase: 'failed', errorCode: 0x03, errorName: 'Unexpected PDU', reason: 'test fixture' }],
  ])('%s: stepping it again is a no-op, not a throw', (_label, terminalState) => {
    const result = step(terminalState, hex(PDU_TYPE_SAMPLE_COMPLETE.message));
    expect(result).toEqual({ state: terminalState, send: [] });
  });
});

// ===========================================================================
// provisioningErrorName (Table 5.41, transcribed in full).
// ===========================================================================

describe('provisioningErrorName (Table 5.41 "Provisioning error codes")', () => {
  test.each([
    [0x00, 'Prohibited'],
    [0x01, 'Invalid PDU'],
    [0x02, 'Invalid Format'],
    [0x03, 'Unexpected PDU'],
    [0x04, 'Confirmation Failed'],
    [0x05, 'Out of Resources'],
    [0x06, 'Decryption Failed'],
    [0x07, 'Unexpected Error'],
    [0x08, 'Cannot Assign Addresses'],
    [0x09, 'Invalid Data'],
    [0x0a, 'RFU'],
    [0x7f, 'RFU'],
    [0xff, 'RFU'],
  ])('0x%s -> %s', (code, name) => {
    expect(provisioningErrorName(code)).toBe(name);
  });
});

// ===========================================================================
// beginProvisioning input validation - caller mistakes, thrown rather than
// deriving a plausible wrong answer (same stance `pdu.ts`/`crypto.ts` take).
// ===========================================================================

describe('beginProvisioning input validation', () => {
  test('rejects a wrong-length ephemeral public key', () => {
    expect(() =>
      beginProvisioning({
        attentionDuration: 0,
        ephemeralKeyPair: { ...ephemeralKeyPair, publicKey: ephemeralKeyPair.publicKey.subarray(0, 63) },
        randomProvisioner,
        provisioningData,
      }),
    ).toThrow('provisioning machine field "ephemeralKeyPair.publicKey" must be 64 bytes, got 63');
  });

  test('rejects a wrong-length ephemeral private key', () => {
    expect(() =>
      beginProvisioning({
        attentionDuration: 0,
        ephemeralKeyPair: { ...ephemeralKeyPair, privateKey: ephemeralKeyPair.privateKey.subarray(0, 31) },
        randomProvisioner,
        provisioningData,
      }),
    ).toThrow('provisioning machine field "ephemeralKeyPair.privateKey" must be 32 bytes, got 31');
  });

  test('rejects a wrong-length randomProvisioner', () => {
    expect(() =>
      beginProvisioning({
        attentionDuration: 0,
        ephemeralKeyPair,
        randomProvisioner: randomProvisioner.subarray(0, 15),
        provisioningData,
      }),
    ).toThrow('provisioning machine field "randomProvisioner" must be 16 bytes, got 15');
  });

  test('rejects a wrong-length NetKey', () => {
    expect(() =>
      beginProvisioning({
        attentionDuration: 0,
        ephemeralKeyPair,
        randomProvisioner,
        provisioningData: { ...provisioningData, netKey: provisioningData.netKey.subarray(0, 15) },
      }),
    ).toThrow('provisioning machine field "provisioningData.netKey" must be 16 bytes, got 15');
  });

  test('rejects a NetKey Index outside the 12-bit domain (Section 4.3.1.1)', () => {
    expect(() =>
      beginProvisioning({
        attentionDuration: 0,
        ephemeralKeyPair,
        randomProvisioner,
        provisioningData: { ...provisioningData, netKeyIndex: 0x1000 },
      }),
    ).toThrow('provisioning machine field "provisioningData.netKeyIndex" must be an integer in [0, 4095], got 4096');
  });

  test('rejects an attentionDuration outside one octet', () => {
    expect(() =>
      beginProvisioning({
        attentionDuration: 256,
        ephemeralKeyPair,
        randomProvisioner,
        provisioningData,
      }),
    ).toThrow('provisioning machine field "attentionDuration" must be an integer in [0, 255], got 256');
  });

  // Table 3.5: 0x0000 is Unassigned, not unicast; 0x8000-0xffff is
  // Virtual/Group. Both ends of the narrowed range are exercised.
  test('rejects a unicast address of 0x0000 (Unassigned Address)', () => {
    expect(() =>
      beginProvisioning({
        attentionDuration: 0,
        ephemeralKeyPair,
        randomProvisioner,
        provisioningData: { ...provisioningData, unicastAddress: 0x0000 },
      }),
    ).toThrow(
      'provisioning machine field "provisioningData.unicastAddress" must be a unicast address, an integer in [1, 32767] (Table 3.5 - 0x0000 is Unassigned, 0x8000-0xffff is Virtual/Group), got 0',
    );
  });

  test('rejects a unicast address of 0x8000 (the first Virtual Address)', () => {
    expect(() =>
      beginProvisioning({
        attentionDuration: 0,
        ephemeralKeyPair,
        randomProvisioner,
        provisioningData: { ...provisioningData, unicastAddress: 0x8000 },
      }),
    ).toThrow('provisioning machine field "provisioningData.unicastAddress" must be a unicast address, an integer in [1, 32767]');
  });

  test('accepts the boundary unicast addresses 0x0001 and 0x7fff', () => {
    expect(() =>
      beginProvisioning({
        attentionDuration: 0,
        ephemeralKeyPair,
        randomProvisioner,
        provisioningData: { ...provisioningData, unicastAddress: 0x0001 },
      }),
    ).not.toThrow();
    expect(() =>
      beginProvisioning({
        attentionDuration: 0,
        ephemeralKeyPair,
        randomProvisioner,
        provisioningData: { ...provisioningData, unicastAddress: 0x7fff },
      }),
    ).not.toThrow();
  });
});

// ===========================================================================
// Hardcoded-looking fields the published sample happens to leave at zero
// (Attention Duration, Flags) - a review found both could be hardcoded to
// 0x00 inside the implementation and every existing test would still
// pass, since the sample never exercises a non-zero value for either.
// ===========================================================================

describe('fields the published sample happens to leave at zero', () => {
  test('a non-zero attentionDuration reaches the Invite PDU exactly', () => {
    const result = beginProvisioning({
      attentionDuration: 0x05,
      ephemeralKeyPair,
      randomProvisioner,
      provisioningData,
    });
    // Table 5.17: Type octet (0x00 Invite) || Parameters (Attention
    // Duration, 1 octet) - independent of any other fixture, built by
    // hand from Table 5.18's own one-field layout.
    expect(result.send).toEqual([Buffer.from([0x00, 0x05])]);
  });

  test('a non-zero Flags byte reaches the encrypted Provisioning Data (Table 5.48: bit 0 Key Refresh Phase 2, bit 1 IV Update in progress)', () => {
    const nonZeroFlags = 0x03;
    let result = beginProvisioning({
      attentionDuration: PDU_TYPE_SAMPLE_INVITE.fields.attentionDuration,
      ephemeralKeyPair,
      randomProvisioner,
      provisioningData: { ...provisioningData, flags: nonZeroFlags },
    });
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
    expect(result.state.phase).toBe('awaitingComplete');

    // provisioningData never participates in deriving SessionKey/
    // SessionNonce (Section 5.4.2.5's own formulas take only ECDHSecret
    // and ProvisioningSalt), so they are unchanged from the published
    // sample regardless of `flags` - decrypting with those SAME published
    // values recovers the plaintext this step actually encrypted.
    const dataBytes = result.send[0] as Buffer;
    const decodedData = decodeProvisioningPdu(dataBytes);
    expect(decodedData?.type).toBe('data');
    const { encryptedProvisioningData, mic } = decodedData as ProvisioningData;
    const plaintext = ccmDecrypt(hex(PROVISIONING_SAMPLE.sessionKey), hex(PROVISIONING_SAMPLE.sessionNonce), encryptedProvisioningData, mic);
    expect(plaintext).toEqual(
      Buffer.concat([
        provisioningData.netKey,
        fullPlaintext.subarray(16, 18), // Key Index, unchanged.
        Buffer.from([nonZeroFlags]),
        fullPlaintext.subarray(19, 23), // IV Index, unchanged.
        fullPlaintext.subarray(23, 25), // Unicast Address, unchanged.
      ]),
    );
  });
});
