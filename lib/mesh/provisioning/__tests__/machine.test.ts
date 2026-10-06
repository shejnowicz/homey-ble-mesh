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
// THE FULL ORDERING SWEEP: every PDU type, at every phase.
//
// The per-phase cases above pin each phase against ONE specific wrong type,
// which a review measured to be weaker than it looks: a bypass that accepts
// one SPECIFIC other type survived at two phases, because no case at those
// phases ever fed that particular type. (The realistic defect - a handler
// losing its type check entirely - is caught everywhere by the cases above,
// which is why that finding was Minor.) Driving every type this project's
// `pdu.ts` decodes at every phase closes it exhaustively.
//
// The Provisioning Failed PDU is deliberately NOT in this sweep: `pdu.ts`'s
// own DIRECTION table makes it legal at every phase (it replaces whatever
// the Provisionee was about to send), so it is never "unexpected" and is
// covered by its own tests under "malformed or foreign bytes" below.
// ===========================================================================

describe('per-phase type checks, swept over every PDU type this module decodes', () => {
  // Each entry is a complete, decodable PDU of that type: the published
  // sample where Section 8.7 publishes one, and - for Input Complete, which
  // this document publishes no sample for (see `vectors.ts`'s own NO
  // FABRICATED SAMPLES note) - its own published empty-Parameters shape.
  const everyType: ReadonlyArray<[string, Buffer]> = [
    ['invite', hex(PDU_TYPE_SAMPLE_INVITE.message)],
    ['capabilities', hex(PDU_TYPE_SAMPLE_CAPABILITIES.message)],
    ['start', hex(PDU_TYPE_SAMPLE_START.message)],
    ['publicKey', hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message)],
    ['inputComplete', encodeProvisioningPdu({ type: 'inputComplete' })],
    ['confirmation', hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message)],
    ['random', hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message)],
    ['data', hex(PDU_TYPE_SAMPLE_DATA.message)],
    ['complete', hex(PDU_TYPE_SAMPLE_COMPLETE.message)],
  ];

  function driveToPhase(target: string) {
    let result = begin();
    if (target === 'awaitingCapabilities') return result;
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    if (target === 'awaitingPublicKeyDevice') return result;
    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    if (target === 'awaitingConfirmationDevice') return result;
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message));
    if (target === 'awaitingRandomDevice') return result;
    result = step(result.state, hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
    return result; // awaitingComplete
  }

  // phase, the label this module's own `unexpectedType` message uses, and
  // the one type that phase legitimately accepts (skipped in its sweep).
  describe.each<[string, string, string]>([
    ['awaitingCapabilities', 'Capabilities', 'capabilities'],
    ['awaitingPublicKeyDevice', 'Public Key', 'publicKey'],
    ['awaitingConfirmationDevice', 'Confirmation', 'confirmation'],
    ['awaitingRandomDevice', 'Random', 'random'],
    ['awaitingComplete', 'Complete', 'complete'],
  ])('at %s (expecting a %s PDU)', (phase, label, acceptedType) => {
    const wrongTypes = everyType.filter(([typeName]) => typeName !== acceptedType);

    test.each(wrongTypes)('a %s PDU is rejected as Unexpected PDU (Table 5.41 0x03)', (typeName, pduBytes) => {
      const atPhase = driveToPhase(phase);
      expect(atPhase.state.phase).toBe(phase);

      const result = step(atPhase.state, pduBytes);
      expect(result.send).toEqual([]);
      expect(result.state).toEqual({
        phase: 'failed',
        errorCode: 0x03,
        errorName: 'Unexpected PDU',
        reason: `expected a ${label} PDU but received a ${typeName} PDU`,
      });
    });

    test('the sweep above really did omit exactly one type - the accepted one', () => {
      expect(everyType).toHaveLength(wrongTypes.length + 1);
      expect(everyType.map(([typeName]) => typeName)).toContain(acceptedType);
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

  // THE ONE CHECK IN THIS MODULE WHOSE WEAKENING HAS A SECURITY
  // CONSEQUENCE, so it gets the one exhaustive sweep in this file.
  //
  // The mutation test above does not prove the comparison checks all 16
  // bytes: it corrupts a byte of RANDOM, not of the stored confirmation, so
  // the recomputed value differs from the stored one starting at byte 0 - a
  // comparison truncated to any prefix, even one byte, would still catch
  // it. A first round closed the prefix direction with a single case
  // corrupting the LAST byte; a second review measured that this still left
  // the suite blind in the other direction, because BOTH negative cases
  // then differed at that last position, so a comparison keeping only the
  // last byte - or only the second half - passed all 542 tests. A forged
  // confirmation getting through means provisioning a node that never
  // proved it knows the shared secret.
  //
  // So: one case per position. Each flips exactly ONE bit of the published,
  // already-verified ConfirmationDevice (never a value taken on trust),
  // feeds that as the device's Confirmation PDU, then completes the
  // exchange with the GENUINE published RandomDevice - so the recomputed
  // ConfirmationDevice equals the published value everywhere EXCEPT that
  // one position. A comparison that ignores position `i` for any reason
  // (prefix, suffix, single byte, either half) fails the case for `i`.
  describe.each(Array.from({ length: 16 }, (_unused, index) => index))(
    'a device confirmation differing from the published value ONLY at byte %i',
    (index) => {
      test('still fails as Confirmation Failed - no single-position comparison survives this sweep', () => {
        const genuineConfirmationDevice = hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.fields.confirmation);
        expect(genuineConfirmationDevice).toHaveLength(16);
        const almostGenuineConfirmationDevice = Buffer.from(genuineConfirmationDevice);
        almostGenuineConfirmationDevice[index] = (almostGenuineConfirmationDevice[index] as number) ^ 0x01;
        // Sanity check on the fixture itself: EXACTLY this one byte differs
        // - otherwise this case would not be testing the position it claims.
        expect(almostGenuineConfirmationDevice.subarray(0, index)).toEqual(genuineConfirmationDevice.subarray(0, index));
        expect(almostGenuineConfirmationDevice.subarray(index + 1)).toEqual(genuineConfirmationDevice.subarray(index + 1));
        expect(almostGenuineConfirmationDevice[index]).not.toBe(genuineConfirmationDevice[index]);

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
        // reproduces the GENUINE value, which disagrees with the altered one
        // stored above at exactly one position, this case's own.
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
    },
  );

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

// ===========================================================================
// EVERY Provisioning Data field is the CALLER's, not the sample's.
//
// A review measured that replacing the NetKey, its index, the IV index or
// the unicast address with the published sample's literal values inside
// `machine.ts` each passed all 542 tests. The test above varies only two
// fields (Attention Duration and Flags), and the way it builds its expected
// plaintext - by splicing the published plaintext around the one byte it
// changed - would match whatever the implementation hardcoded for the rest.
//
// These are exactly the fields the next plan's address allocator will
// supply. Mis-wiring one would provision every bulb into the SAMPLE's
// network at the SAMPLE's address, and would present on hardware as "the
// bulb provisions and then never answers," with nothing locally able to say
// why. So this case drives the exchange with ALL of them set to values
// unlike the sample's and asserts the decrypted block byte by byte,
// assembled BY HAND from those values per Table 5.47's own field order and
// sizes - never read back from this module's own encoder.
//
// The five caller values are SYNTHETIC. They are not published anywhere in
// the specification and carry no citation of their own; they exist only to
// be recognisably unlike the sample's in every field (asserted below before
// anything else), exactly as this file's non-zero Flags case and
// `config/__tests__/composition.test.ts`'s synthetic Features values do.
// ===========================================================================

describe('the Provisioning Data block carries the caller-supplied network membership, never the published sample', () => {
  const callerNetKey = Buffer.from([
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
  ]);
  const callerNetKeyIndex = 0x0abc; // 12-bit domain (Section 4.3.1.1), unlike the sample's 0x0567.
  const callerFlags = 0x02; // Table 5.48 bit 1 (IV Update), unlike the sample's 0x00.
  const callerIvIndex = 0x89abcdef; // 32 bits, unlike the sample's 0x01020304.
  const callerUnicastAddress = 0x7a5c; // Table 3.5 unicast range, unlike the sample's 0x0b0c.

  // Table 5.47 "Provisioning data format": Network Key (16) || Key Index (2)
  // || Flags (1) || IV Index (4) || Unicast Address (2), 25 octets, every
  // multi-octet field big-endian (Section 3.1.1's Provisioning rule - see
  // machine.ts's PROVISIONING DATA FIELD ENCODING note). Written out as
  // literal octets, hand-derived from the five values above: 0x0abc -> 0a bc;
  // 0x89abcdef -> 89 ab cd ef; 0x7a5c -> 7a 5c.
  const expectedPlaintext = Buffer.from([
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, // Network Key
    0x0a, 0xbc, // Key Index
    0x02, // Flags
    0x89, 0xab, 0xcd, 0xef, // IV Index
    0x7a, 0x5c, // Unicast Address
  ]);

  test('the fixture is actually unlike the published sample in every field (so this case can catch a hardcoded one)', () => {
    expect(expectedPlaintext).toHaveLength(25);
    expect(fullPlaintext).toHaveLength(25);
    expect(callerNetKey).not.toEqual(provisioningData.netKey);
    expect(callerNetKeyIndex).not.toBe(provisioningData.netKeyIndex);
    expect(callerFlags).not.toBe(provisioningData.flags);
    expect(callerIvIndex).not.toBe(provisioningData.ivIndex);
    expect(callerUnicastAddress).not.toBe(provisioningData.unicastAddress);
    // Stronger than field-by-field: not one octet of the hand-assembled
    // block coincides with the published one at the same position, so a
    // hardcoded sample value anywhere in the assembly shows up here.
    for (let i = 0; i < expectedPlaintext.length; i++) {
      expect(expectedPlaintext[i]).not.toBe(fullPlaintext[i]);
    }
  });

  test('all five fields reach the encrypted block exactly as supplied', () => {
    let result = beginProvisioning({
      attentionDuration: PDU_TYPE_SAMPLE_INVITE.fields.attentionDuration,
      ephemeralKeyPair,
      randomProvisioner,
      provisioningData: {
        netKey: callerNetKey,
        netKeyIndex: callerNetKeyIndex,
        flags: callerFlags,
        ivIndex: callerIvIndex,
        unicastAddress: callerUnicastAddress,
      },
    });
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
    expect(result.state.phase).toBe('awaitingComplete');

    // SessionKey/SessionNonce come from ECDHSecret and ProvisioningSalt only
    // (Section 5.4.2.5), and none of the five fields above feeds either, so
    // the published sample's own SessionKey/SessionNonce still decrypt this
    // block - which is what lets the plaintext be checked against hand-built
    // bytes rather than against this module's own ciphertext.
    const decodedData = decodeProvisioningPdu(result.send[0] as Buffer);
    expect(decodedData?.type).toBe('data');
    const { encryptedProvisioningData, mic } = decodedData as ProvisioningData;
    const plaintext = ccmDecrypt(
      hex(PROVISIONING_SAMPLE.sessionKey),
      hex(PROVISIONING_SAMPLE.sessionNonce),
      encryptedProvisioningData,
      mic,
    );
    expect(plaintext).toEqual(expectedPlaintext);
  });
});

// ===========================================================================
// BUFFER OWNERSHIP (machine.ts's INPUT OWNERSHIP note).
//
// Two halves, both measured by a review before being written here.
//
// (a) The defensive copies this module already made - the Invite, the
//     incoming Capabilities PDU, the Start PDU and the Provisioner's own
//     Public Key PDU - had NO test at all: reverting any of them to a bare
//     `.subarray` passed all 542 tests. The two sibling modules that do have
//     aliasing tests (`packet/access.ts`, `packet/lowerTransport.ts`) are the
//     pattern followed here.
//
// (b) The module also RETAINED live references to three caller-owned inputs
//     (the ephemeral key pair, RandomProvisioner, and the NetKey inside
//     `provisioningData`). That was a real defect, not only an untested
//     discipline: zeroing the caller's random after `beginProvisioning`
//     changed the ConfirmationProvisioner this module went on to send and
//     the device key it derived, and zeroing the public key broke the
//     exchange outright - the exact hazard the module's own header invokes
//     two lines above the key pair, where it quotes the specification
//     telling a Provisioner to delete its key pair after use. Fixed by
//     copying in `beginProvisioning`; pinned below.
//
// Every case here uses FRESH copies of the shared fixtures, because the
// point of each is to scribble over a caller's buffer afterwards.
// ===========================================================================

describe('the machine never keeps a live view into a buffer its caller owns', () => {
  function freshInput() {
    return {
      attentionDuration: PDU_TYPE_SAMPLE_INVITE.fields.attentionDuration,
      ephemeralKeyPair: {
        publicKey: Buffer.from(ephemeralKeyPair.publicKey),
        privateKey: Buffer.from(ephemeralKeyPair.privateKey),
      },
      randomProvisioner: Buffer.from(randomProvisioner),
      provisioningData: {
        netKey: Buffer.from(provisioningData.netKey),
        netKeyIndex: provisioningData.netKeyIndex,
        flags: provisioningData.flags,
        ivIndex: provisioningData.ivIndex,
        unicastAddress: provisioningData.unicastAddress,
      },
    };
  }

  /**
   * Runs the rest of the published exchange from `begun` and asserts that
   * every remaining PDU, and the final device key, are still the published
   * ones - i.e. that whatever was scribbled over in between reached nothing.
   */
  function expectTheRestOfTheExchangeIsStillPublished(begun: { state: ProvisioningState; send: readonly Buffer[] }) {
    let result = step(begun.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_START.message), hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_PROVISIONER.message)]);

    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.message)]);

    result = step(result.state, hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message));
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.message)]);

    result = step(result.state, hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_DATA.message)]);

    result = step(result.state, hex(PDU_TYPE_SAMPLE_COMPLETE.message));
    expect(result.state).toEqual({ phase: 'provisioned', deviceKey: hex(PROVISIONING_CRYPTO_SAMPLE.deviceKey) });
  }

  // --- (b) inputs handed to beginProvisioning ------------------------------

  test("zeroing the caller's RandomProvisioner after beginProvisioning changes nothing it later sends", () => {
    const input = freshInput();
    const begun = beginProvisioning(input);
    input.randomProvisioner.fill(0x00);
    expectTheRestOfTheExchangeIsStillPublished(begun);
  });

  test("zeroing the caller's ephemeral key pair after beginProvisioning changes nothing it later sends", () => {
    // Section 5.4.2.3 tells a Provisioner to delete its private-public key
    // pair once the ECDHSecret is computed; a caller may reasonably read
    // that as "zero the buffers I handed in". It must not break the
    // exchange that is still running.
    const input = freshInput();
    const begun = beginProvisioning(input);
    input.ephemeralKeyPair.publicKey.fill(0x00);
    input.ephemeralKeyPair.privateKey.fill(0x00);
    expectTheRestOfTheExchangeIsStillPublished(begun);
  });

  test("zeroing the caller's NetKey after beginProvisioning leaves the Provisioning Data block unchanged", () => {
    const input = freshInput();
    const begun = beginProvisioning(input);
    input.provisioningData.netKey.fill(0x00);
    expectTheRestOfTheExchangeIsStillPublished(begun);
  });

  test("rewriting the caller's provisioningData numbers after beginProvisioning leaves the Provisioning Data block unchanged", () => {
    const input = freshInput();
    const begun = beginProvisioning(input);
    input.provisioningData.netKeyIndex = 0x0fff;
    input.provisioningData.flags = 0xff;
    input.provisioningData.ivIndex = 0xffffffff;
    input.provisioningData.unicastAddress = 0x7fff;
    expectTheRestOfTheExchangeIsStillPublished(begun);
  });

  // --- (a) buffers this module hands back, and the one it is handed --------

  test('overwriting the Invite PDU this module handed back does not change the Confirmation it later computes', () => {
    // A transport adapter is free to reuse or zero a send buffer once it
    // believes the bytes are on the wire; `inviteValue` feeds every
    // ConfirmationSalt computed afterwards (Section 5.4.2.4.1).
    const begun = beginProvisioning(freshInput());
    (begun.send[0] as Buffer).fill(0xff);
    expectTheRestOfTheExchangeIsStillPublished(begun);
  });

  test('overwriting the incoming Capabilities PDU after the step returns does not change the Confirmation', () => {
    // The caller's receive buffer, which a real GATT adapter reuses for the
    // next notification - and `capabilitiesValue` is read much later.
    const begun = beginProvisioning(freshInput());
    const capabilitiesBuffer = hex(PDU_TYPE_SAMPLE_CAPABILITIES.message);
    let result = step(begun.state, capabilitiesBuffer);
    capabilitiesBuffer.fill(0xff);

    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.message)]);
  });

  test('overwriting the Start and Public Key PDUs this module handed back does not change the Confirmation', () => {
    // Both are in the same step's `send` array, and both feed
    // ConfirmationInputs: `startValue` directly, the Provisioner public key
    // through `ephemeralKeyPair.publicKey`. The `startValue` half of this is
    // load-bearing (reverting that copy to a view fails this test). The
    // public-key half is not, and measurement says so: `encodeProvisioningPdu`
    // builds its output with `Buffer.concat`, which copies, so the sent PDU
    // can never alias the stored key whatever `onCapabilities` does - see
    // machine.ts's own BELT AND BRACES note at that site. It is asserted here
    // anyway because a future encoder that stopped copying would make it
    // load-bearing overnight, and this is the test that would notice.
    const begun = beginProvisioning(freshInput());
    let result = step(begun.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    expect(result.send).toHaveLength(2);
    (result.send[0] as Buffer).fill(0xff); // Start
    (result.send[1] as Buffer).fill(0xff); // Public Key (Provisioner)

    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.message)]);
  });

  test('overwriting the Confirmation PDU this module handed back does not change the Random it sends next', () => {
    // `ownConfirmation` is kept for Section 5.4.2.4.2's "values are equal"
    // sanity check, and the same bytes went out in `send`.
    const begun = beginProvisioning(freshInput());
    let result = step(begun.state, hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    result = step(result.state, hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    const sentConfirmation = result.send[0] as Buffer;
    const sentConfirmationCopy = Buffer.from(sentConfirmation);
    sentConfirmation.fill(0xff);

    // The device's own Confirmation, which must still be compared against
    // the unchanged ConfirmationProvisioner rather than against 0xff...
    result = step(result.state, hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message));
    expect(result.send).toEqual([hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.message)]);
    expect(sentConfirmationCopy).toEqual(hex(PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.message));
  });
});
