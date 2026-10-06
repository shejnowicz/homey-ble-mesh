import { encodeProvisioningPdu, decodeProvisioningPdu, ProvisioningPdu } from '../pdu';
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
} from './vectors';

// ===========================================================================
// Known-answer tests: each Type's decode is checked against the published
// `message` bytes, and each Type's encode is checked to reproduce those same
// published bytes - two separate assertions, never one inferred from the
// other (a round trip alone would pass even if encode/decode shared a
// matching mistake).
// ===========================================================================

describe('Provisioning Invite (Section 5.4.1.1, Table 5.18; Section 8.7.3)', () => {
  test('decodeProvisioningPdu recovers the published sample', () => {
    const decoded = decodeProvisioningPdu(hex(PDU_TYPE_SAMPLE_INVITE.message));
    expect(decoded).toEqual({
      type: 'invite',
      attentionDuration: PDU_TYPE_SAMPLE_INVITE.fields.attentionDuration,
    });
  });

  test('encodeProvisioningPdu reproduces the published sample exactly', () => {
    const pdu: ProvisioningPdu = {
      type: 'invite',
      attentionDuration: PDU_TYPE_SAMPLE_INVITE.fields.attentionDuration,
    };
    expect(encodeProvisioningPdu(pdu)).toEqual(hex(PDU_TYPE_SAMPLE_INVITE.message));
  });
});

describe('Provisioning Capabilities (Section 5.4.1.2, Table 5.19; Section 8.7.4)', () => {
  test('decodeProvisioningPdu recovers the published sample', () => {
    const decoded = decodeProvisioningPdu(hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
    expect(decoded).toEqual({
      type: 'capabilities',
      ...PDU_TYPE_SAMPLE_CAPABILITIES.fields,
    });
  });

  test('encodeProvisioningPdu reproduces the published sample exactly', () => {
    const pdu: ProvisioningPdu = {
      type: 'capabilities',
      ...PDU_TYPE_SAMPLE_CAPABILITIES.fields,
    };
    expect(encodeProvisioningPdu(pdu)).toEqual(hex(PDU_TYPE_SAMPLE_CAPABILITIES.message));
  });

  // The two fields this sample happens to leave at 0 - confirms the 16-bit
  // fields are read/written big-endian (Section 3.1.1), not merely zero
  // either way. A fresh value with distinct octets, round-tripped through
  // both functions against each other's output alone would not prove byte
  // order - this is still a structural (not known-answer) check, kept
  // separate from the KAT tests above.
  test('16-bit Capabilities fields round-trip big-endian for non-zero, asymmetric values', () => {
    const pdu: ProvisioningPdu = {
      type: 'capabilities',
      numberOfElements: 0x03,
      algorithms: 0x1234,
      publicKeyType: 0x01,
      oobType: 0x01,
      outputOobSize: 0x08,
      outputOobAction: 0x5678,
      inputOobSize: 0x08,
      inputOobAction: 0x9abc,
    };
    const encoded = encodeProvisioningPdu(pdu);
    // Table 5.19's byte layout: Type, NumberOfElements, Algorithms(BE),
    // PublicKeyType, OOBType, OutputOOBSize, OutputOOBAction(BE),
    // InputOOBSize, InputOOBAction(BE).
    expect(encoded).toEqual(hex('01' + '03' + '1234' + '01' + '01' + '08' + '5678' + '08' + '9abc'));
    expect(decodeProvisioningPdu(encoded)).toEqual(pdu);
  });
});

describe('Provisioning Start (Section 5.4.1.3, Table 5.28; Section 8.7.5)', () => {
  test('decodeProvisioningPdu recovers the published sample', () => {
    const decoded = decodeProvisioningPdu(hex(PDU_TYPE_SAMPLE_START.message));
    expect(decoded).toEqual({
      type: 'start',
      ...PDU_TYPE_SAMPLE_START.fields,
    });
  });

  test('encodeProvisioningPdu reproduces the published sample exactly', () => {
    const pdu: ProvisioningPdu = {
      type: 'start',
      ...PDU_TYPE_SAMPLE_START.fields,
    };
    expect(encodeProvisioningPdu(pdu)).toEqual(hex(PDU_TYPE_SAMPLE_START.message));
  });
});

// Section 8.7.6/8.7.7's own table captions misread "Provisioning Start" for
// both Public Key samples (see vectors.ts's ERRATA NOTE) - these tests are
// named, and matched, by the Type octet (0x03) and the Public Key X/Y
// fields actually present in each sample, not by the mis-copied caption.
describe('Provisioning Public Key (Section 5.4.1.4, Table 5.36; Section 8.7.6/8.7.7)', () => {
  test('decodeProvisioningPdu recovers the published Provisioner sample', () => {
    const decoded = decodeProvisioningPdu(hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_PROVISIONER.message));
    expect(decoded).toEqual({
      type: 'publicKey',
      publicKeyX: hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_PROVISIONER.fields.publicKeyX),
      publicKeyY: hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_PROVISIONER.fields.publicKeyY),
    });
  });

  test('encodeProvisioningPdu reproduces the published Provisioner sample exactly', () => {
    const pdu: ProvisioningPdu = {
      type: 'publicKey',
      publicKeyX: hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_PROVISIONER.fields.publicKeyX),
      publicKeyY: hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_PROVISIONER.fields.publicKeyY),
    };
    expect(encodeProvisioningPdu(pdu)).toEqual(hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_PROVISIONER.message));
  });

  test('decodeProvisioningPdu recovers the published Device sample', () => {
    const decoded = decodeProvisioningPdu(hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
    expect(decoded).toEqual({
      type: 'publicKey',
      publicKeyX: hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.fields.publicKeyX),
      publicKeyY: hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.fields.publicKeyY),
    });
  });

  test('encodeProvisioningPdu reproduces the published Device sample exactly', () => {
    const pdu: ProvisioningPdu = {
      type: 'publicKey',
      publicKeyX: hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.fields.publicKeyX),
      publicKeyY: hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.fields.publicKeyY),
    };
    expect(encodeProvisioningPdu(pdu)).toEqual(hex(PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message));
  });
});

describe('Provisioning Confirmation (Section 5.4.1.6, Table 5.37; Section 8.7.8/8.7.9)', () => {
  test('decodeProvisioningPdu recovers the published Provisioner sample (ConfirmationProvisioner)', () => {
    const decoded = decodeProvisioningPdu(hex(PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.message));
    expect(decoded).toEqual({
      type: 'confirmation',
      confirmation: hex(PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.fields.confirmation),
    });
  });

  test('encodeProvisioningPdu reproduces the published Provisioner sample exactly', () => {
    const pdu: ProvisioningPdu = {
      type: 'confirmation',
      confirmation: hex(PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.fields.confirmation),
    };
    expect(encodeProvisioningPdu(pdu)).toEqual(hex(PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.message));
  });

  test('decodeProvisioningPdu recovers the published Device sample (ConfirmationDevice)', () => {
    const decoded = decodeProvisioningPdu(hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message));
    expect(decoded).toEqual({
      type: 'confirmation',
      confirmation: hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.fields.confirmation),
    });
  });

  test('encodeProvisioningPdu reproduces the published Device sample exactly', () => {
    const pdu: ProvisioningPdu = {
      type: 'confirmation',
      confirmation: hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.fields.confirmation),
    };
    expect(encodeProvisioningPdu(pdu)).toEqual(hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message));
  });

  // Both published Confirmation samples happen to be 16 octets (the
  // document's one worked exchange only uses
  // BTM_ECDH_P256_CMAC_AES128_AES_CCM) - nothing above exercises the
  // 32-octet BTM_ECDH_P256_HMAC_SHA256_AES_CCM case (Section 5.4.2.4.1),
  // so this checks that size is accepted too, structurally (not a
  // known-answer test: there is no published 32-octet Confirmation sample
  // in this document to check against).
  test('a 32-octet confirmation value round-trips (Section 5.4.2.4.1: 256-bit under BTM_ECDH_P256_HMAC_SHA256_AES_CCM)', () => {
    const confirmation = Buffer.alloc(32, 0xab);
    const pdu: ProvisioningPdu = { type: 'confirmation', confirmation };
    const encoded = encodeProvisioningPdu(pdu);
    expect(encoded).toEqual(Buffer.concat([Buffer.from([0x05]), confirmation]));
    expect(decodeProvisioningPdu(encoded)).toEqual(pdu);
  });
});

describe('Provisioning Random (Section 5.4.1.7, Table 5.38; Section 8.7.10/8.7.11)', () => {
  test('decodeProvisioningPdu recovers the published Provisioner sample (RandomProvisioner)', () => {
    const decoded = decodeProvisioningPdu(hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.message));
    expect(decoded).toEqual({
      type: 'random',
      random: hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.fields.random),
    });
  });

  test('encodeProvisioningPdu reproduces the published Provisioner sample exactly', () => {
    const pdu: ProvisioningPdu = {
      type: 'random',
      random: hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.fields.random),
    };
    expect(encodeProvisioningPdu(pdu)).toEqual(hex(PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.message));
  });

  test('decodeProvisioningPdu recovers the published Device sample (RandomDevice)', () => {
    const decoded = decodeProvisioningPdu(hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
    expect(decoded).toEqual({
      type: 'random',
      random: hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.fields.random),
    });
  });

  test('encodeProvisioningPdu reproduces the published Device sample exactly', () => {
    const pdu: ProvisioningPdu = {
      type: 'random',
      random: hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.fields.random),
    };
    expect(encodeProvisioningPdu(pdu)).toEqual(hex(PDU_TYPE_SAMPLE_RANDOM_DEVICE.message));
  });
});

describe('Provisioning Data (Section 5.4.1.8, Table 5.39; Section 8.7.12)', () => {
  test('decodeProvisioningPdu recovers the published sample', () => {
    const decoded = decodeProvisioningPdu(hex(PDU_TYPE_SAMPLE_DATA.message));
    expect(decoded).toEqual({
      type: 'data',
      encryptedProvisioningData: hex(PDU_TYPE_SAMPLE_DATA.fields.encryptedProvisioningData),
      mic: hex(PDU_TYPE_SAMPLE_DATA.fields.mic),
    });
  });

  test('encodeProvisioningPdu reproduces the published sample exactly', () => {
    const pdu: ProvisioningPdu = {
      type: 'data',
      encryptedProvisioningData: hex(PDU_TYPE_SAMPLE_DATA.fields.encryptedProvisioningData),
      mic: hex(PDU_TYPE_SAMPLE_DATA.fields.mic),
    };
    expect(encodeProvisioningPdu(pdu)).toEqual(hex(PDU_TYPE_SAMPLE_DATA.message));
  });
});

describe('Provisioning Complete (Section 5.4.1.9; Section 8.7.13)', () => {
  test('decodeProvisioningPdu recovers the published sample (no parameters)', () => {
    const decoded = decodeProvisioningPdu(hex(PDU_TYPE_SAMPLE_COMPLETE.message));
    expect(decoded).toEqual({ type: 'complete' });
  });

  test('encodeProvisioningPdu reproduces the published sample exactly', () => {
    const pdu: ProvisioningPdu = { type: 'complete' };
    expect(encodeProvisioningPdu(pdu)).toEqual(hex(PDU_TYPE_SAMPLE_COMPLETE.message));
  });
});

// ===========================================================================
// Types with no published wire sample in this document (see vectors.ts's
// "NO FABRICATED SAMPLES" note): Input Complete's and Failed's ENCODING is
// checked directly against each Type's own prose/layout (zero Parameters;
// one Error Code octet) rather than against a specification-published byte
// string - not a substitute for a known-answer test, and not presented as
// one.
// ===========================================================================

describe('Provisioning Input Complete (Section 5.4.1.5: "There are no parameters")', () => {
  test('encodes as the bare Type octet with zero Parameters', () => {
    const pdu: ProvisioningPdu = { type: 'inputComplete' };
    expect(encodeProvisioningPdu(pdu)).toEqual(hex('04'));
  });

  test('decodes the bare Type octet back to inputComplete', () => {
    expect(decodeProvisioningPdu(hex('04'))).toEqual({ type: 'inputComplete' });
  });

  test('a stray Parameters octet on Type 0x04 does not decode (Section 5.4.1.5 has none)', () => {
    expect(decodeProvisioningPdu(hex('0400'))).toBeNull();
  });
});

describe('Provisioning Failed (Section 5.4.1.10, Table 5.40)', () => {
  test('round-trips its one-octet Error Code field (no published sample exists to check against)', () => {
    const pdu: ProvisioningPdu = { type: 'failed', errorCode: 0x03 }; // Table 5.41: 0x03 "Unexpected PDU".
    const encoded = encodeProvisioningPdu(pdu);
    expect(encoded).toEqual(hex('0903'));
    expect(decodeProvisioningPdu(encoded)).toEqual(pdu);
  });
});

// ===========================================================================
// Structural / defensive behaviour: not drawn from a published sample,
// exercising this module's own error handling and the "ignore what you do
// not understand" decode stance (Section 3.7.3.4, applied here the same way
// `access.ts`/`lowerTransport.ts` already apply it to their own layers).
// ===========================================================================

describe('decodeProvisioningPdu: foreign/unrecognised traffic', () => {
  test('returns null for an empty buffer', () => {
    expect(decodeProvisioningPdu(Buffer.alloc(0))).toBeNull();
  });

  test('returns null, not throws, for an unassigned Type value in range', () => {
    // 0x3f is the top of the 6-bit Type field and unassigned by the
    // Bluetooth SIG Assigned Numbers document (see pdu.ts's module header) -
    // ordinary future/foreign traffic, not malformed.
    expect(decodeProvisioningPdu(hex('3f00'))).toBeNull();
  });

  test('returns null, not throws, for an out-of-scope provisioning-record Type (0x0A-0x0D)', () => {
    // 0x0C = Provisioning Records Get (Section 5.4.1.13) - a real, assigned
    // Type this module deliberately does not implement (see pdu.ts's SCOPE
    // note), not a malformed or unassigned one; still returns null, not an
    // error, by the same "not implemented here" reasoning.
    expect(decodeProvisioningPdu(hex('0c'))).toBeNull();
  });

  test('returns null when the Padding bits (Table 5.17) are not 0b00', () => {
    // 0x40 sets bit 6 of the Padding field over an otherwise-valid Invite
    // (Type 0x00) PDU.
    expect(decodeProvisioningPdu(hex('4000'))).toBeNull();
  });

  test('returns null for a Parameters field the wrong length for its Type', () => {
    // Type 0x00 (Invite) demands exactly 1 octet of Parameters (Table 5.18).
    expect(decodeProvisioningPdu(hex('00'))).toBeNull(); // 0 octets
    expect(decodeProvisioningPdu(hex('000000'))).toBeNull(); // 2 octets
  });

  test('returns null for a Confirmation/Random Parameters length that is neither 16 nor 32 octets', () => {
    expect(decodeProvisioningPdu(hex('05' + 'ab'.repeat(15)))).toBeNull();
    expect(decodeProvisioningPdu(hex('06' + 'ab'.repeat(20)))).toBeNull();
  });
});

describe('encodeProvisioningPdu: caller-mistake field validation', () => {
  // A bare `toThrow()` can not fail here on its own merits - these assert
  // the actual message `assertRange`/this module's own Buffer-length guard
  // produce, not merely that SOMETHING throws.
  test('throws with the field name and bound for an out-of-range numeric field', () => {
    expect(() => encodeProvisioningPdu({ type: 'invite', attentionDuration: 256 })).toThrow(
      /provisioning field "attentionDuration" must be an integer in \[0, 255\], got 256/,
    );
    expect(() => encodeProvisioningPdu({ type: 'invite', attentionDuration: -1 })).toThrow(
      /provisioning field "attentionDuration"/,
    );
    expect(() =>
      encodeProvisioningPdu({
        type: 'capabilities',
        numberOfElements: 1,
        algorithms: 0x10000,
        publicKeyType: 0,
        oobType: 0,
        outputOobSize: 0,
        outputOobAction: 0,
        inputOobSize: 0,
        inputOobAction: 0,
      }),
    ).toThrow(/provisioning field "algorithms" must be an integer in \[0, 65535\], got 65536/);
  });

  test('throws with the field name and expected length for a wrong-length Buffer field', () => {
    expect(() =>
      encodeProvisioningPdu({ type: 'publicKey', publicKeyX: Buffer.alloc(31), publicKeyY: Buffer.alloc(32) }),
    ).toThrow(/provisioning field "publicKeyX" must be 32 bytes, got 31/);
    expect(() => encodeProvisioningPdu({ type: 'confirmation', confirmation: Buffer.alloc(20) })).toThrow(
      /provisioning field "confirmation" must be 16 or 32 bytes, got 20/,
    );
    expect(() =>
      encodeProvisioningPdu({ type: 'data', encryptedProvisioningData: Buffer.alloc(25), mic: Buffer.alloc(4) }),
    ).toThrow(/provisioning field "mic" must be 8 bytes, got 4/);
  });
});
