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

  // Every single-octet field this sample happens to leave at 0
  // (numberOfElements aside) - which means a decoder/encoder that swapped
  // ANY two of those fields' positions (publicKeyType<->oobType,
  // outputOobSize<->inputOobSize, or either against numberOfElements) would
  // still reproduce this exact sample, since 0 in field A's slot looks
  // identical to 0 in field B's slot. Caught live by mutation (see the
  // commit message / task report): the first version of this test used
  // publicKeyType=oobType=0x01 and outputOobSize=inputOobSize=0x08 - the
  // SAME value in each pair - so a field-swapping mutation on either pair
  // passed it too. Every one of the five single-octet fields below
  // (numberOfElements, publicKeyType, oobType, outputOobSize, inputOobSize)
  // now has a DIFFERENT value from every other one of the five, and the
  // three 16-bit fields are likewise pairwise distinct and internally
  // asymmetric (high octet != low octet) - so swapping any two field
  // positions, of any width, changes the encoded bytes. The expected hex
  // below is computed BY HAND from Table 5.19's own field order and widths,
  // never by running `encodeProvisioningPdu` and recording its output -
  // doing that would just reproduce whatever swap this test exists to
  // catch.
  test('Capabilities fields all round-trip through their own position (pairwise-distinct octets)', () => {
    const pdu: ProvisioningPdu = {
      type: 'capabilities',
      numberOfElements: 0x03,
      algorithms: 0x1234,
      publicKeyType: 0x01,
      oobType: 0x02,
      outputOobSize: 0x08,
      outputOobAction: 0x5678,
      inputOobSize: 0x07,
      inputOobAction: 0x9abc,
    };
    const encoded = encodeProvisioningPdu(pdu);
    // Table 5.19's byte layout, by hand: Type(01), NumberOfElements(03),
    // Algorithms(1234, BE), PublicKeyType(01), OOBType(02),
    // OutputOOBSize(08), OutputOOBAction(5678, BE), InputOOBSize(07),
    // InputOOBAction(9abc, BE).
    expect(encoded).toEqual(hex('01' + '03' + '1234' + '01' + '02' + '08' + '5678' + '07' + '9abc'));
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

  // The published Start sample (Section 8.7.5) sets ALL FIVE Parameter
  // octets to 0x00 - so the KAT tests above cannot distinguish a correctly
  // laid-out encoder/decoder from one that silently permutes any of
  // algorithm/publicKey/authenticationMethod/authenticationAction/
  // authenticationSize among themselves; every permutation of five zeros is
  // the same five zeros. This test gives the five fields five DIFFERENT
  // values so that no swap of any two field positions can pass unnoticed.
  // Expected hex computed BY HAND from Table 5.28's own field order and
  // widths (all five fields are one octet each), never by running the
  // encoder and recording its output.
  test('Start fields all round-trip through their own position (five distinct octets)', () => {
    const pdu: ProvisioningPdu = {
      type: 'start',
      algorithm: 0x11,
      publicKey: 0x22,
      authenticationMethod: 0x33,
      authenticationAction: 0x44,
      authenticationSize: 0x55,
    };
    const encoded = encodeProvisioningPdu(pdu);
    // Table 5.28's byte layout, by hand: Type(02), Algorithm(11),
    // PublicKey(22), AuthenticationMethod(33), AuthenticationAction(44),
    // AuthenticationSize(55).
    expect(encoded).toEqual(hex('02' + '11' + '22' + '33' + '44' + '55'));
    expect(decodeProvisioningPdu(encoded)).toEqual(pdu);
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

// ===========================================================================
// Buffer aliasing - `decodeProvisioningPdu` must hand back COPIES of the
// recovered bytes, never views onto the caller's own `pdu` (its own module
// header says so; the same reused-receive-buffer reasoning
// `packet/access.ts` and `packet/lowerTransport.ts` already have their own
// aliasing tests for). A review measured that reverting any one of this
// decoder's defensive copies to a bare `.subarray` passed the whole suite,
// because nothing here mutated an input buffer after decoding it. Every
// Type carrying a Buffer field is swept, so no single copy can be reverted
// unnoticed.
// ===========================================================================

describe('decoded Buffer fields do not alias the input PDU', () => {
  test.each<[string, string]>([
    ['publicKey (Public Key X and Y)', PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE.message],
    ['confirmation', PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message],
    ['random', PDU_TYPE_SAMPLE_RANDOM_DEVICE.message],
    ['data (EncProvisioningData and MIC)', PDU_TYPE_SAMPLE_DATA.message],
  ])('%s: overwriting the source PDU after decoding leaves the decoded fields unchanged', (_label, message) => {
    const pdu = hex(message);
    const decoded = decodeProvisioningPdu(pdu);
    expect(decoded).not.toBeNull();
    // Snapshot BEFORE the mutation, so the comparison below is against what
    // was decoded, not against a fixture that could coincidentally match.
    const before = JSON.parse(JSON.stringify(decoded)) as unknown;

    pdu.fill(0xff); // simulate a caller reusing/zeroing its receive buffer.

    expect(JSON.parse(JSON.stringify(decoded)) as unknown).toEqual(before);
    // And the decoded bytes are still the published ones, not 0xff.
    expect(JSON.stringify(decoded)).not.toContain('255,255,255,255');
  });

  test('writing through a decoded Buffer field does not corrupt the caller’s PDU', () => {
    const pdu = hex(PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.message);
    const pduCopy = Buffer.from(pdu);
    const decoded = decodeProvisioningPdu(pdu);
    // Asserted, not optional-chained: `decoded?.x.fill()` would silently
    // skip the write and let this pass vacuously if decode ever returned
    // null (the exact vacuous-pass a review caught in this project's
    // `lowerTransport.test.ts` sibling).
    expect(decoded).not.toBeNull();
    (decoded as { type: 'confirmation'; confirmation: Buffer }).confirmation.fill(0xff);
    expect(pdu).toEqual(pduCopy);
  });
});
