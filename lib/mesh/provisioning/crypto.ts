import { aesCmac, s1 } from '../crypto/cmac';
import { k1 } from '../crypto/derive';

/**
 * Provisioning's security functions (Mesh Protocol v1.1, Section 5.4.2.4
 * "Authentication" and Section 5.4.2.5 "Distribution of provisioning data"),
 * restricted to the BTM_ECDH_P256_CMAC_AES128_AES_CCM algorithm - the only one this project's
 * `crypto/derive.ts` implements (there is no `k5`/`s2`, the key-derivation
 * functions the other algorithm, BTM_ECDH_P256_HMAC_SHA256_AES_CCM, needs;
 * this module's own `RANDOM_LENGTH`/`AUTH_VALUE_LENGTH` constants below are
 * this algorithm's 128-bit sizes, not that algorithm's 256-bit ones).
 *
 * Every derivation here is built from `s1`/`k1`/`aesCmac` (`crypto/cmac.ts`,
 * `crypto/derive.ts`) exactly as Section 5.4.2.4.1/5.4.2.5 states them, each
 * exported as its own function and named after the specification's own name
 * for it (ConfirmationSalt, ConfirmationKey, the confirmation value,
 * ProvisioningSalt, SessionKey, SessionNonce, DevKey) - never collapsed into
 * one end-to-end call, because a single function covering the whole chain
 * would hide exactly the "two compensating mistakes" failure mode the
 * published sample's per-step values exist to catch (see `__tests__/crypto.test.ts`).
 *
 * CONCATENATION ORDER (Section 5.4.2.4.1):
 *
 *   ConfirmationInputs = ProvisioningInvitePDUValue ||
 *                         ProvisioningCapabilitiesPDUValue ||
 *                         ProvisioningStartPDUValue ||
 *                         PublicKeyProvisioner || PublicKeyDevice
 *   ConfirmationSalt   = s1(ConfirmationInputs)
 *   ConfirmationKey    = k1(ECDHSecret, ConfirmationSalt, "prck")
 *
 * ...and the confirmation value itself (Section 5.4.2.4.1 - the formula is
 * textually identical for both sides, only the Random operand differs; see
 * the ERRATA note below). NOTATION: the document sets the key name as a
 * SUBSCRIPT on the function name, which plain text cannot carry, so every
 * formula quoted in this file renders that subscript with an underscore
 * (`AES-CMAC_ConfirmationKey`, `HMAC-SHA-256_ConfirmationKey`) - the one
 * deliberate, systematic departure from verbatim transcription here:
 *
 *   ConfirmationProvisioner = AES-CMAC_ConfirmationKey(RandomProvisioner || AuthValue)
 *   ConfirmationDevice      = AES-CMAC_ConfirmationKey(RandomDevice      || AuthValue)
 *
 * ERRATA (Section 5.4.2.4.1, confirmed against the published sample data,
 * Section 8.17.1): the document's own second formula is printed as
 * "ConfirmationProvisioner=AES-CMAC_ConfirmationKey(RandomDevice || AuthValue)"
 * - the SAME left-hand name as the first formula, which cannot be right.
 * Three independent pieces of evidence agree on the fix:
 *   (1) the paragraph's own lead-in prose, immediately above both formulas,
 *       already names two distinct values ("the confirmation value of the
 *       Provisioner is a 128-bit value, the confirmation value of the
 *       Provisionee is a 128-bit value, and they are computed using:") -
 *       so the second formula is textually introduced as the Provisionee's
 *       own, not a restatement of the first;
 *   (2) the parallel block immediately below, for the OTHER algorithm
 *       (BTM_ECDH_P256_HMAC_SHA256_AES_CCM), gets this right:
 *       "ConfirmationProvisioner=HMAC-SHA-256_ConfirmationKey(RandomProvisioner)"
 *       followed correctly by "ConfirmationDevice=HMAC-SHA-256_ConfirmationKey(RandomDevice)"
 *       - making the CMAC block's repeated name the copy-paste casualty,
 *       not a second, deliberate definition;
 *   (3) the sample's own distinct `ConfirmationDeviceInput`/`ConfirmationDevice`
 *       rows (Section 8.17.1) confirm this second formula, built from
 *       RandomDevice, is the one producing ConfirmationDevice.
 * Matched on the formula's own Random operand and these three independent
 * confirmations, not on the mis-copied left-hand name - the same
 * match-on-position-and-meaning rule `provisioning/__tests__/vectors.ts`
 * already documents for this same section's table-caption errata (quoted
 * from the plan there; this cross-reference deliberately names the rule
 * rather than re-quoting it). `confirmationValue`
 * below is the one function both sides share, taking whichever Random value
 * the caller already knows is its own.
 *
 * Section 5.4.2.5 "Distribution of provisioning data" (ProvisioningSalt/SessionKey/SessionNonce):
 *
 *   ProvisioningSalt = s1(ConfirmationSalt || RandomProvisioner || RandomDevice)
 *   SessionKey       = k1(ECDHSecret, ProvisioningSalt, "prsk")
 *   SessionNonce     = the 13 LEAST SIGNIFICANT octets of
 *                      k1(ECDHSecret, ProvisioningSalt, "prsn")
 *
 * "Least significant" means the rightmost (last) bytes of the 16-octet k1
 * output, not the leftmost - settled by the specification's own wording
 * ("The nonce shall be the 13 least significant octets of" a value, and a
 * least-significant octet is by definition a low-order one, which in a
 * big-endian encoding sits at the END of the byte string) together with the
 * published sample, which pins the direction concretely: `SessionNonceFull`
 * is `c5e02e` || `da7ddbe78b5f62b81d6847487e`, and the published
 * `SessionNonce` is that second, 13-octet piece (the LAST 13 bytes), not the
 * first (Section 8.17.1; both values are reproduced in
 * `__tests__/vectors.ts`'s `PROVISIONING_CRYPTO_SAMPLE.sessionNonceFull` and
 * the already-existing `crypto/__tests__/vectors.ts`'s
 * `PROVISIONING_SAMPLE.sessionNonce`, and the direction is pinned by its own
 * dedicated test in `__tests__/crypto.test.ts`, not only by the KAT).
 *
 * Section 3.9.6.1 "Device key" (Figure 3.52):
 *
 *   DevKey = k1(ECDHSecret, ProvisioningSalt, "prdk")
 *
 * VALIDATION: every Buffer parameter below is a MESSAGE operand to
 * `s1`/`aesCmac`, never the CMAC key - `createCipheriv('aes-128-ecb', ...)`
 * only enforces a key's length (16 bytes), never a message's, so a
 * wrong-length message operand would not throw on its own; it would instead
 * silently fold into the hash and produce a different, still "plausible",
 * wrong answer - the exact failure category this project's `assertBufferLength`-style
 * guards (`pdu.ts`, `ecdh.ts`) exist to turn into a thrown error instead.
 * `ecdhSecret` is likewise validated here even though `k1`'s own `n` operand
 * accepts any length: Section 5.4.2.3 "Exchanging public keys" defines
 * ECDHSecret as `P256(private key, peer public key)` but states no octet
 * count of its own there. 32 octets instead follows from the curve itself
 * (P-256's shared secret is its x-coordinate, a 256-bit/32-octet field
 * element - exactly what `ecdh.ts#sharedSecret` returns) and is confirmed by
 * the Section 8.17.1 sample's own 32-octet published ECDHSecret value, so a
 * wrong-length one reaching this module is a caller bug, not a protocol
 * variation to tolerate.
 */

const PRCK = Buffer.from('prck', 'ascii'); // Section 5.4.2.4.1: ConfirmationKey's k1 "P".
const PRSK = Buffer.from('prsk', 'ascii'); // Section 5.4.2.5: SessionKey's k1 "P".
const PRSN = Buffer.from('prsn', 'ascii'); // Section 5.4.2.5: SessionNonce's k1 "P".
const PRDK = Buffer.from('prdk', 'ascii'); // Section 3.9.6.1: DevKey's k1 "P".

/** Section 5.4.2.5: "The nonce shall be the 13 least significant octets of" SessionNonce's 16-octet k1 output. */
const SESSION_NONCE_LENGTH = 13;

/** Table 5.18: Provisioning Invite PDU Parameters (excluding the Type octet) - Attention Duration, 1 octet. */
const INVITE_VALUE_LENGTH = 1;
/** Table 5.19: Provisioning Capabilities PDU Parameters (excluding the Type octet) - 11 octets. */
const CAPABILITIES_VALUE_LENGTH = 11;
/** Table 5.28: Provisioning Start PDU Parameters (excluding the Type octet) - 5 octets. */
const START_VALUE_LENGTH = 5;
/** Table 5.36: Public Key X (32) || Public Key Y (32) - the same raw, prefix-less P-256 point `ecdh.ts` uses. */
const PUBLIC_KEY_LENGTH = 64;
/** Section 5.4.2.4.1: RandomProvisioner/RandomDevice under BTM_ECDH_P256_CMAC_AES128_AES_CCM - 128-bit. */
const RANDOM_LENGTH = 16;
/** Section 5.4.2.4.1: AuthValue under BTM_ECDH_P256_CMAC_AES128_AES_CCM - 128-bit. */
const AUTH_VALUE_LENGTH = 16;
/** Every `s1`/`aesCmac` output this module passes onward - 128 bits, the AES block size. */
const SALT_OR_KEY_LENGTH = 16;
/** Section 5.4.2.3's ECDHSecret - 32 octets per the P-256 curve's own field size (not a count Section 5.4.2.3 itself states), matching `ecdh.ts#sharedSecret`'s return and the Section 8.17.1 sample. */
const ECDH_SECRET_LENGTH = 32;

function assertLength(field: string, value: Buffer, expected: number): void {
  if (value.length !== expected) {
    throw new Error(`provisioning crypto "${field}" must be ${expected} bytes, got ${value.length}`);
  }
}

/**
 * ConfirmationSalt = s1(ConfirmationInputs), where ConfirmationInputs is the
 * concatenation - in this exact order - of the Invite, Capabilities and
 * Start Provisioning PDUs' own Parameters (opcode excluded) and both sides'
 * raw public keys. Reversing any part of this order changes the hash input
 * and so the result; see the module header's CONCATENATION ORDER note.
 */
export function confirmationSalt(
  provisioningInvitePduValue: Buffer,
  provisioningCapabilitiesPduValue: Buffer,
  provisioningStartPduValue: Buffer,
  publicKeyProvisioner: Buffer,
  publicKeyDevice: Buffer,
): Buffer {
  assertLength('provisioningInvitePduValue', provisioningInvitePduValue, INVITE_VALUE_LENGTH);
  assertLength('provisioningCapabilitiesPduValue', provisioningCapabilitiesPduValue, CAPABILITIES_VALUE_LENGTH);
  assertLength('provisioningStartPduValue', provisioningStartPduValue, START_VALUE_LENGTH);
  assertLength('publicKeyProvisioner', publicKeyProvisioner, PUBLIC_KEY_LENGTH);
  assertLength('publicKeyDevice', publicKeyDevice, PUBLIC_KEY_LENGTH);

  const confirmationInputs = Buffer.concat([
    provisioningInvitePduValue,
    provisioningCapabilitiesPduValue,
    provisioningStartPduValue,
    publicKeyProvisioner,
    publicKeyDevice,
  ]);
  return s1(confirmationInputs);
}

/** ConfirmationKey = k1(ECDHSecret, ConfirmationSalt, "prck"). */
export function confirmationKey(ecdhSecret: Buffer, confirmationSaltValue: Buffer): Buffer {
  assertLength('ecdhSecret', ecdhSecret, ECDH_SECRET_LENGTH);
  assertLength('confirmationSaltValue', confirmationSaltValue, SALT_OR_KEY_LENGTH);
  return k1(ecdhSecret, confirmationSaltValue, PRCK);
}

/**
 * ConfirmationProvisioner/ConfirmationDevice = AES-CMAC_ConfirmationKey(Random
 * || AuthValue) - the one formula both sides share (see the module header's
 * ERRATA note); the caller passes RandomProvisioner for its own
 * ConfirmationProvisioner, RandomDevice for ConfirmationDevice.
 */
export function confirmationValue(confirmationKeyValue: Buffer, random: Buffer, authValue: Buffer): Buffer {
  assertLength('confirmationKeyValue', confirmationKeyValue, SALT_OR_KEY_LENGTH);
  assertLength('random', random, RANDOM_LENGTH);
  assertLength('authValue', authValue, AUTH_VALUE_LENGTH);
  return aesCmac(confirmationKeyValue, Buffer.concat([random, authValue]));
}

/** ProvisioningSalt = s1(ConfirmationSalt || RandomProvisioner || RandomDevice). */
export function provisioningSalt(confirmationSaltValue: Buffer, randomProvisioner: Buffer, randomDevice: Buffer): Buffer {
  assertLength('confirmationSaltValue', confirmationSaltValue, SALT_OR_KEY_LENGTH);
  assertLength('randomProvisioner', randomProvisioner, RANDOM_LENGTH);
  assertLength('randomDevice', randomDevice, RANDOM_LENGTH);
  return s1(Buffer.concat([confirmationSaltValue, randomProvisioner, randomDevice]));
}

/** SessionKey = k1(ECDHSecret, ProvisioningSalt, "prsk"). */
export function sessionKey(ecdhSecret: Buffer, provisioningSaltValue: Buffer): Buffer {
  assertLength('ecdhSecret', ecdhSecret, ECDH_SECRET_LENGTH);
  assertLength('provisioningSaltValue', provisioningSaltValue, SALT_OR_KEY_LENGTH);
  return k1(ecdhSecret, provisioningSaltValue, PRSK);
}

/**
 * SessionNonce = the 13 least significant (i.e. last) octets of
 * k1(ECDHSecret, ProvisioningSalt, "prsn").
 */
export function sessionNonce(ecdhSecret: Buffer, provisioningSaltValue: Buffer): Buffer {
  assertLength('ecdhSecret', ecdhSecret, ECDH_SECRET_LENGTH);
  assertLength('provisioningSaltValue', provisioningSaltValue, SALT_OR_KEY_LENGTH);
  const full = k1(ecdhSecret, provisioningSaltValue, PRSN);
  return full.subarray(full.length - SESSION_NONCE_LENGTH);
}

/** DevKey = k1(ECDHSecret, ProvisioningSalt, "prdk") (Section 3.9.6.1, Figure 3.52). */
export function deviceKey(ecdhSecret: Buffer, provisioningSaltValue: Buffer): Buffer {
  assertLength('ecdhSecret', ecdhSecret, ECDH_SECRET_LENGTH);
  assertLength('provisioningSaltValue', provisioningSaltValue, SALT_OR_KEY_LENGTH);
  return k1(ecdhSecret, provisioningSaltValue, PRDK);
}
