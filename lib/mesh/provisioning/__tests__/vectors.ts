/**
 * Provisioning PDU sample data transcribed from the Bluetooth SIG "Mesh
 * Protocol" specification v1.1 HTML document
 * (https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/MshPRT_v1.1/out/en/index-en.html),
 * fetched on 2026-10-06 (HTTP 200, 9,945,160 bytes - the same document and
 * byte count `packet/__tests__/vectors.ts` and `crypto/__tests__/vectors.ts`
 * record for their own, independent fetches of it). Extracted
 * programmatically: for the field-layout tables (Section 5.4.1, read via
 * `</td>`/`</tr>` converted to separators before tag-stripping, same method
 * the other two fixture files describe), and - because this file's hex
 * values interleave across wrapped table cells in the source HTML (a
 * `Message` row's hex splits across two visual lines) - via a small
 * Python `html.parser.HTMLParser` subclass that walks each `<table>`'s real
 * `<tr>`/`<td>` structure and concatenates each cell's full text content,
 * rather than via the lossier `</td>`/`</tr>`-to-separator method the other
 * two fixture files use (which would have left a sample's hex bytes split
 * across two array entries). Every hex value below was read directly off
 * that structured extraction, not retyped by hand.
 *
 * THIS FILE'S INVENTORY:
 * - `PDU_TYPE_SAMPLE_*` (eleven fixtures): one complete, published
 *   Provisioning PDU - Type octet plus Parameters - for EIGHT of the ten
 *   Types this project's `pdu.ts` implements (every Type this document's
 *   worked exchange actually sends: Invite, Capabilities, Start, Public
 *   Key, Confirmation, Random, Data, Complete), with both directions
 *   recorded separately for Public Key, Confirmation and Random (hence
 *   eleven fixtures for eight Types). The remaining two Types `pdu.ts`
 *   implements - Input Complete and Failed - have NO fixture here, because
 *   this document publishes no worked sample for either (see this file's
 *   own "NO FABRICATED SAMPLES" note below); do not add a fixture for them
 *   that is not itself a published sample. Source: Mesh Protocol
 *   v1.1 Section 8.7 "PB-ADV provisioning sample data", subsections 8.7.3
 *   through 8.7.13 (8.7.1 PB-ADV Link Open and 8.7.2 PB-ADV Link ACK, and
 *   every "PB-ADV Transaction Ack" subsection, are Generic Provisioning
 *   transport PDUs, not Provisioning PDUs, and are out of this file's
 *   scope). This is the SAME worked exchange `crypto/__tests__/vectors.ts`'s
 *   `PROVISIONING_SAMPLE` already uses for its Section 8.17.1 crypto
 *   values (same Provisioner/Device key pairs, same ECDH secret, same
 *   session key/nonce, same encrypted Provisioning Data and MIC) -
 *   cross-checked directly against that fixture's `provisionerPublicKeyX`
 *   while writing this file, byte for byte identical, as expected since
 *   both trace to the same Section 8.7 sample.
 * - Each `PDU_TYPE_SAMPLE_*`'s `message` is the COMPLETE PDU (Type octet
 *   included) exactly as Section 8.7 publishes it under that subsection's
 *   own "Message" row (reassembled across its wrapped table cell where the
 *   source splits one hex value over two rendered lines - see above); its
 *   `fields` object is that subsection's own labelled field rows
 *   (`Attention Duration`, `Number of Elements`, `Algorithms`, ...),
 *   independent transcriptions of the SAME bytes `message` already
 *   contains, included so a test can check the decoder's individual
 *   output fields against the specification's own field-by-field
 *   breakdown, not merely against a byte string nothing separately
 *   verifies.
 *
 * TYPE OCTET PROVENANCE: `pdu.ts`'s module header records, in full, where
 * each of the ten Type values (0x00-0x09) comes from - wire-confirmed by
 * this same Section 8.7 sample for eight of them (every Type that appears
 * in this exchange: Invite, Capabilities, Start, Public Key, Confirmation,
 * Random, Data, Complete), and by the Bluetooth SIG "Assigned Numbers"
 * document (Section 4.3.3 "Mesh Provisioning PDU Types", fetched
 * independently, see `pdu.ts`) for the two this exchange never sends
 * (Input Complete 0x04, never sent because this sample uses no OOB method;
 * Failed 0x09, never sent because this sample succeeds).
 *
 * ERRATA NOTE (the kind the brief warns this document carries): Section
 * 8.7's own table CAPTIONS for the two Public Key subsections (8.7.6 "PB-ADV
 * Provisioning Public Key (Provisioner)" and 8.7.7 "(Device)") each render
 * their summary table under the row caption "Provisioning Start" - visibly
 * wrong, since the very same table's `Message` row begins with the Public
 * Key Type octet `03`, not Start's `02`, and lists `Public Key X`/`Public Key
 * Y` fields Table 5.28 (Start) does not have. Matched on the fields actually
 * present and the Type octet in `Message`, not on the mis-copied caption -
 * exactly the "match on position and meaning, not on a caption" rule the
 * brief states.
 *
 * SECOND ERRATA NOTE: Section 8.7.5's own field-by-field breakdown of the
 * Provisioning Start sample prints its `Public Key` row as `0000` - TWO
 * octets - while Table 5.28 defines Public Key as a ONE-octet field. The
 * `PDU_TYPE_SAMPLE_START` fixture below is unaffected (its `publicKey:
 * 0x00` is read off the `message` bytes directly, one octet at the position
 * Table 5.28 puts it, not off this mis-printed breakdown row), but the
 * divergence is silent unless cross-checked, so it is recorded here rather
 * than left for the next person to rediscover. Two independent
 * cross-checks resolve it in Table 5.28's favour:
 * (1) the SAME subsection's own published `TotalLength` is `0x0006` (6
 * octets: 1 Type octet + 5 Parameter octets) - only consistent with Public
 * Key being ONE octet (Algorithm 1 + PublicKey 1 + AuthenticationMethod 1 +
 * AuthenticationAction 1 + AuthenticationSize 1 = 5), not two (which would
 * make TotalLength 0x0007); and
 * (2) Sections 8.7.8 and 8.7.9 (the Confirmation samples) each separately
 * publish `StartPDUValue : 0000000000` - TEN hex characters, i.e. FIVE
 * octets, exactly the Section 5.4.2.4.1 definition of "the value of the
 * Provisioning Start PDU fields (excluding the opcode)" - which only adds
 * up if every one of those five fields, Public Key included, is one octet.
 * Both cross-checks agree with Table 5.28 and with each other, against the
 * one mis-printed breakdown row.
 *
 * NO FABRICATED SAMPLES: Types 0x0A-0x0D (the out-of-scope certificate-based
 * provisioning record types, see `pdu.ts`'s SCOPE note) and Input Complete/Failed are
 * NOT given `PDU_TYPE_SAMPLE_*` fixtures here, because this document
 * publishes no worked wire sample for any of them - Input Complete and
 * Complete's EMPTY-parameters shape is tested directly against each Type's
 * own prose ("There are no parameters for the Provisioning Input Complete
 * PDU" / "... Provisioning Complete PDU", Sections 5.4.1.5/5.4.1.9) in
 * `pdu.test.ts` rather than against a fabricated non-empty byte string;
 * Complete also happens to have a genuine Section 8.7 sample below
 * (`PDU_TYPE_SAMPLE_COMPLETE`), used for its real known-answer test. Failed
 * has no size ambiguity to speak of (Table 5.40: one mandatory octet) but
 * no published VALUE either, so `pdu.test.ts` exercises it only
 * structurally (encode/decode round-trip over its one-octet Error Code
 * field, never asserted against a specification-published byte string).
 */

export const hex = (s: string): Buffer => Buffer.from(s.replace(/\s+/g, ''), 'hex');

/** Section 8.7.3 "PB-ADV Provisioning Invite". TotalLength 0x0002 (published). */
export const PDU_TYPE_SAMPLE_INVITE = {
  message: '0000',
  fields: {
    attentionDuration: 0x00,
  },
};

/** Section 8.7.4 "PB-ADV Provisioning Capabilities". TotalLength 0x000c (published). */
export const PDU_TYPE_SAMPLE_CAPABILITIES = {
  message: '010100010000000000000000',
  fields: {
    numberOfElements: 0x01,
    algorithms: 0x0001,
    publicKeyType: 0x00,
    oobType: 0x00,
    outputOobSize: 0x00,
    outputOobAction: 0x0000,
    inputOobSize: 0x00,
    inputOobAction: 0x0000,
  },
};

/** Section 8.7.5 "PB-ADV Provisioning Start". TotalLength 0x0006 (published). */
export const PDU_TYPE_SAMPLE_START = {
  message: '020000000000',
  fields: {
    algorithm: 0x00,
    publicKey: 0x00,
    authenticationMethod: 0x00,
    authenticationAction: 0x00,
    authenticationSize: 0x00,
  },
};

/**
 * Section 8.7.6 "PB-ADV Provisioning Public Key (Provisioner)" - the table
 * caption there misreads "Provisioning Start" (see this file's ERRATA NOTE
 * above); matched on the Type octet (`03`) and the Public Key X/Y fields
 * actually present instead. TotalLength 0x0041 (published) = 1 Type octet +
 * 32 + 32. Same `publicKeyX`/`publicKeyY` as
 * `crypto/__tests__/vectors.ts`'s `PROVISIONING_SAMPLE.provisionerPublicKeyX/Y`.
 */
export const PDU_TYPE_SAMPLE_PUBLIC_KEY_PROVISIONER = {
  message:
    '032c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78' +
    'dd919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4f',
  fields: {
    publicKeyX: '2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd',
    publicKeyY: '919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4f',
  },
};

/**
 * Section 8.7.7 "PB-ADV Provisioning Public Key (Device)" - same caption
 * errata as 8.7.6 above. TotalLength 0x0041 (published). Same
 * `publicKeyX`/`publicKeyY` as `crypto/__tests__/vectors.ts`'s
 * `PROVISIONING_SAMPLE.devicePublicKeyX/Y`.
 */
export const PDU_TYPE_SAMPLE_PUBLIC_KEY_DEVICE = {
  message:
    '03f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500' +
    'cc0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279',
  fields: {
    publicKeyX: 'f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc',
    publicKeyY: '0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279',
  },
};

/**
 * Section 8.7.8 "PB-ADV Provisioning Confirmation (Provisioner)" -
 * ConfirmationProvisioner, 16 octets (BTM_ECDH_P256_CMAC_AES128_AES_CCM,
 * Section 5.4.2.4.1). TotalLength 0x0011 (published) = 1 + 16.
 */
export const PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER = {
  message: '05b38a114dfdca1fe153bd2c1e0dc46ac2',
  fields: {
    confirmation: 'b38a114dfdca1fe153bd2c1e0dc46ac2',
  },
};

/** Section 8.7.9 "PB-ADV Provisioning Confirmation (Device)" - ConfirmationDevice. TotalLength 0x0011 (published). */
export const PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE = {
  message: '05eeba521c196b52cc2e37aa40329f554e',
  fields: {
    confirmation: 'eeba521c196b52cc2e37aa40329f554e',
  },
};

/** Section 8.7.10 "PB-ADV Provisioning Random (Provisioner)" - RandomProvisioner. TotalLength 0x0011 (published). */
export const PDU_TYPE_SAMPLE_RANDOM_PROVISIONER = {
  message: '068b19ac31d58b124c946209b5db1021b9',
  fields: {
    random: '8b19ac31d58b124c946209b5db1021b9',
  },
};

/** Section 8.7.11 "PB-ADV Provisioning Random (Device)" - RandomDevice. TotalLength 0x0011 (published). */
export const PDU_TYPE_SAMPLE_RANDOM_DEVICE = {
  message: '0655a2a2bca04cd32ff6f346bd0a0c1a3a',
  fields: {
    random: '55a2a2bca04cd32ff6f346bd0a0c1a3a',
  },
};

/**
 * Section 8.7.12 "PB-ADV Provisioning Data". TotalLength 0x0022 (published)
 * = 1 Type octet + 25 (EncProvisioningData) + 8 (ProvisioningDataMIC). Same
 * `expectedCiphertext`/`expectedTag` as `crypto/__tests__/vectors.ts`'s
 * `PROVISIONING_SAMPLE` (its own AES-CCM encryption of this same
 * Provisioning Data block is what produced these bytes).
 */
export const PDU_TYPE_SAMPLE_DATA = {
  message: '07d0bd7f4a89a2ff6222af59a90a60ad58acfe3123356f5cec2973e0ec50783b10c7',
  fields: {
    encryptedProvisioningData: 'd0bd7f4a89a2ff6222af59a90a60ad58acfe3123356f5cec29',
    mic: '73e0ec50783b10c7',
  },
};

/** Section 8.7.13 "PB-ADV Provisioning Complete". TotalLength 0x0001 (published): Type octet only, no Parameters. */
export const PDU_TYPE_SAMPLE_COMPLETE = {
  message: '08',
  fields: {},
};

/**
 * Section 8.17.1 "BTM_ECDH_P256_CMAC_AES128_AES_CCM algorithm" - the full
 * worked provisioning security-functions computation (Section 5.4.2.4
 * "Authentication" and Section 5.4.2.5), fetched and extracted the same way
 * as the rest of this file. This is the SAME worked exchange as both this
 * file's `PDU_TYPE_SAMPLE_*` fixtures above and
 * `crypto/__tests__/vectors.ts`'s `PROVISIONING_SAMPLE` - every value below
 * that already exists in one of those two places is reused by reference in
 * `crypto.test.ts` rather than copied here a second time:
 *   - `provisionerPublicKeyX/Y`, `devicePublicKeyX/Y`, `expectedSharedSecret`
 *     (= ECDHSecret), `sessionKey`, `sessionNonce` - all in
 *     `crypto/__tests__/vectors.ts`'s `PROVISIONING_SAMPLE`.
 *   - `randomProvisioner`/`confirmationProvisioner` - this file's own
 *     `PDU_TYPE_SAMPLE_RANDOM_PROVISIONER.fields.random` /
 *     `PDU_TYPE_SAMPLE_CONFIRMATION_PROVISIONER.fields.confirmation`.
 *   - `randomDevice`/`confirmationDevice` - this file's own
 *     `PDU_TYPE_SAMPLE_RANDOM_DEVICE.fields.random` /
 *     `PDU_TYPE_SAMPLE_CONFIRMATION_DEVICE.fields.confirmation`.
 *
 * Only the values with no existing home in this repository are given below:
 * the three Provisioning PDUs' published `ProvisioningInvite`/
 * `ProvisioningCapabilities`/`ProvisioningStart` fields EXCLUDING their Type
 * octet (Section 5.4.2.4.1 calls these "...PDUValue"; `PDU_TYPE_SAMPLE_INVITE`
 * etc. above publish the Type-octet-INCLUDING wire `message` instead - cross-
 * checked byte-for-byte: `PDU_TYPE_SAMPLE_INVITE.message` is `00` (Type) +
 * `00`, `PDU_TYPE_SAMPLE_CAPABILITIES.message` is `01` (Type) +
 * `0100010000000000000000`, `PDU_TYPE_SAMPLE_START.message` is `02` (Type) +
 * `0000000000` - each Parameters-only tail below is identical to the
 * corresponding Type-octet-stripped `message` tail), `authValue` (the
 * No-OOB, all-zero 128-bit AuthValue Section 5.4.2.4.1 defines), the
 * genuinely new `confirmationSalt`/`confirmationKey`/`provisioningSalt`
 * intermediates, `sessionNonceFull` (the 16-octet k1 output SessionNonce is
 * truncated FROM - published alongside `SessionNonce` itself, needed to
 * pin which 13 of its 16 octets are kept), and `deviceKey`, the chain's
 * final published value.
 *
 * ERRATA: see `lib/mesh/provisioning/crypto.ts`'s own module header for the
 * Section 5.4.2.4.1 formula that misprints "ConfirmationProvisioner" a
 * second time where it means "ConfirmationDevice" - this file only carries
 * sample DATA, not the prose formulas, so that errata note lives with the
 * code that had to resolve it.
 */
export const PROVISIONING_CRYPTO_SAMPLE = {
  /** Table 5.18 Parameters (Type octet excluded): Attention Duration only. */
  provisioningInvite: '00',
  /** Table 5.19 Parameters (Type octet excluded), 11 octets. */
  provisioningCapabilities: '0100010000000000000000',
  /** Table 5.28 Parameters (Type octet excluded), 5 octets. */
  provisioningStart: '0000000000',
  /** Section 5.4.2.4.1: the No-OOB AuthValue, 128-bit all-zero. */
  authValue: '00000000000000000000000000000000',
  confirmationSalt: '5faabe187337c71cc6c973369dcaa79a',
  confirmationKey: 'e31fe046c68ec339c425fc6629f0336f',
  provisioningSalt: 'a21c7d45f201cf9489a2fb57145015b4',
  /** The 16-octet k1(ECDHSecret, ProvisioningSalt, "prsn") output, before the 13-least-significant-octets truncation (Section 5.4.2.5). */
  sessionNonceFull: 'c5e02eda7ddbe78b5f62b81d6847487e',
  deviceKey: '0520adad5e0142aa3e325087b4ec16d8',
};
