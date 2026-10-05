/**
 * Sample data transcribed from the Bluetooth Mesh specification, section 8.1
 * "Security sample data" (subsections 8.1.1 s1, 8.1.3 k2 (managed flooding),
 * 8.1.5 k3, 8.1.6 k4). Values confirmed against the official Bluetooth SIG
 * "Mesh Protocol" specification document, which carries this section forward
 * unchanged from Mesh Profile 1.0.1 (same section/subsection numbers, same
 * keys, same expected outputs). See task-2-report.md for provenance detail.
 */
export const hex = (s: string): Buffer => Buffer.from(s.replace(/\s+/g, ''), 'hex');

export const S1_TEST = {
  input: Buffer.from('test', 'ascii'),
  expected: 'b73cefbd641ef2ea598c2b6efb62f79c',
};

export const K2_MASTER = {
  n: 'f7a2a44f8e8a8029064f173ddc1e2b00',
  p: '00',
  expectedNid: 0x7f,
  expectedEncryptionKey: '9f589181a0f50de73c8070c7a6d27f46',
  expectedPrivacyKey: '4c715bd4a64b938f99b453351653124f',
};

export const K3_SAMPLE = {
  n: 'f7a2a44f8e8a8029064f173ddc1e2b00',
  expected: 'ff046958233db014',
};

export const K4_SAMPLE = {
  n: '3216d1509884b533248541792b877f98',
  expected: 0x38,
};
