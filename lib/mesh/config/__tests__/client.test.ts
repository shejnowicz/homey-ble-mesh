import {
  encodeConfigCompositionDataGet,
  encodeConfigAppKeyAdd,
  encodeConfigModelAppBind,
  encodeConfigNodeReset,
  decodeConfigStatus,
  describeConfigStatus,
  describeConfigExchange,
  describeConfigOpcode,
} from '../client';
import {
  hex,
  COMPOSITION_DATA_PAGE0_SAMPLE,
  CONFIG_OPCODES,
  CONFIG_APPKEY_ADD_SAMPLE,
  CONFIG_APPKEY_STATUS_SAMPLE,
  CONFIG_STATUS_CODES,
  CONFIG_KEY_INDEX_TOP_OF_RANGE_SAMPLE,
  CONFIG_MODEL_APP_BIND_SAMPLE,
  CONFIG_MODEL_APP_STATUS_SAMPLE,
  CONFIG_COMPOSITION_DATA_GET_SAMPLE,
  CONFIG_COMPOSITION_DATA_STATUS_SAMPLE,
  CONFIG_NODE_RESET_SAMPLE,
  CONFIG_NODE_RESET_STATUS_SAMPLE,
} from './vectors';
import {
  UPPER_TRANSPORT_SAMPLE_DEVICE_KEY,
  ACCESS_SAMPLE_CONFIG_APPKEY_STATUS,
} from '../../packet/__tests__/vectors';

// ===========================================================================
// Cross-binding: this file's own CONFIG_APPKEY_ADD_SAMPLE/
// CONFIG_APPKEY_STATUS_SAMPLE restate Section 8.3.6/8.3.16's wire bytes
// (vectors.ts files are self-contained, per this project's convention) -
// this pins them equal to the SAME bytes `packet/__tests__/vectors.ts`
// already transcribed for a different task, so the two files' copies can
// never silently diverge.
// ===========================================================================

describe('fixture cross-binding (config/vectors.ts vs packet/vectors.ts, same published messages)', () => {
  test('CONFIG_APPKEY_ADD_SAMPLE.message equals Message #6\'s own accessPayload', () => {
    expect(CONFIG_APPKEY_ADD_SAMPLE.message).toBe(UPPER_TRANSPORT_SAMPLE_DEVICE_KEY.accessPayload);
  });

  test('CONFIG_APPKEY_STATUS_SAMPLE.message equals Message #16\'s own expected bytes', () => {
    expect(CONFIG_APPKEY_STATUS_SAMPLE.message).toBe(ACCESS_SAMPLE_CONFIG_APPKEY_STATUS.expected);
  });
});

// ===========================================================================
// Config Composition Data Get (Table 4.86) - encode only.
// ===========================================================================

describe('encodeConfigCompositionDataGet (Table 4.86)', () => {
  test('matches the hand-assembled Opcode||Page wire bytes', () => {
    const pdu = encodeConfigCompositionDataGet(CONFIG_COMPOSITION_DATA_GET_SAMPLE.page);
    expect(pdu).toEqual(hex(CONFIG_COMPOSITION_DATA_GET_SAMPLE.message));
  });

  test('a non-zero page number is placed in the Page octet, not the opcode', () => {
    const pdu = encodeConfigCompositionDataGet(0x07);
    expect(pdu).toEqual(hex('800807'));
  });

  test('rejects a page number above the single-octet domain, naming the field', () => {
    expect(() => encodeConfigCompositionDataGet(256)).toThrow(/config field "page" must be an integer in \[0, 255\], got 256/);
  });
});

// ===========================================================================
// Config AppKey Add (Table 4.119) - encode only. Known-answer: Message #6.
// ===========================================================================

describe('encodeConfigAppKeyAdd (Table 4.119, Section 8.3.6 "Message #6")', () => {
  test('reproduces Message #6 exactly', () => {
    const pdu = encodeConfigAppKeyAdd({
      netKeyIndex: CONFIG_APPKEY_ADD_SAMPLE.netKeyIndex,
      appKeyIndex: CONFIG_APPKEY_ADD_SAMPLE.appKeyIndex,
      appKey: hex(CONFIG_APPKEY_ADD_SAMPLE.appKey),
    });
    expect(pdu).toEqual(hex(CONFIG_APPKEY_ADD_SAMPLE.message));
  });

  test('key indexes at the top of the 12-bit range pack per the hand-derived bytes (not observed from the encoder)', () => {
    const { first, second, packed } = CONFIG_KEY_INDEX_TOP_OF_RANGE_SAMPLE.twoIndex;
    const pdu = encodeConfigAppKeyAdd({
      netKeyIndex: first,
      appKeyIndex: second,
      appKey: Buffer.alloc(16, 0xaa),
    });
    // Opcode (00) || NetKeyIndexAndAppKeyIndex (packed) || AppKey (16 * 0xaa).
    expect(pdu).toEqual(Buffer.concat([hex('00'), hex(packed), Buffer.alloc(16, 0xaa)]));
  });

  test('swapping which index is "first" produces different wire bytes (NetKeyIndex and AppKeyIndex are not interchangeable)', () => {
    const { first, second, packedSwapped } = CONFIG_KEY_INDEX_TOP_OF_RANGE_SAMPLE.twoIndex;
    // Here the SWAPPED roles become the real request: netKeyIndex=second, appKeyIndex=first.
    const pdu = encodeConfigAppKeyAdd({
      netKeyIndex: second,
      appKeyIndex: first,
      appKey: Buffer.alloc(16, 0xaa),
    });
    expect(pdu).toEqual(Buffer.concat([hex('00'), hex(packedSwapped), Buffer.alloc(16, 0xaa)]));
  });

  test('rejects a netKeyIndex past the 12-bit domain, naming the field', () => {
    expect(() =>
      encodeConfigAppKeyAdd({ netKeyIndex: 0x1000, appKeyIndex: 0, appKey: Buffer.alloc(16) }),
    ).toThrow(/config field "netKeyIndex" must be an integer in \[0, 4095\], got 4096/);
  });

  test('rejects an appKeyIndex past the 12-bit domain, naming the field', () => {
    expect(() =>
      encodeConfigAppKeyAdd({ netKeyIndex: 0, appKeyIndex: 0x1000, appKey: Buffer.alloc(16) }),
    ).toThrow(/config field "appKeyIndex" must be an integer in \[0, 4095\], got 4096/);
  });

  test('rejects an AppKey of the wrong length, naming the field and both lengths', () => {
    expect(() =>
      encodeConfigAppKeyAdd({ netKeyIndex: 0, appKeyIndex: 0, appKey: Buffer.alloc(15) }),
    ).toThrow(/config field "appKey" must be 16 bytes \(Table 4\.119\), got 15/);
  });

  test('does not retain a view into the caller-supplied appKey buffer', () => {
    const appKey = Buffer.from(CONFIG_APPKEY_ADD_SAMPLE.appKey, 'hex');
    const pdu = encodeConfigAppKeyAdd({
      netKeyIndex: CONFIG_APPKEY_ADD_SAMPLE.netKeyIndex,
      appKeyIndex: CONFIG_APPKEY_ADD_SAMPLE.appKeyIndex,
      appKey,
    });
    const before = Buffer.from(pdu);
    appKey.fill(0xff);
    expect(pdu).toEqual(before);
  });
});

// ===========================================================================
// Config AppKey Status (Table 4.122) - decode only. Known-answer: Message #16.
// ===========================================================================

describe('decodeConfigStatus: Config AppKey Status (Table 4.122, Section 8.3.16 "Message #16")', () => {
  test('reproduces Message #16\'s decoded fields exactly', () => {
    const result = decodeConfigStatus(hex(CONFIG_APPKEY_STATUS_SAMPLE.message));
    expect(result).toEqual({
      type: 'appKey',
      status: CONFIG_APPKEY_STATUS_SAMPLE.status,
      statusName: 'Success',
      netKeyIndex: CONFIG_APPKEY_STATUS_SAMPLE.netKeyIndex,
      appKeyIndex: CONFIG_APPKEY_STATUS_SAMPLE.appKeyIndex,
    });
  });

  test('a non-Success status (0x0d, "Cannot Bind") is named correctly - the published sample is always Success, so this is the one this task\'s own dispatch instructions warned a lazy decoder could fake', () => {
    // Opcode (8003) || Status (0d) || NetKeyIndexAndAppKeyIndex (same packed bytes as Message #16).
    const pdu = hex('80030d' + '563412');
    const result = decodeConfigStatus(pdu);
    expect(result).toEqual({
      type: 'appKey',
      status: 0x0d,
      statusName: 'Cannot Bind',
      netKeyIndex: 0x456,
      appKeyIndex: 0x123,
    });
  });

  test('key indexes at the top of the 12-bit range unpack per the hand-derived bytes', () => {
    // Decode direction exercised with the MIRRORED role assignment from the
    // encode-direction boundary test above, for different coverage: here
    // netKeyIndex is the SECOND packed index and appKeyIndex the FIRST.
    const { packedSwapped } = CONFIG_KEY_INDEX_TOP_OF_RANGE_SAMPLE.twoIndex;
    const pdu = hex('800300' + packedSwapped);
    const result = decodeConfigStatus(pdu);
    expect(result).toEqual({
      type: 'appKey',
      status: 0x00,
      statusName: 'Success',
      netKeyIndex: 0x001,
      appKeyIndex: 0xfff,
    });
  });

  test('rejects a Parameters field one octet short (Status present, index packing truncated)', () => {
    expect(decodeConfigStatus(hex('8003' + '00' + '5634'))).toBeNull();
  });

  test('rejects a Parameters field one octet too long', () => {
    expect(decodeConfigStatus(hex(CONFIG_APPKEY_STATUS_SAMPLE.message + '00'))).toBeNull();
  });
});

// ===========================================================================
// Config Model App Bind (Table 4.128) - encode only. Hand-assembled sample
// (no Section 8.3 sample exercises this message - see vectors.ts header).
// ===========================================================================

describe('encodeConfigModelAppBind (Table 4.128)', () => {
  test('SIG Model Identifier: matches the hand-assembled wire bytes', () => {
    const pdu = encodeConfigModelAppBind({
      elementAddress: CONFIG_MODEL_APP_BIND_SAMPLE.elementAddress,
      appKeyIndex: CONFIG_MODEL_APP_BIND_SAMPLE.appKeyIndex,
      modelIdentifier: CONFIG_MODEL_APP_BIND_SAMPLE.sigModelIdentifier,
    });
    expect(pdu).toEqual(hex(CONFIG_MODEL_APP_BIND_SAMPLE.messageSig));
  });

  test('Vendor Model Identifier: matches the hand-assembled wire bytes (Company Identifier first, per Table 3.64)', () => {
    const pdu = encodeConfigModelAppBind({
      elementAddress: CONFIG_MODEL_APP_BIND_SAMPLE.elementAddress,
      appKeyIndex: CONFIG_MODEL_APP_BIND_SAMPLE.appKeyIndex,
      modelIdentifier: CONFIG_MODEL_APP_BIND_SAMPLE.vendorModelIdentifier,
    });
    expect(pdu).toEqual(hex(CONFIG_MODEL_APP_BIND_SAMPLE.messageVendor));
  });

  test('a single key index at the top of the 12-bit range packs per the hand-derived bytes (Figure 4.5)', () => {
    const { index, packed } = CONFIG_KEY_INDEX_TOP_OF_RANGE_SAMPLE.singleIndex;
    const pdu = encodeConfigModelAppBind({
      elementAddress: CONFIG_MODEL_APP_BIND_SAMPLE.elementAddress,
      appKeyIndex: index,
      modelIdentifier: CONFIG_MODEL_APP_BIND_SAMPLE.sigModelIdentifier,
    });
    expect(pdu).toEqual(
      Buffer.concat([hex('803d'), hex('0112'), hex(packed), hex('0010')]),
    );
  });

  test('rejects a group address (Table 4.128: "all other address types are Prohibited")', () => {
    expect(() =>
      encodeConfigModelAppBind({ elementAddress: 0xc000, appKeyIndex: 0, modelIdentifier: 0x0000 }),
    ).toThrow(/config field "elementAddress" must be a unicast address in \[0x1, 0x7fff\]/);
  });

  test('rejects the unassigned address 0x0000', () => {
    expect(() =>
      encodeConfigModelAppBind({ elementAddress: 0x0000, appKeyIndex: 0, modelIdentifier: 0x0000 }),
    ).toThrow(/config field "elementAddress" must be a unicast address/);
  });

  test('accepts the unicast range\'s own top value, 0x7fff', () => {
    expect(() =>
      encodeConfigModelAppBind({ elementAddress: 0x7fff, appKeyIndex: 0, modelIdentifier: 0x0000 }),
    ).not.toThrow();
  });

  test('rejects an appKeyIndex past the 12-bit domain', () => {
    expect(() =>
      encodeConfigModelAppBind({ elementAddress: 1, appKeyIndex: 0x1000, modelIdentifier: 0x0000 }),
    ).toThrow(/config field "appKeyIndex" must be an integer in \[0, 4095\], got 4096/);
  });
});

// ===========================================================================
// Config Model App Status (Table 4.130) - decode only. Hand-assembled.
// ===========================================================================

describe('decodeConfigStatus: Config Model App Status (Table 4.130)', () => {
  test('SIG Model Identifier, Success', () => {
    const result = decodeConfigStatus(hex(CONFIG_MODEL_APP_STATUS_SAMPLE.messageSigSuccess));
    expect(result).toEqual({
      type: 'modelApp',
      status: 0x00,
      statusName: 'Success',
      elementAddress: CONFIG_MODEL_APP_STATUS_SAMPLE.elementAddress,
      appKeyIndex: CONFIG_MODEL_APP_STATUS_SAMPLE.appKeyIndex,
      modelIdentifier: CONFIG_MODEL_APP_STATUS_SAMPLE.sigModelIdentifier,
    });
  });

  test('SIG Model Identifier, a non-Success status ("Cannot Bind") - guards against a decoder that only ever reports Success', () => {
    const result = decodeConfigStatus(hex(CONFIG_MODEL_APP_STATUS_SAMPLE.messageSigCannotBind));
    expect(result).toEqual({
      type: 'modelApp',
      status: 0x0d,
      statusName: 'Cannot Bind',
      elementAddress: CONFIG_MODEL_APP_STATUS_SAMPLE.elementAddress,
      appKeyIndex: CONFIG_MODEL_APP_STATUS_SAMPLE.appKeyIndex,
      modelIdentifier: CONFIG_MODEL_APP_STATUS_SAMPLE.sigModelIdentifier,
    });
  });

  test('Vendor Model Identifier, Success', () => {
    const result = decodeConfigStatus(hex(CONFIG_MODEL_APP_STATUS_SAMPLE.messageVendorSuccess));
    expect(result).toEqual({
      type: 'modelApp',
      status: 0x00,
      statusName: 'Success',
      elementAddress: CONFIG_MODEL_APP_STATUS_SAMPLE.elementAddress,
      appKeyIndex: CONFIG_MODEL_APP_STATUS_SAMPLE.appKeyIndex,
      modelIdentifier: CONFIG_MODEL_APP_STATUS_SAMPLE.vendorModelIdentifier,
    });
  });

  test('a single key index at the top of the 12-bit range unpacks per the hand-derived bytes', () => {
    const { index, packed } = CONFIG_KEY_INDEX_TOP_OF_RANGE_SAMPLE.singleIndex;
    const pdu = Buffer.concat([hex('803e'), hex('00'), hex('0112'), hex(packed), hex('0010')]);
    const result = decodeConfigStatus(pdu);
    expect(result).toMatchObject({ type: 'modelApp', appKeyIndex: index });
  });

  test('the packed AppKeyIndex field\'s reserved top nibble is masked off, not mixed into the value - a decoder that forgot to mask would still pass every other test here, since every other sample has that nibble zero', () => {
    // octet0=0x00, octet1=0xAF: masked AppKeyIndex should be 0x0F00 (top
    // nibble 0xA discarded), per `client.ts`'s own `unpackSingleKeyIndex`
    // provenance comment.
    const pdu = Buffer.concat([hex('803e'), hex('00'), hex('0112'), hex('00af'), hex('0010')]);
    const result = decodeConfigStatus(pdu);
    expect(result).toMatchObject({ type: 'modelApp', appKeyIndex: 0x0f00 });
  });

  test('rejects a Parameters length that is neither the SIG (7) nor the Vendor (9) form', () => {
    const malformed = Buffer.concat([hex('803e'), hex('00'), hex('0112'), hex('2301'), hex('000000')]); // 8 octets total.
    expect(decodeConfigStatus(malformed)).toBeNull();
  });
});

// ===========================================================================
// Config Node Reset / Node Reset Status (Tables 4.135/4.136): no parameters
// at all - opcode-only in both directions.
// ===========================================================================

describe('Config Node Reset (Table 4.135) / Config Node Reset Status (Table 4.136)', () => {
  test('encodeConfigNodeReset produces the bare opcode PDU', () => {
    expect(encodeConfigNodeReset()).toEqual(hex(CONFIG_NODE_RESET_SAMPLE.message));
  });

  test('decodeConfigStatus recovers Config Node Reset Status', () => {
    expect(decodeConfigStatus(hex(CONFIG_NODE_RESET_STATUS_SAMPLE.message))).toEqual({ type: 'nodeReset' });
  });

  test('a trailing octet on Config Node Reset Status is rejected, not ignored', () => {
    expect(decodeConfigStatus(hex(CONFIG_NODE_RESET_STATUS_SAMPLE.message + '00'))).toBeNull();
  });

  test('Config Node Reset\'s own opcode is NOT the opcode decodeConfigStatus recognises (it is a request, not a status)', () => {
    expect(decodeConfigStatus(hex(CONFIG_NODE_RESET_SAMPLE.message))).toBeNull();
  });
});

// ===========================================================================
// Config Composition Data Status (Table 4.87) - decode only, Data field
// delegated to `parseCompositionData` (Section 8.10.1 sample reused).
// ===========================================================================

describe('decodeConfigStatus: Config Composition Data Status (Table 4.87)', () => {
  test('recovers Page and the parsed Composition Data together', () => {
    const result = decodeConfigStatus(hex(CONFIG_COMPOSITION_DATA_STATUS_SAMPLE.message));
    if (result === null || result.type !== 'compositionData') {
      throw new Error(`expected a compositionData status, got ${JSON.stringify(result)}`);
    }
    expect(result.page).toBe(CONFIG_COMPOSITION_DATA_STATUS_SAMPLE.page);
    expect(result.composition).toEqual({
      cid: COMPOSITION_DATA_PAGE0_SAMPLE.fields.cid,
      pid: COMPOSITION_DATA_PAGE0_SAMPLE.fields.pid,
      vid: COMPOSITION_DATA_PAGE0_SAMPLE.fields.vid,
      crpl: COMPOSITION_DATA_PAGE0_SAMPLE.fields.crpl,
      features: COMPOSITION_DATA_PAGE0_SAMPLE.fields.decodedFeatures,
      elements: COMPOSITION_DATA_PAGE0_SAMPLE.fields.elements,
    });
  });

  test('a non-zero Page number is recovered independently of the Data field', () => {
    const pdu = Buffer.concat([hex('02'), hex('07'), hex(COMPOSITION_DATA_PAGE0_SAMPLE.message)]);
    const result = decodeConfigStatus(pdu);
    expect(result).toMatchObject({ type: 'compositionData', page: 0x07 });
  });

  test('a Data field that fails to parse yields composition: null, NOT an overall null (the envelope is still well-formed)', () => {
    const pdu = Buffer.concat([hex('02'), hex('00'), hex(COMPOSITION_DATA_PAGE0_SAMPLE.message).subarray(0, 5)]); // truncated page.
    const result = decodeConfigStatus(pdu);
    expect(result).toEqual({ type: 'compositionData', page: 0x00, composition: null });
  });

  test('rejects a Parameters field with no Page octet at all', () => {
    expect(decodeConfigStatus(hex('02'))).toBeNull();
  });
});

// ===========================================================================
// decodeConfigStatus: unrecognised opcodes decode to null (the brief's own
// words: "a status whose opcode we do not recognise decodes to `null`").
// ===========================================================================

describe('decodeConfigStatus: unrecognised opcodes', () => {
  test('an opcode none of the four status messages use decodes to null', () => {
    expect(decodeConfigStatus(hex('8099' + '00'))).toBeNull();
  });

  test('one of the REQUEST opcodes (Config AppKey Add, 0x00) is not a status opcode, so it also decodes to null', () => {
    expect(decodeConfigStatus(hex(CONFIG_APPKEY_ADD_SAMPLE.message))).toBeNull();
  });

  test('the reserved 1-octet opcode 0x7F (Table 3.62) decodes to null, via decodeAccessMessage itself', () => {
    expect(decodeConfigStatus(hex('7f'))).toBeNull();
  });

  test('an empty PDU decodes to null', () => {
    expect(decodeConfigStatus(Buffer.alloc(0))).toBeNull();
  });
});

// ===========================================================================
// describeConfigStatus (Table 4.308) - every published code, plus the RFU
// boundary.
// ===========================================================================

describe('describeConfigStatus (Table 4.308)', () => {
  test.each(CONFIG_STATUS_CODES.map(({ code, name }) => [code, name] as const))(
    '0x%s names "%s"',
    (code, name) => {
      expect(describeConfigStatus(code)).toBe(name);
    },
  );

  // The sweep above is driven by CONFIG_STATUS_CODES itself, so a row
  // deleted from BOTH the fixture and the implementation's own map at once
  // passes it silently (the fixture would just have one fewer entry to
  // check, and the out-of-range tests below don't cover whatever used to
  // be the table's last defined row). These two anchors do NOT read
  // CONFIG_STATUS_CODES at all - they pin the fixture's own size, and the
  // highest defined code's name, as literal, independent values - so the
  // boundary between "defined" and "RFU" is held from below as well as
  // from above (0x16/0xff).
  test('the table defines exactly 22 status codes (0x00 through 0x15), independent of the fixture array', () => {
    expect(CONFIG_STATUS_CODES).toHaveLength(22);
  });

  test('0x15, the highest defined code, names "Invalid Bearer" (hardcoded here, not read from CONFIG_STATUS_CODES, so a row deleted from both the map and the fixture cannot pass silently)', () => {
    expect(describeConfigStatus(0x15)).toBe('Invalid Bearer');
  });

  test('0x16, the first RFU code, names null', () => {
    expect(describeConfigStatus(0x16)).toBeNull();
  });

  test('0xff, the last RFU code, names null', () => {
    expect(describeConfigStatus(0xff)).toBeNull();
  });
});

// ===========================================================================
// CONFIG_OPCODES sanity: every opcode this module's encoders/decoders use
// matches the transcribed Assigned Numbers values exactly (guards against a
// typo in client.ts's own private opcode constants going unnoticed because
// every other test only exercises them indirectly through a full message).
// ===========================================================================

describe('opcode sanity (each message\'s own wire-level opcode octets)', () => {
  test('Config Composition Data Get: 0x8008 -> wire `8008`', () => {
    expect(encodeConfigCompositionDataGet(0).subarray(0, 2)).toEqual(hex('8008'));
    expect(CONFIG_OPCODES.compositionDataGet).toBe(0x8008);
  });

  test('Config Composition Data Status: 0x02 -> wire `02` (1-octet opcode)', () => {
    expect(hex(CONFIG_COMPOSITION_DATA_STATUS_SAMPLE.message).subarray(0, 1)).toEqual(hex('02'));
    expect(CONFIG_OPCODES.compositionDataStatus).toBe(0x02);
  });

  test('Config AppKey Add: 0x00 -> wire `00`', () => {
    expect(encodeConfigAppKeyAdd({ netKeyIndex: 0, appKeyIndex: 0, appKey: Buffer.alloc(16) }).subarray(0, 1)).toEqual(
      hex('00'),
    );
    expect(CONFIG_OPCODES.appKeyAdd).toBe(0x00);
  });

  test('Config AppKey Status: 0x8003 -> wire `8003`', () => {
    expect(hex(CONFIG_APPKEY_STATUS_SAMPLE.message).subarray(0, 2)).toEqual(hex('8003'));
    expect(CONFIG_OPCODES.appKeyStatus).toBe(0x8003);
  });

  test('Config Model App Bind: 0x803d -> wire `803d`', () => {
    expect(hex(CONFIG_MODEL_APP_BIND_SAMPLE.messageSig).subarray(0, 2)).toEqual(hex('803d'));
    expect(CONFIG_OPCODES.modelAppBind).toBe(0x803d);
  });

  test('Config Model App Status: 0x803e -> wire `803e`', () => {
    expect(hex(CONFIG_MODEL_APP_STATUS_SAMPLE.messageSigSuccess).subarray(0, 2)).toEqual(hex('803e'));
    expect(CONFIG_OPCODES.modelAppStatus).toBe(0x803e);
  });

  test('Config Node Reset: 0x8049 -> wire `8049`', () => {
    expect(encodeConfigNodeReset()).toEqual(hex('8049'));
    expect(CONFIG_OPCODES.nodeReset).toBe(0x8049);
  });

  test('Config Node Reset Status: 0x804a -> wire `804a`', () => {
    expect(hex(CONFIG_NODE_RESET_STATUS_SAMPLE.message)).toEqual(hex('804a'));
    expect(CONFIG_OPCODES.nodeResetStatus).toBe(0x804a);
  });
});

// ===========================================================================
// WHICH STATUS ANSWERS WHICH REQUEST (hardware round, 2026-10-08). The one
// table a Configuration Client needs in order to recognise its own reply
// rather than accept whatever arrives first — see the module's own section
// header for what accepting whatever arrives first cost.
// ===========================================================================

describe('describeConfigExchange', () => {
  test('every one of this module\'s four requests names the status that answers it', () => {
    expect(describeConfigExchange(encodeConfigCompositionDataGet(0))).toEqual({
      requestOpcode: CONFIG_OPCODES.compositionDataGet,
      requestName: 'Config Composition Data Get',
      statusOpcode: CONFIG_OPCODES.compositionDataStatus,
      statusName: 'Config Composition Data Status',
    });
    expect(
      describeConfigExchange(
        encodeConfigAppKeyAdd({ netKeyIndex: 0x456, appKeyIndex: 0x123, appKey: Buffer.alloc(16) }),
      ),
    ).toEqual({
      requestOpcode: CONFIG_OPCODES.appKeyAdd,
      requestName: 'Config AppKey Add',
      statusOpcode: CONFIG_OPCODES.appKeyStatus,
      statusName: 'Config AppKey Status',
    });
    expect(
      describeConfigExchange(encodeConfigModelAppBind({ elementAddress: 0x0002, appKeyIndex: 0, modelIdentifier: 0x1000 })),
    ).toEqual({
      requestOpcode: CONFIG_OPCODES.modelAppBind,
      requestName: 'Config Model App Bind',
      statusOpcode: CONFIG_OPCODES.modelAppStatus,
      statusName: 'Config Model App Status',
    });
    expect(describeConfigExchange(encodeConfigNodeReset())).toEqual({
      requestOpcode: CONFIG_OPCODES.nodeReset,
      requestName: 'Config Node Reset',
      statusOpcode: CONFIG_OPCODES.nodeResetStatus,
      statusName: 'Config Node Reset Status',
    });
  });

  test('THE DISCRIMINATING ASSERTION: no request is mapped to another request\'s status', () => {
    // A table with two entries swapped, or one entry pointing at its own
    // request opcode, would pass "every request has an answer" and fail
    // here: the four status opcodes must be four DIFFERENT values, none of
    // them a request opcode.
    const requests = [
      encodeConfigCompositionDataGet(0),
      encodeConfigAppKeyAdd({ netKeyIndex: 0, appKeyIndex: 0, appKey: Buffer.alloc(16) }),
      encodeConfigModelAppBind({ elementAddress: 1, appKeyIndex: 0, modelIdentifier: 0x1000 }),
      encodeConfigNodeReset(),
    ].map((pdu) => describeConfigExchange(pdu));
    const statusOpcodes = requests.map((r) => r?.statusOpcode);
    const requestOpcodes = requests.map((r) => r?.requestOpcode);
    expect(new Set(statusOpcodes).size).toBe(4);
    expect(statusOpcodes.filter((opcode) => requestOpcodes.includes(opcode))).toEqual([]);
  });

  test('a STATUS message handed in where a request belongs is null, not matched against itself', () => {
    // The caller error worth catching loudly: every status opcode below is
    // one this module knows, and not one of them starts an exchange.
    expect(describeConfigExchange(hex(CONFIG_APPKEY_STATUS_SAMPLE.message))).toBeNull();
    expect(describeConfigExchange(hex(CONFIG_MODEL_APP_STATUS_SAMPLE.messageSigSuccess))).toBeNull();
    expect(describeConfigExchange(hex(CONFIG_NODE_RESET_STATUS_SAMPLE.message))).toBeNull();
  });

  test('an opcode this module does not implement, and an undecodable PDU, are both null rather than a throw', () => {
    expect(describeConfigExchange(Buffer.from([0x82, 0x02, 0x01, 0x00]))).toBeNull(); // Generic OnOff Set — a real opcode, not ours
    expect(describeConfigExchange(Buffer.alloc(0))).toBeNull();
    expect(describeConfigExchange(Buffer.from([0x7f]))).toBeNull(); // the reserved opcode decodeAccessMessage refuses
  });
});

describe('describeConfigOpcode', () => {
  test('names all eight of this module\'s messages', () => {
    expect(describeConfigOpcode(CONFIG_OPCODES.compositionDataGet)).toBe('Config Composition Data Get');
    expect(describeConfigOpcode(CONFIG_OPCODES.compositionDataStatus)).toBe('Config Composition Data Status');
    expect(describeConfigOpcode(CONFIG_OPCODES.appKeyAdd)).toBe('Config AppKey Add');
    expect(describeConfigOpcode(CONFIG_OPCODES.appKeyStatus)).toBe('Config AppKey Status');
    expect(describeConfigOpcode(CONFIG_OPCODES.modelAppBind)).toBe('Config Model App Bind');
    expect(describeConfigOpcode(CONFIG_OPCODES.modelAppStatus)).toBe('Config Model App Status');
    expect(describeConfigOpcode(CONFIG_OPCODES.nodeReset)).toBe('Config Node Reset');
    expect(describeConfigOpcode(CONFIG_OPCODES.nodeResetStatus)).toBe('Config Node Reset Status');
  });

  test('is null for an opcode this module does not implement — a node may send anything its models define', () => {
    expect(describeConfigOpcode(0x8202)).toBeNull(); // Generic OnOff Set
    expect(describeConfigOpcode(0x8201)).toBeNull(); // Generic OnOff Get
  });
});
