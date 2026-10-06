import { parseCompositionData } from '../composition';
import { COMPOSITION_DATA_PAGE0_SAMPLE, hex } from './vectors';

describe('parseCompositionData', () => {
  describe('the published Section 8.10.1 sample', () => {
    const buffer = hex(COMPOSITION_DATA_PAGE0_SAMPLE.message);
    const expected = COMPOSITION_DATA_PAGE0_SAMPLE.fields;

    test('parses the header fields exactly as published', () => {
      const result = parseCompositionData(buffer);
      expect(result).not.toBeNull();
      expect(result?.cid).toBe(expected.cid);
      expect(result?.pid).toBe(expected.pid);
      expect(result?.vid).toBe(expected.vid);
      expect(result?.crpl).toBe(expected.crpl);
    });

    test('decodes Features per Table 4.3, not per the sample prose errata (see vectors.ts)', () => {
      const result = parseCompositionData(buffer);
      expect(result?.features).toEqual(expected.decodedFeatures);
    });

    test('decodes the one published element - Loc, SIG Models and Vendor Models - exactly', () => {
      const result = parseCompositionData(buffer);
      expect(result?.elements).toEqual(expected.elements);
    });

    test('the full known-answer result, end to end', () => {
      const result = parseCompositionData(buffer);
      expect(result).toEqual({
        cid: expected.cid,
        pid: expected.pid,
        vid: expected.vid,
        crpl: expected.crpl,
        features: expected.decodedFeatures,
        elements: expected.elements,
      });
    });
  });

  describe('truncation: every prefix of the published sample is rejected', () => {
    const fullBuffer = hex(COMPOSITION_DATA_PAGE0_SAMPLE.message);

    // Walk the length from zero to one less than the sample's own length
    // (28 octets) - every single prefix must be `null`, including the
    // 10-octet "header only, zero elements" prefix, which looks
    // structurally complete by Table 4.2 alone but is still rejected
    // (Section 2.3.4: a node always has at least one element).
    for (let length = 0; length < fullBuffer.length; length++) {
      test(`length ${length} of ${fullBuffer.length} is rejected`, () => {
        expect(parseCompositionData(fullBuffer.subarray(0, length))).toBeNull();
      });
    }

    test('sanity: the full, untruncated buffer is NOT rejected', () => {
      expect(parseCompositionData(fullBuffer)).not.toBeNull();
    });
  });

  describe('trailing garbage past a complete page is rejected, not ignored', () => {
    const fullBuffer = hex(COMPOSITION_DATA_PAGE0_SAMPLE.message);

    test('one extra octet that cannot start another element header', () => {
      const withExtra = Buffer.concat([fullBuffer, Buffer.from([0x00])]);
      expect(parseCompositionData(withExtra)).toBeNull();
    });

    test('three extra octets - a short, truncated element header', () => {
      const withExtra = Buffer.concat([fullBuffer, Buffer.from([0x00, 0x00, 0x05])]);
      expect(parseCompositionData(withExtra)).toBeNull();
    });
  });

  describe('zero elements is rejected even though the header alone looks well-formed', () => {
    test('a 10-octet header-only buffer (Section 2.3.4: impossible for a real node)', () => {
      const headerOnly = hex(COMPOSITION_DATA_PAGE0_SAMPLE.message).subarray(0, 10);
      expect(headerOnly.length).toBe(10);
      expect(parseCompositionData(headerOnly)).toBeNull();
    });
  });

  describe('an element with zero SIG models and zero Vendor models (NumS=0, NumV=0)', () => {
    test('parses to an element with two empty model lists, not a crash or a skipped element', () => {
      // Header bytes are the published sample's own CID/PID/VID/CRPL/Features
      // (0x000C/0x001A/0x0001/0x0008/0x0003, the first 20 hex characters =
      // 10 octets of the published message); the element record appended
      // after it is synthetic (Loc=0x0000, NumS=0, NumV=0: "0000" + "00" +
      // "00") built to exercise the zero-models loop boundary the one
      // published sample (NumS=5, NumV=1) cannot exercise on its own.
      const header = COMPOSITION_DATA_PAGE0_SAMPLE.message.slice(0, 20);
      const buffer = hex(header + '00000000');
      expect(buffer.length).toBe(14);
      const result = parseCompositionData(buffer);
      expect(result?.elements).toEqual([{ loc: 0x0000, sigModels: [], vendorModels: [] }]);
    });
  });

  describe('element count bounds (Section 4.2.2.1 lower bound, Section 2.3.4 upper bound)', () => {
    // Each synthetic element is the minimal 4-octet form (Loc=0x0000,
    // NumS=0, NumV=0) used above for the zero-models case - these tests
    // are purely about COUNTING elements, not about any one element's own
    // contents, so the cheapest valid element shape is used, repeated.
    const header = COMPOSITION_DATA_PAGE0_SAMPLE.message.slice(0, 20);
    const minimalElement = Buffer.from([0x00, 0x00, 0x00, 0x00]);

    function bufferWithElementCount(count: number): Buffer {
      return Buffer.concat([hex(header), Buffer.concat(Array(count).fill(minimalElement))]);
    }

    test('255 elements (1 primary + 254 secondary, Section 2.3.4) is accepted', () => {
      const result = parseCompositionData(bufferWithElementCount(255));
      expect(result?.elements).toHaveLength(255);
    });

    test('256 elements is rejected - past the Section 2.3.4 upper bound', () => {
      expect(parseCompositionData(bufferWithElementCount(256))).toBeNull();
    });
  });

  describe('two elements back to back (the published sample has only one)', () => {
    test('parses both elements, in order, from genuine published element bytes repeated twice', () => {
      const header = COMPOSITION_DATA_PAGE0_SAMPLE.message.slice(0, 20); // CID..Features, 10 octets = 20 hex chars
      const elementBytes = COMPOSITION_DATA_PAGE0_SAMPLE.message.slice(20); // the one published element, 18 octets
      const buffer = hex(header + elementBytes + elementBytes);

      const result = parseCompositionData(buffer);
      expect(result?.elements).toHaveLength(2);
      expect(result?.elements[0]).toEqual(COMPOSITION_DATA_PAGE0_SAMPLE.fields.elements[0]);
      expect(result?.elements[1]).toEqual(COMPOSITION_DATA_PAGE0_SAMPLE.fields.elements[0]);
    });

    test('truncating after the first complete element but partway through the second is still rejected', () => {
      const header = COMPOSITION_DATA_PAGE0_SAMPLE.message.slice(0, 20);
      const elementBytes = COMPOSITION_DATA_PAGE0_SAMPLE.message.slice(20);
      // First element complete (18 octets), second element header complete
      // (4 octets) but its model lists cut short.
      const buffer = hex(header + elementBytes + elementBytes.slice(0, 8));
      expect(parseCompositionData(buffer)).toBeNull();
    });
  });

  describe('Features bits 4-15 (RFU) never leak into a named flag, and every named bit is independently pinned', () => {
    // These two Features values are NOT published anywhere in the document -
    // only 0x0003 is (Section 8.10.1) - so they carry no specification
    // citation of their own; they exist purely to drive this module's own
    // bitmask arithmetic (Table 4.3's bit assignments, already cited in
    // composition.ts) down every path the one published sample cannot
    // reach, exactly as `provisioning/machine.ts`'s own tests added a
    // synthetic non-zero Flags byte for the same reason.
    const header = COMPOSITION_DATA_PAGE0_SAMPLE.message.slice(0, 16); // CID, PID, VID, CRPL (8 octets = 16 hex chars)
    const elementBytes = COMPOSITION_DATA_PAGE0_SAMPLE.message.slice(20);

    test('all four named bits set (0x000F) decode to all four flags true', () => {
      const buffer = hex(header + '0F00' + elementBytes);
      expect(parseCompositionData(buffer)?.features).toEqual({
        relay: true,
        proxy: true,
        friend: true,
        lowPower: true,
      });
    });

    test('only RFU bits set (0xFFF0, every named bit clear) decode to all four flags false', () => {
      const buffer = hex(header + 'F0FF' + elementBytes);
      expect(parseCompositionData(buffer)?.features).toEqual({
        relay: false,
        proxy: false,
        friend: false,
        lowPower: false,
      });
    });

    // Relay (bit 0) and Proxy (bit 1) had no isolation case of their own
    // until a review measured the gap: the ONE published Features value
    // (0x0003, Section 8.10.1) sets BOTH, and the synthetic cases above set
    // all four or none, so swapping the two bits' constants outright passed
    // all 542 tests. That is pointed here, because this task's whole errata
    // argument is about which of those two bits the published 0x0003 means
    // (see composition.ts's ERRATA note: the sample's prose says "Relay and
    // Friend", Table 4.3 says Relay and Proxy). These two cases pin each of
    // them alone.
    test('only Relay (bit 0, 0x0001) decodes to relay alone', () => {
      const buffer = hex(header + '0100' + elementBytes);
      expect(parseCompositionData(buffer)?.features).toEqual({
        relay: true,
        proxy: false,
        friend: false,
        lowPower: false,
      });
    });

    test('only Proxy (bit 1, 0x0002) decodes to proxy alone', () => {
      const buffer = hex(header + '0200' + elementBytes);
      expect(parseCompositionData(buffer)?.features).toEqual({
        relay: false,
        proxy: true,
        friend: false,
        lowPower: false,
      });
    });

    test('only Friend (bit 2, 0x0004) decodes to friend alone', () => {
      const buffer = hex(header + '0400' + elementBytes);
      expect(parseCompositionData(buffer)?.features).toEqual({
        relay: false,
        proxy: false,
        friend: true,
        lowPower: false,
      });
    });

    test('only Low Power (bit 3, 0x0008) decodes to lowPower alone', () => {
      const buffer = hex(header + '0800' + elementBytes);
      expect(parseCompositionData(buffer)?.features).toEqual({
        relay: false,
        proxy: false,
        friend: false,
        lowPower: true,
      });
    });
  });

  describe('does not retain a view into the caller-supplied buffer', () => {
    test('mutating the input buffer after parsing does not change the already-returned result', () => {
      const buffer = hex(COMPOSITION_DATA_PAGE0_SAMPLE.message);
      const result = parseCompositionData(buffer);
      expect(result).not.toBeNull();
      const before = JSON.parse(JSON.stringify(result));

      buffer.fill(0xff);

      expect(result).toEqual(before);
    });
  });
});
