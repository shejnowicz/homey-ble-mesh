/**
 * The integer-field range guard and the four field widths it is used
 * against, shared across the packet layer's modules instead of each one
 * keeping its own copy.
 *
 * Widths are taken from Mesh Protocol v1.1 Table 3.10 "Network PDU field
 * definitions" (TTL 7 bits, SEQ 24 bits, SRC/DST 16 bits), repeated in
 * Table 3.67 "CTL and TTL field format" (TTL) and Table 3.66 "Network
 * nonce format" (SEQ 3 octets, SRC 2 octets, IV Index 4 octets), and
 * Section 3.9.4 "IV Index", which states directly that "the IV Index is a
 * 32-bit value".
 */

export const MAX_TTL = 0x7f; // 7 bits (Table 3.10, Table 3.67).
export const MAX_SEQ = 0xffffff; // 24 bits (Table 3.10; Section 3.4.4.5; Table 3.66).
export const MAX_ADDRESS = 0xffff; // 16 bits (Table 3.10; Table 3.5 "16-bit address allocations").
export const MAX_IV_INDEX = 0xffffffff; // 32 bits (Section 3.9.4; Table 3.66).

/**
 * Throws when `value` is not an integer in `[0, max]`. `name` is the
 * caller-supplied prefix identifying both the module and the field - e.g.
 * `nonce field "ttl"` or `network PDU field "seq"` - so each module's
 * error messages stay exactly as specific as they were before this guard
 * was shared.
 */
export function assertRange(name: string, value: number, max: number): void {
  if (!Number.isInteger(value) || value < 0 || value > max) {
    throw new Error(`${name} must be an integer in [0, ${max}], got ${value}`);
  }
}
