import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * A Homey driver/device/app module must end with `module.exports = <Class>`,
 * which is how the platform loads it. That assignment REPLACES the module's
 * exports object outright, so any `export class`/`export const`/
 * `export function` in the same file becomes unreachable at runtime: the
 * compiler writes it onto the original `exports` object, and
 * `module.exports = …` then throws that object away.
 *
 * TypeScript does not warn, and neither does jest — both resolve a named
 * export at compile time, from the source, never from the CommonJS artifact
 * the hub actually requires. The project shipped exactly this defect to the
 * owner's own hardware: `app.ts` imported `HomeyBluetoothPort` from
 * `drivers/light/driver.ts`, and pairing died with
 * "driver_1.HomeyBluetoothPort is not a constructor" AFTER a clean scan had
 * already found all three bulbs. 1027 passing tests had nothing to say about
 * it, because not one of them imported that class.
 *
 * So this is a source-level check, like its sibling import-boundary test: it
 * reads the files rather than importing them, because importing is precisely
 * the thing that cannot see the bug.
 *
 * TYPE-ONLY exports are exempt and deliberately so. `export interface` and
 * `export type` are erased before any JavaScript exists, so nothing can look
 * them up at runtime and nothing can be undefined.
 */
const ROOTS = [join(__dirname, '..', '..', 'drivers'), join(__dirname, '..', '..')];

function listTsFiles(dir: string, recurse: boolean): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '.homeybuild' || entry === '__tests__') continue;
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      if (recurse) files.push(...listTsFiles(full, true));
    } else if (entry.endsWith('.ts') && !entry.endsWith('.test.ts')) {
      files.push(full);
    }
  }
  return files;
}

/** Every `export` that produces a runtime binding. `export type` and
 *  `export interface` are absent on purpose — see the header. */
const RUNTIME_EXPORT = /^export\s+(?:default\s+|abstract\s+)?(?:class|const|function|let|var|enum)\b/m;
const CLOBBERS_EXPORTS = /^module\.exports\s*=/m;

describe('a module that assigns module.exports has no named runtime exports', () => {
  const candidates = [
    ...listTsFiles(ROOTS[0] as string, true),
    ...listTsFiles(ROOTS[1] as string, false),
  ];

  test('the scan actually found the project files it polices', () => {
    // Guards the guard: a listTsFiles that silently returned [] would make
    // every assertion below vacuous, which is the failure mode this whole
    // file exists to prevent.
    expect(candidates.length).toBeGreaterThanOrEqual(3);
    expect(candidates.some((f) => f.endsWith('app.ts'))).toBe(true);
    expect(candidates.some((f) => f.endsWith(join('light', 'driver.ts')))).toBe(true);
  });

  for (const file of candidates) {
    const source = readFileSync(file, 'utf8');
    if (!CLOBBERS_EXPORTS.test(source)) continue;

    test(`${file} exports nothing that module.exports would discard`, () => {
      const offenders = source
        .split('\n')
        .map((line, index) => ({ line, number: index + 1 }))
        .filter(({ line }) => RUNTIME_EXPORT.test(line));

      expect(
        offenders.map(({ number, line }) => `${number}: ${line.trim()}`),
      ).toEqual([]);
    });
  }
});
