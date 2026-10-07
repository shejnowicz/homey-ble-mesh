import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The architecture's load-bearing rule: lib/mesh must never import `homey`
 * or any Node module that performs I/O; only `node:crypto` is allowed. This
 * walks every .ts file under lib/mesh and enforces that for real, rather
 * than leaving it as a comment (see lib/mesh/index.ts).
 *
 * lib/models (the Bluetooth SIG Mesh Model layer - lighting et al., built on
 * top of lib/mesh/packet/access.ts) is held to the exact same rule (this
 * project's own ruling for that plan of work, not a separate relaxation):
 * a model is pure wire-format encode/decode, with no more business sending
 * I/O than the packet layer underneath it has. Both roots are walked by the
 * same loop below, rather than lib/models getting a second, drifted copy of
 * this check.
 *
 * This checker deliberately lives OUTSIDE both policed directories (at
 * lib/__tests__, a sibling of each) rather than inside either one: the
 * check itself needs node:fs and node:path to walk the tree, and living
 * outside the directories it polices means it is never itself a file the
 * rule has to make an exception for.
 */
const POLICED_ROOTS = [join(__dirname, '..', 'mesh'), join(__dirname, '..', 'models')];

function listTsFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      files.push(...listTsFiles(full));
    } else if (entry.endsWith('.ts')) {
      files.push(full);
    }
  }
  return files;
}

// Every way a module specifier can appear in TypeScript/CommonJS source:
// static `import ... from '...'`, side-effect `import '...'`,
// `export ... from '...'`, `require('...')` and dynamic `import('...')`.
const IMPORT_PATTERNS = [
  /\bfrom\s+['"]([^'"]+)['"]/g,
  /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\bimport\(\s*['"]([^'"]+)['"]\s*\)/g,
  /^\s*import\s+['"]([^'"]+)['"]/gm,
];

function extractSpecifiers(source: string): string[] {
  const specifiers: string[] = [];
  for (const pattern of IMPORT_PATTERNS) {
    for (const match of source.matchAll(pattern)) {
      const specifier = match[1];
      if (specifier) specifiers.push(specifier);
    }
  }
  return specifiers;
}

function isAllowed(specifier: string): boolean {
  return specifier.startsWith('.') || specifier === 'node:crypto';
}

test('lib/mesh and lib/models files only import relative modules or node:crypto', () => {
  const files = POLICED_ROOTS.flatMap((root) => listTsFiles(root));
  // Sanity check: make sure this walked real, non-empty trees rather than
  // silently passing over nothing - lib/models existing but empty (or not
  // existing yet) would otherwise make this test vacuously pass.
  expect(files.length).toBeGreaterThan(0);
  for (const root of POLICED_ROOTS) {
    expect(listTsFiles(root).length).toBeGreaterThan(0);
  }

  const violations: string[] = [];
  for (const file of files) {
    const source = readFileSync(file, 'utf8');
    for (const specifier of extractSpecifiers(source)) {
      if (!isAllowed(specifier)) {
        violations.push(`${file}: '${specifier}'`);
      }
    }
  }
  expect(violations).toEqual([]);
});

describe('the specifier check itself rejects what it must', () => {
  test.each([
    'crypto',
    'node:fs',
    'node:net',
    'homey',
  ])('%s is not allowed', (specifier) => {
    expect(isAllowed(specifier)).toBe(false);
  });

  test.each([
    './cmac',
    '../derive',
    'node:crypto',
  ])('%s is allowed', (specifier) => {
    expect(isAllowed(specifier)).toBe(true);
  });
});

/**
 * A DIFFERENT, narrower rule for ONE file outside both policed roots above —
 * review finding (smaller item): `drivers/light/pairing.ts` is deliberately
 * pure orchestration with no `homey` import (its own module header: "the
 * ONE file in drivers/light that imports homey" is `driver.ts`, not this
 * one), and nothing previously checked that mechanically. A mutation adding
 * `import Homey from 'homey'` to pairing.ts still typechecks cleanly
 * (`@types/homey` resolves fine) and only fails once ts-jest actually tries
 * to RUN the test file with no real `homey` package installed — i.e. the
 * TYPE system alone cannot catch this regression, only a test can. This is
 * a DENY-list, not the ALLOW-list the two policed roots above use:
 * `pairing.ts` legitimately imports many relative modules (and could
 * legitimately import other node builtins later), so the only thing worth
 * asserting here is the one specifier it must never contain.
 */
test('drivers/light/pairing.ts never imports homey', () => {
  const file = join(__dirname, '..', '..', 'drivers', 'light', 'pairing.ts');
  const source = readFileSync(file, 'utf8');
  const specifiers = extractSpecifiers(source);
  expect(specifiers).not.toContain('homey');
});
