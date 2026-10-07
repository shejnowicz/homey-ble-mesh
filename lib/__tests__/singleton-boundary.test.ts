import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Task 7 review finding (the THIRD appearance of this exact hazard in this
 * project, after driver.ts's own pairing store and this project's general
 * "singletons for a shared radio" pattern): `NetworkStore`'s sequence-number
 * allocator keeps its "next number" cursor IN MEMORY, loaded once at
 * construction (store.ts's own module header). A SECOND instance built over
 * the same settings starts from the same persisted ceiling and can reissue a
 * sequence number the first instance already used — since every message this
 * app sends shares one source address (ours), that number space is global,
 * not per-destination, so a receiving node's own replay protection then
 * silently drops whichever of two colliding messages it saw second. This was
 * fixed once already (driver.ts used to construct its own store for
 * pairing) and the fix was defended only by a comment — two mutations
 * reinstating a second instance survived the entire gate. This test makes
 * "exactly one `NetworkStore`, in app.ts" a MECHANICAL fact a mutation has
 * to defeat, not a convention to remember.
 *
 * Lives beside import-boundary.test.ts and uses the identical technique
 * (scan raw source text, not an AST, not a running app) for the identical
 * reason: this has to see `app.ts`/`driver.ts`/`device.ts`, every one of
 * which imports `homey` and so cannot be imported by a test itself.
 */

const PROJECT_ROOT = join(__dirname, '..', '..');
const EXCLUDED_DIR_NAMES = new Set(['node_modules', '.homeybuild', '.git', '__tests__']);

function listTsFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (EXCLUDED_DIR_NAMES.has(entry)) continue;
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

test('NetworkStore is constructed exactly once across the whole app, and that one place is app.ts', () => {
  const files = listTsFiles(PROJECT_ROOT);
  // Sanity check: make sure this walked a real, non-empty tree rather than
  // silently passing over nothing (the same discipline import-boundary.test.ts
  // already applies to its own walk).
  expect(files.length).toBeGreaterThan(0);

  const constructionSites: string[] = [];
  for (const file of files) {
    const source = readFileSync(file, 'utf8');
    const matches = source.match(/\bnew\s+NetworkStore\s*\(/g);
    for (let i = 0; i < (matches?.length ?? 0); i++) constructionSites.push(file);
  }

  expect(constructionSites).toEqual([join(PROJECT_ROOT, 'app.ts')]);
});
