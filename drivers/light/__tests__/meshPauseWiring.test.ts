import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * `lib/adapter/__tests__/meshPause.test.ts` pins the pause ITSELF — that it
 * waits for the teardown, bounds the wait, and resumes only when the mesh
 * had been running. Nothing there can see whether `driver.ts` and `app.ts`
 * still USE it: both import `homey`, so no jest test can import either
 * (`import-boundary.test.ts` and `device-wiring.test.ts` both record the
 * same constraint and the same consequence).
 *
 * That gap is exactly where the 2026-10-09 defect lived. The ordering rule
 * was four lines inside `driver.ts#onPair`, outside the gate, and the whole
 * gate passed with the disconnect unawaited. So this scans the source text,
 * the same technique `device-wiring.test.ts` uses for the same reason: it
 * cannot prove the wiring is CORRECT — `meshPause.test.ts` does that — only
 * that these two files still route through the tested code instead of
 * growing a second, untested copy of it.
 */

const DRIVER_TS = join(__dirname, '..', 'driver.ts');
const APP_TS = join(__dirname, '..', '..', '..', 'app.ts');

function read(file: string): string {
  return readFileSync(file, 'utf8');
}

describe('driver.ts pairs through the shared, tested withMeshPaused', () => {
  const source = read(DRIVER_TS);

  test('it imports withMeshPaused from lib/adapter/meshPause', () => {
    expect(source).toMatch(/import\s*\{[^}]*\bwithMeshPaused\b[^}]*\}\s*from\s*'\.\.\/\.\.\/lib\/adapter\/meshPause'/);
  });

  test('it defines no withMeshPaused of its own', () => {
    // A local re-definition would shadow the import and silently take the
    // ordering rule back out of the gate — which is how this shipped.
    expect(source).not.toMatch(/(?:const|let|var|function)\s+withMeshPaused\b/);
  });

  test('BOTH pairing handlers run inside withMeshPaused — the multi-bulb one is where two live GATT connections would actually happen', () => {
    // Inherited from `device-wiring.test.ts`, where this assertion lived
    // until `withMeshPaused` moved into lib/adapter: the whole reason the
    // pause exists is the second bulb onward, which is precisely what
    // `pair_nodes` is for. A multi-bulb handler that skipped it would
    // reintroduce the hazard the single-bulb one was fixed for.
    const wrapped = source.match(/withMeshPaused\(host,/g) ?? [];
    expect(wrapped).toHaveLength(2);
    for (const handler of ['pair_node', 'pair_nodes']) {
      const start = source.indexOf(`setHandler('${handler}'`);
      expect(start).toBeGreaterThan(-1);
      // The wrapper must be the FIRST thing the handler does, before any
      // call that touches the radio.
      expect(source.slice(start, start + 400)).toMatch(/withMeshPaused\(host,/);
    }
  });

  test('it never calls pauseMeshForPairing itself', () => {
    // The only legitimate caller is `withMeshPaused`. A direct call here
    // would be a second, unawaited pause path.
    expect(source).not.toMatch(/host\.pauseMeshForPairing\(/);
  });
});

describe('app.ts delegates the pause to the tested implementation', () => {
  const source = read(APP_TS);

  test('pauseMeshForPairing is async and returns pauseProxyForPairing', () => {
    expect(source).toMatch(/async pauseMeshForPairing\(\): Promise<boolean>/);
    const start = source.indexOf('async pauseMeshForPairing(): Promise<boolean>');
    const body = source.slice(start, source.indexOf('\n  }', start));
    expect(body).toMatch(/return pauseProxyForPairing\(/);
    // The manager must not be stopped here as well — that is
    // `pauseProxyForPairing`'s job, and doing it twice would mean the
    // second stop happens with nothing left to wait for.
    expect(body).not.toMatch(/\.stop\(\)/);
  });

  test('it imports pauseProxyForPairing from lib/adapter/meshPause', () => {
    expect(source).toMatch(/import\s*\{[^}]*\bpauseProxyForPairing\b[^}]*\}\s*from\s*'\.\/lib\/adapter\/meshPause'/);
  });
});
