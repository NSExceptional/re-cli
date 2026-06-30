import { createHash, randomBytes } from 'node:crypto';
import { statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';

export function binaryHash(filePath: string): string {
  const stat = statSync(filePath);
  const h = createHash('sha256');
  h.update(filePath);
  h.update(String(stat.mtimeMs));
  h.update(String(stat.size));
  return h.digest('hex').slice(0, 16);
}

// Architectures in a Mach-O, via `lipo -archs`. A thin binary reports its single arch (e.g.
// ["arm64"]); a fat binary reports several. Returns [] when lipo can't read the file. Used to
// treat `--arch X` as a no-op on a binary that is ALREADY thin X, so the run path and
// status/wait resolve the same cache key instead of disagreeing (a thin binary has no slice to
// extract, so it keys on its whole-binary hash everywhere).
export function machoArchs(filePath: string): string[] {
  try {
    const r = spawnSync('lipo', ['-archs', filePath], { encoding: 'utf8' });
    if (r.status !== 0 || !r.stdout) return [];
    return r.stdout.trim().split(/\s+/).filter(Boolean);
  } catch {
    return [];
  }
}

export function resultKey(
  binHash: string,
  command: string,
  params: Record<string, unknown>,
): string {
  const h = createHash('sha256');
  h.update(binHash);
  h.update(command);
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(params).sort()) sorted[k] = params[k];
  h.update(JSON.stringify(sorted));
  return h.digest('hex').slice(0, 20);
}

export function randomId(): string {
  return randomBytes(8).toString('hex');
}

export function expandHome(p: string): string {
  return p.startsWith('~') ? p.replace('~', homedir()) : p;
}

export function elapsed(startMs: number): number {
  return Math.round((Date.now() - startMs) / 10) / 100;
}
