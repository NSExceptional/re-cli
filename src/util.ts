import { createHash, randomBytes } from 'node:crypto';
import { statSync, renameSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';

// A cached database at or above this size is backed up (not destroyed) before a forced
// overwrite — a big .i64 represents hours of analysis. Small ones are cheap to rebuild.
export const IDB_BACKUP_THRESHOLD_BYTES = 2 * 1024 ** 3;  // 2 GB

// Preserve a LARGE existing database before a forced overwrite destroys it, by renaming it to
// `<path>.<unix-ts>.bak` (a same-directory move — instant, no multi-GB copy). Returns the backup
// path if one was made; null if the file is absent or below the threshold (overwrite in place).
// THROWS if a large database exists but couldn't be moved — the caller must then refuse the
// overwrite rather than destroy hours of work without a backup.
export function backupLargeIdb(idbPath: string, thresholdBytes = IDB_BACKUP_THRESHOLD_BYTES): string | null {
  let size: number;
  try {
    size = statSync(idbPath).size;
  } catch {
    return null;  // nothing there to back up
  }
  if (size <= thresholdBytes) return null;  // small — safe to overwrite without a backup
  const backup = `${idbPath}.${Math.floor(Date.now() / 1000)}.bak`;
  renameSync(idbPath, backup);
  return backup;
}

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
