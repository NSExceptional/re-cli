import { existsSync, readFileSync, writeFileSync, mkdirSync, statSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { expandHome } from './util.ts';
import type { REResult } from './result.ts';

function moduleSegment(module?: string): string {
  // Module install paths can contain slashes; flatten for filesystem use.
  return module ? module.replace(/[\/\\]/g, '_').replace(/^_+/, '') : '';
}

export function idbPath(cacheDir: string, hash: string, module?: string): string {
  const parts = [expandHome(cacheDir), 'idb', hash];
  if (module) parts.push(moduleSegment(module));
  parts.push('binary.i64');
  return join(...parts);
}

export function hopPath(cacheDir: string, hash: string, module?: string): string {
  const parts = [expandHome(cacheDir), 'hop', hash];
  if (module) parts.push(moduleSegment(module));
  parts.push('binary.hop');
  return join(...parts);
}

export function idbCacheDir(cacheDir: string, hash: string, module?: string): string {
  const parts = [expandHome(cacheDir), 'idb', hash];
  if (module) parts.push(moduleSegment(module));
  return join(...parts);
}

export function hasIdb(cacheDir: string, hash: string, module?: string): boolean {
  return existsSync(idbPath(cacheDir, hash, module));
}

export function hasHop(cacheDir: string, hash: string, module?: string): boolean {
  return existsSync(hopPath(cacheDir, hash, module));
}

export function resultPath(cacheDir: string, key: string): string {
  return join(expandHome(cacheDir), 'results', `${key}.json`);
}

export function getCachedResult(
  cacheDir: string,
  key: string,
  ttlSec: number,
): REResult | null {
  const p = resultPath(cacheDir, key);
  if (!existsSync(p)) return null;
  try {
    const ageSec = (Date.now() - statSync(p).mtimeMs) / 1000;
    if (ageSec > ttlSec) return null;
    return JSON.parse(readFileSync(p, 'utf8')) as REResult;
  } catch {
    return null;
  }
}

export function saveResult(cacheDir: string, key: string, result: REResult): void {
  const dir = join(expandHome(cacheDir), 'results');
  mkdirSync(dir, { recursive: true });
  writeFileSync(resultPath(cacheDir, key), JSON.stringify(result));
}

export function ensureIdbDir(cacheDir: string, hash: string, module?: string): string {
  const dir = idbCacheDir(cacheDir, hash, module);
  mkdirSync(dir, { recursive: true });
  return dir;
}

// Self-describing metadata written next to each cached database (idb/<hash>/meta.json), so a
// bare hash folder is identifiable — which binary it is, where it came from, how it was built.
export interface IdbMeta {
  name: string;                    // basename of the original binary
  path: string;                    // absolute path the binary was analyzed from
  arch?: string;                   // --arch slice, if any
  module?: string;                 // DSC module, if the source is a dyld shared cache
  backend: string;                 // 'ida' | 'hopper'
  backendVersion?: string | null;  // e.g. IDA kernel version
  binHash: string;                 // this folder's hash (self-reference)
  analyzedAt: string;              // ISO 8601 — when the database was built
  mtimeMs: number;                 // stat of the analyzed binary/slice (the hash inputs)
  size: number;                    // byte size of the analyzed binary/slice
}

export function writeIdbMeta(cacheDir: string, hash: string, module: string | undefined, meta: IdbMeta): void {
  try {
    const dir = idbCacheDir(cacheDir, hash, module);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'meta.json'), JSON.stringify(meta, null, 2) + '\n');
  } catch {
    // Metadata is best-effort — never fail a query because we couldn't write it.
  }
}

export function readIdbMeta(cacheDir: string, hash: string, module?: string): Partial<IdbMeta> | null {
  try {
    return JSON.parse(readFileSync(join(idbCacheDir(cacheDir, hash, module), 'meta.json'), 'utf8'));
  } catch {
    return null;
  }
}

// IDA's unpacked working files, which coexist with the packed binary.i64 only while a database
// is open. The daemon deletes them on a graceful exit; this is the backstop for a hard kill.
const IDB_UNPACKED_EXTS = ['id0', 'id1', 'id2', 'nam', 'til'];

// Remove unpacked working files a hard-killed (SIGKILL / power loss) daemon left behind, so IDA
// re-opens the packed binary.i64 cleanly and the ~GB of scratch doesn't linger. Keeps the .i64.
// Returns bytes reclaimed. Caller must ensure no live process still holds this database open.
export function purgeUnpackedIdb(idbDir: string): number {
  let freed = 0;
  for (const ext of IDB_UNPACKED_EXTS) {
    const f = join(idbDir, `binary.${ext}`);
    try { freed += statSync(f).size; unlinkSync(f); } catch { /* absent — fine */ }
  }
  return freed;
}
