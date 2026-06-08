import { existsSync, readFileSync, writeFileSync, mkdirSync, statSync } from 'node:fs';
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
