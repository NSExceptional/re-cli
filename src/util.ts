import { createHash, randomBytes } from 'node:crypto';
import { statSync } from 'node:fs';
import { homedir } from 'node:os';

export function binaryHash(filePath: string): string {
  const stat = statSync(filePath);
  const h = createHash('sha256');
  h.update(filePath);
  h.update(String(stat.mtimeMs));
  h.update(String(stat.size));
  return h.digest('hex').slice(0, 16);
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
