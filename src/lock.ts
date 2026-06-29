// Advisory lock around a one-shot fresh analysis. Without it, two `re` invocations
// that both miss the cache run `idat64 -A -c -o<same .i64>` concurrently and clobber
// each other's database (observed in the field as two idat64 processes on one binary).
// The daemon path has its own startup lock (see daemon.ts); this covers the one-shot
// path the daemon decision skips (--daemon=off, sub-gate sizes, --no-idb-cache).
//
// The lock is an atomic `mkdir` — the same primitive daemon.ts uses — keyed the same
// way as a daemon, so the two never analyze the same binary at once.

import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';
import { expandHome } from './util.ts';

export interface AnalysisLock {
  release(): void;
}

interface Held {
  acquired: true;
  lock: AnalysisLock;
}
interface Contended {
  acquired: false;
  holderPid: number;
  startedAt: number;
}

function lockDir(cacheDir: string, key: string): string {
  return join(expandHome(cacheDir), 'analysis-locks', key);
}

function pidAlive(pid: number): boolean {
  if (!pid || pid < 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (e) { return (e as NodeJS.ErrnoException)?.code === 'EPERM'; }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// Try to take the lock. If held by a live process, report the holder; if held by a
// dead one (crashed mid-analysis), reclaim it.
export function tryAcquireAnalysisLock(cacheDir: string, key: string): Held | Contended {
  const dir = lockDir(cacheDir, key);
  mkdirSync(join(expandHome(cacheDir), 'analysis-locks'), { recursive: true });
  try {
    mkdirSync(dir);  // atomic: throws EEXIST if another holder exists
  } catch {
    let holderPid = 0;
    let startedAt = 0;
    try {
      const m = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8')) as { pid: number; startedAt: number };
      holderPid = m.pid; startedAt = m.startedAt;
    } catch {}
    if (holderPid && !pidAlive(holderPid)) {
      // Stale lock from a crashed run — clear and retry once.
      try { rmSync(dir, { recursive: true, force: true }); } catch {}
      return tryAcquireAnalysisLock(cacheDir, key);
    }
    return { acquired: false, holderPid, startedAt };
  }
  try { writeFileSync(join(dir, 'meta.json'), JSON.stringify({ pid: process.pid, startedAt: Date.now() })); } catch {}
  let released = false;
  return {
    acquired: true,
    lock: { release() { if (released) return; released = true; try { rmSync(dir, { recursive: true, force: true }); } catch {} } },
  };
}

// Who, if anyone, currently holds the analysis lock for this key (for `re status`).
// Returns null if free or held only by a dead process.
export function analysisLockHolder(cacheDir: string, key: string): { pid: number; startedAt: number } | null {
  const dir = lockDir(cacheDir, key);
  if (!existsSync(dir)) return null;
  try {
    const m = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8')) as { pid: number; startedAt: number };
    if (m.pid && !pidAlive(m.pid)) return null;
    return { pid: m.pid, startedAt: m.startedAt };
  } catch {
    return { pid: 0, startedAt: 0 };  // lock dir exists but meta not yet written
  }
}

// Block until the current holder releases the lock or dies. Polls cheaply.
export async function waitForAnalysisLock(cacheDir: string, key: string): Promise<void> {
  const dir = lockDir(cacheDir, key);
  while (existsSync(dir)) {
    let holderPid = 0;
    try {
      holderPid = (JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8')) as { pid: number }).pid;
    } catch {}
    if (holderPid && !pidAlive(holderPid)) return;  // holder died; caller will reclaim
    await sleep(500);
  }
}
