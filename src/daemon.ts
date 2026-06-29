// Persistent disassembler daemon — keeps a backend process warm with the database
// loaded so a series of distinct queries against a large binary run at warm-cache speed
// instead of paying a cold multi-GB database load each time.
//
// The daemon process is a normal IDA/Hopper run launched with the `_daemon.py` bootstrap
// as its script; that bootstrap binds a Unix-domain socket and loops, exec'ing the exact
// same composed command scripts the CLI builds for one-shot runs (see scripts/*/_daemon.py
// and the RE_DAEMON note in scripts/*/_base.py). This module is the client side: it
// launches daemons, tracks them in a registry, and ships scripts to them over the socket.

import net from 'node:net';
import { spawn } from 'node:child_process';
import {
  existsSync, mkdirSync, writeFileSync, readFileSync, rmSync,
  readdirSync, openSync, closeSync,
} from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import process from 'node:process';
import type { BackendName } from './backends/types.ts';
import { buildIdaCommand } from './backends/ida.ts';
import { buildHopperCommand } from './backends/hopper.ts';
import { expandHome } from './util.ts';
import { startNarrator } from './progress.ts';

const SCRIPTS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts');

// Sockets live in a short, user-scoped dir to stay well under macOS's ~104-char
// Unix-domain socket path limit (the cache dir + a flattened module path would not).
const SOCK_DIR = `/tmp/re-cli-${typeof process.getuid === 'function' ? process.getuid() : 'u'}`;

export interface DaemonMeta {
  pid: number;
  socketPath: string;
  backend: BackendName;
  binaryPath: string;
  binHash: string;
  module?: string;
  startedAt: number;
}

export interface DaemonStatus {
  key: string;
  backend: BackendName;
  binaryPath: string;
  module?: string;
  pid: number;
  alive: boolean;
  startedAt: number;
  input?: string | null;
}

// What the runner hands us to launch/route a single query.
export interface DaemonRunSpec {
  cacheDir: string;
  backend: BackendName;
  toolPath: string;
  binHash: string;
  module?: string;
  binaryPath: string;       // original target path (for the registry + `daemon stop`)
  effectiveBinary: string;  // sliced/original binary the backend loads on fresh analysis
  idbPath?: string;         // cached .i64 to open (IDA fast-path)
  outputIdbPath?: string;   // where a fresh .i64 is saved (IDA, first analysis)
  hopPath?: string;         // cached .hop to open (Hopper fast-path)
  idleTimeout: number;      // seconds
  timeoutMs: number;        // startup/request cap; 0 = none
  extraEnv?: Record<string, string>;
  label: string;            // progress-narration label
}

export type DaemonOutcome =
  | { status: 'served' }                    // query ran; output file written as usual
  | { status: 'execError'; error: string }  // daemon ran the script but it crashed unexpectedly
  | { status: 'unavailable'; error: string }; // couldn't start/reach a daemon — caller should fall back

// ─── Keys & paths ─────────────────────────────────────────────────────────────

function shortHash(s: string): string {
  return createHash('sha256').update(s).digest('hex').slice(0, 8);
}

export function daemonKey(backend: BackendName, binHash: string, module?: string): string {
  return module ? `${backend}-${binHash}-${shortHash(module)}` : `${backend}-${binHash}`;
}

function registryDir(cacheDir: string, key: string): string {
  return join(expandHome(cacheDir), 'daemons', key);
}

function socketPathFor(key: string): string {
  return join(SOCK_DIR, `${key}.sock`);
}

function metaPath(dir: string): string {
  return join(dir, 'meta.json');
}

function readMeta(dir: string): DaemonMeta | null {
  try {
    return JSON.parse(readFileSync(metaPath(dir), 'utf8')) as DaemonMeta;
  } catch {
    return null;
  }
}

function writeMeta(dir: string, meta: DaemonMeta): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(metaPath(dir), JSON.stringify(meta));
}

function cleanup(dir: string, socketPath: string): void {
  try { rmSync(metaPath(dir), { force: true }); } catch {}
  try { rmSync(socketPath, { force: true }); } catch {}
}

// ─── Small process/socket helpers ──────────────────────────────────────────────

function pidAlive(pid: number): boolean {
  if (!pid || pid < 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (e) { return (e as NodeJS.ErrnoException)?.code === 'EPERM'; }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function canConnect(socketPath: string, timeoutMs = 1000): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = net.createConnection(socketPath);
    const done = (v: boolean) => { try { sock.destroy(); } catch {} resolve(v); };
    sock.once('connect', () => done(true));
    sock.once('error', () => done(false));
    sock.setTimeout(timeoutMs, () => done(false));
  });
}

// Length-prefixed (4-byte big-endian) JSON request/response over the UDS.
function sendRequest(socketPath: string, req: object, timeoutMs: number): Promise<any> {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(socketPath);
    const chunks: Buffer[] = [];
    let expected = -1;
    let settled = false;
    const fail = (e: unknown) => { if (!settled) { settled = true; try { sock.destroy(); } catch {} reject(e); } };
    const ok = (v: unknown) => { if (!settled) { settled = true; try { sock.end(); } catch {} resolve(v); } };

    sock.once('connect', () => {
      const body = Buffer.from(JSON.stringify(req), 'utf8');
      const hdr = Buffer.alloc(4);
      hdr.writeUInt32BE(body.length, 0);
      sock.write(hdr);
      sock.write(body);
    });
    sock.on('data', (d) => {
      chunks.push(d);
      const buf = Buffer.concat(chunks);
      if (expected < 0 && buf.length >= 4) expected = buf.readUInt32BE(0);
      if (expected >= 0 && buf.length >= 4 + expected) {
        try { ok(JSON.parse(buf.subarray(4, 4 + expected).toString('utf8'))); }
        catch (e) { fail(e); }
      }
    });
    sock.once('error', fail);
    // Inactivity cap. 0 = none: a warm query is fast, but a slow first decompile etc.
    // should not be cut off unless the user asked for a timeout.
    if (timeoutMs > 0) sock.setTimeout(timeoutMs, () => fail(new Error('daemon request timed out')));
  });
}

// Poll until the daemon's socket is connectable (== ready, since it binds only after
// analysis). Narrates progress; bails if the process backing the daemon dies first.
async function waitReady(
  socketPath: string,
  logPath: string,
  label: string,
  timeoutMs: number,
  isAlive?: () => boolean,
): Promise<boolean> {
  const stop = startNarrator(logPath, label);
  const start = Date.now();
  try {
    while (true) {
      if (await canConnect(socketPath)) return true;
      if (timeoutMs > 0 && Date.now() - start > timeoutMs) return false;
      if (isAlive && !isAlive()) return false;
      await sleep(400);
    }
  } finally {
    stop();
  }
}

// ─── Launch ─────────────────────────────────────────────────────────────────────

function spawnDaemon(spec: DaemonRunSpec, key: string, socketPath: string, logPath: string): number {
  mkdirSync(SOCK_DIR, { recursive: true, mode: 0o700 });
  const daemonScript = join(SCRIPTS_DIR, spec.backend, '_daemon.py');

  const invoke = {
    binaryPath: spec.effectiveBinary,
    idbPath: spec.idbPath,
    outputIdbPath: spec.outputIdbPath,
    hopPath: spec.hopPath,
    scriptPath: daemonScript,
    logPath,
    module: spec.module,
  };
  const { cmd, args } = spec.backend === 'ida'
    ? buildIdaCommand(invoke, spec.toolPath)
    : buildHopperCommand(invoke, spec.toolPath);

  const env: Record<string, string> = {
    ...process.env as Record<string, string>,
    ...(spec.extraEnv ?? {}),
    RE_DAEMON: '1',
    RE_DAEMON_SOCKET: socketPath,
    RE_DAEMON_IDLE: String(spec.idleTimeout),
  };
  // IDA never calls qexit in daemon mode, so its save-on-exit won't fire; tell the
  // bootstrap to persist a freshly analyzed .i64 so later one-shot runs can reuse it.
  if (spec.backend === 'ida' && spec.outputIdbPath) env.RE_DAEMON_SAVE_IDB = spec.outputIdbPath;

  // IDA writes its analysis log via -L<logPath>; Hopper has no -L, so capture its
  // stdout/stderr (incl. the bootstrap's own progress lines) into the same log file.
  let stdio: 'ignore' | ['ignore', number, number] = 'ignore';
  let logFd: number | undefined;
  if (spec.backend === 'hopper') {
    logFd = openSync(logPath, 'a');
    stdio = ['ignore', logFd, logFd];
  }

  const child = spawn(cmd, args, { detached: true, stdio, env });
  const pid = child.pid ?? -1;
  child.unref();
  if (logFd !== undefined) { try { closeSync(logFd); } catch {} }
  return pid;
}

async function ensureReady(spec: DaemonRunSpec, key: string, socketPath: string, dir: string, logPath: string)
  : Promise<{ ok: true } | { ok: false; error: string }> {
  // 1. Reuse a healthy existing daemon. (binaryHash already keys on path+mtime+size, so a
  //    changed binary routes to a different key — no explicit staleness recheck needed.)
  const existing = readMeta(dir);
  if (existing && pidAlive(existing.pid) && await canConnect(socketPath)) {
    return { ok: true };
  }
  if (existing && !pidAlive(existing.pid)) cleanup(dir, socketPath);

  // 2. Become the starter, or wait for whoever already is. Atomic mkdir is the lock so
  //    two concurrent first-queries can't both analyze.
  const lockDir = join(dir, 'lock');
  let haveLock = false;
  try {
    mkdirSync(dir, { recursive: true });
    mkdirSync(lockDir);
    haveLock = true;
  } catch {
    haveLock = false;
  }

  if (haveLock) {
    try {
      try { writeFileSync(join(lockDir, 'pid'), String(process.pid)); } catch {}
      const pid = spawnDaemon(spec, key, socketPath, logPath);
      const ready = await waitReady(socketPath, logPath, spec.label, spec.timeoutMs, () => pidAlive(pid));
      if (!ready) return { ok: false, error: 'daemon failed to become ready' };
      writeMeta(dir, {
        pid, socketPath, backend: spec.backend,
        binaryPath: spec.binaryPath, binHash: spec.binHash,
        ...(spec.module ? { module: spec.module } : {}),
        startedAt: Date.now(),
      });
      return { ok: true };
    } finally {
      try { rmSync(lockDir, { recursive: true, force: true }); } catch {}
    }
  }

  // 3. Another process is starting it — wait for its socket, bailing if that starter dies.
  const starterPid = (() => {
    try { return Number(readFileSync(join(lockDir, 'pid'), 'utf8')); } catch { return 0; }
  })();
  if (starterPid) {
    process.stderr.write(`[re] another re process is starting a daemon for this binary (pid ${starterPid}); waiting…\n`);
  }
  const starterAlive = () => {
    try { return pidAlive(Number(readFileSync(join(lockDir, 'pid'), 'utf8'))); }
    catch { return existsSync(lockDir); }
  };
  const ready = await waitReady(socketPath, logPath, spec.label, spec.timeoutMs, starterAlive);
  if (ready) return { ok: true };
  return { ok: false, error: 'daemon (started by another process) did not become ready' };
}

// Cheap check: is a healthy daemon already serving this key? Used by the runner to
// decide strategy — a live daemon holds an exclusive lock on the database, so a
// one-shot run against the same binary would fail to open it.
export async function probeDaemon(
  cacheDir: string,
  backend: BackendName,
  binHash: string,
  module?: string,
): Promise<boolean> {
  const key = daemonKey(backend, binHash, module);
  const dir = registryDir(cacheDir, key);
  const meta = readMeta(dir);
  if (!meta) return false;
  if (!pidAlive(meta.pid)) { cleanup(dir, socketPathFor(key)); return false; }
  return canConnect(meta.socketPath);
}

// ─── Public entry: run one query through a (possibly auto-started) daemon ────────

export async function runOnDaemon(spec: DaemonRunSpec, scriptText: string): Promise<DaemonOutcome> {
  const key = daemonKey(spec.backend, spec.binHash, spec.module);
  const socketPath = socketPathFor(key);
  const dir = registryDir(spec.cacheDir, key);
  const logPath = join(dir, 'daemon.log');

  const ready = await ensureReady(spec, key, socketPath, dir, logPath);
  if (!ready.ok) return { status: 'unavailable', error: ready.error };

  try {
    const resp = await sendRequest(socketPath, { id: 1, type: 'exec', script: scriptText }, spec.timeoutMs);
    if (resp?.ok) return { status: 'served' };
    return { status: 'execError', error: String(resp?.error ?? 'daemon exec failed') };
  } catch (e) {
    // Connection dropped mid-flight (e.g. daemon crashed): let the caller fall back.
    return { status: 'unavailable', error: `daemon request failed: ${e instanceof Error ? e.message : String(e)}` };
  }
}

// ─── Management (re daemon list/stop) ────────────────────────────────────────────

export async function listDaemons(cacheDir: string): Promise<DaemonStatus[]> {
  const base = join(expandHome(cacheDir), 'daemons');
  if (!existsSync(base)) return [];
  const out: DaemonStatus[] = [];
  for (const key of readdirSync(base)) {
    const dir = join(base, key);
    const meta = readMeta(dir);
    if (!meta) continue;
    const alive = pidAlive(meta.pid) && await canConnect(meta.socketPath);
    let input: string | null = null;
    if (alive) {
      try {
        const r = await sendRequest(meta.socketPath, { id: 1, type: 'ping' }, 2000);
        input = r?.meta?.input ?? null;
      } catch {}
    } else {
      cleanup(dir, meta.socketPath); // prune dead entries lazily
    }
    out.push({
      key, backend: meta.backend, binaryPath: meta.binaryPath,
      module: meta.module, pid: meta.pid, alive, startedAt: meta.startedAt, input,
    });
  }
  return out;
}

async function stopDaemonByKey(cacheDir: string, key: string): Promise<boolean> {
  const dir = registryDir(cacheDir, key);
  const meta = readMeta(dir);
  if (!meta) return false;
  let stopped = false;
  try { await sendRequest(meta.socketPath, { id: 1, type: 'quit' }, 3000); stopped = true; } catch {}
  if (pidAlive(meta.pid)) { try { process.kill(meta.pid, 'SIGTERM'); stopped = true; } catch {} }
  cleanup(dir, meta.socketPath);
  return stopped;
}

export async function stopDaemonsForBinary(cacheDir: string, binaryPath: string): Promise<number> {
  const list = await listDaemons(cacheDir);
  let n = 0;
  for (const d of list) {
    if (d.binaryPath === binaryPath && await stopDaemonByKey(cacheDir, d.key)) n++;
  }
  return n;
}

export async function stopAllDaemons(cacheDir: string): Promise<number> {
  const list = await listDaemons(cacheDir);
  let n = 0;
  for (const d of list) {
    if (await stopDaemonByKey(cacheDir, d.key)) n++;
  }
  return n;
}
