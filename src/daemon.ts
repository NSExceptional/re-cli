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
import { expandHome, backupLargeIdb } from './util.ts';
import { purgeUnpackedIdb } from './cache.ts';
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
  force?: boolean;          // allow a fresh analysis to overwrite an existing .i64 at outputIdbPath
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
  // Remove the WHOLE registry dir, not just meta.json. It's runtime state for one live daemon
  // (meta.json liveness record + daemon.log + lock/), so once that process is gone it's pure
  // clutter — a heavily-analyzed binary leaves a multi-hundred-MB daemon.log behind. A later
  // start recreates the dir. The socket lives under /tmp (not in dir), so unlink it separately.
  try { rmSync(dir, { recursive: true, force: true }); } catch {}
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

// ─── Streaming request (issue #13) ──────────────────────────────────────────────
//
// A streaming exec differs from `sendRequest` in that the daemon emits MANY framed
// messages for one request: zero-or-more non-terminal frames (carrying `partial`/
// `progress` payloads) followed by exactly one terminal frame. Each frame is the same
// length-prefixed (4-byte big-endian) JSON envelope used elsewhere; we just keep reading
// frames off the same connection until we see one tagged `final: true`.
//
// This is how we satisfy spec §11.1's GOAL ("a live IDA that streams") without building a
// separate `idat64 --listen` — the existing warm daemon already IS a persistent IDA, so
// we extend its socket protocol to multiplex frames instead of returning a single {ok}.

export interface StreamFrame {
  // What kind of payload this frame carries. The daemon-side streaming script tags each
  // emitted frame; the runner translates these into spec events.
  kind: 'partial' | 'progress' | 'final' | 'log';
  final?: boolean;
  // partial: an array of raw item dicts (op-internal key names).
  items?: Record<string, unknown>[];
  // progress: phase/percent hints.
  phase?: string;
  percent?: number | null;
  // final: terminal status from the script's perspective.
  ok?: boolean;
  reason?: string;       // 'natural' | 'db_settled' | 'max_matches' | 'max_wait' (script view)
  error?: string;        // populated when ok === false
  count?: number;        // total items the script delivered
}

export interface StreamExecHandle {
  // Resolves when the terminal frame arrives or the connection ends.
  done: Promise<{ terminal: StreamFrame | null; closedEarly: boolean }>;
  // Ask the daemon to stop the in-flight stream early (best-effort: closes the
  // connection, which the daemon-side loop treats as a cooperative stop signal).
  stop(): void;
}

// Open a streaming exec on the daemon. `onFrame` is invoked for every non-terminal frame
// as it arrives. The returned handle's `done` settles on the terminal frame.
export function streamExecOnDaemon(
  socketPath: string,
  scriptText: string,
  deadlineSec: number,
  onFrame: (f: StreamFrame) => void,
  timeoutMs: number,
  op?: string,
): StreamExecHandle {
  let resolveDone!: (v: { terminal: StreamFrame | null; closedEarly: boolean }) => void;
  let rejectDone!: (e: unknown) => void;
  const done = new Promise<{ terminal: StreamFrame | null; closedEarly: boolean }>((res, rej) => {
    resolveDone = res; rejectDone = rej;
  });

  const sock = net.createConnection(socketPath);
  let buf = Buffer.alloc(0);
  let expected = -1;
  let settled = false;
  let terminal: StreamFrame | null = null;

  const finish = (closedEarly: boolean) => {
    if (settled) return;
    settled = true;
    try { sock.end(); } catch {}
    resolveDone({ terminal, closedEarly });
  };
  const fail = (e: unknown) => {
    if (settled) return;
    settled = true;
    try { sock.destroy(); } catch {}
    rejectDone(e);
  };

  sock.once('connect', () => {
    const req = { id: 1, type: 'stream_exec', script: scriptText, deadline: deadlineSec, op };
    const body = Buffer.from(JSON.stringify(req), 'utf8');
    const hdr = Buffer.alloc(4);
    hdr.writeUInt32BE(body.length, 0);
    sock.write(hdr);
    sock.write(body);
  });

  sock.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    // Drain as many complete frames as are buffered.
    for (;;) {
      if (expected < 0) {
        if (buf.length < 4) break;
        expected = buf.readUInt32BE(0);
      }
      if (buf.length < 4 + expected) break;
      const frameBuf = buf.subarray(4, 4 + expected);
      buf = buf.subarray(4 + expected);
      expected = -1;
      let frame: StreamFrame;
      try { frame = JSON.parse(frameBuf.toString('utf8')) as StreamFrame; }
      catch (e) { fail(e); return; }
      if (frame.kind === 'final' || frame.final) {
        terminal = frame;
        finish(false);
        return;
      }
      try { onFrame(frame); } catch {}
    }
  });

  sock.once('error', fail);
  // The connection ending without a terminal frame is "closed early" (e.g. daemon died
  // mid-stream); the runner synthesizes a terminal event so the caller never gets NoOutput.
  sock.once('close', () => finish(true));
  if (timeoutMs > 0) sock.setTimeout(timeoutMs, () => fail(new Error('daemon stream timed out')));

  return {
    done,
    stop() { try { sock.end(); } catch {} },
  };
}

// Poll until the daemon's socket is connectable (== ready, since it binds only after
// analysis). Narrates progress; bails if the process backing the daemon dies first.
async function waitReady(
  socketPath: string,
  logPath: string,
  label: string,
  timeoutMs: number,
  isAlive?: () => boolean,
  maxWaitMs?: number,
): Promise<'ready' | 'timeout' | 'dead'> {
  // Phase 3: the daemon now binds its socket BEFORE finishing analysis, so for a warm or
  // already-loaded binary this returns 'ready' fast. `maxWaitMs` (the streaming query's
  // --max-wait budget) bounds how long we'll wait for a still-loading cold binary's socket to
  // appear: on expiry we return 'timeout' (the daemon is alive and warming) so the caller can
  // emit a deterministic complete{max_wait} instead of blocking on a long cold analysis.
  const stop = startNarrator(logPath, label);
  const start = Date.now();
  try {
    while (true) {
      if (await canConnect(socketPath)) return 'ready';
      const elapsed = Date.now() - start;
      if (timeoutMs > 0 && elapsed > timeoutMs) return 'timeout';
      if (maxWaitMs !== undefined && maxWaitMs > 0 && elapsed > maxWaitMs) return 'timeout';
      if (isAlive && !isAlive()) return 'dead';
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

  // Backstop for a hard-killed prior session (SIGKILL / power loss skips the daemon's graceful
  // handler): clear stale unpacked working files before opening a warm .i64, so IDA re-unpacks
  // it cleanly (no stale-lock recovery prompt, no leftover ~GB scratch). Only for a warm reload
  // — a fresh analysis has no .i64, and any components present are its own in-flight work.
  if (spec.backend === 'ida' && spec.idbPath) {
    const freed = purgeUnpackedIdb(dirname(spec.idbPath));
    if (freed > 0) process.stderr.write(`[re] cleared ${(freed / 1073741824).toFixed(1)} GB of stale unpacked database scratch\n`);
  }

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

async function ensureReady(spec: DaemonRunSpec, key: string, socketPath: string, dir: string, logPath: string, maxWaitMs?: number)
  : Promise<{ ok: true } | { ok: false; error: string; warming?: boolean }> {
  // 1. Reuse a healthy existing daemon. (binaryHash already keys on path+mtime+size, so a
  //    changed binary routes to a different key — no explicit staleness recheck needed.)
  const existing = readMeta(dir);
  if (existing && pidAlive(existing.pid)) {
    if (await canConnect(socketPath)) return { ok: true };
    // Phase 3: the daemon PROCESS is alive but its socket isn't bound yet — it now binds
    // mid-analysis, so this is WARMING, not failed. Wait for its socket (bounded by the
    // caller's deadline) instead of spawning a second IDA on the same binary — that rival
    // process is the duplicate-process bug (acceptance #3). A stale start-lock left by a
    // crashed/killed client must not divert us into starting one.
    const r = await waitReady(socketPath, logPath, spec.label, spec.timeoutMs, () => pidAlive(existing.pid), maxWaitMs);
    if (r === 'ready') return { ok: true };
    if (r === 'timeout') return { ok: false, warming: true, error: 'daemon warming (startup deadline reached)' };
    cleanup(dir, socketPath);  // 'dead': daemon died while waiting — fall through to restart
  } else if (existing && !pidAlive(existing.pid)) {
    cleanup(dir, socketPath);
  }

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
      // Destructive-overwrite guard (defense in depth): a fresh daemon analysis writes a NEW
      // .i64 to outputIdbPath via `-c -o`, destroying any database already there. Refuse unless
      // forced. (Cold binaries have no .i64 here, so this only fires on the dangerous case.)
      if (spec.outputIdbPath && existsSync(spec.outputIdbPath)) {
        if (!spec.force) {
          return { ok: false, error:
            `refusing to overwrite the existing analysis at ${spec.outputIdbPath}: a fresh analysis would ` +
            `destroy it. Pass --destructively-overwrite-existing to re-analyze (a database over 2 GB is backed ` +
            `up first), or 're cache clear' to discard it.` };
        }
        // Forced: back up a large database before clobbering — never truly destructive.
        try {
          const backup = backupLargeIdb(spec.outputIdbPath);
          if (backup) process.stderr.write(`[re] backed up existing database to ${backup} before overwriting\n`);
        } catch (e) {
          return { ok: false, error:
            `could not back up the existing database at ${spec.outputIdbPath} before overwriting ` +
            `(${e instanceof Error ? e.message : String(e)}); refusing to destroy it.` };
        }
      }
      try { writeFileSync(join(lockDir, 'pid'), String(process.pid)); } catch {}
      const pid = spawnDaemon(spec, key, socketPath, logPath);
      // Register immediately (Phase 3): the socket now binds mid-analysis, so we may return
      // while the daemon is still warming. Writing meta now keeps it discoverable (consumers
      // gate readiness on canConnect, so an unconnectable warming daemon reads as not-ready).
      writeMeta(dir, {
        pid, socketPath, backend: spec.backend,
        binaryPath: spec.binaryPath, binHash: spec.binHash,
        ...(spec.module ? { module: spec.module } : {}),
        startedAt: Date.now(),
      });
      const ready = await waitReady(socketPath, logPath, spec.label, spec.timeoutMs, () => pidAlive(pid), maxWaitMs);
      if (ready === 'ready') return { ok: true };
      if (ready === 'timeout') return { ok: false, warming: true, error: 'daemon still warming (startup deadline reached)' };
      return { ok: false, error: 'daemon failed to become ready' };
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
  const ready = await waitReady(socketPath, logPath, spec.label, spec.timeoutMs, starterAlive, maxWaitMs);
  if (ready === 'ready') return { ok: true };
  if (ready === 'timeout') return { ok: false, warming: true, error: 'daemon (started by another process) still warming' };
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

// Status of the daemon for one binary (for `re status`): the process may be alive but
// still warming (socket not yet bound) — distinguishable via `ready`.
export async function daemonFor(
  cacheDir: string,
  backend: BackendName,
  binHash: string,
  module?: string,
): Promise<{ pid: number; startedAt: number; ready: boolean; settled: boolean | null } | null> {
  const dir = registryDir(cacheDir, daemonKey(backend, binHash, module));
  const meta = readMeta(dir);
  if (!meta || !pidAlive(meta.pid)) return null;
  const ready = await canConnect(meta.socketPath);
  // Phase 3: the socket now binds mid-analysis, so "connectable" no longer implies "done".
  // Ping for the settled flag (auto_is_ok) so `re status`/`re wait` can tell a streamable
  // but still-warming daemon apart from a fully-analyzed one. null = couldn't determine.
  let settled: boolean | null = null;
  if (ready) {
    try {
      const r = await sendRequest(meta.socketPath, { id: 1, type: 'ping' }, 2000);
      const v = r?.meta?.settled;
      settled = typeof v === 'boolean' ? v : null;
    } catch { settled = null; }
  }
  return { pid: meta.pid, startedAt: meta.startedAt, ready, settled };
}

// Is a daemon currently STARTING for this binary — analyzing before its socket binds and
// meta.json is written? Returns the starter pid, else null. Lets `re status` report
// "warming" during the long first analysis instead of a misleading "none".
export function daemonStarting(cacheDir: string, backend: BackendName, binHash: string, module?: string): number | null {
  const pidFile = join(registryDir(cacheDir, daemonKey(backend, binHash, module)), 'lock', 'pid');
  try {
    const pid = Number(readFileSync(pidFile, 'utf8').trim());
    return pid && pidAlive(pid) ? pid : null;
  } catch {
    return null;
  }
}

// Live streaming telemetry for `re status` (issue #13 criterion #2): items emitted so far,
// phase, and a rough ETA for any in-flight streaming query, fetched via the daemon's `ping`
// WITHOUT consuming the query. Returns null when no daemon is reachable or none is streaming.
export interface DaemonStreamStats {
  op: string | null;
  itemsEmitted: number;
  phase: string | null;
  elapsedSec: number;
  etaSec: number | null;
  settled: boolean | null;
}
export async function daemonStreamStats(
  cacheDir: string,
  backend: BackendName,
  binHash: string,
  module?: string,
): Promise<DaemonStreamStats | null> {
  const dir = registryDir(cacheDir, daemonKey(backend, binHash, module));
  const meta = readMeta(dir);
  if (!meta || !pidAlive(meta.pid)) return null;
  try {
    const r = await sendRequest(meta.socketPath, { id: 1, type: 'ping' }, 2000);
    const s = r?.meta?.stream;
    return s ? (s as DaemonStreamStats) : null;
  } catch {
    return null;
  }
}

// ─── Public entry: run one query through a (possibly auto-started) daemon ────────

export async function runOnDaemon(spec: DaemonRunSpec, scriptText: string): Promise<DaemonOutcome> {
  const key = daemonKey(spec.backend, spec.binHash, spec.module);
  const socketPath = socketPathFor(key);
  const dir = registryDir(spec.cacheDir, key);
  const logPath = join(dir, 'daemon.log');

  const ready = await ensureReady(spec, key, socketPath, dir, logPath);
  if (!ready.ok) return { status: 'unavailable', error: ready.error };

  // Phase 3: the socket binds mid-analysis, so a cold-binary exec drives autoanalysis inside
  // the daemon (via the op script's auto_wait) and can take minutes. Narrate the daemon's
  // analysis log meanwhile so a legacy (non-streaming) query stays observable instead of
  // blocking silently — previously waitReady narrated this window before the socket bound.
  const stopNarrator = startNarrator(logPath, spec.label);
  try {
    const resp = await sendRequest(socketPath, { id: 1, type: 'exec', script: scriptText }, spec.timeoutMs);
    if (resp?.ok) return { status: 'served' };
    return { status: 'execError', error: String(resp?.error ?? 'daemon exec failed') };
  } catch (e) {
    // Connection dropped mid-flight (e.g. daemon crashed): let the caller fall back.
    return { status: 'unavailable', error: `daemon request failed: ${e instanceof Error ? e.message : String(e)}` };
  } finally {
    stopNarrator();
  }
}

// Streaming variant of runOnDaemon (issue #13): ensures a daemon is up, then opens a
// streaming exec. Returns the daemon's pid (for the `meta.ida_pid` field), a handle to
// the stream, and whether a daemon was reachable at all (so the runner can fall back).
export async function runStreamOnDaemon(
  spec: DaemonRunSpec,
  scriptText: string,
  deadlineSec: number,
  onFrame: (f: StreamFrame) => void,
  op?: string,
): Promise<
  | { status: 'streaming'; pid: number; handle: StreamExecHandle }
  | { status: 'warming'; pid: number }
  | { status: 'unavailable'; error: string }
> {
  const key = daemonKey(spec.backend, spec.binHash, spec.module);
  const socketPath = socketPathFor(key);
  const dir = registryDir(spec.cacheDir, key);
  const logPath = join(dir, 'daemon.log');

  // Bound the startup wait by the stream's deadline (--max-wait budget): a cold huge binary
  // can take minutes just to LOAD before its socket binds, and we must never block past the
  // budget. On expiry the daemon keeps warming in the background and we report 'warming'.
  const ready = await ensureReady(spec, key, socketPath, dir, logPath, deadlineSec * 1000);
  if (!ready.ok) {
    if (ready.warming) {
      const pid = readMeta(dir)?.pid ?? daemonStarting(spec.cacheDir, spec.backend, spec.binHash, spec.module) ?? -1;
      return { status: 'warming', pid };
    }
    return { status: 'unavailable', error: ready.error };
  }

  const meta = readMeta(dir);
  const pid = meta?.pid ?? -1;
  const handle = streamExecOnDaemon(socketPath, scriptText, deadlineSec, onFrame, spec.timeoutMs, op);
  return { status: 'streaming', pid, handle };
}

// ─── Management (re daemon list/stop) ────────────────────────────────────────────

export async function listDaemons(cacheDir: string): Promise<DaemonStatus[]> {
  const base = join(expandHome(cacheDir), 'daemons');
  if (!existsSync(base)) return [];
  const out: DaemonStatus[] = [];
  for (const key of readdirSync(base)) {
    const dir = join(base, key);
    const meta = readMeta(dir);
    if (!meta) {
      // No liveness record: either a daemon is mid-startup (about to write meta) or this is an
      // orphaned leftover (a stopped daemon's daemon.log/lock — pre-fix, cleanup only stripped
      // meta.json). Keep it only while a starter pid is still live; otherwise prune the dir.
      let starterAlive = false;
      try { starterAlive = pidAlive(Number(readFileSync(join(dir, 'lock', 'pid'), 'utf8').trim())); } catch {}
      if (!starterAlive) { try { rmSync(dir, { recursive: true, force: true }); } catch {} }
      continue;
    }
    // Phase 3: prune ONLY when the process is dead. A daemon that's alive but not yet
    // connectable is WARMING (binds its socket mid-analysis) — pruning it here would orphan
    // a live IDA (undiscoverable, and the next query would spawn a duplicate). `alive` in the
    // listing means "connectable/ready"; warming daemons list as not-ready but are kept.
    if (!pidAlive(meta.pid)) { cleanup(dir, meta.socketPath); continue; }
    const connectable = await canConnect(meta.socketPath);
    let input: string | null = null;
    if (connectable) {
      try {
        const r = await sendRequest(meta.socketPath, { id: 1, type: 'ping' }, 2000);
        input = r?.meta?.input ?? null;
      } catch {}
    }
    out.push({
      key, backend: meta.backend, binaryPath: meta.binaryPath,
      module: meta.module, pid: meta.pid, alive: connectable, startedAt: meta.startedAt, input,
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
