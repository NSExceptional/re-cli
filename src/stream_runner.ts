// Streaming query orchestrator (issue #13). Owns the run-time half of the streaming API:
// it composes the streaming IDA script, drives the daemon's stream_exec protocol, applies
// the stop conditions (§4.1) and min-batch buffering, enforces within-query dedup (§5.4),
// and — critically — GUARANTEES a terminal event (§5.7/5.8/5.9, acceptance #1/#6) so the
// legacy `NoOutput` failure mode is impossible.
//
// The pure event/format/validate logic lives in stream.ts; this module is the impure glue
// (spawning, sockets, timers, signals). It is intentionally separate from run() in
// runner.ts so the non-streaming path is untouched (backwards-compat, §12).

import { existsSync, readFileSync, mkdirSync, statSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import process from 'node:process';
import type { Config } from './config.ts';
import type { BackendName } from './result.ts';
import { binaryHash, expandHome, elapsed } from './util.ts';
import { hasIdb, idbPath, ensureIdbDir } from './cache.ts';
import {
  runStreamOnDaemon, type DaemonRunSpec, type StreamFrame, type StreamExecHandle,
} from './daemon.ts';
import {
  EventSink, identityOf, newQueryId, now,
  type ResolvedStream, type CacheState, type CompleteReason, type ErrorKind,
  type StreamEvent, type MetaEvent, type CompleteEvent, type ErrorEvent, type InterruptedEvent,
  type PartialEvent, type SnapshotEvent,
} from './stream.ts';

const SCRIPTS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts');

export interface StreamRunOptions {
  resolved: ResolvedStream;
  binary: string;
  arch?: string;
  module?: string;
  params: Record<string, unknown>;
  config: Config;
  backend: 'auto' | 'ida' | 'hopper';
  timeout: number;  // seconds; 0 = none
}

// Compose the streaming script: same preamble + _base.py the one-shot path uses, then the
// `<op>.stream.py` body (which drives the daemon-injected emit/should_stop helpers).
function composeStreamScript(op: string, params: Record<string, unknown>): string {
  const basePath = join(SCRIPTS_DIR, 'ida', '_base.py');
  const bodyPath = join(SCRIPTS_DIR, 'ida', `${op}.stream.py`);
  if (!existsSync(bodyPath)) throw new Error(`No streaming script for op '${op}'`);
  // _RE_OUTPUT_PATH is unused by streaming scripts but the preamble/_base.py reference it;
  // pass a harmless placeholder so the shared base loads cleanly.
  const paramsHex = Buffer.from(JSON.stringify(params)).toString('hex');
  const preamble = [
    'import json as _json',
    'import os as _os',
    `_RE_OUTPUT_PATH = ${JSON.stringify('/dev/null')}`,
    `_RE_COMMAND = ${JSON.stringify(op)}`,
    `_RE_PARAMS = _json.loads(bytes.fromhex(${JSON.stringify(paramsHex)}))`,
    '',
  ].join('\n');
  return preamble + '\n' + readFileSync(basePath, 'utf8') + '\n' + readFileSync(bodyPath, 'utf8');
}

// Minimal cache-state classification (spec §9). cold: no .i64. warm: .i64 present and
// current. stale: .i64 older than binary mtime. We DON'T implement the `partial`
// (attach-to-foreign-IDA) state here — the warm daemon model means an in-flight analysis
// is our own daemon, surfaced as cold/warm by whether the .i64 has been persisted.
function classifyCache(cacheDir: string, binHash: string, effectiveBinary: string, module?: string): CacheState {
  if (!hasIdb(cacheDir, binHash, module)) return 'cold';
  try {
    const idbMtime = statSync(idbPath(cacheDir, binHash, module)).mtimeMs;
    const binMtime = statSync(effectiveBinary).mtimeMs;
    // SPEC-GAP: §9 says stale ⇒ error cache_corrupt. But our binHash already folds in
    // mtime+size, so a changed binary normally routes to a different hash and we never
    // see a truly stale .i64 under the same key. We keep the check defensively.
    if (binMtime > idbMtime + 1000) return 'stale';
  } catch { /* fall through to warm */ }
  return 'warm';
}

// Map a terminal outcome to the process exit code (§8).
export function exitCodeFor(terminal: 'complete' | 'error' | 'interrupted', kind?: ErrorKind): number {
  if (terminal === 'complete') return 0;
  if (terminal === 'interrupted') return 130;
  // error
  if (kind === 'file_not_found' || kind === 'validate_error') return 2;  // §8: IDA was connected
  return 3;
}

// The orchestrator. Returns the exit code; all output is written through the EventSink.
export async function runStream(opts: StreamRunOptions): Promise<number> {
  const { resolved } = opts;
  const op = resolved.op;
  const queryId = newQueryId();
  const start = Date.now();
  const sink = new EventSink(resolved);

  // ── Resolve binary + hash (mirrors runner.run's prologue) ──
  if (!existsSync(opts.binary)) {
    return emitTerminalError(sink, queryId,'file_not_found',
      `Binary not found: ${opts.binary}`, 0, null);
  }

  const cacheDir = opts.config.cache.dir;
  const originalHash = binaryHash(opts.binary);
  // Slice extraction is duplicated from runner.run; kept local to avoid coupling.
  const effectiveBinary = opts.arch && !opts.module
    ? extractSlice(opts.binary, opts.arch, cacheDir, originalHash)
    : opts.binary;
  const binHash = effectiveBinary !== opts.binary ? binaryHash(effectiveBinary) : originalHash;
  const backend = resolveBackendName(opts.backend, opts.config);

  // Streaming requires the IDA backend (Hopper has no auto_queue / incremental model yet).
  if (backend !== 'ida') {
    return emitTerminalError(sink, queryId,'validate_error',
      `streaming requires the IDA backend (got: ${backend})`, 0, null);
  }

  const toolPath = opts.config.tools.idat64;
  if (!toolPath || !existsSync(toolPath)) {
    return emitTerminalError(sink, queryId,'ida_crashed',
      'idat64 not found. Set RE_IDAT64 or add to ~/.config/re-cli/config.json', 0, null);
  }

  let cacheState = classifyCache(cacheDir, binHash, effectiveBinary, opts.module);

  // Temp dir for the daemon log / save path bookkeeping (mirrors runner.run).
  const useIdb = cacheState === 'warm';
  const outputIdbPath = useIdb
    ? undefined
    : join(ensureIdbDir(cacheDir, binHash, opts.module), 'binary.i64');

  let script: string;
  try { script = composeStreamScript(op, opts.params); }
  catch (e) {
    return emitTerminalError(sink, queryId,'script_crashed',
      `failed to compose streaming script: ${e instanceof Error ? e.message : String(e)}`, 0, null);
  }

  const sizeMb = statSync(effectiveBinary).size / 1048576;
  const label = `ida ${op} (stream): ${useIdb ? 'warm db' : 'fresh analysis'} of ${basename(opts.binary)} (${sizeMb.toFixed(1)} MB)`;

  const spec: DaemonRunSpec = {
    cacheDir, backend, toolPath, binHash,
    module: opts.module,
    binaryPath: opts.binary,
    effectiveBinary,
    idbPath: useIdb ? idbPath(cacheDir, binHash, opts.module) : undefined,
    outputIdbPath,
    idleTimeout: opts.config.daemon.idleTimeout,
    timeoutMs: opts.timeout * 1000,
    label,
  };

  // ── Deadline (spec §11.3): the daemon-side wait is bounded by this. Default to the
  //    --max-wait budget, else a sane default so we never block 80 minutes. ──
  const DEFAULT_DEADLINE = 600;
  const deadlineSec = resolved.flags.maxWait ?? DEFAULT_DEADLINE;

  // Snapshot mode (§5.5): a warm cache with neither --stream nor a stop condition emits a
  // single `snapshot` of all items, then `complete` — instead of incremental `partial`s.
  const snapshotMode = cacheState === 'warm' && !resolved.flags.stream && !resolved.bounded;

  // Will the daemon already be serving (so meta.ida_pid is known up front)? We learn the
  // real pid after runStreamOnDaemon; emit meta after we connect so ida_pid is accurate.
  // Stop-condition + dedup state.
  const seen = new Set<string>();
  let runningCount = 0;
  let stopReason: CompleteReason | null = null;
  const pending: Record<string, unknown>[] = [];  // min-batch-size buffer / snapshot accumulator
  const minBatch = resolved.flags.minBatchSize;
  const maxMatches = resolved.flags.maxMatches;

  let metaEmitted = false;
  const emitMeta = (pid: number | null) => {
    if (metaEmitted || resolved.flags.noMeta) return;
    metaEmitted = true;
    const meta: MetaEvent = {
      event: 'meta', query_id: queryId, ts: now(),
      binary: opts.binary, binary_hash: binHash, op,
      cache_state: cacheState, ida_pid: pid, params: opts.params,
    };
    sink.push(meta);
  };

  // Flush buffered items as a partial event (respects min-batch unless forced at the end).
  // In snapshot mode we never flush mid-stream — items accumulate and are emitted as one
  // `snapshot` by emitSnapshot() at the end.
  const flushPending = (force: boolean) => {
    if (snapshotMode) return;
    if (!pending.length) return;
    if (!force && pending.length < minBatch) return;
    const items = pending.splice(0, pending.length);
    runningCount += items.length;
    const ev: PartialEvent = {
      event: 'partial', query_id: queryId, ts: now(),
      items, running_count: runningCount,
      // SPEC-GAP: cursor (§5.4) is a real resume token in the full design; until --resume
      // lands we emit a stable-but-opaque cursor encoding the running count.
      cursor: makeCursor(binHash, runningCount),
    };
    sink.push(ev);
  };

  // Emit the single snapshot event (§5.5) from the accumulated buffer.
  const emitSnapshot = () => {
    const items = pending.splice(0, pending.length);
    runningCount = items.length;
    const ev: SnapshotEvent = {
      event: 'snapshot', query_id: queryId, ts: now(), items, count: items.length,
    };
    sink.push(ev);
  };

  // Race-safe cooperative stop. A frame, the max-wait timer, or a signal can all ask to
  // stop; the handle may not be assigned yet when the first request lands (it's set right
  // after runStreamOnDaemon resolves, before any socket data is processed — but we guard
  // regardless). If the handle isn't ready, we mark intent and apply it on assignment.
  let stopRequested = false;
  let handle: StreamExecHandle | undefined;
  const requestStop = () => {
    stopRequested = true;
    handle?.stop();
  };

  // Translate one daemon frame into buffered items / progress, applying dedup + max-matches.
  const onFrame = (f: StreamFrame): void => {
    if (f.kind === 'progress') {
      sink.push({
        event: 'progress', query_id: queryId, ts: now(),
        items_emitted: runningCount,
        phase: (f.phase as any) ?? 'analyzing',
        percent: f.percent ?? null, etaSec: null,
      });
      return;
    }
    if (f.kind === 'partial' && f.items) {
      for (const item of f.items) {
        if (stopReason) break;
        const id = identityOf(op, item);
        if (id !== null) {
          if (seen.has(id)) continue;  // §5.4 within-query dedup
          seen.add(id);
        }
        pending.push(item);
        if (maxMatches !== undefined && runningCount + pending.length >= maxMatches) {
          stopReason = 'max_matches';
          break;
        }
      }
      flushPending(false);
      if (stopReason === 'max_matches') requestStop();  // we have enough
    }
  };

  // ── Drive the daemon stream ──

  // max-wait wall-clock timer: fire a cooperative stop and record the reason.
  let maxWaitTimer: ReturnType<typeof setTimeout> | undefined;
  if (resolved.flags.maxWait !== undefined) {
    maxWaitTimer = setTimeout(() => {
      if (!stopReason) stopReason = 'max_wait';
      requestStop();
    }, resolved.flags.maxWait * 1000);
  }

  // SIGINT/SIGTERM → graceful interrupt (§5.9). Installed for the stream's duration.
  let interrupted: 'SIGINT' | 'SIGTERM' | null = null;
  const onSignal = (sig: 'SIGINT' | 'SIGTERM') => {
    interrupted = sig;
    requestStop();
  };
  const sigint = () => onSignal('SIGINT');
  const sigterm = () => onSignal('SIGTERM');
  process.on('SIGINT', sigint);
  process.on('SIGTERM', sigterm);

  try {
    const started = await runStreamOnDaemon(spec, script, deadlineSec, onFrame);
    if (started.status === 'unavailable') {
      // We could not reach/spawn a daemon. The streaming protocol REQUIRES a live IDA, and
      // §11.1 disallows the old one-shot path here. Surface a terminal error (never NoOutput).
      return emitTerminalError(sink, queryId,'ida_crashed',
        `could not start a streaming IDA session: ${started.error}`, runningCount, null);
    }
    emitMeta(started.pid);
    handle = started.handle;
    // Apply any stop requested before the handle existed (max-wait/signal during startup).
    if (stopRequested) handle.stop();

    const { terminal, closedEarly } = await handle.done;

    // Flush any remaining buffered items (min-batch is relaxed at the end, §4.1). In
    // snapshot mode this is a no-op; the snapshot is emitted just before `complete` below.
    flushPending(true);

    if (interrupted) {
      // §5.9 graceful interrupt. Best-effort cache state: the daemon persists on settle;
      // we report the current truth. In snapshot mode no `snapshot` was emitted, so count
      // the items we had buffered for partial_count.
      const interruptedCount = snapshotMode ? pending.length : runningCount;
      cacheState = classifyCache(cacheDir, binHash, effectiveBinary, opts.module);
      const ev: InterruptedEvent = {
        event: 'interrupted', query_id: queryId, ts: now(),
        partial_count: interruptedCount,
        cursor: interruptedCount ? makeCursor(binHash, interruptedCount) : null,
        cache_state: cacheState,
      };
      sink.push(ev);
      return exitCodeFor('interrupted');
    }

    // Terminal frame missing (daemon died mid-stream) AND no items → script_crashed (§6/§11.2.4).
    if (!terminal && closedEarly) {
      return emitTerminalError(sink, queryId,'script_crashed',
        'streaming IDA session ended without a terminal frame (daemon crashed?)',
        runningCount, null);
    }

    if (terminal && terminal.ok === false) {
      return emitTerminalError(sink, queryId,'script_crashed',
        terminal.error ?? 'streaming script failed', runningCount, null);
    }

    // Snapshot mode: emit the single snapshot now (§5.5), right before complete.
    if (snapshotMode) emitSnapshot();

    // Successful completion. Reason precedence: a client-side stop (max_matches/max_wait)
    // wins; otherwise honor the script's own reason (natural / db_settled).
    const reason: CompleteReason = stopReason
      ?? (terminal?.reason as CompleteReason | undefined)
      ?? 'natural';
    cacheState = classifyCache(cacheDir, binHash, effectiveBinary, opts.module);
    const complete: CompleteEvent = {
      event: 'complete', query_id: queryId, ts: now(),
      count: runningCount, reason,
      durationSec: elapsed(start),
      cursor: runningCount ? makeCursor(binHash, runningCount) : null,
      cache_state: cacheState,
    };
    sink.push(complete);
    return exitCodeFor('complete');
  } catch (e) {
    flushPending(true);
    return emitTerminalError(sink, queryId,'ida_crashed',
      `streaming failed: ${e instanceof Error ? e.message : String(e)}`, runningCount, null);
  } finally {
    if (maxWaitTimer) clearTimeout(maxWaitTimer);
    process.removeListener('SIGINT', sigint);
    process.removeListener('SIGTERM', sigterm);
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────────

// Emit a terminal `error` event (§5.8) and return its exit code. Error events carry no
// cache_state and no durationSec per §5.8, so this needs neither a cache nor a start time.
function emitTerminalError(
  sink: EventSink,
  queryId: string,
  kind: ErrorKind,
  message: string,
  partialCount: number,
  logExcerpt: string | null,
): number {
  const ev: ErrorEvent = {
    event: 'error', query_id: queryId, ts: now(),
    kind, message, partial_count: partialCount, log_excerpt: logExcerpt,
  };
  sink.push(ev);
  return exitCodeFor('error', kind);
}

// Opaque resume cursor (§5.4/§5.7). Until --resume lands this is a forward-compatible
// placeholder: a versioned base64 of {h: binHash, n: count}. Documented as deferred.
function makeCursor(binHash: string, count: number): string {
  const payload = Buffer.from(JSON.stringify({ h: binHash, n: count }), 'utf8').toString('base64');
  return `v1-${payload}`;
}

function resolveBackendName(requested: 'auto' | BackendName, config: Config): BackendName {
  if (requested !== 'auto') return requested;
  if (config.defaults.backend !== 'auto') return config.defaults.backend;
  return 'ida';
}

// Duplicated from runner.ts (kept local to avoid widening runner's export surface).
function extractSlice(binary: string, arch: string, cacheDir: string, originalHash: string): string {
  const sliceDir = join(expandHome(cacheDir), 'slices');
  mkdirSync(sliceDir, { recursive: true });
  const slicePath = join(sliceDir, `${originalHash}-${arch}`);
  if (!existsSync(slicePath)) {
    const { status } = spawnSync('lipo', [binary, '-thin', arch, '-output', slicePath]);
    if (status !== 0) return binary;
  }
  return slicePath;
}
