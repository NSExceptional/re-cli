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
import { binaryHash, expandHome, elapsed, machoArchs } from './util.ts';
import { hasIdb, idbPath, idbCacheDir, ensureIdbDir, writeIdbMeta } from './cache.ts';
import {
  runStreamOnDaemon, type DaemonRunSpec, type StreamFrame, type StreamExecHandle,
} from './daemon.ts';
import {
  EventSink, identityOf, newQueryId, now,
  encodeCursor, decodeCursor, CursorError, diffSnapshots,
  newCadenceState, shouldEmitStatus, shouldEmitProgress,
  type ResolvedStream, type CacheState, type CompleteReason, type ErrorKind,
  type StreamEvent, type MetaEvent, type CompleteEvent, type ErrorEvent, type InterruptedEvent,
  type PartialEvent, type SnapshotEvent, type DeltaEvent, type StatusEvent, type ProgressEvent,
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
  force?: boolean;  // allow a fresh analysis to overwrite an existing cached .i64
}

// Options that tune one streaming-script invocation (issue #13 phase 2):
//   resumeSeen  — identities the prior (interrupted) run already delivered; the script
//                 skips them so they are never re-emitted (server-side dedup, §5.4/§9).
//   watchPass   — true for a --watch re-run: do a single snapshot pass (no deadline wait,
//                 no incremental subscription) so the runner can diff it for deltas.
interface ScriptOptions {
  resumeSeen?: string[];
  watchPass?: boolean;
}

// Compose the streaming script: same preamble + _base.py the one-shot path uses, then the
// `<op>.stream.py` body (which drives the daemon-injected emit/should_stop helpers).
function composeStreamScript(op: string, params: Record<string, unknown>, opts: ScriptOptions = {}): string {
  const basePath = join(SCRIPTS_DIR, 'ida', '_base.py');
  const bodyPath = join(SCRIPTS_DIR, 'ida', `${op}.stream.py`);
  if (!existsSync(bodyPath)) throw new Error(`No streaming script for op '${op}'`);
  // _RE_OUTPUT_PATH is unused by streaming scripts but the preamble/_base.py reference it;
  // pass a harmless placeholder so the shared base loads cleanly.
  const paramsHex = Buffer.from(JSON.stringify(params)).toString('hex');
  // Resume watermark travels as hex-encoded JSON like params so odd identity strings can't
  // break the literal. The script reads _RE_RESUME_SEEN (a set) and skips those identities.
  const seenHex = Buffer.from(JSON.stringify(opts.resumeSeen ?? [])).toString('hex');
  const preamble = [
    'import json as _json',
    'import os as _os',
    `_RE_OUTPUT_PATH = ${JSON.stringify('/dev/null')}`,
    `_RE_COMMAND = ${JSON.stringify(op)}`,
    `_RE_PARAMS = _json.loads(bytes.fromhex(${JSON.stringify(paramsHex)}))`,
    `_RE_RESUME_SEEN = set(_json.loads(bytes.fromhex(${JSON.stringify(seenHex)})))`,
    `_RE_WATCH_PASS = ${opts.watchPass ? 'True' : 'False'}`,
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
    return emitTerminalError(sink, queryId, 'file_not_found',
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
    return emitTerminalError(sink, queryId, 'validate_error',
      `streaming requires the IDA backend (got: ${backend})`, 0, null);
  }

  const toolPath = opts.config.tools.idat64;
  if (!toolPath || !existsSync(toolPath)) {
    return emitTerminalError(sink, queryId, 'ida_crashed',
      'idat64 not found. Set RE_IDAT64 or add to ~/.config/re-cli/config.json', 0, null);
  }

  let cacheState = classifyCache(cacheDir, binHash, effectiveBinary, opts.module);

  // §9 / acceptance: a stale .i64 (binary mtime newer than the cached database) is corrupt
  // wrt this binary. Emit terminal error.kind:"cache_corrupt" rather than silently
  // re-analyzing inside a --max-wait budget. (Our binHash folds in mtime+size so a changed
  // binary usually routes to a fresh key; this defends the rare in-place-same-key case.)
  if (cacheState === 'stale') {
    return emitTerminalError(sink, queryId, 'cache_corrupt',
      `cached database is stale: ${opts.binary} was modified after its .i64 was built. ` +
      `Delete the cache (re cache clear) or re-run without a cache to re-analyze.`,
      0, null);
  }

  // ── --resume (§4.3, §9; acceptance #4): decode the cursor against THIS binary+op. A
  //    mismatch (different binary, wrong op, corrupt, or a v1 placeholder) is a hard
  //    validate error so resume never silently re-delivers or dedups the wrong set. ──
  const resumeSeen: string[] = [];
  if (resolved.flags.resume !== undefined) {
    try {
      const payload = decodeCursor(resolved.flags.resume, binHash, op);
      resumeSeen.push(...payload.w);
    } catch (e) {
      if (e instanceof CursorError) {
        return emitTerminalError(sink, queryId, 'validate_error', e.message, 0, null);
      }
      throw e;
    }
  }

  // Temp dir for the daemon log / save path bookkeeping (mirrors runner.run).
  const useIdb = cacheState === 'warm';
  const outputIdbPath = useIdb
    ? undefined
    : join(ensureIdbDir(cacheDir, binHash, opts.module), 'binary.i64');

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
    force: opts.force,
    label,
  };

  // ── Deadline (spec §11.3): the daemon-side wait is bounded by this. Default to the
  //    --max-wait budget, else a sane default so we never block 80 minutes. ──
  const DEFAULT_DEADLINE = 600;
  const deadlineSec = resolved.flags.maxWait ?? DEFAULT_DEADLINE;

  // Snapshot mode (§5.5): a warm cache with neither --stream nor a stop condition emits a
  // single `snapshot` of all items, then `complete`. --watch ALSO starts with a snapshot
  // (§5.6) regardless of cache state, then transitions to deltas.
  const snapshotMode = (cacheState === 'warm' && !resolved.flags.stream && !resolved.bounded)
    || resolved.flags.watch;

  // Shared run context so the initial pass and the watch loop see the same state/helpers.
  const ctx: RunContext = {
    opts, resolved, op, queryId, start, sink, cacheDir, binHash, effectiveBinary, spec,
    deadlineSec, snapshotMode,
    seen: new Set<string>(resumeSeen),  // server-side dedup seeded with the resume watermark
    resumeSeen,
    runningCount: 0,
    cacheState,
  };

  const code = await (resolved.flags.watch ? runWatch(ctx) : runStreamOnce(ctx));
  // Self-describing cache metadata (idb/<hash>/meta.json): if a cold stream settled a fresh
  // .i64, record what it is. Backfill only — don't churn an existing file's analyzedAt.
  try {
    const idbFile = idbPath(cacheDir, binHash, opts.module);
    const metaFile = join(idbCacheDir(cacheDir, binHash, opts.module), 'meta.json');
    if (existsSync(idbFile) && !existsSync(metaFile)) {
      const s = statSync(effectiveBinary);
      writeIdbMeta(cacheDir, binHash, opts.module, {
        name: basename(opts.binary),
        path: opts.binary,
        ...(opts.arch ? { arch: opts.arch } : {}),
        ...(opts.module ? { module: opts.module } : {}),
        backend: 'ida',
        backendVersion: null,
        binHash,
        analyzedAt: new Date(statSync(idbFile).mtimeMs).toISOString(),
        mtimeMs: s.mtimeMs,
        size: s.size,
      });
    }
  } catch { /* metadata is best-effort */ }
  return code;
}

// ─── Shared run context ────────────────────────────────────────────────────────────

interface RunContext {
  opts: StreamRunOptions;
  resolved: ResolvedStream;
  op: string;
  queryId: string;
  start: number;
  sink: EventSink;
  cacheDir: string;
  binHash: string;
  effectiveBinary: string;
  spec: DaemonRunSpec;
  deadlineSec: number;
  snapshotMode: boolean;
  seen: Set<string>;        // delivered identities (within-query dedup + resume watermark)
  resumeSeen: string[];     // identities carried in from --resume (already counted as 0)
  runningCount: number;
  cacheState: CacheState;
}

// Emit `meta` once (unless --no-meta). Shared by both run paths.
function emitMeta(ctx: RunContext, pid: number | null): void {
  if (ctx.resolved.flags.noMeta) return;
  const meta: MetaEvent = {
    event: 'meta', query_id: ctx.queryId, ts: now(),
    binary: ctx.opts.binary, binary_hash: ctx.binHash, op: ctx.op,
    cache_state: ctx.cacheState, ida_pid: pid, params: ctx.opts.params,
  };
  ctx.sink.push(meta);
}

// The resume cursor for any terminal/partial event: the FULL delivered-identity set
// (prior watermark ∪ this run's deliveries), so a chain of resumes never loses items.
function cursorFor(ctx: RunContext): string | null {
  return encodeCursor(ctx.binHash, ctx.op, ctx.seen);
}

// ─── Single streaming pass (non-watch): the §7 meta→[status]→progress*→partial*→terminal ──
async function runStreamOnce(ctx: RunContext): Promise<number> {
  const { resolved, op, queryId, start, sink } = ctx;
  const minBatch = resolved.flags.minBatchSize;
  const maxMatches = resolved.flags.maxMatches;

  let script: string;
  try { script = composeStreamScript(op, ctx.opts.params, { resumeSeen: ctx.resumeSeen }); }
  catch (e) {
    return emitTerminalError(sink, queryId, 'script_crashed',
      `failed to compose streaming script: ${e instanceof Error ? e.message : String(e)}`, 0, null);
  }

  let stopReason: CompleteReason | null = null;
  const pending: Record<string, unknown>[] = [];  // min-batch buffer / snapshot accumulator
  const cadence = newCadenceState();
  // Latest phase/percent the daemon reported, surfaced by the cadence timer.
  let lastPhase: ProgressEvent['phase'] = 'analyzing';
  let lastPercent: number | null = null;

  // Flush buffered items as a partial event (respects min-batch unless forced at the end).
  const flushPending = (force: boolean) => {
    if (ctx.snapshotMode) return;
    if (!pending.length) return;
    if (!force && pending.length < minBatch) return;
    const items = pending.splice(0, pending.length);
    ctx.runningCount += items.length;
    cadence.firstItemSeen = true;  // suppress further status/progress (§5.3)
    const ev: PartialEvent = {
      event: 'partial', query_id: queryId, ts: now(),
      items, running_count: ctx.runningCount, cursor: cursorFor(ctx),
    };
    sink.push(ev);
  };

  const emitSnapshot = () => {
    const items = pending.splice(0, pending.length);
    ctx.runningCount = items.length;
    const ev: SnapshotEvent = {
      event: 'snapshot', query_id: queryId, ts: now(), items, count: items.length,
    };
    sink.push(ev);
  };

  // Race-safe cooperative stop (handle may not exist yet when max-wait/signal fires).
  let stopRequested = false;
  let handle: StreamExecHandle | undefined;
  const requestStop = () => { stopRequested = true; handle?.stop(); };

  // Daemon frames: partial → buffer+dedup+max-matches; progress → update phase/percent
  // state (the cadence TIMER decides whether to actually emit a progress event, ruling #4).
  const onFrame = (f: StreamFrame): void => {
    if (f.kind === 'progress') {
      if (f.phase) lastPhase = f.phase as ProgressEvent['phase'];
      lastPercent = f.percent ?? lastPercent;
      return;
    }
    if (f.kind === 'partial' && f.items) {
      for (const item of f.items) {
        if (stopReason) break;
        const id = identityOf(op, item);
        if (id !== null) {
          if (ctx.seen.has(id)) continue;  // §5.4 dedup (also covers resume watermark)
          ctx.seen.add(id);
        }
        pending.push(item);
        if (maxMatches !== undefined && ctx.runningCount + pending.length >= maxMatches) {
          stopReason = 'max_matches';
          break;
        }
      }
      flushPending(false);
      if (stopReason === 'max_matches') requestStop();
    }
  };

  // ── Cadence timer (§5.2/§5.3, ruling #4): one `status` if the first item is slower than
  //    --status-threshold; `progress` ~every 10s while waiting; both suppressed once items
  //    flow. Driven by a 1s tick so the gates are checked promptly without busy-waiting. ──
  const thresholdMs = resolved.flags.statusThreshold * 1000;
  const PROGRESS_INTERVAL_MS = 10_000;
  const cadenceTimer = setInterval(() => {
    const t = now();
    if (shouldEmitStatus(cadence, start, t, thresholdMs)) {
      cadence.statusEmitted = true;
      const ev: StatusEvent = {
        event: 'status', query_id: queryId, ts: t,
        stage: phaseToStage(lastPhase), etaSec: null,
      };
      sink.push(ev);
    }
    if (shouldEmitProgress(cadence, t, PROGRESS_INTERVAL_MS)) {
      cadence.lastProgressAt = t;
      const ev: ProgressEvent = {
        event: 'progress', query_id: queryId, ts: t,
        items_emitted: ctx.runningCount, phase: lastPhase,
        percent: lastPercent, etaSec: null,
      };
      sink.push(ev);
    }
  }, 1_000);
  if (typeof cadenceTimer.unref === 'function') cadenceTimer.unref();

  // max-wait wall-clock timer.
  let maxWaitTimer: ReturnType<typeof setTimeout> | undefined;
  if (resolved.flags.maxWait !== undefined) {
    maxWaitTimer = setTimeout(() => {
      if (!stopReason) stopReason = 'max_wait';
      requestStop();
    }, resolved.flags.maxWait * 1000);
  }

  // SIGINT/SIGTERM → graceful interrupt (§5.9).
  let interrupted = false;
  const onSignal = () => { interrupted = true; requestStop(); };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);

  try {
    const started = await runStreamOnDaemon(ctx.spec, script, ctx.deadlineSec, onFrame, op);
    if (started.status === 'unavailable') {
      return emitTerminalError(sink, queryId, 'ida_crashed',
        `could not start a streaming IDA session: ${started.error}`, ctx.runningCount, null);
    }
    if (started.status === 'warming') {
      // Phase 3 (acceptance #1/#5): the daemon is still loading/analyzing this cold binary and
      // didn't become connectable within the --max-wait budget. Return a deterministic
      // terminal event — never a hang, never NoOutput. Analysis continues in the background;
      // a later query (or --resume) attaches to the now-warmer database.
      emitMeta(ctx, started.pid);
      ctx.cacheState = classifyCache(ctx.cacheDir, ctx.binHash, ctx.effectiveBinary, ctx.opts.module);
      const complete: CompleteEvent = {
        event: 'complete', query_id: queryId, ts: now(),
        count: 0, reason: 'max_wait', durationSec: elapsed(start),
        cursor: ctx.seen.size ? cursorFor(ctx) : null, cache_state: ctx.cacheState,
      };
      sink.push(complete);
      return exitCodeFor('complete');
    }
    emitMeta(ctx, started.pid);
    handle = started.handle;
    if (stopRequested) handle.stop();

    // Hard client-side deadline (Phase 3). The daemon's cooperative stop is only checked
    // BETWEEN analysis slices, and a single auto_wait_range slice or a full rescan over a huge
    // binary (100k+ functions) can't be interrupted mid-call — so on big binaries the daemon
    // can overshoot --max-wait by minutes. Guarantee the user-facing bound here: if no terminal
    // frame arrives within the deadline + a short grace, stop the stream, flush what we have,
    // and synthesize the terminal ourselves. The orphaned daemon stream notices the closed
    // socket on its next check and unwinds, keeping the database warming in the background.
    const HARD_GRACE_MS = 5000;
    const hardCapMs = ctx.deadlineSec * 1000 + HARD_GRACE_MS;
    const capped = await Promise.race([
      handle.done.then((d) => ({ timedOut: false as const, ...d })),
      sleep(Math.max(0, hardCapMs - (Date.now() - start))).then(() => ({ timedOut: true as const })),
    ]);
    flushPending(true);

    if (capped.timedOut) {
      handle.stop();  // best-effort: tell the daemon to unwind at its next slice boundary
      ctx.cacheState = classifyCache(ctx.cacheDir, ctx.binHash, ctx.effectiveBinary, ctx.opts.module);
      if (interrupted) {
        sink.push({
          event: 'interrupted', query_id: queryId, ts: now(),
          partial_count: ctx.runningCount, cursor: cursorFor(ctx), cache_state: ctx.cacheState,
        } as InterruptedEvent);
        return exitCodeFor('interrupted');
      }
      sink.push({
        event: 'complete', query_id: queryId, ts: now(),
        count: ctx.runningCount, reason: stopReason ?? 'max_wait',
        durationSec: elapsed(start), cursor: cursorFor(ctx), cache_state: ctx.cacheState,
      } as CompleteEvent);
      return exitCodeFor('complete');
    }
    const { terminal, closedEarly } = capped;

    if (interrupted) {
      const interruptedCount = ctx.snapshotMode ? pending.length : ctx.runningCount;
      ctx.cacheState = classifyCache(ctx.cacheDir, ctx.binHash, ctx.effectiveBinary, ctx.opts.module);
      const ev: InterruptedEvent = {
        event: 'interrupted', query_id: queryId, ts: now(),
        partial_count: interruptedCount,
        // Cursor covers everything delivered (incl. snapshot-buffered items that were not
        // yet sent as `partial`, so resume after a snapshot-mode interrupt is exact).
        cursor: cursorFor(ctx),
        cache_state: ctx.cacheState,
      };
      sink.push(ev);
      return exitCodeFor('interrupted');
    }

    if (!terminal && closedEarly) {
      return emitTerminalError(sink, queryId, 'script_crashed',
        'streaming IDA session ended without a terminal frame (daemon crashed?)',
        ctx.runningCount, null);
    }
    if (terminal && terminal.ok === false) {
      return emitTerminalError(sink, queryId, 'script_crashed',
        terminal.error ?? 'streaming script failed', ctx.runningCount, null);
    }

    if (ctx.snapshotMode) emitSnapshot();

    // §5.7 reason precedence: client-side stop wins; else honor the script's own reason.
    // `cursor_exhausted` when --resume found nothing new (the watermark already covered
    // everything currently in the DB).
    let reason: CompleteReason = stopReason
      ?? (terminal?.reason as CompleteReason | undefined)
      ?? 'natural';
    if (ctx.resumeSeen.length && ctx.runningCount === 0 && stopReason === null) {
      reason = 'cursor_exhausted';
    }
    ctx.cacheState = classifyCache(ctx.cacheDir, ctx.binHash, ctx.effectiveBinary, ctx.opts.module);
    const complete: CompleteEvent = {
      event: 'complete', query_id: queryId, ts: now(),
      count: ctx.runningCount, reason, durationSec: elapsed(start),
      cursor: cursorFor(ctx), cache_state: ctx.cacheState,
    };
    sink.push(complete);
    return exitCodeFor('complete');
  } catch (e) {
    flushPending(true);
    return emitTerminalError(sink, queryId, 'ida_crashed',
      `streaming failed: ${e instanceof Error ? e.message : String(e)}`, ctx.runningCount, null);
  } finally {
    clearInterval(cadenceTimer);
    if (maxWaitTimer) clearTimeout(maxWaitTimer);
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
  }
}

// ─── --watch mode (§5.6): snapshot, then poll+diff on an interval, emitting deltas ──────
//
// Implementation is poll-based, not hook-based: we re-run the op as a single snapshot pass
// against the live (still-warming or settled) database every WATCH_POLL_MS, diff by identity
// against the prior result set (diffSnapshots), and emit a `delta{added,removed}` whenever
// something changed. This is the "pragmatic implementation" the scope calls for; its
// limitation (vs. a true ida_idp mutation hook) is documented in the report: latency is the
// poll interval, and `mutation` is a best-effort guess from the shape of the change, not the
// actual IDA event that caused it. Runs until SIGINT/SIGTERM or --max-wait.
async function runWatch(ctx: RunContext): Promise<number> {
  const { resolved, op, queryId, start, sink } = ctx;
  const WATCH_POLL_MS = 2_000;

  // Run one snapshot pass against the daemon and return the full (deduped-by-identity)
  // result set. Used for the initial snapshot AND each poll. A short per-pass deadline keeps
  // each poll responsive on a still-warming DB instead of blocking the whole budget.
  const passDeadline = Math.min(ctx.deadlineSec, 10);
  const runPass = async (): Promise<{ items: Record<string, unknown>[]; pid: number } | { error: string }> => {
    let script: string;
    try { script = composeStreamScript(op, ctx.opts.params, { watchPass: true }); }
    catch (e) { return { error: e instanceof Error ? e.message : String(e) }; }
    const collected: Record<string, unknown>[] = [];
    const localSeen = new Set<string>();
    const onFrame = (f: StreamFrame): void => {
      if (f.kind === 'partial' && f.items) {
        for (const item of f.items) {
          const id = identityOf(op, item);
          if (id !== null) { if (localSeen.has(id)) continue; localSeen.add(id); }
          collected.push(item);
        }
      }
    };
    const started = await runStreamOnDaemon(ctx.spec, script, passDeadline, onFrame, op);
    if (started.status === 'unavailable') return { error: started.error };
    // Cold binary still warming: no items this pass — emit an empty snapshot and keep polling
    // until the daemon's socket binds and analysis surfaces matches (Phase 3).
    if (started.status === 'warming') return { items: [], pid: started.pid };
    // Hard bound (Phase 3): don't wait past the pass deadline + grace for a daemon stuck in an
    // uninterruptible slice — take whatever items arrived and let the next poll continue.
    const handle = started.handle;
    const res = await Promise.race([
      handle.done.then((d) => ({ timedOut: false as const, terminal: d.terminal })),
      sleep((passDeadline + 5) * 1000).then(() => ({ timedOut: true as const, terminal: undefined })),
    ]);
    if (res.timedOut) handle.stop();
    if (res.terminal && res.terminal.ok === false) return { error: res.terminal.error ?? 'watch pass failed' };
    return { items: collected, pid: started.pid };
  };

  // Stop control.
  let stop = false;
  let stopReason: CompleteReason | null = null;
  const onSignal = () => { stop = true; };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  let maxWaitTimer: ReturnType<typeof setTimeout> | undefined;
  if (resolved.flags.maxWait !== undefined) {
    maxWaitTimer = setTimeout(() => { stop = true; stopReason = 'max_wait'; },
      resolved.flags.maxWait * 1000);
  }

  try {
    // Initial snapshot (§5.6: "after the initial snapshot is delivered, keep subscribed").
    const first = await runPass();
    if ('error' in first) {
      return emitTerminalError(sink, queryId, 'ida_crashed',
        `could not start a streaming IDA session: ${first.error}`, 0, null);
    }
    emitMeta(ctx, first.pid);
    let prior = first.items;
    for (const it of prior) { const id = identityOf(op, it); if (id !== null) ctx.seen.add(id); }
    ctx.runningCount = prior.length;
    sink.push({ event: 'snapshot', query_id: queryId, ts: now(), items: prior, count: prior.length } as SnapshotEvent);

    // Poll loop: re-run, diff, emit deltas until stopped.
    while (!stop) {
      await sleep(WATCH_POLL_MS);
      if (stop) break;
      const next = await runPass();
      if ('error' in next) continue;  // transient pass failure: try again next tick
      const { added, removed } = diffSnapshots(op, prior, next.items);
      if (added.length || removed.length) {
        for (const it of added) { const id = identityOf(op, it); if (id !== null) ctx.seen.add(id); }
        ctx.runningCount += added.length - removed.length;
        const ev: DeltaEvent = {
          event: 'delta', query_id: queryId, ts: now(),
          added, removed, mutation: guessMutation(added.length, removed.length),
        };
        sink.push(ev);
      }
      prior = next.items;
    }

    // §7 watch terminal: --max-wait → complete; SIGINT/SIGTERM → interrupted.
    ctx.cacheState = classifyCache(ctx.cacheDir, ctx.binHash, ctx.effectiveBinary, ctx.opts.module);
    if (stopReason === 'max_wait') {
      sink.push({
        event: 'complete', query_id: queryId, ts: now(),
        count: ctx.runningCount, reason: 'max_wait', durationSec: elapsed(start),
        cursor: cursorFor(ctx), cache_state: ctx.cacheState,
      } as CompleteEvent);
      return exitCodeFor('complete');
    }
    sink.push({
      event: 'interrupted', query_id: queryId, ts: now(),
      partial_count: ctx.runningCount, cursor: cursorFor(ctx), cache_state: ctx.cacheState,
    } as InterruptedEvent);
    return exitCodeFor('interrupted');
  } catch (e) {
    return emitTerminalError(sink, queryId, 'ida_crashed',
      `watch failed: ${e instanceof Error ? e.message : String(e)}`, ctx.runningCount, null);
  } finally {
    if (maxWaitTimer) clearTimeout(maxWaitTimer);
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
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

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// Map a progress `phase` to the §5.2 `status.stage` enum. The progress vocabulary has two
// extra values (`idle`, `done`) with no status equivalent; collapse them to `analyzing`
// since `status` only fires while still waiting for the first item.
function phaseToStage(phase: ProgressEvent['phase']): StatusEvent['stage'] {
  switch (phase) {
    case 'swift_metadata': return 'swift_metadata';
    case 'indexing':       return 'indexing';
    case 'decompiling':    return 'decompiling';
    default:               return 'analyzing';
  }
}

// Best-effort map of a poll-diff shape to the §5.6 `mutation` enum. We can't see the real
// IDA event that caused the change (poll-based watch), so we infer from the diff: pure
// additions look like new functions/data; removals like renames/removals; a mix like
// reanalysis. Documented as approximate in the report.
function guessMutation(added: number, removed: number): DeltaEvent['mutation'] {
  if (added > 0 && removed === 0) return 'functions_added';
  if (added === 0 && removed > 0) return 'functions_removed';
  if (added > 0 && removed > 0) return 'functions_renamed';  // identity churn ≈ rename
  return 'reanalysis';
}

function resolveBackendName(requested: 'auto' | BackendName, config: Config): BackendName {
  if (requested !== 'auto') return requested;
  if (config.defaults.backend !== 'auto') return config.defaults.backend;
  return 'ida';
}

// Duplicated from runner.ts (kept local to avoid widening runner's export surface).
function extractSlice(binary: string, arch: string, cacheDir: string, originalHash: string): string {
  // Thin binary → nothing to slice; --arch is a no-op. Return the whole binary so the cache key
  // matches `re status`/`re wait --arch` (which also fall back to the whole-binary hash).
  const archs = machoArchs(binary);
  if (archs.length <= 1) {
    process.stderr.write(
      `[re] ${basename(binary)} is a thin ${archs[0] ?? arch} binary; --arch ${arch} ignored (slicing only applies to fat binaries)\n`);
    return binary;
  }
  const sliceDir = join(expandHome(cacheDir), 'slices');
  mkdirSync(sliceDir, { recursive: true });
  const slicePath = join(sliceDir, `${originalHash}-${arch}`);
  if (!existsSync(slicePath)) {
    const { status } = spawnSync('lipo', [binary, '-thin', arch, '-output', slicePath]);
    if (status !== 0) return binary;
  }
  return slicePath;
}
