import { existsSync, readFileSync, writeFileSync, rmSync, statSync } from 'node:fs';
import { mkdirSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import process from 'node:process';
import { spawn, spawnSync } from 'node:child_process';
import type { BackendName } from './backends/types.ts';
import type { Config } from './config.ts';
import type { REResult } from './result.ts';
import { binaryHash, resultKey, randomId, elapsed, expandHome } from './util.ts';
import {
  hasIdb, idbPath, idbCacheDir, ensureIdbDir,
  hasHop, hopPath,
  getCachedResult, saveResult,
} from './cache.ts';
import { buildIdaCommand } from './backends/ida.ts';
import { buildHopperCommand } from './backends/hopper.ts';
import { runOnDaemon, probeDaemon, daemonKey } from './daemon.ts';
import { tryAcquireAnalysisLock, waitForAnalysisLock, type AnalysisLock } from './lock.ts';
import { startNarrator } from './progress.ts';

export type DaemonMode = 'auto' | 'on' | 'off';

const SCRIPTS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts');

export interface RunOptions {
  backend: 'auto' | BackendName;
  command: string;
  binary: string;
  params: Record<string, unknown>;
  config: Config;
  noCache: boolean;
  noIdbCache: boolean;
  timeout: number;
  arch?: string;
  module?: string;  // when set, treat `binary` as a DSC and load this module from it
  daemonMode?: DaemonMode;  // auto (default) | on (force) | off (never)
}

function resolveBackend(
  requested: 'auto' | BackendName,
  config: Config,
): BackendName {
  if (requested !== 'auto') return requested;
  if (config.defaults.backend !== 'auto') return config.defaults.backend;
  return 'ida';
}

function composeScript(
  backend: BackendName,
  command: string,
  outputPath: string,
  params: Record<string, unknown>,
): string {
  const basePath = join(SCRIPTS_DIR, backend, '_base.py');
  const bodyPath = join(SCRIPTS_DIR, backend, `${command}.py`);

  if (!existsSync(basePath)) throw new Error(`No base script for backend: ${backend}`);
  if (!existsSync(bodyPath)) throw new Error(`No script for command '${command}' (backend: ${backend})`);

  // Encode params as hex so any string content (quotes, backslashes, nulls) is safe
  const paramsHex = Buffer.from(JSON.stringify(params)).toString('hex');
  const preamble = [
    'import json as _json',
    'import os as _os',
    `_RE_OUTPUT_PATH = ${JSON.stringify(outputPath)}`,
    `_RE_COMMAND = ${JSON.stringify(command)}`,
    `_RE_PARAMS = _json.loads(bytes.fromhex(${JSON.stringify(paramsHex)}))`,
    '',
  ].join('\n');

  return preamble + '\n' + readFileSync(basePath, 'utf8') + '\n' + readFileSync(bodyPath, 'utf8');
}

// Run the backend asynchronously and narrate progress to STDERR. A blocking
// spawnSync would freeze the event loop for the whole (possibly multi-minute)
// analysis and discard the disassembler's output, so a caller — human or
// program — sees nothing until it finishes or is killed, indistinguishable from
// a hang. Instead we stream a heartbeat (with the tail of the backend's own log)
// so the run is observably alive. stdout stays reserved for the JSON result.
function spawnTool(
  cmd: string,
  args: string[],
  timeoutMs: number,
  logPath: string,
  label: string,
  extraEnv?: Record<string, string>,
): Promise<{ timedOut: boolean; exitCode: number }> {
  return new Promise((resolve) => {
    const env = extraEnv ? { ...process.env, ...extraEnv } : process.env;
    const child = spawn(cmd, args, { stdio: 'ignore', env });

    let timedOut = false;
    let settled = false;
    // Narrate progress to stderr (deduped, with a coarse phase) so the run is
    // observably alive without spamming repeats. stdout stays the JSON result.
    const stopNarrator = startNarrator(logPath, label);

    // A timeout is opt-in (--timeout N). With none, analysis runs to completion —
    // large binaries legitimately take many minutes, and the heartbeat above keeps
    // the run observable so a watcher can intervene if it ever truly hangs.
    const killer = timeoutMs > 0
      ? setTimeout(() => {
          timedOut = true;
          child.kill('SIGKILL');
        }, timeoutMs)
      : undefined;

    const finish = (code: number) => {
      if (settled) return;
      settled = true;
      stopNarrator();
      if (killer) clearTimeout(killer);
      resolve({ timedOut, exitCode: code });
    };

    child.on('exit', (code) => finish(code ?? 0));
    child.on('error', () => finish(1));
  });
}

function mkError(
  opts: RunOptions,
  binHash: string,
  backend: BackendName | null,
  dur: number,
  type: string,
  message: string,
  logExcerpt?: string,
): REResult {
  return {
    status: 'error',
    command: opts.command,
    binary: opts.binary,
    binaryHash: binHash,
    backend,
    backendVersion: null,
    durationSec: dur,
    cached: false,
    data: null,
    error: { type, message, ...(logExcerpt ? { logExcerpt } : {}) },
  };
}

function extractSlice(binary: string, arch: string, cacheDir: string, originalHash: string): string {
  const sliceDir = join(expandHome(cacheDir), 'slices');
  mkdirSync(sliceDir, { recursive: true });
  const slicePath = join(sliceDir, `${originalHash}-${arch}`);
  if (!existsSync(slicePath)) {
    const { status } = spawnSync('lipo', [binary, '-thin', arch, '-output', slicePath]);
    if (status !== 0) return binary; // not a fat binary or arch not present
  }
  return slicePath;
}

// Decide whether this query should run through a warm daemon or a one-shot spawn.
// `daemonAlive` is whether one is already serving this binary — if so we must route
// through it (it holds an exclusive lock on the database, so a one-shot can't open it).
function daemonDecision(
  opts: RunOptions,
  sizeMb: number,
  daemonAlive: boolean,
): { use: boolean; notice?: string } {
  const mode = opts.daemonMode ?? 'auto';

  if (daemonAlive) {
    // The cached database is locked by the running daemon; only it can read it now.
    // Routing through it returns identical (warm) results, so honor that over the
    // flags that would otherwise force a one-shot.
    if (mode === 'off') {
      return { use: true, notice: '[re] a daemon is serving this binary; --daemon=off ignored (stop it with: re daemon stop <binary>)' };
    }
    if (opts.noIdbCache) {
      return { use: true, notice: '[re] a daemon is serving this binary; --no-idb-cache ignored (stop it with: re daemon stop <binary>)' };
    }
    return { use: true };
  }

  // No daemon yet — decide whether to start one.
  if (mode === 'off') return { use: false };
  // A daemon implies a persisted/warm database; --no-idb-cache asks for fresh,
  // non-persisted analysis, so the two are mutually exclusive — stay one-shot.
  if (opts.noIdbCache) {
    return {
      use: false,
      notice: mode === 'on'
        ? '[re] --no-idb-cache forces fresh analysis; skipping daemon'
        : undefined,
    };
  }
  if (mode === 'on') return { use: true };  // force, overriding size gate + enabled
  const cfg = opts.config.daemon;
  if (!cfg.enabled) return { use: false };
  if (sizeMb < cfg.autostartMinMb) return { use: false };
  return { use: true };
}

// Turn the JSON a backend script wrote at `outputPath` into a REResult. Shared by the
// one-shot and daemon paths. keepTmp signals the temp dir should be preserved for
// post-mortem (missing/garbled output).
function buildResultFromOutput(
  opts: RunOptions,
  binHash: string,
  backend: BackendName,
  start: number,
  outputPath: string,
  logPath: string,
): { result: REResult; keepTmp: boolean } {
  if (!existsSync(outputPath)) {
    const logExcerpt = existsSync(logPath) ? readFileSync(logPath, 'utf8').slice(-3000) : undefined;
    return {
      result: mkError(opts, binHash, backend, elapsed(start), 'NoOutput',
        'Script produced no output — check logExcerpt for details', logExcerpt),
      keepTmp: true,
    };
  }
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(readFileSync(outputPath, 'utf8')) as Record<string, unknown>;
  } catch (e) {
    return {
      result: mkError(opts, binHash, backend, elapsed(start), 'ParseError',
        `Failed to parse script output: ${e}`),
      keepTmp: true,
    };
  }
  const result: REResult = {
    status: (raw['status'] as REResult['status']) ?? 'ok',
    command: opts.command,
    binary: opts.binary,
    binaryHash: binHash,
    backend,
    backendVersion: (raw['backendVersion'] as string | null) ?? null,
    durationSec: elapsed(start),
    cached: false,
    data: raw['data'] ?? null,
    error: (raw['error'] as REResult['error']) ?? null,
  };
  return { result, keepTmp: false };
}

// Memoize the result and, after a fresh IDA analysis, record idb-cache metadata.
// Behavior matches the original one-shot path; reused by the daemon path.
function finalizeCaching(
  opts: RunOptions,
  binHash: string,
  backend: BackendName,
  cacheKeyParams: Record<string, unknown>,
  result: REResult,
  useIdb: boolean,
  effectiveBinary: string,
  cacheDir: string,
): void {
  if (!opts.noCache && result.status === 'ok') {
    saveResult(cacheDir, resultKey(binHash, opts.command, cacheKeyParams), result);
  }
  if (!useIdb && backend === 'ida') {
    const idbDir = idbCacheDir(cacheDir, binHash, opts.module);
    const idbFile = join(idbDir, 'binary.i64');
    if (existsSync(idbFile)) {
      const s = statSync(effectiveBinary);
      writeFileSync(join(idbDir, 'meta.json'), JSON.stringify({
        path: opts.binary,
        mtimeMs: s.mtimeMs,
        size: s.size,
        ...(opts.module ? { module: opts.module } : {}),
      }));
    }
  }
}

export async function run(opts: RunOptions): Promise<REResult> {
  const start = Date.now();

  if (!existsSync(opts.binary)) {
    return {
      status: 'error', command: opts.command, binary: opts.binary, binaryHash: '',
      backend: null, backendVersion: null, durationSec: 0, cached: false, data: null,
      error: { type: 'FileNotFound', message: `Binary not found: ${opts.binary}` },
    };
  }

  const cacheDir = opts.config.cache.dir;
  const originalHash = binaryHash(opts.binary);
  // DSCs are not fat Mach-Os; skip slice extraction when loading a module from a DSC.
  const effectiveBinary = opts.arch && !opts.module
    ? extractSlice(opts.binary, opts.arch, cacheDir, originalHash)
    : opts.binary;
  const binHash = effectiveBinary !== opts.binary ? binaryHash(effectiveBinary) : originalHash;

  // Result cache fast-path: module is part of the key so different modules cache separately.
  const cacheKeyParams = opts.module ? { ...opts.params, __module: opts.module } : opts.params;
  if (!opts.noCache) {
    const rKey = resultKey(binHash, opts.command, cacheKeyParams);
    const cached = getCachedResult(cacheDir, rKey, opts.config.cache.resultTtl);
    if (cached) return { ...cached, cached: true, durationSec: elapsed(start) };
  }

  const backend = resolveBackend(opts.backend, opts.config);
  const toolPath = backend === 'ida' ? opts.config.tools.idat64 : opts.config.tools.hopper;

  if (!toolPath || !existsSync(toolPath)) {
    const toolName = backend === 'ida' ? 'idat64' : 'hopper';
    return mkError(opts, binHash, backend, elapsed(start), 'ToolNotFound',
      `${toolName} not found. Set RE_${toolName.toUpperCase()} env var or add to ~/.config/re-cli/config.json`);
  }

  let useIdb = !opts.noIdbCache && backend === 'ida' && hasIdb(cacheDir, binHash, opts.module);
  const useHop = !opts.noIdbCache && backend === 'hopper' && hasHop(cacheDir, binHash, opts.module);

  const tmpDir = join(tmpdir(), `re_${randomId()}`);
  mkdirSync(tmpDir, { recursive: true });

  const scriptPath = join(tmpDir, 'script.py');
  const outputPath = join(tmpDir, 'output.json');
  const logPath = join(tmpDir, 'ida.log');

  let keepTmp = false;

  try {
    let script: string;
    try {
      script = composeScript(backend, opts.command, outputPath, opts.params);
    } catch (e) {
      return mkError(opts, binHash, backend, elapsed(start), 'ScriptError', String(e));
    }
    writeFileSync(scriptPath, script);

    // Build subprocess command
    let cmd: string;
    let args: string[];

    if (backend === 'ida') {
      const outputIdbPath = useIdb
        ? undefined
        : join(ensureIdbDir(cacheDir, binHash, opts.module), 'binary.i64');
      ({ cmd, args } = buildIdaCommand({
        binaryPath: effectiveBinary,
        idbPath: useIdb ? idbPath(cacheDir, binHash, opts.module) : undefined,
        outputIdbPath,
        scriptPath,
        logPath,
        module: opts.module,
      }, toolPath));
    } else {
      ({ cmd, args } = buildHopperCommand({
        binaryPath: effectiveBinary,
        hopPath: useHop ? hopPath(cacheDir, binHash, opts.module) : undefined,
        scriptPath,
        logPath,
        module: opts.module,
      }, toolPath));
    }

    const extraEnv = backend === 'ida' && opts.module
      ? { IDA_DYLD_CACHE_MODULE: opts.module }
      : undefined;

    const sizeMb = statSync(effectiveBinary).size / 1048576;
    const archTag = opts.arch ? ` ${opts.arch}` : '';
    const moduleTag = opts.module ? `::${basename(opts.module)} ` : '';
    const mode = (useIdb || useHop) ? 'reading cached database' : 'fresh analysis';
    const label = `${backend} ${opts.command}: ${mode} of ${moduleTag}${basename(opts.binary)} (${sizeMb.toFixed(1)} MB${archTag})`;

    // ── Strategy: route through a warm daemon, or spawn a one-shot process ──
    const daemonAlive = await probeDaemon(cacheDir, backend, binHash, opts.module);
    const decision = daemonDecision(opts, sizeMb, daemonAlive);
    if (decision.notice) process.stderr.write(decision.notice + '\n');

    if (decision.use) {
      const outputIdbPath = (backend === 'ida' && !useIdb)
        ? join(ensureIdbDir(cacheDir, binHash, opts.module), 'binary.i64')
        : undefined;
      const outcome = await runOnDaemon({
        cacheDir, backend, toolPath, binHash,
        module: opts.module,
        binaryPath: opts.binary,
        effectiveBinary,
        idbPath: backend === 'ida' && useIdb ? idbPath(cacheDir, binHash, opts.module) : undefined,
        outputIdbPath,
        hopPath: backend === 'hopper' && useHop ? hopPath(cacheDir, binHash, opts.module) : undefined,
        idleTimeout: opts.config.daemon.idleTimeout,
        timeoutMs: opts.timeout * 1000,
        extraEnv,
        label,
      }, script);

      if (outcome.status === 'served') {
        const fin = buildResultFromOutput(opts, binHash, backend, start, outputPath, logPath);
        keepTmp = fin.keepTmp;
        if (!fin.keepTmp) {
          finalizeCaching(opts, binHash, backend, cacheKeyParams, fin.result, useIdb, effectiveBinary, cacheDir);
        }
        return fin.result;
      }
      if (outcome.status === 'execError') {
        keepTmp = true;
        return mkError(opts, binHash, backend, elapsed(start), 'DaemonExecError', outcome.error);
      }
      // 'unavailable' → fall through to a one-shot spawn below.
      process.stderr.write(`[re] daemon unavailable (${outcome.error}); running one-shot\n`);
    }

    // ── One-shot spawn (also the daemon fallback) ──
    // Guard concurrent fresh IDA analyses of the same binary: without a lock both
    // would run `idat64 -A -c -o<same .i64>` and clobber each other. The daemon
    // decision above already funnels big/auto runs through one daemon; this covers
    // the one-shot cases it skips (--daemon=off, sub-gate sizes, --no-idb-cache).
    let analysisLock: AnalysisLock | undefined;
    if (backend === 'ida' && !useIdb) {
      const lockKey = daemonKey(backend, binHash, opts.module);
      let announced = false;
      // Loop until we either hold the lock (our turn to analyze) or can reuse a
      // database a holder just built. Looping (not a single wait) is required so
      // that with 3+ contenders the losers of each round wait again rather than
      // racing ahead unlocked.
      while (true) {
        const res = tryAcquireAnalysisLock(cacheDir, lockKey);
        if (res.acquired) { analysisLock = res.lock; break; }
        if (!announced) {
          announced = true;
          const waited = res.startedAt ? Math.round((Date.now() - res.startedAt) / 1000) : 0;
          const detail = res.holderPid ? ` (pid ${res.holderPid}, ${waited}s in)` : '';
          process.stderr.write(
            `[re] another re process is already analyzing ${basename(opts.binary)}${detail}; waiting…\n`);
        }
        await waitForAnalysisLock(cacheDir, lockKey);
        // Holder released: reuse the database it built rather than re-analyzing,
        // unless the caller forced fresh analysis (--no-idb-cache).
        if (!opts.noIdbCache && hasIdb(cacheDir, binHash, opts.module)) {
          useIdb = true;
          ({ cmd, args } = buildIdaCommand({
            binaryPath: effectiveBinary,
            idbPath: idbPath(cacheDir, binHash, opts.module),
            scriptPath, logPath, module: opts.module,
          }, toolPath));
          process.stderr.write('[re] reusing the freshly built database (warm reload)\n');
          break;
        }
      }
    }

    try {
      const { timedOut } = await spawnTool(cmd, args, opts.timeout * 1000, logPath, label, extraEnv);

      if (timedOut) {
        keepTmp = true;
        return {
          status: 'timeout',
          command: opts.command, binary: opts.binary, binaryHash: binHash,
          backend, backendVersion: null,
          durationSec: elapsed(start), cached: false, data: null,
          error: { type: 'Timeout', message: `Process did not complete within ${opts.timeout}s` },
        };
      }

      const fin = buildResultFromOutput(opts, binHash, backend, start, outputPath, logPath);
      keepTmp = fin.keepTmp;
      if (!fin.keepTmp) {
        finalizeCaching(opts, binHash, backend, cacheKeyParams, fin.result, useIdb, effectiveBinary, cacheDir);
      }
      return fin.result;
    } finally {
      analysisLock?.release();
    }
  } finally {
    if (!keepTmp) {
      try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  }
}
