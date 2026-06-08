import { existsSync, readFileSync, writeFileSync, rmSync, statSync } from 'node:fs';
import { mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
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

function spawnTool(
  cmd: string,
  args: string[],
  timeoutMs: number,
  extraEnv?: Record<string, string>,
): { timedOut: boolean; exitCode: number } {
  const env = extraEnv ? { ...process.env, ...extraEnv } : process.env;
  const result = spawnSync(cmd, args, { stdio: 'ignore', timeout: timeoutMs, env });
  const timedOut =
    result.signal === 'SIGTERM' ||
    (result.error != null && result.error.message.includes('ETIMEDOUT'));
  return { timedOut, exitCode: result.status ?? 0 };
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

export function run(opts: RunOptions): REResult {
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

  const useIdb = !opts.noIdbCache && backend === 'ida' && hasIdb(cacheDir, binHash, opts.module);
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
    const { timedOut } = spawnTool(cmd, args, opts.timeout * 1000, extraEnv);

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

    if (!existsSync(outputPath)) {
      keepTmp = true;
      const logExcerpt = existsSync(logPath)
        ? readFileSync(logPath, 'utf8').slice(-3000)
        : undefined;
      return mkError(opts, binHash, backend, elapsed(start), 'NoOutput',
        'Script produced no output — check logExcerpt for details', logExcerpt);
    }

    let raw: Record<string, unknown>;
    try {
      raw = JSON.parse(readFileSync(outputPath, 'utf8')) as Record<string, unknown>;
    } catch (e) {
      keepTmp = true;
      return mkError(opts, binHash, backend, elapsed(start), 'ParseError',
        `Failed to parse script output: ${e}`);
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

    if (!opts.noCache && result.status === 'ok') {
      const rKey = resultKey(binHash, opts.command, cacheKeyParams);
      saveResult(cacheDir, rKey, result);
    }

    // Save IDB cache metadata after a fresh analysis
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

    return result;
  } finally {
    if (!keepTmp) {
      try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  }
}
