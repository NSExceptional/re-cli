#!/usr/bin/env -S node --experimental-strip-types --no-warnings

import process from 'node:process';
import { spawn } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync, rmSync } from 'node:fs';
import { join, basename } from 'node:path';
import { loadConfig, CONFIG_FILE } from './config.ts';
import { run } from './runner.ts';
import type { DaemonMode } from './runner.ts';
import { listDaemons, stopAllDaemons, stopDaemonsForBinary, daemonFor, daemonStreamStats, daemonKey } from './daemon.ts';
import { analysisLockHolder } from './lock.ts';
import { phaseFromLog } from './progress.ts';
import { expandHome, binaryHash, elapsed } from './util.ts';
import { idbCacheDir, idbPath, resultPath, hasIdb } from './cache.ts';
import {
  resolveDscPath, listDscModules, resolveDscModule,
  listSimRuntimes, formatSimsByPlatform, formatSimsForPlatform,
  parseSimSpec,
} from './dsc.ts';
import type { SimPlatform } from './dsc.ts';
import type { REResult, BackendName } from './result.ts';
import {
  STREAM_VALUE_FLAGS, hasStreamingFlags, parseStreamFlags, validateStream, ValidateError,
} from './stream.ts';
import { runStream } from './stream_runner.ts';

// ─── Arg parsing ────────────────────────────────────────────────────────────

const VALUE_FLAGS = new Set([
  'backend', 'timeout', 'format', 'arch', 'sim', 'dsc', 'daemon',
  'function', 'address', 'count', 'filter', 'type',
  'min-length', 'to', 'from', 'library', 'range',
  'older-than', 'max-size',
  // Streaming API (issue #13) value-taking flags.
  ...STREAM_VALUE_FLAGS,
]);

interface ParsedArgs {
  command: string;
  positional: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') {
      positional.push(...argv.slice(i + 1));
      break;
    }
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const eq = key.indexOf('=');
      if (eq !== -1) {
        flags[key.slice(0, eq)] = key.slice(eq + 1);
      } else if (key.startsWith('no-')) {
        flags[key.slice(3)] = false;
      } else if (VALUE_FLAGS.has(key) && i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
        flags[key] = argv[++i];
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }

  const [command = '', ...rest] = positional;
  return { command, positional: rest, flags };
}

// ─── Output formatting ───────────────────────────────────────────────────────

function printResult(result: REResult, format: string): void {
  if (format === 'pretty') {
    printPretty(result);
  } else {
    process.stdout.write(JSON.stringify(result) + '\n');
  }
}

function printPretty(r: REResult): void {
  const header = `[${r.backend ?? '?'}] ${r.command} ${r.binary} (${r.durationSec}s${r.cached ? ', cached' : ''})`;

  if (r.status === 'error' || r.status === 'timeout') {
    process.stderr.write(`Error: ${r.error?.message ?? 'unknown'}\n`);
    if (r.error?.suggestions?.length) {
      process.stderr.write('Did you mean:\n');
      for (const s of r.error.suggestions) process.stderr.write(`  ${s}\n`);
    }
    if (r.error?.logExcerpt) process.stderr.write(r.error.logExcerpt + '\n');
    return;
  }

  console.log(header);

  if (!r.data) return;

  const data = r.data as Record<string, unknown>;

  switch (r.command) {
    case 'symbols':
    case 'functions': {
      const rows = r.data as Array<{ address: string; name: string; type?: string }>;
      for (const row of rows) {
        console.log(`  ${row.address.padEnd(18)} ${(row.type ?? '').padEnd(10)} ${row.name}`);
      }
      console.log(`  — ${rows.length} entries`);
      break;
    }
    case 'decompile': {
      const d = r.data as { function?: string; address?: string; pseudocode?: string };
      console.log(`  // ${d.function ?? d.address ?? ''}`);
      console.log(d.pseudocode ?? '(no pseudocode)');
      break;
    }
    case 'disasm': {
      const rows = r.data as Array<{ address: string; mnemonic: string; operands?: string }>;
      for (const row of rows) {
        console.log(`  ${row.address.padEnd(18)} ${row.mnemonic} ${row.operands ?? ''}`);
      }
      break;
    }
    case 'info': {
      for (const [k, v] of Object.entries(data)) {
        console.log(`  ${k.padEnd(16)} ${v}`);
      }
      break;
    }
    case 'imports':
    case 'exports': {
      const rows = r.data as Array<{ address?: string; name: string; library?: string }>;
      for (const row of rows) {
        const lib = row.library ? `  [${row.library}]` : '';
        console.log(`  ${(row.address ?? '').padEnd(18)} ${row.name}${lib}`);
      }
      console.log(`  — ${rows.length} entries`);
      break;
    }
    case 'xrefs': {
      const rows = r.data as Array<{ from: string; to: string; type?: string }>;
      for (const row of rows) {
        console.log(`  ${row.from.padEnd(18)} → ${row.to.padEnd(18)} ${row.type ?? ''}`);
      }
      console.log(`  — ${rows.length} xrefs`);
      break;
    }
    case 'strings': {
      const rows = r.data as Array<{ address: string; value: string }>;
      for (const row of rows) {
        console.log(`  ${row.address.padEnd(18)} ${JSON.stringify(row.value)}`);
      }
      console.log(`  — ${rows.length} strings`);
      break;
    }
    case 'segments': {
      const rows = r.data as Array<{ name: string; start: string; end: string; type?: string }>;
      for (const row of rows) {
        console.log(`  ${row.name.padEnd(16)} ${row.start} – ${row.end} ${row.type ?? ''}`);
      }
      break;
    }
    default:
      console.log(JSON.stringify(r.data, null, 2));
  }
}

// ─── Global flags → RunOptions fields ───────────────────────────────────────

// --daemon is tri-state: auto (default) | on (force) | off (never). Accepts truthy/falsy
// spellings too: bare `--daemon` → on, `--no-daemon`/`--daemon=false` → off.
function daemonModeFromFlags(flags: Record<string, string | boolean>): DaemonMode {
  const v = flags['daemon'];
  if (v === undefined) return 'auto';
  if (v === true) return 'on';
  if (v === false) return 'off';
  const s = String(v).toLowerCase();
  if (['off', 'false', 'no', '0', 'disable', 'disabled'].includes(s)) return 'off';
  if (['on', 'true', 'yes', '1', 'force', 'always'].includes(s)) return 'on';
  if (s === 'auto') return 'auto';
  process.stderr.write(`Invalid --daemon value: ${v} (use auto|on|off)\n`);
  process.exit(1);
}

// Default to human-readable output at a terminal, machine-readable JSON when piped or
// redirected (incl. when an agent captures the output). --format always overrides.
function defaultFormat(flags: Record<string, string | boolean>): string {
  return String(flags['format'] ?? (process.stdout.isTTY ? 'pretty' : 'json'));
}

function globalRunOpts(flags: Record<string, string | boolean>, config: ReturnType<typeof loadConfig>) {
  return {
    backend: (flags['backend'] as 'auto' | BackendName | undefined) ?? 'auto',
    noCache:    flags['cache']    === false,
    noIdbCache: flags['idb-cache'] === false,
    timeout:    Number(flags['timeout']) || config.defaults.timeout,
    format:     defaultFormat(flags),
    daemonMode: daemonModeFromFlags(flags),
    config,
  };
}

// ─── Cache subcommands ───────────────────────────────────────────────────────

function dirSize(p: string): number {
  let total = 0;
  const walk = (d: string) => {
    let entries: string[];
    try { entries = readdirSync(d); } catch { return; }
    for (const e of entries) {
      const fp = join(d, e);
      let st;
      try { st = statSync(fp); } catch { continue; }
      if (st.isDirectory()) walk(fp); else total += st.size;
    }
  };
  let top;
  try { top = statSync(p); } catch { return 0; }
  if (top.isDirectory()) walk(p); else total = top.size;
  return total;
}

const fmtMB = (bytes: number): string => (bytes / 1048576).toFixed(1) + ' MB';

// Middle-truncate long paths (DSC module paths especially) so list/du stay columnar.
function truncPath(p: string, max = 64): string {
  if (p.length <= max) return p;
  const keep = max - 1, head = Math.ceil(keep * 0.4), tail = keep - head;
  return p.slice(0, head) + '…' + p.slice(p.length - tail);
}

interface IdbEntry { dir: string; label: string; path: string; module?: string; sizeBytes: number; mtimeMs: number; meta: Record<string, unknown>; }

// Enumerate cached IDB databases (flat standalone + nested DSC-module layouts).
function walkIdbEntries(cacheDir: string): IdbEntry[] {
  const idbDir = join(cacheDir, 'idb');
  const out: IdbEntry[] = [];
  if (!existsSync(idbDir)) return out;
  const add = (dir: string, label: string) => {
    const idb = join(dir, 'binary.i64');
    if (!existsSync(idb)) return;
    let meta: Record<string, unknown> = {};
    try { meta = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8')); } catch {}
    out.push({
      dir, label, path: String(meta.path ?? '(unknown)'),
      module: meta.module as string | undefined,
      sizeBytes: dirSize(dir), mtimeMs: statSync(idb).mtimeMs, meta,
    });
  };
  for (const hash of readdirSync(idbDir)) {
    const hashDir = join(idbDir, hash);
    try { if (!statSync(hashDir).isDirectory()) continue; } catch { continue; }
    if (existsSync(join(hashDir, 'binary.i64'))) add(hashDir, hash);
    else for (const mod of readdirSync(hashDir)) add(join(hashDir, mod), `${hash}/${mod}`);
  }
  return out;
}

async function cmdCache(
  args: string[],
  flags: Record<string, string | boolean>,
  config: ReturnType<typeof loadConfig>,
): Promise<void> {
  const [sub = 'list', ...rest] = args;
  const cacheDir = expandHome(config.cache.dir);

  switch (sub) {
    case 'list': {
      const idbDir = join(cacheDir, 'idb');
      if (!existsSync(idbDir)) { console.log('(no cached IDBs)'); return; }
      const showEntry = (dir: string, label: string) => {
        const idb = join(dir, 'binary.i64');
        if (!existsSync(idb)) return;
        const metaPath = join(dir, 'meta.json');
        const meta = existsSync(metaPath)
          ? JSON.parse(readFileSync(metaPath, 'utf8')) as { path: string; module?: string }
          : { path: '(unknown)' };
        const size = (statSync(idb).size / 1048576).toFixed(1) + ' MB';
        const tag = meta.module ? ` :: ${meta.module}` : '';
        console.log(`  ${label}  ${truncPath(meta.path)}${tag}  (${size})`);
      };
      for (const hash of readdirSync(idbDir)) {
        const hashDir = join(idbDir, hash);
        if (!statSync(hashDir).isDirectory()) continue;
        if (existsSync(join(hashDir, 'binary.i64'))) {
          // Flat layout: standalone binary
          showEntry(hashDir, hash);
        } else {
          // Nested layout: DSC with module subdirs
          for (const mod of readdirSync(hashDir)) {
            showEntry(join(hashDir, mod), `${hash}/${mod}`);
          }
        }
      }
      break;
    }
    case 'clear': {
      if (flags['all']) {
        // Stop daemons first — they hold the databases (and live in /tmp, outside cacheDir).
        await stopAllDaemons(cacheDir);
        rmSync(cacheDir, { recursive: true, force: true });
        console.log(`Cleared: ${cacheDir}`);
      } else {
        const binary = rest[0];
        if (!binary) {
          process.stderr.write('Usage: re cache clear <binary>  (or --all to wipe everything)\n');
          process.exit(1);
        }
        await stopDaemonsForBinary(cacheDir, binary);  // release the lock before deleting
        const hash = binaryHash(binary);
        const dir  = idbCacheDir(cacheDir, hash);
        if (existsSync(dir)) { rmSync(dir, { recursive: true, force: true }); console.log(`Cleared: ${dir}`); }
        else console.log('(nothing cached for that binary)');
      }
      break;
    }
    case 'path': {
      const binary = rest[0];
      if (!binary) { process.stderr.write('Usage: re cache path <binary> [--arch ARCH]\n'); process.exit(1); }
      const arch = flags['arch'] as string | undefined;
      const hash = arch ? effectiveHash(binary, arch, cacheDir) : binaryHash(binary);
      if (!hash) { console.log(`(no ${arch} slice extracted for that binary yet)`); break; }
      const dir = idbCacheDir(cacheDir, hash);
      console.log(dir);
      const idb = join(dir, 'binary.i64');
      if (existsSync(idb)) {
        const s = statSync(idb);
        console.log(`  ${fmtMB(s.size)}  built ${new Date(s.mtimeMs).toISOString()}`);
      } else {
        console.log('  (no database cached yet)');
      }
      break;
    }
    case 'info': {
      console.log(`Cache dir: ${cacheDir}`);
      ['idb', 'hop', 'results'].forEach(sub => {
        const d = join(cacheDir, sub);
        if (!existsSync(d)) return;
        const count = readdirSync(d).length;
        console.log(`  ${sub.padEnd(10)} ${count} entries`);
      });
      break;
    }
    case 'du': {
      const entries = walkIdbEntries(cacheDir).sort((a, b) => b.sizeBytes - a.sizeBytes);
      let idbTotal = 0;
      for (const e of entries) {
        idbTotal += e.sizeBytes;
        const mod = e.module ? ` :: ${e.module}` : '';
        console.log(`  ${fmtMB(e.sizeBytes).padStart(10)}  ${truncPath(e.path)}${mod}`);
      }
      const catSize = (name: string) => { const d = join(cacheDir, name); return existsSync(d) ? dirSize(d) : 0; };
      const hop = catSize('hop'), slices = catSize('slices'), results = catSize('results');
      console.log('  ' + '─'.repeat(46));
      console.log(`  ${fmtMB(idbTotal).padStart(10)}  idb (${entries.length} database${entries.length === 1 ? '' : 's'})`);
      if (hop) console.log(`  ${fmtMB(hop).padStart(10)}  hop`);
      if (slices) console.log(`  ${fmtMB(slices).padStart(10)}  slices`);
      if (results) console.log(`  ${fmtMB(results).padStart(10)}  results`);
      console.log(`  ${fmtMB(idbTotal + hop + slices + results).padStart(10)}  TOTAL`);
      break;
    }
    case 'gc': {
      const entries = walkIdbEntries(cacheDir);
      const toRemove: IdbEntry[] = [];
      if (flags['stale']) {
        // Stale = the source binary is gone, or a newer database exists for the same
        // source (re-analysis after the binary changed leaves the old hash orphaned).
        // We can't reliably compare mtime/size here because a sliced (--arch) entry
        // records the slice's stat under the original path — so use supersession.
        const byPath = new Map<string, IdbEntry[]>();
        for (const e of entries) {
          if (!byPath.has(e.path)) byPath.set(e.path, []);
          byPath.get(e.path)!.push(e);
        }
        for (const e of entries) {
          if (e.path === '(unknown)') continue;
          if (!existsSync(e.path)) { toRemove.push(e); continue; }
          const group = byPath.get(e.path)!;
          if (group.length > 1) {
            const newest = group.reduce((a, b) => (a.mtimeMs >= b.mtimeMs ? a : b));
            if (e !== newest) toRemove.push(e);
          }
        }
      } else if (flags['older-than'] !== undefined) {
        const cutoff = Date.now() - Number(flags['older-than']) * 86_400_000;
        for (const e of entries) if (e.mtimeMs < cutoff) toRemove.push(e);
      } else if (flags['max-size'] !== undefined) {
        const limit = Number(flags['max-size']) * 1_073_741_824;
        let total = entries.reduce((s, e) => s + e.sizeBytes, 0);
        for (const e of [...entries].sort((a, b) => a.mtimeMs - b.mtimeMs)) {
          if (total <= limit) break;
          toRemove.push(e); total -= e.sizeBytes;
        }
      } else {
        process.stderr.write('Usage: re cache gc --stale | --older-than DAYS | --max-size GB\n');
        process.exit(1);
      }
      if (!toRemove.length) { console.log('(nothing to remove)'); break; }
      let freed = 0;
      for (const e of toRemove) {
        await stopDaemonsForBinary(cacheDir, e.path);  // release any daemon holding it
        rmSync(e.dir, { recursive: true, force: true });
        freed += e.sizeBytes;
        console.log(`  removed  ${truncPath(e.path)}  (${fmtMB(e.sizeBytes)})`);
      }
      console.log(`Freed ${fmtMB(freed)} from ${toRemove.length} database${toRemove.length === 1 ? '' : 's'}`);
      break;
    }
    default:
      process.stderr.write(`Unknown cache subcommand: ${sub}\n`);
      process.exit(1);
  }
}

// ─── DSC subcommand ──────────────────────────────────────────────────────────

async function cmdDsc(
  args: string[],
  flags: Record<string, string | boolean>,
  config: ReturnType<typeof loadConfig>,
): Promise<void> {
  const [sub, ...rest] = args;
  if (!sub) {
    process.stderr.write(
      'Usage: re dsc <sims|list|info|symbols|functions|decompile|disasm|xrefs|strings|imports|exports|segments> ...\n'
    );
    process.exit(1);
  }

  // `sims` is its own discovery command, unrelated to DSC source flags.
  if (sub === 'sims') {
    const runtimes = listSimRuntimes();
    if (rest[0]) {
      const platform = rest[0] as SimPlatform;
      // Validate via parseSimSpec — it'll throw on an unknown platform.
      parseSimSpec(platform);
      process.stdout.write(formatSimsForPlatform(platform, runtimes) + '\n');
    } else {
      process.stdout.write(formatSimsByPlatform(runtimes) + '\n');
    }
    return;
  }

  // All other sub-commands need a resolved DSC path.
  const dscPath = resolveDscPath({
    sim: flags['sim'] as string | undefined,
    dsc: flags['dsc'] as string | undefined,
    arch: flags['arch'] as string | undefined,
  });

  if (sub === 'list') {
    const modules = listDscModules(dscPath);
    if (flags['format'] === 'json' || flags['format'] === undefined) {
      process.stdout.write(JSON.stringify(modules.map(m => ({
        path: m.path,
        loadAddress: '0x' + m.loadAddress.toString(16),
        textSize: m.textSize,
      }))) + '\n');
    } else {
      for (const m of modules) process.stdout.write(m.path + '\n');
    }
    return;
  }

  // For analysis operations: positional arg is the module spec.
  const paramsFor = COMMANDS[sub];
  if (!paramsFor) {
    process.stderr.write(`Unknown dsc subcommand: ${sub}\n`);
    process.exit(1);
  }
  const moduleSpec = rest[0];
  if (!moduleSpec) {
    process.stderr.write(`Usage: re dsc ${sub} <module> [flags]\n`);
    process.exit(1);
  }
  const module = resolveDscModule(dscPath, moduleSpec);

  const { backend, noCache, noIdbCache, timeout, format, daemonMode } = globalRunOpts(flags, config);

  if (backend === 'hopper') {
    throw new Error(
      "Hopper backend doesn't support DSC modules — Hopper's DSC loader always shows " +
      "an interactive module-picker dialog that can't be bypassed via its scripting interface. " +
      "Use --backend ida (or the default) for DSC analysis."
    );
  }

  const result = await run({
    backend: backend as 'auto' | BackendName,
    command: sub,
    binary: dscPath,
    params: paramsFor(flags),
    config,
    noCache,
    noIdbCache,
    timeout,
    module,
    daemonMode,
  });

  printResult(result, format);
  process.exit(result.status === 'ok' ? 0 : 1);
}

// ─── Daemon subcommand ───────────────────────────────────────────────────────

async function cmdDaemon(
  args: string[],
  flags: Record<string, string | boolean>,
  config: ReturnType<typeof loadConfig>,
): Promise<void> {
  const [sub = 'list', ...rest] = args;
  const cacheDir = config.cache.dir;

  switch (sub) {
    case 'list':
    case 'status': {
      const list = await listDaemons(cacheDir);
      if (!list.length) { console.log('(no daemons running)'); return; }
      for (const d of list) {
        const mins = Math.round((Date.now() - d.startedAt) / 60000);
        const mod = d.module ? ` :: ${d.module}` : '';
        const dot = d.alive ? '●' : '○';
        console.log(`  ${dot} ${d.backend.padEnd(6)} pid ${String(d.pid).padEnd(7)} up ${mins}m  ${d.binaryPath}${mod}`);
      }
      return;
    }
    case 'stop': {
      if (flags['all']) {
        const n = await stopAllDaemons(cacheDir);
        console.log(`Stopped ${n} daemon(s)`);
        return;
      }
      const binary = rest[0];
      if (!binary) {
        process.stderr.write('Usage: re daemon stop <binary>  (or --all)\n');
        process.exit(1);
      }
      const n = await stopDaemonsForBinary(cacheDir, binary);
      console.log(n ? `Stopped ${n} daemon(s) for ${binary}` : '(no daemon running for that binary)');
      return;
    }
    case 'start': {
      const binary = rest[0];
      if (!binary) {
        process.stderr.write('Usage: re daemon start <binary> [--backend ida|hopper] [--arch ARCH]\n');
        process.exit(1);
      }
      const { backend, timeout } = globalRunOpts(flags, config);
      // Warm the daemon by forcing one through a cheap `info` query. noCache bypasses
      // the result-cache fast-path so we actually reach the daemon (and start it).
      const result = await run({
        backend, command: 'info', binary, params: {}, config,
        noCache: true, noIdbCache: false, timeout,
        arch: flags['arch'] as string | undefined,
        daemonMode: 'on',
      });
      if (result.status === 'ok') {
        console.log(`Daemon ready for ${binary} (${result.backend}, warmed in ${result.durationSec}s). Idle timeout ${config.daemon.idleTimeout}s.`);
      } else {
        process.stderr.write(`Failed to start daemon: ${result.error?.message ?? 'unknown'}\n`);
        process.exit(1);
      }
      return;
    }
    default:
      process.stderr.write(`Unknown daemon subcommand: ${sub}\nUsage: re daemon <list|start|stop> ...\n`);
      process.exit(1);
  }
}

// ─── Status subcommand ───────────────────────────────────────────────────────

function statusBackend(flags: Record<string, string | boolean>, config: ReturnType<typeof loadConfig>): BackendName {
  const req = flags['backend'];
  if (req === 'ida' || req === 'hopper') return req;
  if (config.defaults.backend !== 'auto') return config.defaults.backend;
  return 'ida';
}

// `re status <binary>` — report whether an analysis is ready, warming, or absent,
// by introspecting the three sources of truth: the daemon registry, the one-shot
// analysis lock, and the on-disk idb. No analysis is started.
async function cmdStatus(
  positional: string[],
  flags: Record<string, string | boolean>,
  config: ReturnType<typeof loadConfig>,
): Promise<void> {
  const [binary] = positional;
  const format = defaultFormat(flags);
  if (!binary) { process.stderr.write('Usage: re status <binary> [--arch ARCH] [--backend ida|hopper]\n'); process.exit(1); }
  if (!existsSync(binary)) { process.stderr.write(`Binary not found: ${binary}\n`); process.exit(4); }

  const cacheDir = config.cache.dir;
  const backend = statusBackend(flags, config);
  const arch = flags['arch'] as string | undefined;

  // Resolve the effective hash the run path would use. With --arch, that's the hash of
  // the extracted slice; if it was never extracted, nothing is cached for that arch.
  const originalHash = binaryHash(binary);
  let binHash = originalHash;
  if (arch) {
    const slicePath = join(expandHome(cacheDir), 'slices', `${originalHash}-${arch}`);
    binHash = existsSync(slicePath) ? binaryHash(slicePath) : '';
  }

  const daemon = binHash ? await daemonFor(cacheDir, backend, binHash) : null;
  const holder = binHash ? analysisLockHolder(cacheDir, daemonKey(backend, binHash)) : null;
  const idbExists = binHash ? hasIdb(cacheDir, binHash) : false;

  let database: Record<string, unknown> = { exists: false };
  if (idbExists) {
    const p = idbPath(cacheDir, binHash);
    const s = statSync(p);
    database = { exists: true, path: p, sizeMb: +(s.size / 1048576).toFixed(1), mtime: new Date(s.mtimeMs).toISOString() };
  }

  const warming = (daemon != null && !daemon.ready) || holder != null;
  const ready = (daemon != null && daemon.ready) || idbExists;
  const state = ready ? 'ready' : warming ? 'warming' : 'none';
  const now = Date.now();

  // Issue #13 criterion #2: surface the in-flight analysis phase + items-emitted + ETA.
  // Prefer LIVE daemon telemetry (a streaming query in flight reports exact counters via
  // `ping`, without consuming the query); fall back to the coarse log-tail phase when the
  // daemon is up but not actively streaming.
  let phase: string | null = null;
  let streamItems: number | null = null;
  let streamEta: number | null = null;
  let streamOp: string | null = null;
  if (binHash && daemon && daemon.ready) {
    const stats = await daemonStreamStats(cacheDir, backend, binHash);
    if (stats) {
      phase = stats.phase ?? phase;
      streamItems = stats.itemsEmitted;
      streamEta = stats.etaSec;
      streamOp = stats.op;
    }
  }
  if (phase === null && binHash && warming) {
    const daemonLog = join(expandHome(cacheDir), 'daemons', daemonKey(backend, binHash), 'daemon.log');
    phase = phaseFromLog(daemonLog) ?? null;
  }

  const data = {
    binary, arch: arch ?? null, backend, binaryHash: binHash || null, state,
    daemon: daemon
      ? { running: true, ready: daemon.ready, pid: daemon.pid, uptimeSec: Math.round((now - daemon.startedAt) / 1000) }
      : { running: false },
    analysis: holder
      ? {
          inFlight: true, pid: holder.pid || null,
          elapsedSec: holder.startedAt ? Math.round((now - holder.startedAt) / 1000) : null,
          phase,
          // Live per-query counters from the streaming daemon (issue #13 #2), null if no
          // streaming query is in flight.
          itemsEmitted: streamItems, etaSec: streamEta, op: streamOp,
        }
      : { inFlight: false, phase, itemsEmitted: streamItems, etaSec: streamEta, op: streamOp },
    database,
  };

  if (format === 'pretty') {
    console.log(`${binary}${arch ? ` (${arch})` : ''} — ${state.toUpperCase()}`);
    if (data.daemon.running) console.log(`  daemon     pid ${daemon!.pid}, up ${data.daemon.uptimeSec}s${daemon!.ready ? '' : ' (warming)'}${phase ? ` · ${phase}` : ''}`);
    if (holder) console.log(`  analyzing  pid ${holder.pid || '?'}, ${data.analysis.elapsedSec ?? '?'}s elapsed${phase ? ` · ${phase}` : ''}`);
    if (streamItems !== null) {
      const eta = streamEta === null ? '?' : `${streamEta}s`;
      console.log(`  streaming  ${streamOp ?? 'query'} · ${streamItems} items emitted · ETA ${eta}`);
    }
    if (idbExists) console.log(`  database   ${database.sizeMb} MB, built ${database.mtime}`);
    if (state === 'none') console.log('  (no daemon, no analysis in flight, no cached database)');
  } else {
    process.stdout.write(JSON.stringify(data) + '\n');
  }
  // Exit code lets scripts branch without parsing: ready=0, warming=3, none=4.
  process.exit(state === 'ready' ? 0 : state === 'warming' ? 3 : 4);
}

// ─── Analyze / wait subcommands ──────────────────────────────────────────────

function sleepMs(ms: number): Promise<void> { return new Promise((r) => setTimeout(r, ms)); }

// Resolve the effective hash a query would use; '' if --arch was requested but the
// slice hasn't been extracted yet (so nothing is cached/serving for it).
function effectiveHash(binary: string, arch: string | undefined, cacheDir: string): string {
  const oh = binaryHash(binary);
  if (!arch) return oh;
  const slicePath = join(expandHome(cacheDir), 'slices', `${oh}-${arch}`);
  return existsSync(slicePath) ? binaryHash(slicePath) : '';
}

// `re analyze <binary>` — kick off a warm daemon in the background and return at once,
// so callers can `re analyze X &-style` then `re wait X`. Implemented by re-exec'ing
// this CLI detached as a forced-daemon `info` query, which starts and warms the daemon.
async function cmdAnalyze(
  positional: string[],
  flags: Record<string, string | boolean>,
  _config: ReturnType<typeof loadConfig>,
): Promise<void> {
  const [binary] = positional;
  if (!binary) { process.stderr.write('Usage: re analyze <binary> [--arch ARCH] [--backend ida|hopper]\n'); process.exit(1); }
  if (!existsSync(binary)) { process.stderr.write(`Binary not found: ${binary}\n`); process.exit(4); }

  const childArgs = ['info', binary, '--daemon', 'on', '--no-cache'];
  if (flags['arch']) childArgs.push('--arch', String(flags['arch']));
  if (flags['backend']) childArgs.push('--backend', String(flags['backend']));
  const nodeFlags = process.execArgv.length ? process.execArgv : ['--experimental-strip-types', '--no-warnings'];
  const child = spawn(process.execPath, [...nodeFlags, process.argv[1], ...childArgs], { detached: true, stdio: 'ignore' });
  child.unref();

  const archHint = flags['arch'] ? ` --arch ${flags['arch']}` : '';
  process.stdout.write(JSON.stringify({
    status: 'warming', binary, pid: child.pid ?? null,
    message: `analysis started in the background; run 're wait ${binary}${archHint}' to block until ready`,
  }) + '\n');
}

// `re wait <binary>` — block until an analysis is ready (cached .i64 or a warm daemon),
// narrating elapsed time. Exit 0 ready; with --timeout, exit 3 (still warming) on expiry.
async function cmdWait(
  positional: string[],
  flags: Record<string, string | boolean>,
  config: ReturnType<typeof loadConfig>,
): Promise<void> {
  const [binary] = positional;
  if (!binary) { process.stderr.write('Usage: re wait <binary> [--arch ARCH] [--timeout SEC]\n'); process.exit(1); }
  if (!existsSync(binary)) { process.stderr.write(`Binary not found: ${binary}\n`); process.exit(4); }

  const cacheDir = config.cache.dir;
  const backend = statusBackend(flags, config);
  const arch = flags['arch'] as string | undefined;
  const timeoutMs = (Number(flags['timeout']) || 0) * 1000;
  const format = defaultFormat(flags);
  const start = Date.now();

  const ready = async (): Promise<boolean> => {
    const bh = effectiveHash(binary, arch, cacheDir);
    if (!bh) return false;
    if (hasIdb(cacheDir, bh)) return true;
    const d = await daemonFor(cacheDir, backend, bh);
    return d != null && d.ready;
  };

  let lastBeat = 0;
  for (;;) {
    if (await ready()) {
      const waitedSec = Math.round((Date.now() - start) / 1000);
      if (format === 'pretty') console.log(`${binary} ready (${waitedSec}s)`);
      else process.stdout.write(JSON.stringify({ status: 'ready', binary, waitedSec }) + '\n');
      process.exit(0);
    }
    const elapsedMs = Date.now() - start;
    if (timeoutMs && elapsedMs > timeoutMs) {
      const waitedSec = Math.round(elapsedMs / 1000);
      if (format === 'pretty') process.stderr.write(`${binary} still warming after ${waitedSec}s\n`);
      else process.stdout.write(JSON.stringify({ status: 'warming', binary, waitedSec }) + '\n');
      process.exit(3);
    }
    if (elapsedMs - lastBeat >= 5000) {
      lastBeat = elapsedMs;
      process.stderr.write(`[re] waiting for ${basename(binary)} to be ready… ${Math.round(elapsedMs / 1000)}s\n`);
    }
    await sleepMs(500);
  }
}

// ─── Help ────────────────────────────────────────────────────────────────────

const HELP = `\
re — reverse engineering CLI for IDA Pro and Hopper Disassembler

Usage:
  re [--backend auto|ida|hopper] [--timeout N] [--no-cache] [--no-idb-cache]
     [--format json|pretty] <command> <binary> [flags]

Commands:
  info      <binary>                   Binary metadata
  symbols   <binary> [--filter REGEX] [--type function|data|all]
  functions <binary> [--filter REGEX]
  decompile <binary> --function NAME   Hex-Rays / Hopper pseudocode
  decompile <binary> --address 0xADDR
  disasm    <binary> --function NAME [--count N]
  disasm    <binary> --address 0xADDR  [--count N]
  xrefs     <binary> --to NAME|ADDR    Cross-references
  xrefs     <binary> --from NAME|ADDR
  strings   <binary> [--filter REGEX] [--min-length N]
  imports   <binary> [--library NAME]
  exports   <binary>
  segments  <binary>

  cache list
  cache clear <binary>   (or --all)
  cache path  <binary>               Cache dir + database size/mtime
  cache info
  cache du                           Disk usage per database + totals
  cache gc --stale | --older-than DAYS | --max-size GB   Prune cached databases

  daemon list                        Show running warm-database daemons
  daemon start <binary>              Start (and warm) a daemon for a binary
  daemon stop  <binary>   (or --all) Stop a daemon (frees its memory)

  status    <binary> [--arch ARCH]   Is analysis ready / warming / absent?
                                     (exit 0 ready, 3 warming, 4 none)
  analyze   <binary> [--arch ARCH]   Start warming a daemon in the background, return now
  wait      <binary> [--timeout SEC] Block until ready (exit 0; exit 3 if --timeout hit)

  dsc sims [<platform>]              List installed simulator runtimes
  dsc list                           List modules in the resolved DSC
  dsc <op> <module>                  Run any analysis op against a DSC module
                                     <op> is one of: info, symbols, functions,
                                     decompile, disasm, xrefs, strings,
                                     imports, exports, segments

DSC source flags (for 're dsc <op>' and 're dsc list'):
  (default)                          Host's system DSC
  --sim    <platform>[@version]      Simulator DSC (e.g. ios, ios@18, ios@18.4)
  --dsc    <path>                    Arbitrary DSC file

Global flags:
  --backend    ida | hopper | auto   (default: auto, prefers IDA)
  --arch       arm64 | x86_64        Extract slice from fat binary before analysis
                                     (for DSC: pick the matching DSC arch file)
  --timeout    seconds               Optional hard cap (default: none — runs to completion)
  --no-cache                         Skip result cache
  --no-idb-cache                     Force re-analysis even if .i64 exists (forces one-shot)
  --daemon     auto | on | off       Warm-database daemon (default: auto). auto starts one
                                     for binaries >= daemon.autostartMinMb; on forces it;
                                     off (or --no-daemon) always runs one-shot
  --format     json | pretty         (default: json)

Streaming (issue #13 — functions/symbols/strings/xrefs only):
  --first-match                      Stop after the first match (alias for --max-matches 1)
  --max-matches N                    Stop and emit 'complete' after N items
  --max-wait S                       Stop after S wall-clock seconds (honors partial analysis)
  --min-batch-size N                 Buffer until N items before emitting a 'partial'
  --stream                           Force NDJSON event output even on a warm cache
  --emit       <events>              Whitelist events (aliases: items, progress, status)
  --fields     <fields>              Project items to these fields (op-specific)
  --format     json | jsonl | tsv | pretty   (json requires a bounded query)
  --no-meta                          Suppress the opening 'meta' event
  (--watch and --resume are specified but not yet implemented — they error in validate)

Config: ${CONFIG_FILE}
`;

// ─── Main dispatch ───────────────────────────────────────────────────────────

const COMMANDS: Record<string, (flags: Record<string, string | boolean>) => Record<string, unknown>> = {
  info:      ()      => ({}),
  symbols:   (f)     => pick(f, ['filter', 'type']),
  functions: (f)     => pick(f, ['filter']),
  decompile: (f)     => pick(f, ['function', 'address', 'all']),
  disasm:    (f)     => pick(f, ['function', 'address', 'count']),
  xrefs:     (f)     => pick(f, ['to', 'from', 'type']),
  strings:   (f)     => ({ ...pick(f, ['filter']), ...(f['min-length'] ? { minLength: Number(f['min-length']) } : {}) }),
  imports:   (f)     => pick(f, ['library']),
  exports:   ()      => ({}),
  segments:  ()      => ({}),
};

function pick(
  flags: Record<string, string | boolean>,
  keys: string[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of keys) {
    if (flags[k] !== undefined && flags[k] !== false) out[k] = flags[k];
  }
  return out;
}

async function main(): Promise<void> {
  const { command, positional, flags } = parseArgs(process.argv.slice(2));

  if (!command || flags['help'] || flags['h']) {
    process.stdout.write(HELP);
    process.exit(0);
  }

  const config = loadConfig();
  const { backend, noCache, noIdbCache, timeout, format, daemonMode } = globalRunOpts(flags, config);

  if (command === 'cache') {
    await cmdCache(positional, flags, config);
    return;
  }

  if (command === 'daemon') {
    await cmdDaemon(positional, flags, config);
    return;
  }

  if (command === 'status') {
    await cmdStatus(positional, flags, config);
    return;
  }

  if (command === 'analyze') {
    await cmdAnalyze(positional, flags, config);
    return;
  }

  if (command === 'wait') {
    await cmdWait(positional, flags, config);
    return;
  }

  if (command === 'dsc') {
    try {
      await cmdDsc(positional, flags, config);
    } catch (e) {
      process.stderr.write(`Error: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(1);
    }
    return;
  }

  const paramsFor = COMMANDS[command];
  if (!paramsFor) {
    process.stderr.write(`Unknown command: ${command}\nRun 're --help' for usage.\n`);
    process.exit(1);
  }

  const [binary] = positional;
  if (!binary) {
    process.stderr.write(`Usage: re ${command} <binary> [flags]\n`);
    process.exit(1);
  }

  // ── Streaming API (issue #13) ──
  // When any streaming flag is present, take the NDJSON event path. Validation runs BEFORE
  // touching IDA so bad flag combos exit 1 with a crisp message (§4, §8).
  if (hasStreamingFlags(flags)) {
    let resolved;
    try {
      const sflags = parseStreamFlags(flags);
      resolved = validateStream(command, sflags, Boolean(process.stdout.isTTY));
    } catch (e) {
      if (e instanceof ValidateError) {
        process.stderr.write(`validate error: ${e.message}\n`);
        process.exit(1);  // §8 exit 1: validate failed before connecting to IDA
      }
      throw e;
    }
    // A streamable op with event output goes through the orchestrator; a non-streamable op
    // (info/imports/segments/decompile/disasm) that merely set --format jsonl/--no-meta etc.
    // still has no streaming body — fall through to the legacy run() below for those.
    if (resolved.enabled) {
      const code = await runStream({
        resolved,
        binary,
        arch: flags['arch'] as string | undefined,
        params: paramsFor(flags),
        config,
        backend: backend as 'auto' | BackendName,
        timeout,
      });
      process.exit(code);
    }
  }

  const result = await run({
    backend: backend as 'auto' | BackendName,
    command,
    binary,
    params: paramsFor(flags),
    config,
    noCache,
    noIdbCache,
    timeout,
    arch: flags['arch'] as string | undefined,
    daemonMode,
  });

  printResult(result, format);
  process.exit(result.status === 'ok' ? 0 : 1);
}

main();
