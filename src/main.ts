#!/usr/bin/env -S node --experimental-strip-types --no-warnings

import process from 'node:process';
import { existsSync, readdirSync, readFileSync, statSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig, CONFIG_FILE } from './config.ts';
import { run } from './runner.ts';
import { expandHome, binaryHash, elapsed } from './util.ts';
import { idbCacheDir, idbPath, resultPath } from './cache.ts';
import {
  resolveDscPath, listDscModules, resolveDscModule,
  listSimRuntimes, formatSimsByPlatform, formatSimsForPlatform,
  parseSimSpec,
} from './dsc.ts';
import type { SimPlatform } from './dsc.ts';
import type { REResult, BackendName } from './result.ts';

// ─── Arg parsing ────────────────────────────────────────────────────────────

const VALUE_FLAGS = new Set([
  'backend', 'timeout', 'format', 'arch', 'sim', 'dsc',
  'function', 'address', 'count', 'filter', 'type',
  'min-length', 'to', 'from', 'library', 'range',
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

function globalRunOpts(flags: Record<string, string | boolean>, config: ReturnType<typeof loadConfig>) {
  return {
    backend: (flags['backend'] as 'auto' | BackendName | undefined) ?? 'auto',
    noCache:    flags['cache']    === false,
    noIdbCache: flags['idb-cache'] === false,
    timeout:    Number(flags['timeout']) || config.defaults.timeout,
    format:     String(flags['format'] ?? 'json'),
    config,
  };
}

// ─── Cache subcommands ───────────────────────────────────────────────────────

function cmdCache(
  args: string[],
  flags: Record<string, string | boolean>,
  config: ReturnType<typeof loadConfig>,
): void {
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
        console.log(`  ${label}  ${meta.path}${tag}  (${size})`);
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
        rmSync(cacheDir, { recursive: true, force: true });
        console.log(`Cleared: ${cacheDir}`);
      } else {
        const binary = rest[0];
        if (!binary) {
          process.stderr.write('Usage: re cache clear <binary>  (or --all to wipe everything)\n');
          process.exit(1);
        }
        const hash = binaryHash(binary);
        const dir  = idbCacheDir(cacheDir, hash);
        if (existsSync(dir)) { rmSync(dir, { recursive: true, force: true }); console.log(`Cleared: ${dir}`); }
        else console.log('(nothing cached for that binary)');
      }
      break;
    }
    case 'path': {
      const binary = rest[0];
      if (!binary) { process.stderr.write('Usage: re cache path <binary>\n'); process.exit(1); }
      const hash = binaryHash(binary);
      console.log(idbCacheDir(cacheDir, hash));
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
    default:
      process.stderr.write(`Unknown cache subcommand: ${sub}\n`);
      process.exit(1);
  }
}

// ─── DSC subcommand ──────────────────────────────────────────────────────────

function cmdDsc(
  args: string[],
  flags: Record<string, string | boolean>,
  config: ReturnType<typeof loadConfig>,
): void {
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

  const { backend, noCache, noIdbCache, timeout, format } = globalRunOpts(flags, config);

  const result = run({
    backend: backend as 'auto' | BackendName,
    command: sub,
    binary: dscPath,
    params: paramsFor(flags),
    config,
    noCache,
    noIdbCache,
    timeout,
    module,
  });

  printResult(result, format);
  process.exit(result.status === 'ok' ? 0 : 1);
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
  cache path  <binary>
  cache info

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
  --timeout    seconds               (default: 300)
  --no-cache                         Skip result cache
  --no-idb-cache                     Force re-analysis even if .i64 exists
  --format     json | pretty         (default: json)

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

function main(): void {
  const { command, positional, flags } = parseArgs(process.argv.slice(2));

  if (!command || flags['help'] || flags['h']) {
    process.stdout.write(HELP);
    process.exit(0);
  }

  const config = loadConfig();
  const { backend, noCache, noIdbCache, timeout, format } = globalRunOpts(flags, config);

  if (command === 'cache') {
    cmdCache(positional, flags, config);
    return;
  }

  if (command === 'dsc') {
    try {
      cmdDsc(positional, flags, config);
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

  const result = run({
    backend: backend as 'auto' | BackendName,
    command,
    binary,
    params: paramsFor(flags),
    config,
    noCache,
    noIdbCache,
    timeout,
    arch: flags['arch'] as string | undefined,
  });

  printResult(result, format);
  process.exit(result.status === 'ok' ? 0 : 1);
}

main();
