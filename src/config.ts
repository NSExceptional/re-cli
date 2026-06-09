import { existsSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { execSync } from 'node:child_process';
import { expandHome } from './util.ts';

export interface Config {
  tools: {
    idat64: string;
    hopper: string;
  };
  cache: {
    dir: string;
    resultTtl: number;
    maxSizeGb: number;
    keepIdbs: boolean;
  };
  defaults: {
    backend: 'auto' | 'ida' | 'hopper';
    timeout: number;
  };
  decompile: {
    backend: 'ida' | 'hopper';
  };
}

const CONFIG_DIR = join(homedir(), '.config', 're-cli');
export const CONFIG_FILE = join(CONFIG_DIR, 'config.json');

const DEFAULTS: Config = {
  tools: { idat64: '', hopper: '' },
  cache: { dir: '~/.cache/re-cli', resultTtl: 3600, maxSizeGb: 20, keepIdbs: true },
  defaults: { backend: 'auto', timeout: 300 },
  decompile: { backend: 'ida' },
};

function which(name: string): string {
  try {
    return execSync(`which ${name} 2>/dev/null`, { encoding: 'utf8' }).trim();
  } catch {
    return '';
  }
}

function findTool(envVar: string, knownPaths: string[], binaryName: string): string {
  if (process.env[envVar]) return process.env[envVar]!;
  for (const p of knownPaths) {
    if (existsSync(p)) return p;
  }
  // Glob for versioned IDA installs, e.g. /Applications/IDA Pro 9.0/idabin/idat64
  try {
    const hits = execSync(
      `ls /Applications/ 2>/dev/null | grep -i '^IDA'`,
      { encoding: 'utf8' },
    ).trim().split('\n');
    for (const dir of hits) {
      const p = join('/Applications', dir, 'idabin', binaryName);
      if (existsSync(p)) return p;
    }
  } catch {}
  return which(binaryName);
}

function resolveTools(config: Config): Config {
  const idat64 = config.tools.idat64 || findTool('RE_IDAT64', [
    '/Applications/IDA Pro/idabin/idat64',
  ], 'idat64');

  const hopper = config.tools.hopper || findTool('RE_HOPPER', [
    '/Applications/Hopper Disassembler.app/Contents/MacOS/hopper',
    '/Applications/Hopper Disassembler v5.app/Contents/MacOS/hopper',
    '/Applications/Hopper Disassembler v4.app/Contents/MacOS/hopper',
    '/Applications/Hopper.app/Contents/MacOS/hopper',
  ], 'hopper');

  return { ...config, tools: { idat64, hopper } };
}

export function loadConfig(): Config {
  let raw: Partial<Config> = {};
  if (existsSync(CONFIG_FILE)) {
    try {
      raw = JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) as Partial<Config>;
    } catch {}
  }
  const merged: Config = {
    tools: { ...DEFAULTS.tools, ...raw.tools },
    cache: { ...DEFAULTS.cache, ...raw.cache },
    defaults: { ...DEFAULTS.defaults, ...raw.defaults },
    decompile: { ...DEFAULTS.decompile, ...raw.decompile },
  };
  return resolveTools(merged);
}

export function saveConfig(config: Config): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2) + '\n');
}
