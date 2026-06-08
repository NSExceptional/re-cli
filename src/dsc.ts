import { existsSync, openSync, closeSync, readSync, readdirSync, statSync } from 'node:fs';
import { join, basename } from 'node:path';
import { spawnSync } from 'node:child_process';

export type SimPlatform = 'ios' | 'tvos' | 'watchos' | 'visionos';

export interface SimSpec {
  platform: SimPlatform;
  major?: number;
  minor?: number;
}

export interface SimRuntime {
  platform: SimPlatform;
  version: string;       // e.g. "18.4" or "26.3.1"
  major: number;
  minor: number;
  runtimeId: string;     // "com.apple.CoreSimulator.SimRuntime.iOS-18-6"
  build: string;         // "22G86"
  supportedArchs: string[];
}

const PLATFORM_BY_IDENTIFIER: Record<string, SimPlatform> = {
  'com.apple.platform.iphonesimulator': 'ios',
  'com.apple.platform.appletvsimulator': 'tvos',
  'com.apple.platform.watchsimulator': 'watchos',
  'com.apple.platform.xrsimulator': 'visionos',
};

const PLATFORM_NAMES: Record<SimPlatform, string> = {
  ios: 'iOS', tvos: 'tvOS', watchos: 'watchOS', visionos: 'visionOS',
};

export function parseSimSpec(input: string): SimSpec {
  const [platform, version] = input.split('@', 2);
  if (!(platform in PLATFORM_NAMES)) {
    throw new Error(`Unknown sim platform: ${platform}. Expected one of: ios, tvos, watchos, visionos`);
  }
  if (!version) return { platform: platform as SimPlatform };
  const parts = version.split('.');
  const major = Number(parts[0]);
  if (!Number.isInteger(major)) {
    throw new Error(`Invalid sim version: ${version}`);
  }
  if (parts.length === 1) return { platform: platform as SimPlatform, major };
  const minor = Number(parts[1]);
  if (!Number.isInteger(minor)) {
    throw new Error(`Invalid sim version: ${version}`);
  }
  return { platform: platform as SimPlatform, major, minor };
}

export function listSimRuntimes(): SimRuntime[] {
  const result = spawnSync('xcrun', ['simctl', 'runtime', 'list', '-j'], { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`xcrun simctl runtime list failed: ${result.stderr}`);
  }
  const parsed = JSON.parse(result.stdout) as Record<string, {
    platformIdentifier: string;
    runtimeIdentifier: string;
    version: string;
    build: string;
    state: string;
    supportedArchitectures: string[];
  }>;
  const out: SimRuntime[] = [];
  for (const entry of Object.values(parsed)) {
    if (entry.state !== 'Ready') continue;
    const platform = PLATFORM_BY_IDENTIFIER[entry.platformIdentifier];
    if (!platform) continue;
    const [maj, min] = entry.version.split('.');
    out.push({
      platform,
      version: entry.version,
      major: Number(maj),
      minor: Number(min ?? 0),
      runtimeId: entry.runtimeIdentifier,
      build: entry.build,
      supportedArchs: entry.supportedArchitectures,
    });
  }
  return out;
}

function compareVersions(a: SimRuntime, b: SimRuntime): number {
  return a.major - b.major || a.minor - b.minor || a.version.localeCompare(b.version);
}

export function selectSimRuntime(spec: SimSpec, runtimes: SimRuntime[]): SimRuntime {
  const candidates = runtimes
    .filter(r => r.platform === spec.platform)
    .filter(r => spec.major === undefined || r.major === spec.major)
    .filter(r => spec.minor === undefined || r.minor === spec.minor)
    .sort(compareVersions);
  if (candidates.length === 0) {
    const installed = runtimes
      .filter(r => r.platform === spec.platform)
      .map(r => r.version)
      .join(', ');
    const want = spec.major !== undefined
      ? `${spec.platform}@${spec.major}${spec.minor !== undefined ? '.' + spec.minor : ''}`
      : spec.platform;
    throw new Error(`No installed ${PLATFORM_NAMES[spec.platform]} simulator runtime matches ${want}. Installed: ${installed || '(none)'}`);
  }
  return candidates[0]; // lowest version
}

function hostBuild(): string {
  const r = spawnSync('sw_vers', ['--buildVersion'], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error('sw_vers --buildVersion failed');
  return r.stdout.trim();
}

function hostArch(): string {
  const r = spawnSync('uname', ['-m'], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error('uname -m failed');
  const m = r.stdout.trim();
  return m === 'arm64' ? 'arm64e' : m; // Apple Silicon DSC is arm64e
}

export function resolveSystemDsc(arch?: string): string {
  const a = arch ?? hostArch();
  const candidates = [
    `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_${a}`,
    `/System/Library/dyld/dyld_shared_cache_${a}`,
    `/private/var/db/dyld/dyld_shared_cache_${a}`,
  ];
  for (const p of candidates) if (existsSync(p)) return p;
  throw new Error(`System DSC not found for arch ${a}. Tried: ${candidates.join(', ')}`);
}

export function resolveSimDsc(spec: SimSpec, arch?: string): string {
  const runtime = selectSimRuntime(spec, listSimRuntimes());
  const a = arch ?? (runtime.supportedArchs.includes('arm64') ? 'arm64' : runtime.supportedArchs[0]);
  if (!runtime.supportedArchs.includes(a)) {
    throw new Error(`Runtime ${runtime.runtimeId} doesn't support arch ${a}. Supported: ${runtime.supportedArchs.join(', ')}`);
  }
  const cacheRoot = '/Library/Developer/CoreSimulator/Caches/dyld';
  // The host_build directory is created at sim boot; try the current host first,
  // then any other build directory that contains the runtime.
  const tried: string[] = [];
  const buildDirs = existsSync(cacheRoot) ? readdirSync(cacheRoot) : [];
  const orderedBuilds = [hostBuild(), ...buildDirs.filter(b => b !== hostBuild())];
  for (const build of orderedBuilds) {
    const dscPath = join(cacheRoot, build, `${runtime.runtimeId}.${runtime.build}`, `dyld_sim_shared_cache_${a}`);
    tried.push(dscPath);
    if (existsSync(dscPath)) return dscPath;
  }
  throw new Error(
    `Simulator DSC not built yet for ${runtime.runtimeId} (${runtime.version}). ` +
    `Boot the simulator once to generate it. Tried:\n  ${tried.join('\n  ')}`
  );
}

export interface ResolveOptions {
  sim?: string;     // raw --sim spec, e.g. "ios@18.4"
  dsc?: string;     // explicit DSC path
  arch?: string;
}

export function resolveDscPath(opts: ResolveOptions): string {
  if (opts.dsc) {
    if (!existsSync(opts.dsc)) throw new Error(`DSC not found: ${opts.dsc}`);
    return opts.dsc;
  }
  if (opts.sim) {
    return resolveSimDsc(parseSimSpec(opts.sim), opts.arch);
  }
  return resolveSystemDsc(opts.arch);
}

export function formatSimsByPlatform(runtimes: SimRuntime[]): string {
  const byPlatform = new Map<SimPlatform, string[]>();
  for (const r of runtimes.sort(compareVersions)) {
    const list = byPlatform.get(r.platform) ?? [];
    list.push(r.version);
    byPlatform.set(r.platform, list);
  }
  const lines: string[] = [];
  const order: SimPlatform[] = ['ios', 'tvos', 'watchos', 'visionos'];
  for (const platform of order) {
    const versions = byPlatform.get(platform);
    if (!versions) continue;
    lines.push(`${platform.padEnd(10)}${versions.join(', ')}`);
  }
  return lines.join('\n');
}

export function formatSimsForPlatform(platform: SimPlatform, runtimes: SimRuntime[]): string {
  return runtimes
    .filter(r => r.platform === platform)
    .sort(compareVersions)
    .map(r => `${platform} ${r.version}`)
    .join('\n');
}

// ─── DSC module listing ─────────────────────────────────────────────────────
// Parses the dyld_cache_header.imagesText{Offset,Count} fields (at 0x88/0x90)
// which point to an array of dyld_cache_image_text_info entries (32 bytes each).

export interface DscModule {
  path: string;        // install path, e.g. "/System/Library/Frameworks/Foundation.framework/Foundation"
  loadAddress: bigint;
  textSize: number;
}

export function listDscModules(dscPath: string): DscModule[] {
  const fd = openSync(dscPath, 'r');
  try {
    const hdr = Buffer.alloc(0x100);
    readSync(fd, hdr, 0, hdr.length, 0);
    const magic = hdr.subarray(0, 16).toString('utf8').replace(/\0+$/, '');
    if (!magic.startsWith('dyld_v1')) {
      throw new Error(`Not a DSC file (magic="${magic}"): ${dscPath}`);
    }
    const imagesTextOffset = Number(hdr.readBigUInt64LE(0x88));
    const imagesTextCount = Number(hdr.readBigUInt64LE(0x90));
    if (imagesTextCount === 0 || imagesTextOffset === 0) {
      throw new Error(`DSC has no imagesText entries (old format?): ${dscPath}`);
    }
    const entriesSize = imagesTextCount * 0x20;
    const entries = Buffer.alloc(entriesSize);
    readSync(fd, entries, 0, entriesSize, imagesTextOffset);
    // Each entry's pathOffset is a file offset into the DSC. Read the path-strings region
    // lazily one entry at a time via small reads.
    const out: DscModule[] = [];
    const pathBuf = Buffer.alloc(512);
    for (let i = 0; i < imagesTextCount; i++) {
      const e = entries.subarray(i * 0x20);
      const loadAddress = e.readBigUInt64LE(0x10);
      const textSize = e.readUInt32LE(0x18);
      const pathOffset = e.readUInt32LE(0x1c);
      readSync(fd, pathBuf, 0, pathBuf.length, pathOffset);
      const nul = pathBuf.indexOf(0);
      const path = pathBuf.subarray(0, nul >= 0 ? nul : pathBuf.length).toString('utf8');
      out.push({ path, loadAddress, textSize });
    }
    return out;
  } finally {
    closeSync(fd);
  }
}

/**
 * Resolve a user-supplied module spec to its full install path in the DSC.
 * Accepts: bare name ("Foundation"), basename match, or full install path.
 * Errors with a helpful message if not found or ambiguous.
 */
export function resolveDscModule(dscPath: string, spec: string): string {
  const modules = listDscModules(dscPath);
  // Try exact full-path match first
  const exact = modules.find(m => m.path === spec);
  if (exact) return exact.path;
  // Then basename match
  const byBasename = modules.filter(m => basename(m.path) === spec);
  if (byBasename.length === 1) return byBasename[0].path;
  if (byBasename.length > 1) {
    // Prefer paths under /System/Library/Frameworks/ over private/iOSSupport variants
    const preferred = byBasename.find(m => m.path.startsWith('/System/Library/Frameworks/'));
    if (preferred) return preferred.path;
    throw new Error(
      `Ambiguous module "${spec}". Specify a full install path. Matches:\n  ` +
      byBasename.map(m => m.path).join('\n  ')
    );
  }
  throw new Error(`Module "${spec}" not found in DSC. Use 're dsc list' to see available modules.`);
}
