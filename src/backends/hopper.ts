import type { InvokeOptions, BackendCommand } from './types.ts';

export function buildHopperCommand(opts: InvokeOptions, hopperBin: string): BackendCommand {
  const args: string[] = [];

  if (opts.hopPath) {
    // Open existing .hop document (faster, preserves user comments)
    args.push('-d', opts.hopPath);
  } else {
    // Analyze a new binary
    args.push('-e', opts.binaryPath);
    args.push('-a'); // run auto-analysis
  }

  args.push('-Y', opts.scriptPath);

  return { cmd: hopperBin, args };
}
