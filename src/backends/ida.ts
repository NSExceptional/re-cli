import type { InvokeOptions, BackendCommand } from './types.ts';

export function buildIdaCommand(opts: InvokeOptions, idat64: string): BackendCommand {
  const args: string[] = ['-A'];

  if (opts.idbPath) {
    // Fast path: reload existing .i64 (skips analysis, ~0.3s)
    args.push(`-S${opts.scriptPath}`);
    args.push(`-L${opts.logPath}`);
    args.push(opts.idbPath);
  } else {
    // First run: full analysis, save .i64 to cache
    args.push('-c'); // create new IDB
    if (opts.outputIdbPath) {
      args.push(`-o${opts.outputIdbPath}`);
    }
    args.push(`-S${opts.scriptPath}`);
    args.push(`-L${opts.logPath}`);
    args.push(opts.binaryPath);
  }

  return { cmd: idat64, args };
}
