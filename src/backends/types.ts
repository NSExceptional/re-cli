export type BackendName = 'ida' | 'hopper';

export interface InvokeOptions {
  binaryPath: string;       // original target binary (or DSC path)
  idbPath?: string;         // existing cached .i64 (IDA fast-path)
  outputIdbPath?: string;   // where to write the new .i64
  hopPath?: string;         // existing cached .hop (Hopper fast-path)
  scriptPath: string;       // composed .py script
  logPath: string;          // IDA -L log target
  module?: string;          // when binaryPath is a DSC, the module to load
}

export interface BackendCommand {
  cmd: string;
  args: string[];
}
