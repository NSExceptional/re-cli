export type Status = 'ok' | 'error' | 'timeout';
export type BackendName = 'ida' | 'hopper';

export interface REError {
  type: string;
  message: string;
  logExcerpt?: string;
  suggestions?: string[];
}

export interface REResult<T = unknown> {
  status: Status;
  command: string;
  binary: string;
  binaryHash: string;
  backend: BackendName | null;
  backendVersion: string | null;
  durationSec: number;
  cached: boolean;
  data: T | null;
  error: REError | null;
}
