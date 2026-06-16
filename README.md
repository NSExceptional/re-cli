# re

A reverse-engineering CLI for Darwin (macOS/iOS) binaries. `re` drives **IDA Pro** and **Hopper Disassembler** from the command line and returns structured JSON, so disassembly, decompilation, and cross-reference queries can be scripted, cached, and consumed by other tools (it backs a VS Code reverse-engineering extension).

```bash
re info /bin/ls
re decompile /bin/ls --function _main
re xrefs /Applications/Foo.app/Contents/MacOS/Foo --to _objc_msgSend --arch arm64
re dsc symbols UIKitCore --sim ios@18   # query a module inside a dyld shared cache
```

## Why it exists

IDA and Hopper are GUI-first tools with scripting interfaces that are awkward to invoke ad hoc. `re` wraps them behind one consistent, machine-readable interface:

- **One command surface** over two very different backends.
- **Stable JSON output** — every command returns the same envelope, so callers never screen-scrape a disassembler UI.
- **Aggressive caching** — analyzing a large binary is expensive; `re` does it once and reuses the result.
- **dyld shared cache support** — analyze system frameworks by name without extracting them first.

## Requirements

- **macOS** (Darwin). Backends and `lipo`/`dyld` handling are platform-specific.
- **Node 24+** — run directly via TypeScript type-stripping; there is no build step and no runtime npm dependencies.
- **IDA Pro** and/or **Hopper Disassembler** installed. At least one backend is required; IDA is the default and the only backend that supports decompilation, strings, and dyld shared caches.

## Install

`re` is a single executable TypeScript entrypoint. Symlink it onto your `PATH`:

```bash
chmod +x src/main.ts
ln -sf "$(pwd)/src/main.ts" ~/.local/bin/re   # ensure ~/.local/bin is on PATH
re --help
```

Backends are auto-detected from standard `/Applications` locations. Override detection with the `RE_IDAT64` / `RE_HOPPER` environment variables, or pin paths and defaults in `~/.config/re-cli/config.json` (timeouts, cache directory, default backend, result TTL).

## Usage

```
re [global flags] <command> <binary> [command flags]
```

Run `re --help` for the authoritative, always-current list of commands and flags. At a glance:

| Command | Purpose |
| --- | --- |
| `info` | Binary metadata (arch, type, entry point, size) |
| `symbols` / `functions` | Enumerate symbols / functions, optionally `--filter REGEX` |
| `decompile` | Pseudocode for a `--function NAME` or `--address 0xADDR` |
| `disasm` | Disassembly for a function or address (`--count N`) |
| `xrefs` | Cross-references `--to` / `--from` a name or address |
| `strings` / `imports` / `exports` / `segments` | The usual static views |
| `cache …` | Inspect and clear the analysis cache |
| `dsc …` | List and analyze modules inside a dyld shared cache (incl. simulator runtimes) |

Common global flags: `--backend ida|hopper|auto`, `--arch arm64|x86_64` (thin a fat binary before analysis), `--format json|pretty`, `--timeout SECONDS`, `--no-cache`, `--no-idb-cache`.

### Output contract

Every analysis command prints a single JSON object to **stdout**:

```jsonc
{
  "status": "ok",            // "ok" | "error" | "timeout"
  "command": "info",
  "binary": "/bin/ls",
  "binaryHash": "…",
  "backend": "ida",
  "backendVersion": "…",
  "durationSec": 0.31,
  "cached": false,
  "data": { /* command-specific payload */ },
  "error": null               // { type, message, logExcerpt? } when status != "ok"
}
```

Treat stdout as data: it is exactly this envelope and nothing else. Human-readable rendering (`--format pretty`) and any progress/diagnostic output go to **stderr**, so piping stdout to a JSON parser is always safe. Exit code is `0` on `status: "ok"`, non-zero otherwise.

## How it works

`re` is a thin TypeScript orchestrator over per-backend Python operation scripts. For each invocation it:

1. Resolves the backend and, for fat binaries with `--arch`, thins the requested slice with `lipo`.
2. Composes a Python script from a shared base plus the script for the requested command, passing parameters as hex-encoded JSON so arbitrary string content is injection-safe.
3. Runs IDA/Hopper headless as a subprocess, pointed at the script.
4. Reads the JSON the script writes to a temp file, wraps it in the envelope above, and caches it.

Two layers of caching make repeat queries cheap:

- **Disassembler database cache** — the backend's analyzed database (e.g. IDA `.i64`) is saved keyed by a hash of the binary's path, mtime, and size. Reopening it skips re-analysis entirely. `--no-idb-cache` forces fresh analysis.
- **Result cache** — each command's JSON result is memoized with a TTL. `--no-cache` bypasses it.

Both live under the configured cache directory (default `~/.cache/re-cli`); manage them with `re cache`.

The two backends are not feature-equivalent. IDA is the most complete (decompilation, strings, dyld shared caches). Hopper covers the common static queries but has API gaps it reports explicitly rather than silently faking — prefer IDA when a command is unsupported on Hopper.

## Performance & long-running analysis

First-time analysis of a large binary can take **many minutes** — a few tens of MB is small for a Mach-O, and real targets run far longer. This is the disassembler working, not a hang. Two things make that bearable:

- **No timeout by default.** A fresh analysis runs to completion rather than being cut off. `re` streams progress to stderr the whole time (elapsed seconds plus the tail of the backend's own log) so the run is observably alive; pass `--timeout SECONDS` only if you deliberately want a hard cap (then a run that exceeds it returns `status: "timeout"`).
- **Caching.** Once analyzed, the same query returns in well under a second.

Because a first analysis can outlast a foreground shell/tool limit, run it detached when driving `re` programmatically and let it finish in the background; subsequent queries hit the cache and are instant.

## Working on `re`

- **No build step.** Edit the TypeScript and run `src/main.ts` directly. Type-check with `npm run typecheck` (`tsc --noEmit`) before committing.
- **No runtime dependencies.** The CLI relies only on the Node standard library; keep it that way. `typescript` and `@types/node` are the only (dev) dependencies.
- **Two halves.** TypeScript handles orchestration, argument parsing, caching, config, and output. The disassembler-specific logic lives in the Python operation scripts under `scripts/<backend>/`, one file per command plus a shared base. Adding or changing an operation usually means touching its Python script for each backend you support and wiring the command into the CLI's command table — not reworking the orchestrator.
- **Keep the contract.** A command's Python script must write the documented JSON shape; the CLI is responsible for the surrounding envelope. Never write progress, logs, or warnings to stdout — that stream is reserved for the JSON result. Use stderr.
- **Backends differ on purpose.** When a backend genuinely cannot do something, fail loudly with a clear `error.type`/`message` instead of returning empty or fabricated data.
- **Test against real binaries.** `/bin/ls` is a fast, universal smoke test; use a large app binary (and `--arch`) to exercise the slow analysis and caching paths.

## License

See [LICENSE](LICENSE).
