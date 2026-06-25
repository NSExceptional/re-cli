# Hopper backend — known issues & limitations

`re` supports **Hopper Disassembler** as a secondary backend; **IDA is the primary and
most complete one** (decompilation, strings, dyld shared caches, richer metadata). This
doc collects Hopper-specific gaps and open questions in one place, rather than leaving
them scattered across code comments and issues.

Tested against **Hopper Disassembler 6.3.0** (macOS), detected at
`/Applications/Hopper Disassembler.app/Contents/MacOS/hopper`.

---

## ⚠️ Headless execution doesn't work in our environment (the big blocker)

**Symptom.** A one-shot Hopper run —
`hopper -e <binary> -a -Y <script>` — produces **no output** and exits in ~0.2–0.5 s.
`re` reports:

```jsonc
{ "status": "error", "backend": "hopper",
  "error": { "type": "NoOutput", "message": "Script produced no output …" } }
```

Reproduced with `/bin/ls`, with and without `--arch` thinning:

```bash
re --backend hopper --no-cache --daemon=off info /bin/ls
re --backend hopper --no-cache --daemon=off --arch x86_64 info /bin/ls
```

**Impact.** Hopper is effectively non-functional headless here. This blocks **both** the
one-shot path **and** the daemon (the daemon can only ever be as functional as a one-shot
run). Because Hopper produces no `-L`-style log, there is no `logExcerpt` to diagnose from.

**Suspected causes (unconfirmed).** In rough order of likelihood:
1. Hopper needs an active GUI / window-server session and refuses to do useful work from a
   headless/detached process.
2. License/activation state when launched outside the normal app context.
3. The CLI invocation (`-e`/`-a`/`-Y`) differs or is deprecated in Hopper 6.x.

**Status:** needs investigation on a working Hopper setup. Until then, **use IDA**, which
covers the primary use cases (including the large-database performance work that prompted
the daemon).

---

## Confirmed API limitations (from the code)

These are real, intentional gaps — Hopper fails loudly on them rather than faking data.

| Limitation | Detail | Where |
| --- | --- | --- |
| No headless **quit** API | Scripts force-exit via `os._exit(0)`; there's no clean programmatic shutdown. | `scripts/hopper/_base.py` |
| No **version** exposed to scripts | `backendVersion` is always `null` for Hopper. | `scripts/hopper/_base.py` |
| No **DSC** support | Hopper's dyld-shared-cache loader always shows an interactive module-picker dialog that can't be bypassed via scripting, so `re dsc … --backend hopper` is rejected. | `src/main.ts` (`cmdDsc`) |
| Sparse **`info`** | `format`, `arch`, `bitness`, `entry`, and the address range come back `unknown`/`null` — Hopper's Python API doesn't expose them the way IDA's does. | `scripts/hopper/info.py` |
| Limited **`xrefs`** | Implemented by iterating segments/procedures and their callers/callees rather than a proper cross-reference index; effectively code xrefs only. | `scripts/hopper/xrefs.py` |
| **`.hop` cache never persisted** | The fresh-analysis command has no save step, so the on-disk `.hop` fast-path is dormant and **every one-shot Hopper query re-analyzes** from scratch. (The daemon sidesteps this by keeping the analyzed `Document` warm in memory.) | `src/backends/hopper.ts`; idb-meta is only written for IDA in `src/runner.ts` |

---

## Warm-database daemon — implemented but unvalidated

The Hopper daemon (`scripts/hopper/_daemon.py`) mirrors the IDA one: it's launched as a
`-Y` bootstrap that binds a Unix-domain socket and loops, exec'ing the same composed
command scripts a one-shot run builds. Hopper-specific details:

- `RE_DAEMON=1` makes `_re_exit` a no-op, so a query's `finally: _re_exit(0)` trailer no
  longer kills the process.
- Each request is exec'd in a **copy of the daemon globals**, so Hopper's injected
  `Document` global is visible to the script.
- Best-effort `Document.waitForBackgroundProcessToEnd()` before serving, to ensure
  analysis is done.
- Shutdown via `os._exit(0)` (no quit API).

**It could not be validated** because of the headless blocker above. Open questions for a
working Hopper environment:

- Does Hopper keep the process **resident** when the `-Y` script never returns (blocks in
  the accept loop)?
- On which thread does the `-Y` script run, and can it **bind/serve a socket** there while
  the app stays alive?
- Does `-a` analysis reliably complete **before** the `-Y` script runs?

**Safety net:** if the daemon can't become ready, `re` falls back to a one-shot spawn, so
enabling it cannot make Hopper behavior worse than it already is.

**Tracking:** issue #1 task-list item — *"Validate Hopper daemon persistence in a working
Hopper environment."*

---

## Related, not Hopper-specific

- **Result cache ignores the backend (#2).** A `--backend hopper` query can be served a
  result that IDA produced (and vice-versa), because the cache key omits the backend. Bites
  Hopper but is a general bug.

---

## Reproductions

```bash
# Headless failure (NoOutput):
re --backend hopper --no-cache --daemon=off info /bin/ls

# Confirm IDA works for the same query (control):
re --backend ida --no-cache --daemon=off info /bin/ls
```
