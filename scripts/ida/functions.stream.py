# functions.stream.py — streaming variant of functions.py (issue #13).
#
# Runs ONLY inside the daemon's stream_exec, which injects: _re_emit(items),
# _re_should_stop(), _re_progress(phase, percent), _re_deadline_wait([secs]) and
# _RE_STREAM_DEADLINE. The preamble + _base.py are still prepended, so _RE_PARAMS is
# available. Unlike functions.py it must NOT call _re_wait_analysis() (unbounded); it
# waits against the deadline and streams matches as it finds them. It MUST set
# _re_stream_state['reason'] and return; the daemon sends the terminal frame.
import re as _re_mod
import idautils as _idautils
import ida_funcs as _ida_funcs

_BATCH_MAX = 200


def _row(func_ea):
    name = _ida_funcs.get_func_name(func_ea)
    func = _ida_funcs.get_func(func_ea)
    return {
        'address': hex(func_ea),
        'name': name,
        'size': func.size() if func else None,
    }


def _run():
    filt = _RE_PARAMS.get('filter')
    rx = _re_mod.compile(filt) if filt else None

    # Deadline-bounded settle so we stream against partial state rather than block forever.
    settled = _re_deadline_wait()
    _re_stream_state['settled'] = settled
    _re_progress('analyzing' if not settled else 'done', 100 if settled else None)

    seen = set()       # within-query dedup by identity (addr)
    batch = []

    def flush():
        if batch:
            _re_emit(list(batch))
            del batch[:]

    for func_ea in _idautils.Functions():
        key = hex(func_ea)
        if key in seen:
            continue
        seen.add(key)
        name = _ida_funcs.get_func_name(func_ea)
        if rx and not rx.search(name or ''):
            continue
        batch.append(_row(func_ea))
        if len(batch) >= _BATCH_MAX:
            flush()
            if _re_should_stop():
                _re_stream_state['reason'] = 'max_matches'
                return
    flush()
    # If analysis fully settled, no more functions will appear → db_settled; else natural.
    _re_stream_state['reason'] = 'db_settled' if settled else 'natural'


_run()
