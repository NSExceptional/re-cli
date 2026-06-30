# functions.stream.py — streaming variant of functions.py (issue #13).
#
# Runs ONLY inside the daemon's stream_exec. It defines a `produce()` generator yielding
# (identity, row) for the CURRENT database; the shared driver (_re_stream_run in _base.py)
# owns dedup, batching, the deadline-bounded wait, should_stop, resume-watermark skipping,
# the --watch single-pass mode, AND the §11.2.1 incremental rescan that streams functions
# discovered as analysis continues. Identity field: addr.
import re as _re_mod
import idautils as _idautils
import ida_funcs as _ida_funcs


def _run():
    filt = _RE_PARAMS.get('filter')
    rx = _re_mod.compile(filt) if filt else None

    def produce():
        for func_ea in _idautils.Functions():
            name = _ida_funcs.get_func_name(func_ea)
            if rx and not rx.search(name or ''):
                continue
            func = _ida_funcs.get_func(func_ea)
            yield hex(func_ea), {
                'address': hex(func_ea),
                'name': name,
                'size': func.size() if func else None,
            }

    _re_stream_run(produce)


_run()
