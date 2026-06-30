# strings.stream.py — streaming variant of strings.py (issue #13). Defines produce(); the
# shared driver (_re_stream_run in _base.py) owns dedup / batching / deadline / should_stop /
# resume / --watch / incremental rescan. Identity field: addr.
import re as _re_mod
import idautils as _idautils

_ENCODINGS = {0: 'C', 1: 'Pascal', 2: 'LEN2', 3: 'UNICODE', 4: 'LEN4', 5: 'ULEN2', 6: 'ULEN4'}


def _run():
    min_len = int(_RE_PARAMS.get('minLength') or 0)
    filt = _RE_PARAMS.get('filter')
    rx = _re_mod.compile(filt) if filt else None

    def produce():
        # Rebuild the string collection each scan so the incremental rescan picks up strings
        # found as analysis continues.
        sc = _idautils.Strings()
        sc.setup(strtypes=list(_ENCODINGS.keys()))
        for s in sc:
            val = str(s)
            if min_len and len(val) < min_len:
                continue
            if rx and not rx.search(val):
                continue
            yield hex(s.ea), {
                'address': hex(s.ea), 'length': s.length,
                'encoding': _ENCODINGS.get(s.strtype, str(s.strtype)), 'value': val,
            }

    _re_stream_run(produce)


_run()
