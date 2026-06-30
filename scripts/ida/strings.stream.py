# strings.stream.py — streaming variant of strings.py (issue #13). See functions.stream.py
# for the injected-helper contract. Identity field: addr.
import re as _re_mod
import idautils as _idautils

_BATCH_MAX = 200
_ENCODINGS = {0: 'C', 1: 'Pascal', 2: 'LEN2', 3: 'UNICODE', 4: 'LEN4', 5: 'ULEN2', 6: 'ULEN4'}


def _run():
    min_len = int(_RE_PARAMS.get('minLength') or 0)
    filt = _RE_PARAMS.get('filter')
    rx = _re_mod.compile(filt) if filt else None

    settled = _re_deadline_wait()
    _re_stream_state['settled'] = settled
    _re_progress('indexing' if not settled else 'done', 100 if settled else None)

    sc = _idautils.Strings()
    sc.setup(strtypes=list(_ENCODINGS.keys()))

    seen = set()
    batch = []

    def flush():
        if batch:
            _re_emit(list(batch))
            del batch[:]

    for s in sc:
        key = hex(s.ea)
        if key in seen:
            continue
        seen.add(key)
        val = str(s)
        if min_len and len(val) < min_len:
            continue
        if rx and not rx.search(val):
            continue
        batch.append({
            'address': hex(s.ea), 'length': s.length,
            'encoding': _ENCODINGS.get(s.strtype, str(s.strtype)), 'value': val,
        })
        if len(batch) >= _BATCH_MAX:
            flush()
            if _re_should_stop():
                _re_stream_state['reason'] = 'max_matches'
                return
    flush()
    _re_stream_state['reason'] = 'db_settled' if settled else 'natural'


_run()
