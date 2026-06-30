# symbols.stream.py — streaming variant of symbols.py (issue #13). See functions.stream.py
# for the injected-helper contract. Identity field: addr.
import re as _re_mod
import idautils as _idautils
import idc as _idc

_BATCH_MAX = 200


def _run():
    filt = _RE_PARAMS.get('filter')
    rx = _re_mod.compile(filt) if filt else None
    sym_type = _RE_PARAMS.get('type', 'all')

    settled = _re_deadline_wait()
    _re_stream_state['settled'] = settled
    _re_progress('indexing' if not settled else 'done', 100 if settled else None)

    seen = set()
    batch = []

    def flush():
        if batch:
            _re_emit(list(batch))
            del batch[:]

    for ea, name in _idautils.Names():
        key = hex(ea)
        if key in seen:
            continue
        seen.add(key)
        if rx and not rx.search(name or ''):
            continue
        flags = _idc.get_full_flags(ea)
        kind = 'function' if _idc.is_code(flags) else 'data'
        if sym_type != 'all' and sym_type != kind:
            continue
        demangled = _idc.demangle_name(name, _idc.get_inf_attr(_idc.INF_SHORT_DN)) or None
        batch.append({'address': hex(ea), 'name': name, 'type': kind, 'demangled': demangled})
        if len(batch) >= _BATCH_MAX:
            flush()
            if _re_should_stop():
                _re_stream_state['reason'] = 'max_matches'
                return
    flush()
    _re_stream_state['reason'] = 'db_settled' if settled else 'natural'


_run()
