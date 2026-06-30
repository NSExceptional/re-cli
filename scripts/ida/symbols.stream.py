# symbols.stream.py — streaming variant of symbols.py (issue #13). Defines produce(); the
# shared driver (_re_stream_run in _base.py) owns dedup / batching / deadline / should_stop /
# resume / --watch / incremental rescan. Identity field: addr.
import re as _re_mod
import idautils as _idautils
import idc as _idc


def _run():
    filt = _RE_PARAMS.get('filter')
    rx = _re_mod.compile(filt) if filt else None
    sym_type = _RE_PARAMS.get('type', 'all')

    def produce():
        for ea, name in _idautils.Names():
            if rx and not rx.search(name or ''):
                continue
            flags = _idc.get_full_flags(ea)
            kind = 'function' if _idc.is_code(flags) else 'data'
            if sym_type != 'all' and sym_type != kind:
                continue
            demangled = _idc.demangle_name(name, _idc.get_inf_attr(_idc.INF_SHORT_DN)) or None
            yield hex(ea), {'address': hex(ea), 'name': name, 'type': kind, 'demangled': demangled}

    _re_stream_run(produce)


_run()
