# xrefs.stream.py — streaming variant of xrefs.py (issue #13). Defines produce(); the shared
# driver (_re_stream_run in _base.py) owns dedup / batching / deadline / should_stop /
# resume / --watch / incremental rescan. Identity field: from. Xrefs to/from a single
# resolved EA are usually a small, fast set, but the uniform driver still streams + honors
# should_stop/deadline (and rescans, so xrefs added by later analysis surface too).
import idautils as _idautils
import idc as _idc

try:
    import ida_xref as _ida_xref
    _CODE_TYPES = frozenset([
        _ida_xref.fl_CF, _ida_xref.fl_CN,
        _ida_xref.fl_JF, _ida_xref.fl_JN,
        _ida_xref.fl_F,  _ida_xref.fl_U,
    ])
except ImportError:
    _ida_xref = None
    _CODE_TYPES = frozenset()


def _resolve(sym_or_addr):
    if sym_or_addr.startswith('0x') or sym_or_addr.startswith('0X'):
        return int(sym_or_addr, 0)
    ea = _idc.get_name_ea_simple(sym_or_addr)
    if ea == _idc.BADADDR:
        raise ValueError('Symbol not found: %s' % sym_or_addr)
    return ea


def _run():
    to_target = _RE_PARAMS.get('to')
    from_target = _RE_PARAMS.get('from')
    xref_type = _RE_PARAMS.get('type', 'all')

    if to_target:
        target = _resolve(to_target)
        direction = 'to'
    elif from_target:
        target = _resolve(from_target)
        direction = 'from'
    else:
        raise ValueError('Provide --to NAME or --from NAME')

    def produce():
        xrefs = _idautils.XrefsTo(target, 0) if direction == 'to' else _idautils.XrefsFrom(target, 0)
        for xref in xrefs:
            kind = 'code' if (xref.type in _CODE_TYPES) else 'data'
            if xref_type != 'all' and xref_type != kind:
                continue
            yield hex(xref.frm), {
                'from': hex(xref.frm), 'fromName': _idc.get_name(xref.frm) or None,
                'to': hex(xref.to), 'toName': _idc.get_name(xref.to) or None, 'type': kind,
            }

    _re_stream_run(produce)


_run()
