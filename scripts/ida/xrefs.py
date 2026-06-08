# xrefs.py — cross-references to or from a symbol or address
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
        raise ValueError(f'Symbol not found: {sym_or_addr}')
    return ea


def _collect():
    _re_wait_analysis()
    to_target   = _RE_PARAMS.get('to')
    from_target = _RE_PARAMS.get('from')
    xref_type   = _RE_PARAMS.get('type', 'all')

    if to_target:
        ea    = _resolve(to_target)
        xrefs = _idautils.XrefsTo(ea, 0)
    elif from_target:
        ea    = _resolve(from_target)
        xrefs = _idautils.XrefsFrom(ea, 0)
    else:
        raise ValueError('Provide --to NAME or --from NAME')

    results = []
    for xref in xrefs:
        kind = 'code' if (xref.type in _CODE_TYPES) else 'data'
        if xref_type != 'all' and xref_type != kind:
            continue
        results.append({
            'from':     hex(xref.frm),
            'fromName': _idc.get_name(xref.frm) or None,
            'to':       hex(xref.to),
            'toName':   _idc.get_name(xref.to) or None,
            'type':     kind,
        })
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
