# xrefs.stream.py — streaming variant of xrefs.py (issue #13). See functions.stream.py for
# the injected-helper contract. Identity field: from. Xrefs to/from a single resolved EA
# are typically a bounded, fast set, but we still stream + honor should_stop/deadline so
# the protocol is uniform (and so an xref hunt with --max-matches terminates promptly).
import idautils as _idautils
import idc as _idc

_BATCH_MAX = 200

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

    settled = _re_deadline_wait()
    _re_stream_state['settled'] = settled
    _re_progress('analyzing' if not settled else 'done', 100 if settled else None)

    if to_target:
        xrefs = _idautils.XrefsTo(_resolve(to_target), 0)
    elif from_target:
        xrefs = _idautils.XrefsFrom(_resolve(from_target), 0)
    else:
        raise ValueError('Provide --to NAME or --from NAME')

    seen = set()
    batch = []

    def flush():
        if batch:
            _re_emit(list(batch))
            del batch[:]

    for xref in xrefs:
        key = hex(xref.frm)          # identity: from
        if key in seen:
            continue
        seen.add(key)
        kind = 'code' if (xref.type in _CODE_TYPES) else 'data'
        if xref_type != 'all' and xref_type != kind:
            continue
        batch.append({
            'from': hex(xref.frm), 'fromName': _idc.get_name(xref.frm) or None,
            'to': hex(xref.to), 'toName': _idc.get_name(xref.to) or None, 'type': kind,
        })
        if len(batch) >= _BATCH_MAX:
            flush()
            if _re_should_stop():
                _re_stream_state['reason'] = 'max_matches'
                return
    flush()
    _re_stream_state['reason'] = 'db_settled' if settled else 'natural'


_run()
