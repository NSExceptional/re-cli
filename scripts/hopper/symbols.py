# symbols.py (Hopper) — list named addresses across all segments
import re as _re_mod


def _collect():
    doc = Document.getCurrentDocument()
    filt     = _RE_PARAMS.get('filter')
    sym_type = _RE_PARAMS.get('type', 'all')
    results  = []
    for si in range(doc.getSegmentCount()):
        seg    = doc.getSegment(si)
        addrs  = seg.getNamedAddresses()
        labels = seg.getLabelsList()
        for ea, name in zip(addrs, labels):
            if not name:
                continue
            if filt and not _re_mod.search(filt, name):
                continue
            proc = seg.getProcedureAtAddress(ea)
            kind = 'function' if proc is not None else 'data'
            if sym_type != 'all' and sym_type != kind:
                continue
            results.append({
                'address':   hex(ea),
                'name':      name,
                'type':      kind,
                'demangled': None,
            })
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
