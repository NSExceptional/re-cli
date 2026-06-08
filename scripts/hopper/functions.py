# functions.py (Hopper) — list all analyzed procedures
import re as _re_mod


def _collect():
    doc    = Document.getCurrentDocument()
    filt   = _RE_PARAMS.get('filter')
    results = []
    for si in range(doc.getSegmentCount()):
        seg = doc.getSegment(si)
        for pi in range(seg.getProcedureCount()):
            proc = seg.getProcedureAtIndex(pi)
            ea   = proc.getEntryPoint()
            name = seg.getNameAtAddress(ea) or hex(ea)
            if filt and not _re_mod.search(filt, name):
                continue
            results.append({
                'address': hex(ea),
                'name':    name,
                'size':    None,
            })
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
