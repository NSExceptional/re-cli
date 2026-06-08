# exports.py (Hopper) — list entry points / exported symbols


def _collect():
    doc     = Document.getCurrentDocument()
    results = []

    for si in range(doc.getSegmentCount()):
        seg = doc.getSegment(si)
        for pi in range(seg.getProcedureCount()):
            proc  = seg.getProcedureAtIndex(pi)
            ea    = proc.getEntryPoint()
            name  = seg.getNameAtAddress(ea) or hex(ea)
            # In Hopper there's no direct "is exported" flag in the scripting API;
            # we approximate by listing all non-stub named procedures.
            if name.startswith('sub_') or name.startswith('j_'):
                continue
            results.append({
                'address': hex(ea),
                'name':    name,
                'ordinal': None,
            })
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
