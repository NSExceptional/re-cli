# imports.py (Hopper) — list imported symbols
# Hopper exposes imported symbols as named addresses in an external segment.


def _collect():
    doc        = Document.getCurrentDocument()
    lib_filter = (_RE_PARAMS.get('library') or '').lower()
    results    = []

    for si in range(doc.getSegmentCount()):
        seg  = doc.getSegment(si)
        name = seg.getName() if hasattr(seg, 'getName') else ''
        # External/import stubs are typically in __TEXT.__stubs or __DATA.__got / __la_symbol_ptr
        addrs  = seg.getNamedAddresses()
        labels = seg.getLabelsList()
        for ea, label in zip(addrs, labels):
            if not label or not label.startswith('_'):
                continue
            # Very rough heuristic: any named address in a non-code segment
            proc = seg.getProcedureAtAddress(ea)
            if proc is not None:
                continue  # skip normal functions
            results.append({
                'address': hex(ea),
                'name':    label,
                'library': None,
                'ordinal': None,
            })

    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
