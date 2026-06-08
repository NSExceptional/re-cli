# segments.py (Hopper) — list binary segments


def _collect():
    doc     = Document.getCurrentDocument()
    results = []
    for si in range(doc.getSegmentCount()):
        seg   = doc.getSegment(si)
        start = seg.getStartingAddress()
        size  = seg.getMappedSize()
        name  = seg.getName() if hasattr(seg, 'getName') else f'seg_{si}'
        results.append({
            'name':  name,
            'start': hex(start),
            'end':   hex(start + size),
            'size':  size,
            'type':  'unknown',
        })
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
