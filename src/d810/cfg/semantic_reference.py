"""Migration shim: ``d810.cfg.semantic_reference`` -> ``d810.ir.semantic_reference`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.ir import semantic_reference as _canonical

sys.modules[__name__] = _canonical
