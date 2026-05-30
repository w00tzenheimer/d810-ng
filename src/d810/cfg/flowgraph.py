"""Migration shim: ``d810.cfg.flowgraph`` -> ``d810.ir.flowgraph`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.ir import flowgraph as _canonical

sys.modules[__name__] = _canonical
