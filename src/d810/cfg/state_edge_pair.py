"""Migration shim: ``d810.cfg.state_edge_pair`` -> ``d810.ir.state_edge_pair`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.ir import state_edge_pair as _canonical

sys.modules[__name__] = _canonical
