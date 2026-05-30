"""Migration shim: ``d810.cfg.shared_corridor`` -> ``d810.analyses.control_flow.shared_corridor`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import shared_corridor as _canonical

sys.modules[__name__] = _canonical
