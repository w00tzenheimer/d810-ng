"""Migration shim: ``d810.cfg.postdominator`` -> ``d810.analyses.control_flow.postdominator`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import postdominator as _canonical

sys.modules[__name__] = _canonical
