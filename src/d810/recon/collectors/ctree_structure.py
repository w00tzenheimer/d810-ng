"""Migration shim: ``d810.recon.collectors.ctree_structure`` -> ``d810.analyses.control_flow.ctree_structure`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import ctree_structure as _canonical

sys.modules[__name__] = _canonical
