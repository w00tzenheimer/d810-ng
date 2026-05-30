"""Migration shim: ``d810.recon.flow.path_horizon`` -> ``d810.analyses.control_flow.path_horizon`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import path_horizon as _canonical

sys.modules[__name__] = _canonical
