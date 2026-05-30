"""Migration shim: ``d810.recon.flow.narrow_branch_local_discovery`` -> ``d810.analyses.control_flow.narrow_branch_local_discovery`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import narrow_branch_local_discovery as _canonical

sys.modules[__name__] = _canonical
