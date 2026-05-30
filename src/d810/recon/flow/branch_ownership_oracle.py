"""Migration shim: ``d810.recon.flow.branch_ownership_oracle`` -> ``d810.analyses.control_flow.branch_ownership_oracle`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import branch_ownership_oracle as _canonical

sys.modules[__name__] = _canonical
