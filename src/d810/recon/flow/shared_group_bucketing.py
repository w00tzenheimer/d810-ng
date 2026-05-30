"""Migration shim: ``d810.recon.flow.shared_group_bucketing`` -> ``d810.analyses.control_flow.shared_group_bucketing`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import shared_group_bucketing as _canonical

sys.modules[__name__] = _canonical
