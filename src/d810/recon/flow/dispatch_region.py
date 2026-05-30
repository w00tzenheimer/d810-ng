"""Migration shim: ``d810.recon.flow.dispatch_region`` -> ``d810.analyses.control_flow.dispatch_region`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import dispatch_region as _canonical

sys.modules[__name__] = _canonical
