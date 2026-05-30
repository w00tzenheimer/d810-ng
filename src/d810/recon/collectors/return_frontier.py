"""Migration shim: ``d810.recon.collectors.return_frontier`` -> ``d810.analyses.control_flow.return_frontier_collector`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import return_frontier_collector as _canonical

sys.modules[__name__] = _canonical
