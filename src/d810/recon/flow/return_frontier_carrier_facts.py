"""Migration shim: ``d810.recon.flow.return_frontier_carrier_facts`` -> ``d810.analyses.control_flow.return_frontier_carrier_facts`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import return_frontier_carrier_facts as _canonical

sys.modules[__name__] = _canonical
