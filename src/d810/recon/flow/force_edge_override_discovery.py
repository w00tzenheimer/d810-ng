"""Migration shim: ``d810.recon.flow.force_edge_override_discovery`` -> ``d810.analyses.control_flow.force_edge_override_discovery`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import force_edge_override_discovery as _canonical

sys.modules[__name__] = _canonical
