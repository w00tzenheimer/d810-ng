"""Migration shim: ``d810.recon.flow.return_corridor_discovery`` -> ``d810.analyses.control_flow.return_corridor_discovery`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import return_corridor_discovery as _canonical

sys.modules[__name__] = _canonical
