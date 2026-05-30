"""Migration shim: ``d810.recon.flow.edge_metadata`` -> ``d810.analyses.control_flow.edge_metadata`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import edge_metadata as _canonical

sys.modules[__name__] = _canonical
