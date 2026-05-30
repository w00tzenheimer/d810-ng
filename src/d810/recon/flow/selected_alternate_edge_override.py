"""Migration shim: ``d810.recon.flow.selected_alternate_edge_override`` -> ``d810.analyses.control_flow.selected_alternate_edge_override`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import selected_alternate_edge_override as _canonical

sys.modules[__name__] = _canonical
