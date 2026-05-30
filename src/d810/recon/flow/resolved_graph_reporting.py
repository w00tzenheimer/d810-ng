"""Migration shim: ``d810.recon.flow.resolved_graph_reporting`` -> ``d810.analyses.control_flow.resolved_graph_reporting`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import resolved_graph_reporting as _canonical

sys.modules[__name__] = _canonical
