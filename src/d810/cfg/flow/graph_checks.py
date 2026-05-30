"""Migration shim: ``d810.cfg.flow.graph_checks`` -> ``d810.analyses.control_flow.graph_checks`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import graph_checks as _canonical

sys.modules[__name__] = _canonical
