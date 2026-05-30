"""Migration shim: ``d810.cfg.flow.terminal_frontier`` -> ``d810.analyses.control_flow.terminal_frontier`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import terminal_frontier as _canonical

sys.modules[__name__] = _canonical
