"""Migration shim: ``d810.cfg.dominator`` -> ``d810.analyses.control_flow.dominator`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import dominator as _canonical

sys.modules[__name__] = _canonical
