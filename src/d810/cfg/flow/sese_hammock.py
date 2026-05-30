"""Migration shim: ``d810.cfg.flow.sese_hammock`` -> ``d810.analyses.control_flow.sese_hammock`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import sese_hammock as _canonical

sys.modules[__name__] = _canonical
