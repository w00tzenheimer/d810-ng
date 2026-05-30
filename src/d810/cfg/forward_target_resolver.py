"""Migration shim: ``d810.cfg.forward_target_resolver`` -> ``d810.analyses.control_flow.forward_target_resolver`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import forward_target_resolver as _canonical

sys.modules[__name__] = _canonical
