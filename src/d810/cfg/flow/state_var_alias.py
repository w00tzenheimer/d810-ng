"""Migration shim: ``d810.cfg.flow.state_var_alias`` -> ``d810.analyses.control_flow.state_var_alias`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import state_var_alias as _canonical

sys.modules[__name__] = _canonical
