"""Migration shim: ``d810.recon.flow.guarded_state_machine`` -> ``d810.analyses.control_flow.guarded_state_machine`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import guarded_state_machine as _canonical

sys.modules[__name__] = _canonical
