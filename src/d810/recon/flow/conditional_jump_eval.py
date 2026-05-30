"""Migration shim: ``d810.recon.flow.conditional_jump_eval`` -> ``d810.analyses.control_flow.conditional_jump_eval`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import conditional_jump_eval as _canonical

sys.modules[__name__] = _canonical
