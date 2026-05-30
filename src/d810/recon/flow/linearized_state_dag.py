"""Migration shim: ``d810.recon.flow.linearized_state_dag`` -> ``d810.analyses.control_flow.linearized_state_dag`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import linearized_state_dag as _canonical

sys.modules[__name__] = _canonical
