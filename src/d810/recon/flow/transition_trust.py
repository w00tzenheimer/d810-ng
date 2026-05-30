"""Migration shim: ``d810.recon.flow.transition_trust`` -> ``d810.analyses.control_flow.transition_trust`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import transition_trust as _canonical

sys.modules[__name__] = _canonical
