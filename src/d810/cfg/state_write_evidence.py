"""Migration shim: ``d810.cfg.state_write_evidence`` -> ``d810.analyses.control_flow.state_write_evidence`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import state_write_evidence as _canonical

sys.modules[__name__] = _canonical
