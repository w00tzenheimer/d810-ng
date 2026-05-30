"""Migration shim: ``d810.recon.flow.runtime_evidence`` -> ``d810.analyses.control_flow.runtime_evidence`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import runtime_evidence as _canonical

sys.modules[__name__] = _canonical
