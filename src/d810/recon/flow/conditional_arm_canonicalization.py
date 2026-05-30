"""Migration shim: ``d810.recon.flow.conditional_arm_canonicalization`` -> ``d810.analyses.control_flow.conditional_arm_canonicalization`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import conditional_arm_canonicalization as _canonical

sys.modules[__name__] = _canonical
