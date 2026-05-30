"""Migration shim: ``d810.recon.collectors.fixpred_signals`` -> ``d810.analyses.control_flow.fixpred_signals`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import fixpred_signals as _canonical

sys.modules[__name__] = _canonical
