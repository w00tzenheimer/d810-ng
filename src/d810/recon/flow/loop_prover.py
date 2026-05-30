"""Migration shim: ``d810.recon.flow.loop_prover`` -> ``d810.analyses.control_flow.loop_prover`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import loop_prover as _canonical

sys.modules[__name__] = _canonical
