"""Migration shim: ``d810.recon.flow.full_coverage_chain_probe`` -> ``d810.analyses.control_flow.full_coverage_chain_probe`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import full_coverage_chain_probe as _canonical

sys.modules[__name__] = _canonical
