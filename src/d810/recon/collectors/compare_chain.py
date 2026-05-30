"""Migration shim: ``d810.recon.collectors.compare_chain`` -> ``d810.analyses.control_flow.compare_chain_collector`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import compare_chain_collector as _canonical

sys.modules[__name__] = _canonical
