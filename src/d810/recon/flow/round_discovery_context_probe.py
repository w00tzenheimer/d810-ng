"""Migration shim: ``d810.recon.flow.round_discovery_context_probe`` -> ``d810.analyses.control_flow.round_discovery_context_probe`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import round_discovery_context_probe as _canonical

sys.modules[__name__] = _canonical
