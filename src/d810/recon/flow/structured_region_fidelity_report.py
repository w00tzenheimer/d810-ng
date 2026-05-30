"""Migration shim: ``d810.recon.flow.structured_region_fidelity_report`` -> ``d810.analyses.control_flow.structured_region_fidelity_report`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import structured_region_fidelity_report as _canonical

sys.modules[__name__] = _canonical
