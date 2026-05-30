"""Migration shim: ``d810.recon.flow.carrier_resolution`` -> ``d810.analyses.control_flow.carrier_resolution`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import carrier_resolution as _canonical

sys.modules[__name__] = _canonical
