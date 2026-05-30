"""Migration shim: ``d810.recon.flow.target_entry_resolution`` -> ``d810.analyses.control_flow.target_entry_resolution`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import target_entry_resolution as _canonical

sys.modules[__name__] = _canonical
