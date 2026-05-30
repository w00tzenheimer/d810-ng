"""Migration shim: ``d810.recon.flow.local_select_loop`` -> ``d810.analyses.control_flow.local_select_loop`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import local_select_loop as _canonical

sys.modules[__name__] = _canonical
