"""Migration shim: ``d810.recon.flow.selector_shell`` -> ``d810.analyses.control_flow.selector_shell`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import selector_shell as _canonical

sys.modules[__name__] = _canonical
