"""Migration shim: ``d810.cfg.spurious_backedge_redirect`` -> ``d810.analyses.control_flow.spurious_backedge_redirect`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import spurious_backedge_redirect as _canonical

sys.modules[__name__] = _canonical
