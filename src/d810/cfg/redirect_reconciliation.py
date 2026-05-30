"""Migration shim: ``d810.cfg.redirect_reconciliation`` -> ``d810.analyses.control_flow.redirect_reconciliation`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import redirect_reconciliation as _canonical

sys.modules[__name__] = _canonical
