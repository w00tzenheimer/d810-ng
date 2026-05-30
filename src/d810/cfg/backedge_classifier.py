"""Migration shim: ``d810.cfg.backedge_classifier`` -> ``d810.analyses.control_flow.backedge_classifier`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import backedge_classifier as _canonical

sys.modules[__name__] = _canonical
