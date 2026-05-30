"""Migration shim: ``d810.recon.flow.persisted_recon_dag`` -> ``d810.analyses.control_flow.persisted_recon_dag`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import persisted_recon_dag as _canonical

sys.modules[__name__] = _canonical
