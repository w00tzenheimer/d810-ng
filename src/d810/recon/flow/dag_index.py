"""Migration shim: ``d810.recon.flow.dag_index`` -> ``d810.analyses.control_flow.recon_dag_index`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import recon_dag_index as _canonical

sys.modules[__name__] = _canonical
