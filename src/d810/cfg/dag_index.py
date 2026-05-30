"""Migration shim: ``d810.cfg.dag_index`` -> ``d810.analyses.control_flow.dag_index`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import dag_index as _canonical

sys.modules[__name__] = _canonical
