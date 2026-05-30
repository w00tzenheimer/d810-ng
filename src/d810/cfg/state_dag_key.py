"""Migration shim: ``d810.cfg.state_dag_key`` -> ``d810.ir.state_dag_key`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.ir import state_dag_key as _canonical

sys.modules[__name__] = _canonical
