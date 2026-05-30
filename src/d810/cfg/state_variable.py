"""Migration shim: ``d810.cfg.state_variable`` -> ``d810.ir.state_variable`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.ir import state_variable as _canonical

sys.modules[__name__] = _canonical
