"""Migration shim: ``d810.cfg.mop_identity`` -> ``d810.ir.mop_identity`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.ir import mop_identity as _canonical

sys.modules[__name__] = _canonical
