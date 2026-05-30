"""Migration shim: ``d810.cfg.observability`` -> ``d810.core.observability_cfg`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.core import observability_cfg as _canonical

sys.modules[__name__] = _canonical
