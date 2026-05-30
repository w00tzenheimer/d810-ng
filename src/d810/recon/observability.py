"""Migration shim: ``d810.recon.observability`` -> ``d810.core.observability_recon`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.core import observability_recon as _canonical

sys.modules[__name__] = _canonical
