"""Migration shim: ``d810.recon.collectors.cfg_shape`` -> ``d810.analyses.control_flow.cfg_shape`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import cfg_shape as _canonical

sys.modules[__name__] = _canonical
