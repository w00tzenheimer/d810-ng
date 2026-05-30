"""Migration shim: ``d810.recon.flow.reconstruction_discovery_indexes`` -> ``d810.analyses.control_flow.reconstruction_discovery_indexes`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import reconstruction_discovery_indexes as _canonical

sys.modules[__name__] = _canonical
