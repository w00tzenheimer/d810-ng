"""Migration shim: ``d810.recon.flow.dispatcher_analysis`` -> ``d810.analyses.control_flow.dispatcher_analysis`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import dispatcher_analysis as _canonical

sys.modules[__name__] = _canonical
