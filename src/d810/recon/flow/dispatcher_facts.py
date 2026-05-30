"""Migration shim: ``d810.recon.flow.dispatcher_facts`` -> ``d810.analyses.control_flow.dispatcher_facts`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import dispatcher_facts as _canonical

sys.modules[__name__] = _canonical
