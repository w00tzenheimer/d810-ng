"""Migration shim: ``d810.recon.facts.collectors.return_carrier`` -> ``d810.analyses.value_flow.return_carrier`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.value_flow import return_carrier as _canonical

sys.modules[__name__] = _canonical
