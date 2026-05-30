"""Migration shim: ``d810.recon.facts.model`` -> ``d810.analyses.value_flow.model`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.value_flow import model as _canonical

sys.modules[__name__] = _canonical
