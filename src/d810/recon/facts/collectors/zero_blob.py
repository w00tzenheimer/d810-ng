"""Migration shim: ``d810.recon.facts.collectors.zero_blob`` -> ``d810.analyses.value_flow.zero_blob`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.value_flow import zero_blob as _canonical

sys.modules[__name__] = _canonical
