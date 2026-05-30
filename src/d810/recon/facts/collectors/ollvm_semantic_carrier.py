"""Migration shim: ``d810.recon.facts.collectors.ollvm_semantic_carrier`` -> ``d810.analyses.value_flow.ollvm_semantic_carrier`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.value_flow import ollvm_semantic_carrier as _canonical

sys.modules[__name__] = _canonical
