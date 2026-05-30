"""Migration shim: ``d810.recon.facts.collectors.terminal_byte_emitter`` -> ``d810.analyses.value_flow.terminal_byte_emitter`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.value_flow import terminal_byte_emitter as _canonical

sys.modules[__name__] = _canonical
