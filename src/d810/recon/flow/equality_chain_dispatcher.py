"""Migration shim: ``d810.recon.flow.equality_chain_dispatcher`` relocated to ``d810.analyses.control_flow.equality_chain_dispatcher`` (LS11, ticket d81-mt50).

sys.modules alias that preserves the old import path during the LS11
dispatcher-cluster relocation.  Re-exports every public AND private
symbol of the canonical module.  Deleted in LS11 C9 once all consumers
repoint to the canonical home.
"""
import sys

from d810.analyses.control_flow import equality_chain_dispatcher as _canonical

sys.modules[__name__] = _canonical
