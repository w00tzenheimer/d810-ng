"""Migration shim: ``d810.recon.flow.switch_case_transition_analysis`` relocated to ``d810.analyses.control_flow.switch_case_transition_analysis`` (LS11, ticket d81-mt50).

sys.modules alias that preserves the old import path during the LS11
dispatcher-cluster relocation.  Re-exports every public AND private
symbol of the canonical module.  Deleted in LS11 C9 once all consumers
repoint to the canonical home.
"""
import sys

from d810.analyses.control_flow import switch_case_transition_analysis as _canonical

sys.modules[__name__] = _canonical
