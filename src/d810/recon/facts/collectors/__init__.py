"""Built-in maturity fact collectors."""
from __future__ import annotations

from d810.analyses.value_flow.induction_carrier import (
    InductionVariableFactCollector,
)
from d810.analyses.value_flow.byte_emit_corridor import ByteEmitCorridorFactCollector
from d810.analyses.value_flow.call_anchor import CallAnchorFactCollector
from d810.analyses.value_flow.loop_carrier import (
    LoopPredicateValueFactCollector,
)
from d810.analyses.value_flow.ollvm_semantic_carrier import (
    OllvmValueFlowEvidenceCollector,
)
from d810.analyses.value_flow.return_carrier import (
    ReturnSlotFactCollector,
    ReturnValueFactCollector,
)
from d810.analyses.value_flow.return_frontier import ReturnFrontierFactCollector
from d810.recon.facts.collectors.state_transition_anchor import (
    StateTransitionAnchorFactCollector,
)
from d810.analyses.value_flow.state_write_anchor import (
    StateWriteAnchorFactCollector,
)
from d810.analyses.value_flow.terminal_byte_emitter import (
    TerminalByteEmitterFactCollector,
)
from d810.analyses.value_flow.zero_blob import ZeroBlobFactCollector

__all__ = [
    "ByteEmitCorridorFactCollector",
    "CallAnchorFactCollector",
    "InductionVariableFactCollector",
    "LoopPredicateValueFactCollector",
    "OllvmValueFlowEvidenceCollector",
    "ReturnFrontierFactCollector",
    "ReturnSlotFactCollector",
    "ReturnValueFactCollector",
    "StateTransitionAnchorFactCollector",
    "StateWriteAnchorFactCollector",
    "TerminalByteEmitterFactCollector",
    "ZeroBlobFactCollector",
]
