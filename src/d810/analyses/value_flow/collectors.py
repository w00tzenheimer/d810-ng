"""Built-in maturity fact collectors (canonical aggregation).

Single import surface for the value-flow + control-flow fact collectors that
the reconnaissance fact pipeline registers. Relocated from the dissolved
``d810.recon.facts.collectors`` package (dissolution, llr-mdz2); the concrete
collectors live in their ``d810.analyses.value_flow.*`` /
``d810.analyses.control_flow.*`` modules and are re-exported here.
"""
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
from d810.analyses.control_flow.state_transition_anchor import (
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
