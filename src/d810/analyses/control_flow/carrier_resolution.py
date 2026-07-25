'Portable carrier-resolution boundary for exit-path effect discovery.\n\nPreanalysis (this layer) computes carrier classification from portable\n``FlowGraph`` snapshots alone.  When a state-variable write is indirect\nand the snapshot cannot name the constant, preanalysis delegates that single\ngenuinely-live question -- "what constant did this indirect state write\nresolve to?" -- to an injected :class:`CarrierResolver`.\n\nThe live implementation lives in the optimizer layer (which is permitted\nto import Hex-Rays), so preanalysis never imports ``d810.hexrays`` to answer it.\n'

from __future__ import annotations

from d810.core.typing import Protocol, runtime_checkable
from d810.analyses.control_flow.state_machine_analysis import CarrierResolutionResult


@runtime_checkable
class CarrierResolver(Protocol):
    "Resolve an indirect state-var write the snapshot alone cannot.\n\n    Implemented in the optimizer/backend layer, which holds the live\n    ``mba``.  Returns ``None`` when the write cannot be resolved, in\n    which case preanalysis keeps its snapshot-derived carrier bucket.\n"

    def resolve_indirect_state_write(
        self,
        candidate_serial: int,
        state_var_stkoff: int,
    ) -> CarrierResolutionResult | None: ...
