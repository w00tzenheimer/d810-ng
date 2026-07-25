"Flow-automaton family: recognizers for small semantic automata.\n\nPer the LLVM/LiSA taxonomy in ``docs/plans/preanalysis-and-cfg-restructuring.md``,\nthis family hosts ``FakeJump`` / ``SingleIteration`` / ``BadWhileLoop`` style\nrecognizers and their lowering policy.  Net-new scaffold (LS13 C1); concrete\nrecognizers land in the deferred C4.  Import-time IDA-free.\n"

from __future__ import annotations

from d810.families.flow_automaton.protocols import (
    FlowAutomatonComposition,
    FlowAutomatonRecognizer,
)

__all__ = ["FlowAutomatonComposition", "FlowAutomatonRecognizer"]
