"""Flow-automaton family: recognizers for small semantic automata.

Per the LLVM/LiSA taxonomy in ``docs/plans/recon-and-cfg-restructuring.md``,
this family hosts ``FakeJump`` / ``SingleIteration`` / ``BadWhileLoop`` style
recognizers and their lowering policy.  Net-new scaffold (LS13 C1); concrete
recognizers land in the deferred C4.  Import-time IDA-free.
"""
from __future__ import annotations

from d810.families.flow_automaton.protocols import (
    FlowAutomatonComposition,
    FlowAutomatonRecognizer,
)

__all__ = ["FlowAutomatonComposition", "FlowAutomatonRecognizer"]
