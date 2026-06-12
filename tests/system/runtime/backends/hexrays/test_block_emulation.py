"""``HexRaysBlockEmulator`` prove-exact-or-abstain contract (S4 B, llr-1szn).

Runtime test (imports the live Hex-Rays evidence backend, so it cannot be a unit
test). Exercises the abstain paths the soundness contract demands -- a ``None``
block, and a block whose instructions resolve no state-var write.

``eval_block`` now resolves the block's first state-var write through the Hex-Rays
microcode interpreter over the DEF-USE chain history (ticket llr-a93i), not the
old ``store`` -> stk/reg projection (``store`` is advisory; the live history is
authoritative). A genuinely-folding live block is covered by the unflatten Docker
probe (the ``emu-consult: ... folded=True`` log line); here we pin the abstain
shape so a regression to a *wrong* ExactResult is caught cheaply.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.data_flow.concolic import Abstain, ConcreteStore, ExactResult
from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.backends.hexrays.evidence.emulation import HexRaysBlockEmulator


@dataclass
class _FakeBlock:
    """A microcode block stand-in: ``head`` -> linked ``next`` instructions."""

    head: object | None = None


@dataclass
class _FakeInsn:
    """An instruction with no resolvable opcode -> the stepper resolves nothing."""

    opcode: object | None = None
    d: object | None = None
    next: object | None = None


_STATE_STKOFF = 0x64
_STATE_CELL = LocationRef.stack(_STATE_STKOFF, 8)


def _emulator() -> HexRaysBlockEmulator:
    return HexRaysBlockEmulator(
        mba=None, state_var_stkoff=_STATE_STKOFF, state_cell=_STATE_CELL
    )


class TestAbstainContract:
    """Prove-exact-or-abstain: never assert a wrong ExactResult."""

    def test_none_block_abstains(self) -> None:
        assert isinstance(_emulator().eval_block(None, ConcreteStore.of({})), Abstain)

    def test_block_with_no_state_write_abstains(self) -> None:
        # An instruction whose opcode is None resolves nothing -> no state write.
        block = _FakeBlock(head=_FakeInsn(opcode=None))
        outcome = _emulator().eval_block(block, ConcreteStore.of({}))
        assert isinstance(outcome, Abstain)

    def test_eval_insn_is_unsupported(self) -> None:
        from d810.analyses.data_flow.concolic.emulation import InsnRef, Unsupported

        outcome = _emulator().eval_insn(
            InsnRef(op="add", dest=_STATE_CELL, operands=(1, 2), width=8),
            ConcreteStore.of({}),
        )
        assert isinstance(outcome, Unsupported)


class TestFoldExactInteroperates:
    """An ExactResult from this emulator folds through fold_exact unchanged."""

    def test_exact_result_keys_the_state_cell(self) -> None:
        # Directly build the ExactResult shape the emulator emits and confirm
        # fold_exact accepts it against a TOP floor (the unflatten probe's floor).
        from d810.analyses.data_flow.concolic import (
            ConcolicValue,
            PrecisionStatus,
            fold_exact,
        )

        outcome = ExactResult({_STATE_CELL: 0xDEADBEEF})
        folded = fold_exact(ConcolicValue.top(8), outcome, _STATE_CELL)
        assert folded.status is PrecisionStatus.CONCRETE
        assert folded.concrete == 0xDEADBEEF
