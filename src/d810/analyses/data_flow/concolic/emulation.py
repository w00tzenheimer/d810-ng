"""``EmulationCapability`` -- the concrete precision oracle seam (S3).

The fusion's concrete refiner: an *optional* capability that proves the exact value
of an instruction's result when (and only when) it can.  Soundness lives in the
contract, not the implementation:

* :class:`ExactResult` -- the backend ASSERTS this is the exact value for the
  modeled fragment.  Cross-checked against the abstract floor by
  :func:`~d810.analyses.data_flow.concolic.concrete_refiner.fold_exact` before it
  is ever trusted -- a *wrong* ExactResult is caught and discarded.
* :class:`Abstain` -- the backend can run but is not sure of exactness; stay
  abstract (no precision lost, none gained).
* :class:`Unsupported` -- the op/shape is not modeled; stay abstract.

"Incomplete, yes.  Wrong, no": an emulator may ``Abstain``/``Unsupported`` freely,
but it must never assert a wrong :class:`ExactResult`.  :class:`ReferenceEmulator`
is the pure-Python reference impl used by the unit tests and as the headless
default; the Hex-Rays impl (wrapping ``forward_eval_insn``) lands with the S4
wiring in ``backends/hexrays/evidence/emulation.py``.

Co-located in ``analyses/data_flow/concolic`` for S3 because it references
:class:`LocationRef` (whose relocation to ``ir`` is S5); a backend impl lives a
layer up and imports this downward.  Ticket llr-iqm3 / epic llr-7ouc.  Portable:
no IDA, no z3.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Mapping, Protocol

from d810.analyses.data_flow.concolic.refs import LocationRef

__all__ = [
    "ExactResult",
    "Abstain",
    "Unsupported",
    "EmulationOutcome",
    "ConcreteStore",
    "InsnRef",
    "EmulationCapability",
    "ReferenceEmulator",
]


# -- outcome ADTs (ExactResult | Abstain | Unsupported) ------------------------
@dataclass(frozen=True, slots=True)
class ExactResult:
    """The backend asserts these cell values are exact for the modeled fragment."""

    cells: Mapping[LocationRef, int] = field(default_factory=dict)

    def value_for(self, loc: LocationRef) -> int | None:
        """The exact value written to ``loc`` (``None`` if this result omits it)."""
        v = self.cells.get(loc)
        return None if v is None else int(v)


@dataclass(frozen=True, slots=True)
class Abstain:
    """The backend declines (precision unknown) -- stay abstract."""

    reason: str = ""


@dataclass(frozen=True, slots=True)
class Unsupported:
    """The op/shape is not modeled -- stay abstract."""

    reason: str = ""


#: What an :class:`EmulationCapability` returns.
EmulationOutcome = ExactResult | Abstain | Unsupported


# -- the concrete store the emulator reads -------------------------------------
@dataclass(frozen=True, slots=True)
class ConcreteStore:
    """A fully-resolved ``LocationRef -> int`` snapshot the emulator evaluates over."""

    cells: Mapping[LocationRef, int] = field(default_factory=dict)

    @staticmethod
    def of(cells: Mapping[LocationRef, int]) -> "ConcreteStore":
        return ConcreteStore(dict(cells))

    def get(self, loc: LocationRef) -> int | None:
        v = self.cells.get(loc)
        return None if v is None else int(v)


# -- the portable instruction reference the emulator evaluates -----------------
@dataclass(frozen=True, slots=True)
class InsnRef:
    """A portable instruction: ``dest = op(operands)`` at ``width`` bytes-of-bits.

    ``operands`` entries are each a :class:`LocationRef` (read from the store) or a
    plain ``int`` immediate.  This is the portable seam the Hex-Rays backend lifts
    live ``minsn_t`` into (a later slice); the value layer never sees a mop.
    """

    op: str
    dest: LocationRef
    operands: tuple = ()
    width: int = 8


class EmulationCapability(Protocol):
    """Concrete precision oracle: prove-exact-or-abstain (never wrong)."""

    def eval_insn(self, insn: InsnRef, store: ConcreteStore) -> EmulationOutcome: ...

    def eval_block(self, block: object, store: ConcreteStore) -> EmulationOutcome: ...


# -- the pure reference implementation -----------------------------------------
_BINARY = {
    "add": lambda a, b: a + b,
    "sub": lambda a, b: a - b,
    "mul": lambda a, b: a * b,
    "and": lambda a, b: a & b,
    "or": lambda a, b: a | b,
    "xor": lambda a, b: a ^ b,
    "shl": lambda a, b: a << b,
    "shr": lambda a, b: a >> b,  # logical (operands are mask-nonnegative)
}
_UNARY = {
    "not": lambda a: ~a,
    "neg": lambda a: -a,
    "mov": lambda a: a,
}


class ReferenceEmulator:
    """Pure integer ``EmulationCapability`` over a :class:`ConcreteStore`.

    Proves exactness for the modeled op set when every operand is resolved; returns
    :class:`Abstain` on a store miss (it *could* run but cannot, here) and
    :class:`Unsupported` for an op it does not model.  It NEVER asserts a wrong
    :class:`ExactResult` -- that is the contract ``fold_exact`` relies on.  Modular
    arithmetic masked to ``insn.width`` bits, mirroring the lattice widths.
    """

    def eval_insn(self, insn: InsnRef, store: ConcreteStore) -> EmulationOutcome:
        mask = (1 << insn.width) - 1
        values: list[int] = []
        for operand in insn.operands:
            if isinstance(operand, LocationRef):
                resolved = store.get(operand)
                if resolved is None:
                    return Abstain(f"unresolved operand {operand!r}")
                values.append(resolved & mask)
            else:
                values.append(int(operand) & mask)

        if insn.op in _BINARY:
            if len(values) != 2:
                return Unsupported(f"{insn.op} expects 2 operands, got {len(values)}")
            result = _BINARY[insn.op](values[0], values[1]) & mask
        elif insn.op in _UNARY:
            if len(values) != 1:
                return Unsupported(f"{insn.op} expects 1 operand, got {len(values)}")
            result = _UNARY[insn.op](values[0]) & mask
        else:
            return Unsupported(f"unmodeled op {insn.op!r}")

        return ExactResult({insn.dest: result})

    def eval_block(self, block: object, store: ConcreteStore) -> EmulationOutcome:
        # Block-stepping is the Hex-Rays impl's job (over forward_eval_insn); the
        # pure reference emulator models single instructions only.
        return Unsupported("block stepping not modeled in the reference emulator")
