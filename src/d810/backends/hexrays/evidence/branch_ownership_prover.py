"""Hex-Rays live-microcode provers for branch-ownership refinement (llr-f1cs).

The portable branch-ownership refiners
(:mod:`d810.analyses.control_flow.branch_ownership_oracle`) classify a
conditional state-machine arm but cannot, by themselves, decide whether a
predicate is path-constant: that requires a live backward symbolic slice
(``MopTracker``) or a Z3/JumpFixer constant proof over the live ``mba``.  Those
engine-backed steps belong in the Hex-Rays backend, not in portable
``analyses`` (the lazy
``importlib.import_module("d810.evaluator.hexrays_microcode.tracker")`` /
``importlib.import_module("d810.backends.ast.z3")`` dodges they used to hide
behind violated both the import-linter layering and the project "no lazy
imports" rule).

This module is that backend adapter.  It imports ``MopTracker`` /
``Z3MopProver`` at **top level** (allowed -- the backend may import
``d810.evaluator`` and ``d810.backends.ast``) and holds the live ``mba``.  Each
prover implements the portable port from
:mod:`d810.analyses.control_flow.branch_ownership_oracle`:

* :class:`HexRaysMopTrackerPredicateProver` ->
  :class:`~d810.analyses.control_flow.branch_ownership_oracle.PredicateOwnershipProver`
  (``resolve(PredicateRef) -> PredicateOwnershipResult | None``);
* :class:`HexRaysZ3JumpTakenProver` ->
  :class:`~d810.analyses.control_flow.branch_ownership_oracle.JumpTakenProver`
  (``prove_jump_taken(PredicateRef) -> bool | None``).

The portable refiner hands only a
:class:`~d810.analyses.control_flow.branch_ownership_oracle.PredicateRef`
(block serial + arm + predecessor serial + an
:class:`~d810.ir.flowgraph.InsnSnapshot` tail); the prover re-resolves the live
block + tail from ``predicate.source_block`` via ``mba.get_mblock`` and runs
the engine.  No live ``mblock_t``/``minsn_t``/``mop_t`` ever crosses back into
``analyses``.
"""

from __future__ import annotations

from d810.backends.ast.z3 import Z3MopProver
from d810.capabilities.providers import BranchOwnershipProverProvider
from d810.evaluator.hexrays_microcode.tracker import (
    MopTracker,
    get_all_possibles_values,
)
from d810.analyses.control_flow.conditional_jump_eval import conditional_operand_size
from d810.analyses.control_flow.branch_ownership_oracle import (
    OpcodeLabelResolver,
    PredicateKind,
    PredicateOwnershipKind,
    PredicateOwnershipResult,
    PredicateRef,
    _constant_mop_value,
    _eval_conditional_tail,
    _opcode_name,
    _predicate_kind,
)

_MASK64 = 0xFFFFFFFFFFFFFFFF


def _live_tail(mba: object | None, predicate: PredicateRef):
    """Re-resolve the live ``(block, tail)`` for *predicate* from its serial."""
    if mba is None:
        return None, None
    try:
        block = mba.get_mblock(int(predicate.source_block))
    except Exception:
        return None, None
    if block is None:
        return None, None
    tail = getattr(block, "tail", None)
    return block, tail


class HexRaysMopTrackerPredicateProver:
    """Live MopTracker-backed :class:`PredicateOwnershipProver`.

    Re-resolves the live block + tail from ``predicate.source_block`` and runs a
    backward symbolic slice (``MopTracker``) to fold the branch predicate's
    operands to constants -- the relocated, de-lazied
    ``_resolve_predicate_with_moptracker`` / ``_resolve_mop_value``.
    """

    def __init__(
        self,
        mba: object | None,
        *,
        max_nb_block: int = 20,
        max_path: int = 8,
        opcode_label_resolver: OpcodeLabelResolver | None = None,
    ) -> None:
        self._mba = mba
        self._max_nb_block = max_nb_block
        self._max_path = max_path
        self._opcode_label_resolver = opcode_label_resolver

    def resolve(
        self,
        predicate: PredicateRef,
    ) -> PredicateOwnershipResult | None:
        block, tail = _live_tail(self._mba, predicate)
        if tail is None:
            return None
        return _resolve_predicate_with_moptracker(
            self._mba,
            tail,
            block=block,
            via_pred=predicate.via_pred,
            max_nb_block=self._max_nb_block,
            max_path=self._max_path,
            opcode_label_resolver=self._opcode_label_resolver,
        )


class HexRaysZ3JumpTakenProver:
    """Live Z3-backed :class:`JumpTakenProver`.

    Re-resolves the live tail from ``predicate.source_block`` and proves whether
    the conditional jump is statically taken via ``Z3MopProver`` -- the
    relocated, de-lazied ``Z3BranchOwnershipOracle._prove_jump_taken`` live path
    (the pure constant-fold path stays in portable analyses).
    """

    def __init__(
        self,
        mba: object | None,
        *,
        prover_factory=None,
        opcode_label_resolver: OpcodeLabelResolver | None = None,
    ) -> None:
        self._mba = mba
        self._prover_factory = prover_factory
        self._opcode_label_resolver = opcode_label_resolver

    def prove_jump_taken(
        self,
        predicate: PredicateRef,
    ) -> bool | None:
        _block, tail = _live_tail(self._mba, predicate)
        if tail is None:
            return None
        pred_kind = _predicate_kind(tail, self._opcode_label_resolver)
        if pred_kind is PredicateKind.TRUTHY:
            return self._prove_jcnd_taken(tail)
        left = getattr(tail, "l", None)
        right = getattr(tail, "r", None)
        if left is None or right is None:
            return None
        if pred_kind in {PredicateKind.EQ, PredicateKind.NE}:
            prover = self._make_prover()
            if prover is None:
                return None
            if _z3_are_equal(prover, left, right, block=_block, tail=tail):
                return pred_kind is PredicateKind.EQ
            if _z3_are_unequal(prover, left, right, block=_block, tail=tail):
                return pred_kind is PredicateKind.NE
        return None

    def _prove_jcnd_taken(self, tail: object) -> bool | None:
        cond = getattr(tail, "l", None)
        if cond is None:
            return None
        prover = self._make_prover()
        if prover is None:
            return None
        if _z3_is_always_zero(prover, cond, block=None, tail=tail):
            return False
        if _z3_is_always_nonzero(prover, cond, block=None, tail=tail):
            return True
        return None

    def _make_prover(self) -> object | None:
        if self._prover_factory is not None:
            try:
                return self._prover_factory()
            except Exception:
                return None
        try:
            return Z3MopProver()
        except Exception:
            return None


def build_branch_ownership_prover_provider() -> BranchOwnershipProverProvider:
    """Build the backend prover-factory bundle for the composition root.

    Mirrors ``register_mop_ops`` / ``register_condition_chain_walkers``: the
    Hex-Rays backend constructs this from its live-microcode prover classes and
    the composition root registers it via
    :func:`d810.capabilities.providers.register_branch_ownership_provers`.  The
    portable refiner factory then reads it without importing this IDA-coupled
    module.

    The bundle exposes two factories:

    * ``moptracker_predicate_resolver(mba, opcode_label_resolver)`` ->
      :class:`HexRaysMopTrackerPredicateProver` (the
      ``PredicateOwnershipProver`` port);
    * ``z3_jump_taken_prover(mba, opcode_label_resolver)`` ->
      :class:`HexRaysZ3JumpTakenProver` (the ``JumpTakenProver`` port).

    The discarded-arm side-effect guard is no longer a backend seam: it is a
    portable, FlowGraph-native function in the analyses oracle (F4).
    """

    def _moptracker_predicate_resolver(
        mba: object | None,
        *,
        opcode_label_resolver: OpcodeLabelResolver | None = None,
    ) -> HexRaysMopTrackerPredicateProver:
        return HexRaysMopTrackerPredicateProver(
            mba,
            opcode_label_resolver=opcode_label_resolver,
        )

    def _z3_jump_taken_prover(
        mba: object | None,
        *,
        opcode_label_resolver: OpcodeLabelResolver | None = None,
    ) -> HexRaysZ3JumpTakenProver:
        return HexRaysZ3JumpTakenProver(
            mba,
            opcode_label_resolver=opcode_label_resolver,
        )

    return BranchOwnershipProverProvider(
        moptracker_predicate_resolver=_moptracker_predicate_resolver,
        z3_jump_taken_prover=_z3_jump_taken_prover,
    )


def _resolve_predicate_with_moptracker(
    mba: object | None,
    tail: object,
    *,
    block: object | None,
    via_pred: int | None,
    max_nb_block: int,
    max_path: int,
    opcode_label_resolver: OpcodeLabelResolver | None = None,
) -> PredicateOwnershipResult:
    l_mop = getattr(tail, "l", None)
    r_mop = getattr(tail, "r", None)
    if l_mop is None or r_mop is None:
        return PredicateOwnershipResult(
            PredicateOwnershipKind.UNRESOLVED,
            "missing_predicate_operands",
        )

    left = _resolve_mop_value(
        mba,
        tail,
        l_mop,
        block=block,
        via_pred=via_pred,
        max_nb_block=max_nb_block,
        max_path=max_path,
    )
    right = _resolve_mop_value(
        mba,
        tail,
        r_mop,
        block=block,
        via_pred=via_pred,
        max_nb_block=max_nb_block,
        max_path=max_path,
    )
    if left is None or right is None:
        return PredicateOwnershipResult(
            PredicateOwnershipKind.UNRESOLVED,
            "moptracker_unresolved_predicate",
            evidence={
                "left_resolved": left is not None,
                "right_resolved": right is not None,
            },
        )

    # The live operand size feeds the relational-predicate mask exactly as the
    # former in-helper ``conditional_operand_size(tail.l, tail.r)`` read did; the
    # portable helper no longer reaches into the live operand slots itself
    # (d81-qlal), so the backend (which owns the live ``mop_t``) supplies it.
    taken = _eval_conditional_tail(
        tail,
        int(left),
        int(right),
        opcode_label_resolver=opcode_label_resolver,
        operand_size=conditional_operand_size(l_mop, r_mop),
    )
    if taken is None:
        return PredicateOwnershipResult(
            PredicateOwnershipKind.UNRESOLVED,
            "unsupported_conditional_opcode",
            evidence={
                "opcode": _opcode_name(tail, opcode_label_resolver),
                "left_value": int(left) & _MASK64,
                "right_value": int(right) & _MASK64,
            },
        )
    return PredicateOwnershipResult(
        PredicateOwnershipKind.PATH_CONSTANT,
        "moptracker_resolved_predicate_constant",
        taken=bool(taken),
        evidence={
            "opcode": _opcode_name(tail, opcode_label_resolver),
            "left_value": int(left) & _MASK64,
            "right_value": int(right) & _MASK64,
        },
    )


def _resolve_mop_value(
    mba: object | None,
    tail: object,
    mop: object,
    *,
    block: object | None,
    via_pred: int | None,
    max_nb_block: int,
    max_path: int,
) -> int | None:
    direct = _constant_mop_value(mop)
    if direct is not None:
        return direct
    block = block or getattr(tail, "block", None) or getattr(tail, "blk", None)
    if block is None and mba is not None:
        serial = getattr(tail, "block_serial", None)
        if serial is not None:
            try:
                block = mba.get_mblock(int(serial))
            except Exception:
                block = None
    if block is None:
        return None

    try:
        MopTracker.reset()
        tracker = MopTracker(
            [mop],
            max_nb_block=max_nb_block,
            max_path=max_path,
        )
        must_use_pred = None
        if via_pred is not None and mba is not None:
            try:
                must_use_pred = mba.get_mblock(int(via_pred))
            except Exception:
                must_use_pred = None
        histories = tracker.search_backward(
            block,
            tail,
            must_use_pred=must_use_pred,
        )
        values = get_all_possibles_values(histories, [mop])
    except Exception:
        return None
    concrete = {int(entry[0]) for entry in values if entry and entry[0] is not None}
    if len(concrete) != 1:
        return None
    return next(iter(concrete))


def _z3_are_equal(
    prover: object,
    left: object,
    right: object,
    *,
    block: object,
    tail: object,
) -> bool:
    try:
        return bool(prover.are_equal(left, right, blk=block, ins=tail))
    except TypeError:
        try:
            return bool(prover.are_equal(left, right))
        except Exception:
            return False
    except Exception:
        return False


def _z3_are_unequal(
    prover: object,
    left: object,
    right: object,
    *,
    block: object,
    tail: object,
) -> bool:
    try:
        return bool(prover.are_unequal(left, right, blk=block, ins=tail))
    except TypeError:
        try:
            return bool(prover.are_unequal(left, right))
        except Exception:
            return False
    except Exception:
        return False


def _z3_is_always_zero(
    prover: object,
    mop: object,
    *,
    block: object,
    tail: object,
) -> bool:
    try:
        return bool(prover.is_always_zero(mop, blk=block, ins=tail))
    except TypeError:
        try:
            return bool(prover.is_always_zero(mop))
        except Exception:
            return False
    except Exception:
        return False


def _z3_is_always_nonzero(
    prover: object,
    mop: object,
    *,
    block: object,
    tail: object,
) -> bool:
    try:
        return bool(prover.is_always_nonzero(mop, blk=block, ins=tail))
    except TypeError:
        try:
            return bool(prover.is_always_nonzero(mop))
        except Exception:
            return False
    except Exception:
        return False


__all__ = [
    "BranchOwnershipProverProvider",
    "HexRaysMopTrackerPredicateProver",
    "HexRaysZ3JumpTakenProver",
    "build_branch_ownership_prover_provider",
]
