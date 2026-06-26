"""Hex-Rays live-microcode provers for branch-ownership refinement (llr-f1cs F3).

The portable branch-ownership refiners
(:mod:`d810.analyses.control_flow.branch_ownership_oracle`) classify a
conditional state-machine arm but cannot, by themselves, decide whether a
predicate is path-constant or real-data-dependent: that requires a live
backward symbolic slice (``MopTracker``) or a Z3/JumpFixer constant proof over
the live ``mba``.  Those engine-backed steps belong in the Hex-Rays backend,
not in portable ``analyses`` (the lazy
``importlib.import_module("d810.evaluator.hexrays_microcode.tracker")`` dodge
they used to hide behind violated both the import-linter layering and the
project "no lazy imports" rule).

This module is that backend adapter.  It imports ``MopTracker`` /
``Z3MopProver`` at **top level** (allowed -- the backend may import
``d810.evaluator`` and ``d810.backends.ast``) and touches the live ``mba``
directly.  It builds the three injectable seams the portable oracles already
accept:

* :func:`build_moptracker_predicate_resolver` -> ``predicate_resolver``
  (``MopTrackerBranchOwnershipOracle.predicate_resolver``);
* :func:`build_z3_prover_factory` -> ``prover_factory``
  (``Z3BranchOwnershipOracle.prover_factory``);
* :func:`build_discarded_side_effect_guard` -> ``side_effect_guard``
  (``Z3BranchOwnershipOracle.side_effect_guard``).

With these injected, the portable oracles never reach for the lazy tracker /
lazy z3 import and never call the ``get_condition_chain_walkers().get_block``
seam for predicate resolution -- the live work runs here.  The pure
classification helpers (opcode/predicate evaluation, constant folding) are
imported from the portable oracle module; only the live-microcode steps live
here.
"""
from __future__ import annotations

from d810.core.typing import Callable
from d810.backends.ast.z3 import Z3MopProver
from d810.capabilities.providers import BranchOwnershipProverProvider
from d810.evaluator.hexrays_microcode.tracker import (
    MopTracker,
    get_all_possibles_values,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.semantics import CallKind
from d810.analyses.control_flow.branch_ownership_oracle import (
    OpcodeLabelResolver,
    PredicateOwnershipKind,
    PredicateOwnershipResult,
    PredicateResolver,
    SideEffectGuard,
    _block_nsucc,
    _constant_mop_value,
    _eval_conditional_tail,
    _format_insn_text,
    _opcode_name,
    _resolved_opcode_label,
)

_MASK64 = 0xFFFFFFFFFFFFFFFF


def build_moptracker_predicate_resolver(
    mba: object | None,
    *,
    max_nb_block: int = 20,
    max_path: int = 8,
    opcode_label_resolver: OpcodeLabelResolver | None = None,
) -> PredicateResolver:
    """Return a ``predicate_resolver(tail, block, via_pred)`` backed by MopTracker.

    The returned callable runs a live backward symbolic slice over the ``mba``
    to fold the branch predicate's operands to constants, mirroring the former
    in-analyses ``_resolve_predicate_with_moptracker`` but with a **top-level**
    ``MopTracker`` import and direct ``mba.get_mblock`` lookups.
    """

    def _resolve(
        tail: object,
        block: object | None,
        via_pred: int | None,
    ) -> PredicateOwnershipResult:
        return _resolve_predicate_with_moptracker(
            mba,
            tail,
            block=block,
            via_pred=via_pred,
            max_nb_block=max_nb_block,
            max_path=max_path,
            opcode_label_resolver=opcode_label_resolver,
        )

    return _resolve


def build_z3_prover_factory() -> Callable[[], object]:
    """Return a ``prover_factory()`` that instantiates a live ``Z3MopProver``.

    Replaces the portable oracle's lazy
    ``importlib.import_module("d810.backends.ast.z3")`` fallback with a
    top-level backend import.
    """

    def _make() -> object:
        return Z3MopProver()

    return _make


def build_discarded_side_effect_guard(
    *,
    discarded_side_effect_depth: int = 3,
    required_constant_markers: tuple[str, ...] = (),
    opcode_label_resolver: OpcodeLabelResolver | None = None,
) -> SideEffectGuard:
    """Return a ``side_effect_guard(mba, discarded, chosen)`` over the live CFG.

    Mirrors the former in-analyses ``_discarded_corridor_side_effect_reason``
    but walks the live ``mba`` blocks directly (``mba.get_mblock`` +
    ``block.succ``) instead of the
    ``get_condition_chain_walkers().get_block``/``block_successors`` seam.
    """

    markers = tuple(
        str(marker).upper() for marker in required_constant_markers if str(marker)
    )

    def _guard(
        mba: object | None,
        discarded_target: int,
        chosen_target: int,
    ) -> str | None:
        return _discarded_corridor_side_effect_reason(
            mba,
            start_serial=int(discarded_target),
            preserved_target=int(chosen_target),
            max_depth=int(discarded_side_effect_depth),
            required_constant_markers=markers,
            opcode_label_resolver=opcode_label_resolver,
        )

    return _guard


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

    taken = _eval_conditional_tail(
        tail,
        int(left),
        int(right),
        opcode_label_resolver=opcode_label_resolver,
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
    concrete = {
        int(entry[0])
        for entry in values
        if entry and entry[0] is not None
    }
    if len(concrete) != 1:
        return None
    return next(iter(concrete))


def _discarded_corridor_side_effect_reason(
    mba: object | None,
    *,
    start_serial: int,
    preserved_target: int,
    max_depth: int,
    required_constant_markers: tuple[str, ...],
    opcode_label_resolver: OpcodeLabelResolver | None = None,
) -> str | None:
    if mba is None:
        return "missing_mba_for_side_effect_guard"
    try:
        qty = int(getattr(mba, "qty", 0) or 0)
    except (TypeError, ValueError):
        qty = 0

    if qty and (start_serial < 0 or start_serial >= qty):
        return "discarded_target_out_of_range"

    visited: set[int] = set()
    queue: list[tuple[int, int]] = [(int(start_serial), 0)]
    while queue:
        serial, depth = queue.pop(0)
        if serial in visited or serial == int(preserved_target):
            continue
        if qty and (serial < 0 or serial >= qty):
            continue
        visited.add(serial)
        try:
            block = mba.get_mblock(int(serial))
        except Exception:
            return "discarded_block_unavailable"
        if block is None:
            return "discarded_block_unavailable"

        block_reason = _block_side_effect_reason(
            block,
            required_constant_markers=required_constant_markers,
            opcode_label_resolver=opcode_label_resolver,
        )
        if block_reason is not None:
            return block_reason
        if depth >= int(max_depth):
            continue
        nsucc = _block_nsucc(block)
        if nsucc is None:
            return "discarded_successors_unknown"
        if nsucc > 2:
            return "discarded_successors_not_local_corridor"
        for idx in range(nsucc):
            try:
                succ = int(block.succ(idx))
            except Exception:
                return "discarded_successor_unavailable"
            if succ not in visited:
                queue.append((succ, depth + 1))
    return None


def _block_side_effect_reason(
    block: object,
    *,
    required_constant_markers: tuple[str, ...],
    opcode_label_resolver: OpcodeLabelResolver | None = None,
) -> str | None:
    for insn in _iter_block_insns(block):
        label = _resolved_opcode_label(insn, opcode_label_resolver)
        if isinstance(label, CallKind) or _opcode_name(
            insn,
            opcode_label_resolver,
        ) in {"call", "icall"}:
            return "discarded_arm_contains_unknown_call_side_effect"
        if label is ValueOpKind.STORE:
            is_store = True
        else:
            is_store = _opcode_name(insn, opcode_label_resolver) in {"store", "stx"}
        if not is_store:
            continue
        if not required_constant_markers:
            return "discarded_arm_contains_payload_store"
        formatted = _format_insn_text(insn).upper()
        if any(marker in formatted for marker in required_constant_markers):
            return "discarded_arm_contains_payload_store"
    return None


def _iter_block_insns(block: object, *, max_insns: int = 512):
    insn = getattr(block, "head", None)
    seen = 0
    while insn is not None and seen < max_insns:
        yield insn
        seen += 1
        insn = getattr(insn, "next", None)


def build_branch_ownership_prover_provider() -> BranchOwnershipProverProvider:
    """Build the backend prover-factory bundle for the composition root.

    Mirrors ``register_mop_ops`` / ``register_condition_chain_walkers``: the
    Hex-Rays backend constructs this from its live-microcode builders and the
    composition root registers it via
    :func:`d810.capabilities.providers.register_branch_ownership_provers`.  The
    portable refiner factory then reads it without importing this IDA-coupled
    module.
    """

    return BranchOwnershipProverProvider(
        moptracker_predicate_resolver=build_moptracker_predicate_resolver,
        z3_prover_factory=build_z3_prover_factory,
        discarded_side_effect_guard=build_discarded_side_effect_guard,
    )


__all__ = [
    "BranchOwnershipProverProvider",
    "build_branch_ownership_prover_provider",
    "build_discarded_side_effect_guard",
    "build_moptracker_predicate_resolver",
    "build_z3_prover_factory",
]
