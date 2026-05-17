"""MopTracker-backed branch ownership proof production.

This module stays in recon: it only classifies conditional state-machine branch
arms and emits :class:`BranchOwnershipProof` rows.  It does not plan or apply
CFG rewrites.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from enum import Enum

from d810.core.typing import Callable
from d810.recon.flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
)

_MASK64 = 0xFFFFFFFFFFFFFFFF


class PredicateOwnershipKind(str, Enum):
    """Recon-level predicate ownership outcome."""

    PATH_CONSTANT = "PATH_CONSTANT"
    REAL_DATA_DEPENDENT = "REAL_DATA_DEPENDENT"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True, slots=True)
class PredicateOwnershipResult:
    """Result of resolving one branch predicate."""

    kind: PredicateOwnershipKind
    reason: str
    taken: bool | None = None
    evidence: dict[str, object] = field(default_factory=dict)


PredicateResolver = Callable[
    [object, object | None, int | None],
    PredicateOwnershipResult,
]


class MopTrackerBranchOwnershipOracle:
    """Refine diagnostic branch ownership rows with microcode evidence."""

    def __init__(
        self,
        *,
        mba: object | None,
        max_nb_block: int = 20,
        max_path: int = 8,
        predicate_resolver: PredicateResolver | None = None,
    ) -> None:
        self._mba = mba
        self._max_nb_block = max_nb_block
        self._max_path = max_path
        self._predicate_resolver = predicate_resolver

    def refine(
        self,
        proof: BranchOwnershipProof,
        edge: object,
    ) -> BranchOwnershipProof | None:
        """Return a stronger proof for *edge*, or ``None`` to keep the input."""

        if proof.proof_kind != BranchOwnershipProofKind.UNRESOLVED:
            return None
        if proof.source_block is None or proof.branch_arm is None:
            return None
        if proof.source_state is None or proof.target_state is None:
            return None
        if proof.target_entry is None:
            return None
        if _edge_kind_name(edge) != "CONDITIONAL_TRANSITION":
            return None

        block = self._get_block(proof.source_block)
        if block is None or _block_nsucc(block) != 2:
            return None
        tail = getattr(block, "tail", None)
        if tail is None:
            return None

        via_pred = _path_predecessor(edge, proof.source_block)
        result = self._resolve_predicate(tail, block, via_pred)
        if result.kind == PredicateOwnershipKind.PATH_CONSTANT:
            if result.taken is None:
                return None
            taken_arm = 1 if bool(result.taken) else 0
            if int(proof.branch_arm) == taken_arm:
                return self._replace_proof(
                    proof,
                    proof_kind=(
                        BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE
                        if bool(result.taken)
                        else BranchOwnershipProofKind.OPAQUE_ALWAYS_FALSE
                    ),
                    trusted=True,
                    reason="moptracker_path_constant_taken_arm",
                    oracle_kind="moptracker_branch_ownership",
                    result=result,
                    extra_evidence={
                        "taken_arm": taken_arm,
                        "path_constant_arm": int(proof.branch_arm),
                        "via_pred": via_pred,
                    },
                )
            return self._replace_proof(
                proof,
                proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
                trusted=True,
                reason="moptracker_path_constant_non_taken_arm",
                oracle_kind="moptracker_branch_ownership",
                result=result,
                extra_evidence={
                    "taken_arm": taken_arm,
                    "nonsemantic_arm": int(proof.branch_arm),
                    "via_pred": via_pred,
                },
            )

        if result.kind == PredicateOwnershipKind.REAL_DATA_DEPENDENT:
            return self._replace_proof(
                proof,
                proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
                trusted=True,
                reason="moptracker_real_data_dependent_predicate",
                oracle_kind="moptracker_branch_ownership",
                result=result,
                extra_evidence={"via_pred": via_pred},
            )

        return None

    def _replace_proof(
        self,
        proof: BranchOwnershipProof,
        *,
        proof_kind: BranchOwnershipProofKind,
        trusted: bool,
        reason: str,
        oracle_kind: str,
        result: PredicateOwnershipResult,
        extra_evidence: dict[str, object],
    ) -> BranchOwnershipProof:
        evidence = dict(proof.evidence)
        evidence.update(result.evidence)
        evidence.update(extra_evidence)
        evidence["predicate_ownership_kind"] = result.kind.value
        evidence["predicate_ownership_reason"] = result.reason
        return BranchOwnershipProof(
            proof_id=proof.proof_id,
            proof_kind=proof_kind,
            trusted=trusted,
            reason=reason,
            source_block=proof.source_block,
            branch_arm=proof.branch_arm,
            source_state=proof.source_state,
            target_state=proof.target_state,
            target_entry=proof.target_entry,
            predicate_block=proof.predicate_block,
            dispatcher_entry_block=proof.dispatcher_entry_block,
            oracle_kind=oracle_kind,
            evidence=evidence,
            payload=dict(proof.payload),
        )

    def _get_block(self, serial: int) -> object | None:
        if self._mba is None:
            return None
        try:
            return self._mba.get_mblock(int(serial))
        except Exception:
            return None

    def _resolve_predicate(
        self,
        tail: object,
        block: object | None,
        via_pred: int | None,
    ) -> PredicateOwnershipResult:
        if self._predicate_resolver is not None:
            return self._predicate_resolver(tail, block, via_pred)
        return _resolve_predicate_with_moptracker(
            self._mba,
            tail,
            block=block,
            via_pred=via_pred,
            max_nb_block=self._max_nb_block,
            max_path=self._max_path,
        )


def _resolve_predicate_with_moptracker(
    mba: object | None,
    tail: object,
    *,
    block: object | None,
    via_pred: int | None,
    max_nb_block: int,
    max_path: int,
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

    taken = _eval_conditional_tail(tail, int(left), int(right))
    if taken is None:
        return PredicateOwnershipResult(
            PredicateOwnershipKind.UNRESOLVED,
            "unsupported_conditional_opcode",
            evidence={
                "opcode": _opcode_name(tail),
                "left_value": int(left) & _MASK64,
                "right_value": int(right) & _MASK64,
            },
        )
    return PredicateOwnershipResult(
        PredicateOwnershipKind.PATH_CONSTANT,
        "moptracker_resolved_predicate_constant",
        taken=bool(taken),
        evidence={
            "opcode": _opcode_name(tail),
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
        tracker_module = importlib.import_module(
            "d810.evaluator.hexrays_microcode.tracker"
        )
        MopTracker = getattr(tracker_module, "MopTracker", None)
        get_all_possibles_values = getattr(
            tracker_module,
            "get_all_possibles_values",
            None,
        )
    except Exception:
        return None
    if MopTracker is None or get_all_possibles_values is None:
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


def _constant_mop_value(mop: object) -> int | None:
    value = getattr(mop, "nnn_value", None)
    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    nnn = getattr(mop, "nnn", None)
    value = getattr(nnn, "value", None)
    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    value = getattr(mop, "value", None)
    if value is not None and _mop_type_name(mop) in {"mop_n", "2"}:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return None


def _eval_conditional_tail(tail: object, left: int, right: int) -> bool | None:
    opcode = _opcode_name(tail)
    size = _operand_size(getattr(tail, "l", None), getattr(tail, "r", None))
    if opcode in {"m_jz", "jz", "op_44"}:
        return left == right
    if opcode in {"m_jnz", "jnz", "op_45"}:
        return left != right
    if opcode in {"m_jge", "jge", "op_50"}:
        return _signed(left, size) >= _signed(right, size)
    if opcode in {"m_jg", "jg", "op_49"}:
        return _signed(left, size) > _signed(right, size)
    if opcode in {"m_jle", "jle", "op_48"}:
        return _signed(left, size) <= _signed(right, size)
    if opcode in {"m_jl", "jl", "op_47"}:
        return _signed(left, size) < _signed(right, size)
    if opcode in {"m_jae", "jae"}:
        return (left & _mask_for_size(size)) >= (right & _mask_for_size(size))
    if opcode in {"m_ja", "ja"}:
        return (left & _mask_for_size(size)) > (right & _mask_for_size(size))
    if opcode in {"m_jbe", "jbe"}:
        return (left & _mask_for_size(size)) <= (right & _mask_for_size(size))
    if opcode in {"m_jb", "jb"}:
        return (left & _mask_for_size(size)) < (right & _mask_for_size(size))
    return None


def _signed(value: int, size: int) -> int:
    bits = max(1, int(size)) * 8
    mask = (1 << bits) - 1
    value &= mask
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _mask_for_size(size: int) -> int:
    bits = max(1, int(size)) * 8
    return (1 << bits) - 1


def _operand_size(*mops: object | None) -> int:
    for mop in mops:
        size = getattr(mop, "size", None)
        if size is not None:
            try:
                return int(size)
            except (TypeError, ValueError):
                pass
    return 4


def _opcode_name(tail: object) -> str:
    opcode = getattr(tail, "opcode", None)
    if opcode is None:
        opcode = getattr(tail, "op", None)
    try:
        import ida_hexrays  # type: ignore
    except Exception:
        ida_hexrays = None
    if ida_hexrays is not None:
        for name in (
            "m_jz",
            "m_jnz",
            "m_jge",
            "m_jg",
            "m_jle",
            "m_jl",
            "m_jae",
            "m_ja",
            "m_jbe",
            "m_jb",
        ):
            if opcode == getattr(ida_hexrays, name, None):
                return name
    return f"op_{opcode}"


def _edge_kind_name(edge: object) -> str:
    kind = getattr(edge, "kind", None)
    name = getattr(kind, "name", None)
    return str(name if name is not None else kind)


def _path_predecessor(edge: object, source_block: int) -> int | None:
    path = tuple(getattr(edge, "ordered_path", ()) or ())
    try:
        index = path.index(int(source_block))
    except ValueError:
        return None
    if index <= 0:
        return None
    return int(path[index - 1])


def _block_nsucc(block: object) -> int | None:
    nsucc = getattr(block, "nsucc", None)
    if callable(nsucc):
        try:
            return int(nsucc())
        except Exception:
            return None
    if nsucc is not None:
        try:
            return int(nsucc)
        except (TypeError, ValueError):
            return None
    return None


def _mop_type_name(mop: object) -> str:
    t = getattr(mop, "t", None)
    name = getattr(t, "name", None)
    return str(name if name is not None else t)


__all__ = [
    "MopTrackerBranchOwnershipOracle",
    "PredicateOwnershipKind",
    "PredicateOwnershipResult",
]
