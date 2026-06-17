"""Microcode-backed branch ownership proof production.

This module is pure classification (``d810.analyses.control_flow``): it only classifies conditional state-machine branch
arms and emits :class:`BranchOwnershipProof` rows.  It does not plan or apply
CFG rewrites.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from enum import Enum

from d810.core.typing import Callable
from d810.capabilities.providers import get_bst_walkers
from d810.analyses.control_flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
)
from d810.analyses.control_flow.conditional_jump_eval import (
    conditional_jump_opcode_name,
    conditional_jump_taken,
    conditional_operand_size,
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
OpcodeNameResolver = Callable[[object], str | None]


@dataclass(frozen=True, slots=True)
class BranchTargetIdentity:
    """Immediate CFG identity for a conditional branch tail."""

    opcode: str
    jump_target: int
    fallthrough_target: int
    chosen_target: int
    discarded_target: int
    taken: bool

    @property
    def taken_arm(self) -> int:
        return 1 if self.taken else 0

    @property
    def discarded_arm(self) -> int:
        return 0 if self.taken else 1

    def target_for_arm(self, arm: int) -> int:
        return self.jump_target if int(arm) == 1 else self.fallthrough_target


SideEffectGuard = Callable[
    [object | None, int, int],
    str | None,
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
        opcode_name_resolver: OpcodeNameResolver | None = None,
    ) -> None:
        self._mba = mba
        self._max_nb_block = max_nb_block
        self._max_path = max_path
        self._predicate_resolver = predicate_resolver
        self._opcode_name_resolver = opcode_name_resolver

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
            return get_bst_walkers().get_block(self._mba, int(serial))
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
            opcode_name_resolver=self._opcode_name_resolver,
        )


class Z3BranchOwnershipOracle:
    """Refine branch ownership rows using read-only JumpFixer/Z3 proofs."""

    def __init__(
        self,
        *,
        mba: object | None,
        prover_factory: Callable[[], object] | None = None,
        side_effect_guard: SideEffectGuard | None = None,
        discarded_side_effect_depth: int = 3,
        required_constant_markers: tuple[str, ...] = (),
        opcode_name_resolver: OpcodeNameResolver | None = None,
    ) -> None:
        self._mba = mba
        self._prover_factory = prover_factory
        self._side_effect_guard = side_effect_guard
        self._discarded_side_effect_depth = max(0, int(discarded_side_effect_depth))
        self._opcode_name_resolver = opcode_name_resolver
        self._required_constant_markers = tuple(
            str(marker).upper()
            for marker in required_constant_markers
            if str(marker)
        )

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

        identity = self._prove_branch_identity(block, tail)
        if identity is None:
            return None

        evidence = self._identity_evidence(
            proof=proof,
            edge=edge,
            identity=identity,
        )
        if int(proof.branch_arm) == identity.taken_arm:
            return self._replace_proof(
                proof,
                proof_kind=(
                    BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE
                    if identity.taken
                    else BranchOwnershipProofKind.OPAQUE_ALWAYS_FALSE
                ),
                trusted=True,
                reason="z3_jumpfixer_constant_taken_arm",
                evidence=evidence,
            )

        guard_reason = self._discarded_side_effect_guard(identity)
        if guard_reason is not None:
            evidence["side_effect_guard_reason"] = guard_reason
            return self._replace_proof(
                proof,
                proof_kind=BranchOwnershipProofKind.UNRESOLVED,
                trusted=False,
                reason="z3_jumpfixer_discarded_arm_side_effect_guard",
                evidence=evidence,
            )

        return self._replace_proof(
            proof,
            proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
            trusted=True,
            reason="z3_jumpfixer_constant_discarded_arm",
            evidence=evidence,
        )

    def _get_block(self, serial: int) -> object | None:
        if self._mba is None:
            return None
        try:
            return get_bst_walkers().get_block(self._mba, int(serial))
        except Exception:
            return None

    def _prove_branch_identity(
        self,
        block: object,
        tail: object,
    ) -> BranchTargetIdentity | None:
        jump_target = _mop_block_ref(getattr(tail, "d", None))
        fallthrough_target = _fallthrough_target(block)
        if jump_target is None or fallthrough_target is None:
            return None
        taken = self._prove_jump_taken(block, tail)
        if taken is None:
            return None
        chosen_target = jump_target if taken else fallthrough_target
        discarded_target = fallthrough_target if taken else jump_target
        return BranchTargetIdentity(
            opcode=_opcode_name(tail, self._opcode_name_resolver),
            jump_target=int(jump_target),
            fallthrough_target=int(fallthrough_target),
            chosen_target=int(chosen_target),
            discarded_target=int(discarded_target),
            taken=bool(taken),
        )

    def _prove_jump_taken(self, block: object, tail: object) -> bool | None:
        opcode = _opcode_name(tail, self._opcode_name_resolver)
        if opcode in {"m_jcnd", "jcnd"}:
            return self._prove_jcnd_taken(block, tail)

        left = getattr(tail, "l", None)
        right = getattr(tail, "r", None)
        if left is None or right is None:
            return None
        direct = _eval_conditional_from_constants(
            tail,
            left,
            right,
            opcode_name_resolver=self._opcode_name_resolver,
        )
        if direct is not None:
            return direct

        if opcode in {"m_jz", "jz", "m_jnz", "jnz"}:
            prover = self._make_prover()
            if prover is None:
                return None
            if _z3_are_equal(prover, left, right, block=block, tail=tail):
                return opcode in {"m_jz", "jz"}
            if _z3_are_unequal(prover, left, right, block=block, tail=tail):
                return opcode in {"m_jnz", "jnz"}
        return None

    def _prove_jcnd_taken(self, block: object, tail: object) -> bool | None:
        cond = getattr(tail, "l", None)
        if cond is None:
            return None
        direct = _constant_mop_value(cond)
        if direct is not None:
            return int(direct) != 0

        prover = self._make_prover()
        if prover is None:
            return None
        if _z3_is_always_zero(prover, cond, block=block, tail=tail):
            return False
        if _z3_is_always_nonzero(prover, cond, block=block, tail=tail):
            return True
        return None

    def _make_prover(self) -> object | None:
        if self._prover_factory is not None:
            try:
                return self._prover_factory()
            except Exception:
                return None
        try:
            z3_module = importlib.import_module("d810.backends.ast.z3")
            prover_cls = getattr(z3_module, "Z3MopProver", None)
        except Exception:
            return None
        if prover_cls is None:
            return None
        try:
            return prover_cls()
        except Exception:
            return None

    def _discarded_side_effect_guard(
        self,
        identity: BranchTargetIdentity,
    ) -> str | None:
        if self._side_effect_guard is not None:
            try:
                return self._side_effect_guard(
                    self._mba,
                    int(identity.discarded_target),
                    int(identity.chosen_target),
                )
            except Exception:
                return "side_effect_guard_error"
        return _discarded_corridor_side_effect_reason(
            self._mba,
            start_serial=int(identity.discarded_target),
            preserved_target=int(identity.chosen_target),
            max_depth=int(self._discarded_side_effect_depth),
            required_constant_markers=self._required_constant_markers,
            opcode_name_resolver=self._opcode_name_resolver,
        )

    def _identity_evidence(
        self,
        *,
        proof: BranchOwnershipProof,
        edge: object,
        identity: BranchTargetIdentity,
    ) -> dict[str, object]:
        evidence = dict(proof.evidence)
        evidence.update({
            "predicate_ownership_kind": PredicateOwnershipKind.PATH_CONSTANT.value,
            "predicate_ownership_reason": "z3_jumpfixer_proved_constant",
            "opcode": identity.opcode,
            "opcode_sense": _opcode_sense(identity.opcode),
            "jump_target": identity.jump_target,
            "fallthrough_target": identity.fallthrough_target,
            "chosen_target": identity.chosen_target,
            "discarded_target": identity.discarded_target,
            "taken": identity.taken,
            "taken_arm": identity.taken_arm,
            "discarded_arm": identity.discarded_arm,
            "edge_branch_target": identity.target_for_arm(int(proof.branch_arm)),
            "edge_target_entry": proof.target_entry,
            "source_block": proof.source_block,
            "predicate_block": proof.predicate_block,
            "source_state": _hex_state(proof.source_state),
            "target_state": _hex_state(proof.target_state),
            "target_entry": proof.target_entry,
            "branch_arm": proof.branch_arm,
            "via_pred": _path_predecessor(edge, proof.source_block),
        })
        return evidence

    def _replace_proof(
        self,
        proof: BranchOwnershipProof,
        *,
        proof_kind: BranchOwnershipProofKind,
        trusted: bool,
        reason: str,
        evidence: dict[str, object],
    ) -> BranchOwnershipProof:
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
            oracle_kind="z3_jumpfixer_branch_ownership",
            evidence=evidence,
            payload=dict(proof.payload),
        )


def _resolve_predicate_with_moptracker(
    mba: object | None,
    tail: object,
    *,
    block: object | None,
    via_pred: int | None,
    max_nb_block: int,
    max_path: int,
    opcode_name_resolver: OpcodeNameResolver | None = None,
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
        opcode_name_resolver=opcode_name_resolver,
    )
    if taken is None:
        return PredicateOwnershipResult(
            PredicateOwnershipKind.UNRESOLVED,
            "unsupported_conditional_opcode",
            evidence={
                "opcode": _opcode_name(tail, opcode_name_resolver),
                "left_value": int(left) & _MASK64,
                "right_value": int(right) & _MASK64,
            },
        )
    return PredicateOwnershipResult(
        PredicateOwnershipKind.PATH_CONSTANT,
        "moptracker_resolved_predicate_constant",
        taken=bool(taken),
        evidence={
            "opcode": _opcode_name(tail, opcode_name_resolver),
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
                block = get_bst_walkers().get_block(mba, int(serial))
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
                must_use_pred = get_bst_walkers().get_block(mba, int(via_pred))
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


def _eval_conditional_tail(
    tail: object,
    left: int,
    right: int,
    opcode_name_resolver: OpcodeNameResolver | None = None,
) -> bool | None:
    opcode = _opcode_name(tail, opcode_name_resolver)
    size = conditional_operand_size(getattr(tail, "l", None), getattr(tail, "r", None))
    return conditional_jump_taken(opcode, left, right, operand_size=size)


def _eval_conditional_from_constants(
    tail: object,
    left_mop: object,
    right_mop: object,
    opcode_name_resolver: OpcodeNameResolver | None = None,
) -> bool | None:
    left = _constant_mop_value(left_mop)
    if left is None:
        return None
    right = _constant_mop_value(right_mop)
    if right is None:
        return None
    return _eval_conditional_tail(
        tail,
        int(left),
        int(right),
        opcode_name_resolver=opcode_name_resolver,
    )


def _opcode_name(
    tail: object,
    opcode_name_resolver: OpcodeNameResolver | None = None,
) -> str:
    name = getattr(tail, "opcode_name", None)
    if isinstance(name, str) and name:
        return name
    opcode = getattr(tail, "opcode", None)
    if opcode is None:
        opcode = getattr(tail, "op", None)
    if isinstance(opcode, str):
        return opcode
    kind = getattr(tail, "kind", None)
    kind_value = getattr(kind, "value", kind)
    if isinstance(kind_value, str):
        semantic_name = {
            "store": "m_stx",
            "call": "m_call",
        }.get(kind_value)
        if semantic_name is not None:
            return semantic_name
    if opcode_name_resolver is not None:
        try:
            resolved = opcode_name_resolver(tail)
        except Exception:
            resolved = None
        if isinstance(resolved, str) and resolved:
            return resolved
    canonical = conditional_jump_opcode_name(opcode)
    if canonical is not None:
        return f"m_{canonical}"
    return f"op_{opcode}"


def _opcode_sense(opcode: str) -> str:
    canonical = conditional_jump_opcode_name(opcode) or opcode
    return {
        "jz": "jump_if_equal",
        "jnz": "jump_if_not_equal",
        "jcnd": "jump_if_nonzero",
        "jb": "jump_if_unsigned_below",
        "jae": "jump_if_unsigned_above_or_equal",
        "ja": "jump_if_unsigned_above",
        "jbe": "jump_if_unsigned_below_or_equal",
        "jl": "jump_if_signed_less",
        "jge": "jump_if_signed_greater_or_equal",
        "jg": "jump_if_signed_greater",
        "jle": "jump_if_signed_less_or_equal",
    }.get(canonical, opcode)


def _mop_block_ref(mop: object | None) -> int | None:
    if mop is None:
        return None
    value = getattr(mop, "b", None)
    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    target = getattr(mop, "target", None)
    if target is not None:
        try:
            return int(target)
        except (TypeError, ValueError):
            return None
    return None


def _fallthrough_target(block: object) -> int | None:
    nextb = getattr(block, "nextb", None)
    serial = getattr(nextb, "serial", None)
    if serial is not None:
        try:
            return int(serial)
        except (TypeError, ValueError):
            return None
    return None


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


def _discarded_corridor_side_effect_reason(
    mba: object | None,
    *,
    start_serial: int,
    preserved_target: int,
    max_depth: int,
    required_constant_markers: tuple[str, ...],
    opcode_name_resolver: OpcodeNameResolver | None = None,
) -> str | None:
    if mba is None:
        return "missing_mba_for_side_effect_guard"
    try:
        qty = int(getattr(mba, "qty", 0) or 0)
    except (TypeError, ValueError):
        qty = 0

    if qty and (start_serial < 0 or start_serial >= qty):
        return "discarded_target_out_of_range"

    walkers = get_bst_walkers()
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
            block = walkers.get_block(mba, int(serial))
        except Exception:
            return "discarded_block_unavailable"
        if block is None:
            return "discarded_block_unavailable"

        block_reason = _block_side_effect_reason(
            block,
            required_constant_markers=required_constant_markers,
            opcode_name_resolver=opcode_name_resolver,
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
        try:
            succs = walkers.block_successors(block)
        except Exception:
            return "discarded_successor_unavailable"
        for idx in range(nsucc):
            try:
                succ = int(succs[idx])
            except Exception:
                return "discarded_successor_unavailable"
            if succ not in visited:
                queue.append((succ, depth + 1))
    return None


def _block_side_effect_reason(
    block: object,
    *,
    required_constant_markers: tuple[str, ...],
    opcode_name_resolver: OpcodeNameResolver | None = None,
) -> str | None:
    for insn in _iter_block_insns(block):
        opcode = _opcode_name(insn, opcode_name_resolver)
        if opcode in {"m_call", "m_icall", "call", "icall"}:
            return "discarded_arm_contains_unknown_call_side_effect"
        if opcode not in {"m_stx", "stx"}:
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


def _format_insn_text(insn: object) -> str:
    dstr = getattr(insn, "dstr", None)
    if callable(dstr):
        try:
            return str(dstr())
        except Exception:
            return repr(insn)
    text = getattr(insn, "text", None)
    if text is not None:
        return str(text)
    display = getattr(insn, "display", None)
    if display is not None:
        return str(display)
    return repr(insn)


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


def _hex_state(value: int | None) -> str | None:
    if value is None:
        return None
    return f"0x{int(value) & _MASK64:016x}"


__all__ = [
    "BranchTargetIdentity",
    "MopTrackerBranchOwnershipOracle",
    "PredicateOwnershipKind",
    "PredicateOwnershipResult",
    "Z3BranchOwnershipOracle",
]
