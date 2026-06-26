"""Branch ownership proof production (portable classification).

This module is pure classification (``d810.analyses.control_flow``): it only
classifies conditional state-machine branch arms and emits
:class:`BranchOwnershipProof` rows.  It does not plan or apply CFG rewrites,
and it is Hex-Rays-free.

The engine-backed predicate proofs (MopTracker backward symbolic slicing, Z3
constant proofs, live-CFG side-effect guards) are NOT here -- they live in the
Hex-Rays backend adapter
(:mod:`d810.backends.hexrays.evidence.branch_ownership_prover`) and are injected
through the :class:`PredicateOwnershipProver` / ``jump_taken_prover`` /
``side_effect_guard`` ports.  These refiners consume a portable
:class:`~d810.ir.flowgraph.FlowGraph` snapshot for the block-topology gate and
hand the backend only a portable :class:`PredicateRef` (block serial + arm +
predecessor serial + an :class:`~d810.ir.flowgraph.InsnSnapshot` tail).  No live
``mblock_t``/``minsn_t``/``mop_t`` crosses into this layer, and there is no
lazy import of any backend/evaluator module (ticket llr-f1cs).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.core.typing import Callable, Protocol, runtime_checkable
from d810.ir.flowgraph import FlowGraph, InsnSnapshot
from d810.analyses.control_flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
)
from d810.analyses.control_flow.conditional_jump_eval import (
    conditional_jump_opcode_name,
    conditional_operand_size,
    predicate_jump_taken,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import PredicateKind
from d810.ir.semantics import CallKind
from d810.ir.varnode import Space, varnode_from_mop_snapshot

_MASK64 = 0xFFFFFFFFFFFFFFFF
_SHORT_JUMP_PREDICATES = {
    "jz": PredicateKind.EQ,
    "jnz": PredicateKind.NE,
    "jcnd": PredicateKind.TRUTHY,
    "jae": PredicateKind.UGE,
    "jb": PredicateKind.ULT,
    "ja": PredicateKind.UGT,
    "jbe": PredicateKind.ULE,
    "jg": PredicateKind.SGT,
    "jge": PredicateKind.SGE,
    "jl": PredicateKind.SLT,
    "jle": PredicateKind.SLE,
}


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


OpcodeLabelResolver = Callable[[object], object | None]


@dataclass(frozen=True, slots=True)
class PredicateRef:
    """Portable descriptor for one conditional-branch predicate.

    Carries only portable identities across the analyses/backend port: the
    source block serial, the branch arm, the path predecessor serial, and a
    portable :class:`~d810.ir.flowgraph.InsnSnapshot` of the branch tail (plus
    its rendered text for text-driven matchers).  A backend prover re-resolves
    the live block/operands from the serial; no live ``mblock_t``/``minsn_t``/
    ``mop_t`` crosses this boundary (ticket llr-f1cs).
    """

    source_block: int
    branch_arm: int
    via_pred: int | None = None
    tail: InsnSnapshot | None = None
    tail_text: str = ""


@runtime_checkable
class PredicateOwnershipProver(Protocol):
    """Backend-supplied prover that resolves a branch predicate's ownership.

    The portable refiner hands a :class:`PredicateRef` (portable identities
    only) and receives a :class:`PredicateOwnershipResult` or ``None`` when the
    backend cannot prove anything.  The Hex-Rays implementation lives under
    ``d810.backends.hexrays.evidence`` (MopTracker symbolic slicing); it holds
    the live ``mba`` and re-resolves the block + operands from
    ``predicate.source_block``.  With no prover injected, analyses classify the
    arm as :attr:`PredicateOwnershipKind.UNRESOLVED`.
    """

    def resolve(
        self,
        predicate: PredicateRef,
    ) -> PredicateOwnershipResult | None: ...


@runtime_checkable
class JumpTakenProver(Protocol):
    """Backend-supplied prover for the Z3/JumpFixer constant-branch proof.

    Given a portable :class:`PredicateRef`, the backend re-resolves the live
    tail operands and proves whether the conditional jump is statically taken
    (``True``), not taken (``False``), or unprovable (``None``).  No live
    operand crosses back into analyses; only a tri-state boolean does.
    """

    def prove_jump_taken(
        self,
        predicate: PredicateRef,
    ) -> bool | None: ...


SideEffectGuard = Callable[
    [object | None, int, int],
    str | None,
]


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


class MopTrackerBranchOwnershipOracle:
    """Refine diagnostic branch ownership rows with microcode evidence.

    Portable: the block-topology gate reads a
    :class:`~d810.ir.flowgraph.FlowGraph` snapshot and the predicate proof is
    delegated to an injected :class:`PredicateOwnershipProver`.  With no prover
    injected (headless / portable), every arm stays ``UNRESOLVED``.
    """

    def __init__(
        self,
        *,
        flow_graph: FlowGraph | None,
        predicate_resolver: PredicateOwnershipProver | None = None,
        opcode_label_resolver: OpcodeLabelResolver | None = None,
    ) -> None:
        self._flow_graph = flow_graph
        self._predicate_resolver = predicate_resolver
        self._opcode_label_resolver = opcode_label_resolver

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
        if self._predicate_resolver is None:
            return None

        block = self._get_block(proof.source_block)
        if block is None or _block_nsucc(block) != 2:
            return None
        tail = getattr(block, "tail", None)
        if tail is None:
            return None

        via_pred = _path_predecessor(edge, proof.source_block)
        predicate = PredicateRef(
            source_block=int(proof.source_block),
            branch_arm=int(proof.branch_arm),
            via_pred=via_pred,
            tail=tail,
            tail_text=getattr(tail, "display_text", "") or "",
        )
        result = self._predicate_resolver.resolve(predicate)
        if result is None:
            return None
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
        if self._flow_graph is None:
            return None
        try:
            return self._flow_graph.get_block(int(serial))
        except Exception:
            return None


class Z3BranchOwnershipOracle:
    """Refine branch ownership rows using read-only JumpFixer/Z3 proofs.

    Portable: the gate + branch-target topology are computed from a
    :class:`~d810.ir.flowgraph.FlowGraph` snapshot; the live constant proof is
    delegated to an injected ``jump_taken_prover``
    (:class:`JumpTakenProver`), and the discarded-arm side-effect veto to an
    injected ``side_effect_guard``.  With neither injected, no proof is
    produced.
    """

    def __init__(
        self,
        *,
        flow_graph: FlowGraph | None,
        jump_taken_prover: JumpTakenProver | None = None,
        side_effect_guard: SideEffectGuard | None = None,
        discarded_side_effect_depth: int = 3,
        required_constant_markers: tuple[str, ...] = (),
        opcode_label_resolver: OpcodeLabelResolver | None = None,
    ) -> None:
        self._flow_graph = flow_graph
        self._jump_taken_prover = jump_taken_prover
        self._side_effect_guard = side_effect_guard
        self._discarded_side_effect_depth = max(0, int(discarded_side_effect_depth))
        self._opcode_label_resolver = opcode_label_resolver
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

        via_pred = _path_predecessor(edge, proof.source_block)
        identity = self._prove_branch_identity(proof, block, tail, via_pred)
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
        if self._flow_graph is None:
            return None
        try:
            return self._flow_graph.get_block(int(serial))
        except Exception:
            return None

    def _prove_branch_identity(
        self,
        proof: BranchOwnershipProof,
        block: object,
        tail: object,
        via_pred: int | None,
    ) -> BranchTargetIdentity | None:
        jump_target = _mop_block_ref(getattr(tail, "d", None))
        fallthrough_target = _fallthrough_target(block, jump_target)
        if jump_target is None or fallthrough_target is None:
            return None
        taken = self._prove_jump_taken(proof, tail, via_pred)
        if taken is None:
            return None
        chosen_target = jump_target if taken else fallthrough_target
        discarded_target = fallthrough_target if taken else jump_target
        return BranchTargetIdentity(
            opcode=_opcode_name(tail, self._opcode_label_resolver),
            jump_target=int(jump_target),
            fallthrough_target=int(fallthrough_target),
            chosen_target=int(chosen_target),
            discarded_target=int(discarded_target),
            taken=bool(taken),
        )

    def _prove_jump_taken(
        self,
        proof: BranchOwnershipProof,
        tail: object,
        via_pred: int | None,
    ) -> bool | None:
        predicate = _predicate_kind(tail, self._opcode_label_resolver)

        # Constant-fold path: pure, snapshot-only, no live operands required.
        if predicate is PredicateKind.TRUTHY:
            cond = getattr(tail, "l", None)
            direct = _constant_mop_value(cond) if cond is not None else None
            if direct is not None:
                return int(direct) != 0
        else:
            left = getattr(tail, "l", None)
            right = getattr(tail, "r", None)
            if left is not None and right is not None:
                direct = _eval_conditional_from_constants(
                    tail,
                    left,
                    right,
                    opcode_label_resolver=self._opcode_label_resolver,
                )
                if direct is not None:
                    return direct

        # Live constant proof: delegate to the injected backend prover.
        if self._jump_taken_prover is None:
            return None
        ref = PredicateRef(
            source_block=int(proof.source_block),
            branch_arm=int(proof.branch_arm),
            via_pred=via_pred,
            tail=tail,
            tail_text=getattr(tail, "display_text", "") or "",
        )
        try:
            return self._jump_taken_prover.prove_jump_taken(ref)
        except Exception:
            return None

    def _discarded_side_effect_guard(
        self,
        identity: BranchTargetIdentity,
    ) -> str | None:
        if self._side_effect_guard is not None:
            try:
                return self._side_effect_guard(
                    self._flow_graph,
                    int(identity.discarded_target),
                    int(identity.chosen_target),
                )
            except Exception:
                return "side_effect_guard_error"
        return _discarded_corridor_side_effect_reason(
            self._flow_graph,
            start_serial=int(identity.discarded_target),
            preserved_target=int(identity.chosen_target),
            max_depth=self._discarded_side_effect_depth,
            required_constant_markers=self._required_constant_markers,
            opcode_label_resolver=self._opcode_label_resolver,
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


def _constant_mop_value(mop: object) -> int | None:
    try:
        vn = varnode_from_mop_snapshot(mop)
    except (AttributeError, TypeError, ValueError):
        vn = None
    if vn is not None and vn.space is Space.CONST:
        return int(vn.offset)

    value = getattr(mop, "value", None)
    if value is None:
        value = getattr(mop, "nnn_value", None)
    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return None


def _eval_conditional_tail(
    tail: object,
    left: int,
    right: int,
    opcode_label_resolver: OpcodeLabelResolver | None = None,
) -> bool | None:
    predicate = _predicate_kind(tail, opcode_label_resolver)
    size = conditional_operand_size(getattr(tail, "l", None), getattr(tail, "r", None))
    return predicate_jump_taken(predicate, left, right, operand_size=size)


def _predicate_kind(
    tail: object,
    opcode_label_resolver: OpcodeLabelResolver | None = None,
) -> PredicateKind | None:
    raw = getattr(tail, "predicate_kind", None)
    if raw is None:
        raw = getattr(tail, "branch_predicate", None)
    if isinstance(raw, PredicateKind):
        return raw
    if raw is not None:
        try:
            return PredicateKind(str(raw))
        except ValueError:
            pass

    resolved = _resolved_opcode_label(tail, opcode_label_resolver)
    if isinstance(resolved, PredicateKind):
        return resolved

    canonical = conditional_jump_opcode_name(
        _opcode_name(tail, opcode_label_resolver)
    )
    return _SHORT_JUMP_PREDICATES.get(canonical)


def _eval_conditional_from_constants(
    tail: object,
    left_mop: object,
    right_mop: object,
    opcode_label_resolver: OpcodeLabelResolver | None = None,
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
        opcode_label_resolver=opcode_label_resolver,
    )


def _opcode_name(
    tail: object,
    opcode_label_resolver: OpcodeLabelResolver | None = None,
) -> str:
    name = getattr(tail, "opcode_name", None)
    if isinstance(name, str) and name:
        return name
    opcode = getattr(tail, "opcode", None)
    if opcode is None:
        opcode = getattr(tail, "op", None)
    if isinstance(opcode, str):
        return opcode
    # Prefer the portable predicate identity (snapshot tails carry it) so a
    # conditional-jump tail renders as its canonical short branch name
    # ("jz"/"jnz"/"jcnd"/...) rather than the coarse InsnKind value
    # ("equality_jump"); this keeps ``_opcode_sense`` byte-identical to the
    # former live-minsn -> resolver -> short-name path.
    predicate = getattr(tail, "predicate_kind", None)
    if predicate is None:
        predicate = getattr(tail, "branch_predicate", None)
    if isinstance(predicate, PredicateKind):
        short = conditional_jump_opcode_name(predicate)
        if short is not None:
            return short
    kind = getattr(tail, "kind", None)
    kind_value = getattr(kind, "value", kind)
    if isinstance(kind_value, str):
        return kind_value
    resolved = _resolved_opcode_label(tail, opcode_label_resolver)
    resolved_text = _semantic_label_text(resolved)
    if resolved_text is not None:
        return resolved_text
    canonical = conditional_jump_opcode_name(opcode)
    if canonical is not None:
        return canonical
    return f"op_{opcode}"


def _resolved_opcode_label(
    insn: object,
    opcode_label_resolver: OpcodeLabelResolver | None = None,
) -> object | None:
    if opcode_label_resolver is None:
        return None
    try:
        return opcode_label_resolver(insn)
    except Exception:
        return None


def _semantic_label_text(value: object | None) -> str | None:
    if isinstance(value, (PredicateKind, ValueOpKind, CallKind)):
        return value.value
    if isinstance(value, str) and value:
        return value
    return None


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
    value = getattr(mop, "block_ref", None)
    if value is None:
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


def _fallthrough_target(block: object, jump_target: int | None) -> int | None:
    """Return the fall-through successor serial for a two-way block.

    Reads the portable :class:`~d810.ir.flowgraph.BlockSnapshot.succs` topology:
    the fall-through arm is the successor that is not the explicit jump target.
    Falls back to a live ``block.nextb.serial`` only when the snapshot does not
    expose ``succs`` (legacy fakes).
    """
    succs = getattr(block, "succs", None)
    if succs is not None:
        try:
            succ_serials = [int(s) for s in succs]
        except (TypeError, ValueError):
            succ_serials = []
        if len(succ_serials) == 2 and jump_target is not None:
            for serial in succ_serials:
                if serial != int(jump_target):
                    return serial
    nextb = getattr(block, "nextb", None)
    serial = getattr(nextb, "serial", None)
    if serial is not None:
        try:
            return int(serial)
        except (TypeError, ValueError):
            return None
    return None


def _discarded_corridor_side_effect_reason(
    flow_graph: FlowGraph | None,
    *,
    start_serial: int,
    preserved_target: int,
    max_depth: int,
    required_constant_markers: tuple[str, ...],
    opcode_label_resolver: OpcodeLabelResolver | None = None,
) -> str | None:
    """Portable, FlowGraph-native discarded-arm side-effect guard.

    Walks the discarded-arm corridor over the portable
    :class:`~d810.ir.flowgraph.FlowGraph` snapshot (``get_block`` +
    ``BlockSnapshot.succs``), reading per-block side-effect markers
    (call/store) off the :class:`~d810.ir.flowgraph.InsnSnapshot` kind /
    semantic label / rendered text.  No live ``mba`` is consulted -- this is the
    F4 replacement for the former ``get_block``/``block_successors`` seam BFS.
    """
    if flow_graph is None:
        return "missing_mba_for_side_effect_guard"
    blocks = getattr(flow_graph, "blocks", None)
    try:
        qty = len(blocks) if blocks is not None else 0
    except TypeError:
        qty = 0

    if qty and start_serial not in blocks:
        return "discarded_target_out_of_range"

    visited: set[int] = set()
    queue: list[tuple[int, int]] = [(int(start_serial), 0)]
    while queue:
        serial, depth = queue.pop(0)
        if serial in visited or serial == int(preserved_target):
            continue
        if blocks is not None and serial not in blocks:
            continue
        visited.add(serial)
        block = flow_graph.get_block(int(serial))
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
        succs = getattr(block, "succs", None) or ()
        for succ in succs:
            try:
                succ_serial = int(succ)
            except (TypeError, ValueError):
                return "discarded_successor_unavailable"
            if succ_serial not in visited:
                queue.append((succ_serial, depth + 1))
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
    iterator = getattr(block, "iter_insns", None)
    if callable(iterator):
        yield from iterator()
        return
    insn = getattr(block, "head", None)
    seen = 0
    while insn is not None and seen < max_insns:
        yield insn
        seen += 1
        insn = getattr(insn, "next", None)


def _format_insn_text(insn: object) -> str:
    text = getattr(insn, "display_text", None)
    if text:
        return str(text)
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


def _hex_state(value: int | None) -> str | None:
    if value is None:
        return None
    return f"0x{int(value) & _MASK64:016x}"


__all__ = [
    "BranchTargetIdentity",
    "JumpTakenProver",
    "MopTrackerBranchOwnershipOracle",
    "PredicateOwnershipKind",
    "PredicateOwnershipProver",
    "PredicateOwnershipResult",
    "PredicateRef",
    "SideEffectGuard",
    "Z3BranchOwnershipOracle",
]
