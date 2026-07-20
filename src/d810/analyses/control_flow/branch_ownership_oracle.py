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

d81-qlal -- canonical Instruction port (private helper layer).  The public
classes / Protocols were already strongly typed; this slice strong-types the
residual ``_*`` helper layer and reads branch operands through the canonical
projection instead of backend-shaped ``InsnSnapshot`` operand slots:

* the conditional jump target (was ``_mop_block_ref(tail.d)``) is read off
  ``Instruction.control.target`` (the projection populates it from the branch's
  block operand ``block_ref``);
* the branch predicate (was ``tail.predicate_kind`` / ``tail.branch_predicate``)
  is read off ``Instruction.control.predicate`` / the snapshot's
  ``predicate_kind``;
* the compared operands (was ``tail.l`` / ``tail.r``) are read off the
  slot-aligned :func:`~d810.ir.insn_projection.operand_storages` views, and their
  constants off ``_const_value_from_varnode``;
* the compare width (was ``conditional_operand_size(tail.l, tail.r)``) comes off
  the canonical ``operand_storages`` view sizes (``_compare_operand_size``).

The two ``_*`` helpers re-exported to the Hex-Rays backend prover
(``_constant_mop_value`` / ``_eval_conditional_tail`` / ``_predicate_kind`` /
``_opcode_name``) stay polymorphic over a portable ``MopSnapshot`` *or* a live
``mop_t`` (the backend re-resolves the live tail and hands a live operand); the
live-resolution itself lives in the backend (MopTracker / Z3), not here.  The
``edge`` is a portable :class:`~d810.analyses.control_flow.linearized_state_dag.StateDagEdge`
in production but a duck-typed namespace in unit fixtures, so the edge readers
stay structurally polymorphic (non-operand-slot getattr, justified).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.analyses.control_flow.conditional_jump_eval import (
    conditional_jump_opcode_name,
    predicate_jump_taken,
)
from d810.analyses.value_flow.induction_carrier import _const_value_from_varnode
from d810.core.typing import Callable, Protocol, runtime_checkable
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnSnapshot,
    MopSnapshot,
    PredicateKind,
)
from d810.ir.insn_projection import operand_storages, project_instruction
from d810.ir.semantics import CallKind
from d810.analyses.control_flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
)
from d810.ir.locations import WeakStackSlot
from d810.ir.varnode import Space, Varnode, varnode_from_mop_snapshot

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
    "Preanalysis-level predicate ownership outcome."

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


# An opcode-label resolver maps a tail instruction (a portable ``InsnSnapshot``
# in production, a duck-typed namespace in fixtures) to a portable semantic
# label (``PredicateKind`` / ``ValueOpKind`` / ``CallKind``) or a short opcode
# name string; ``None`` when it cannot resolve one.  It stays ``object``-typed
# on the input because the backend may inject a live-mba resolver.
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


# A side-effect guard inspects the discarded-arm corridor over a portable
# ``FlowGraph`` (or ``None``) given ``(discarded_target, chosen_target)`` block
# serials and returns a veto reason string, else ``None``.
SideEffectGuard = Callable[
    [FlowGraph | None, int, int],
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
        tail = block.tail
        if tail is None:
            return None

        via_pred = _path_predecessor(edge, proof.source_block)
        predicate = PredicateRef(
            source_block=int(proof.source_block),
            branch_arm=int(proof.branch_arm),
            via_pred=via_pred,
            tail=tail,
            tail_text=tail.display_text or "",
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

    def _get_block(self, serial: int) -> BlockSnapshot | None:
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
        tail = block.tail
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

    def _get_block(self, serial: int) -> BlockSnapshot | None:
        if self._flow_graph is None:
            return None
        try:
            return self._flow_graph.get_block(int(serial))
        except Exception:
            return None

    def _prove_branch_identity(
        self,
        proof: BranchOwnershipProof,
        block: BlockSnapshot,
        tail: InsnSnapshot,
        via_pred: int | None,
    ) -> BranchTargetIdentity | None:
        jump_target = _jump_target_block(tail)
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
        tail: InsnSnapshot,
        via_pred: int | None,
    ) -> bool | None:
        predicate = _predicate_kind(tail, self._opcode_label_resolver)

        # Constant-fold path: pure, snapshot-only, no live operands required.
        # The compared operands come from the canonical ``operand_storages``
        # views (was ``tail.l`` / ``tail.r``), and their constants off the
        # ``Space.CONST`` varnode -- never from a raw operand slot.
        left_storage, right_storage, _dest = operand_storages(tail)
        if predicate is PredicateKind.TRUTHY:
            direct = _const_storage_value(left_storage)
            if direct is not None:
                return int(direct) != 0
        else:
            left = _const_storage_value(left_storage)
            right = _const_storage_value(right_storage)
            if left is not None and right is not None:
                direct = _eval_conditional_tail(
                    tail,
                    int(left),
                    int(right),
                    opcode_label_resolver=self._opcode_label_resolver,
                    operand_size=_compare_operand_size(left_storage, right_storage),
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
            tail_text=tail.display_text or "",
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


def _const_storage_value(
    storage: Varnode | WeakStackSlot | None,
) -> int | None:
    """Return the numeric constant of a canonical ``Space.CONST`` storage view.

    Reads the constant off the slot-aligned ``operand_storages`` view rather
    than a raw operand slot; ``None`` for any non-constant storage.
    """
    if isinstance(storage, Varnode):
        return _const_value_from_varnode(storage)
    return None


def _compare_operand_size(
    *storages: Varnode | WeakStackSlot | None,
) -> int:
    """Return the first concrete compare-operand size, else dword semantics.

    Mirrors :func:`~d810.analyses.control_flow.conditional_jump_eval.conditional_operand_size`
    (first non-zero operand size, default 4) but over the canonical
    ``operand_storages`` views instead of raw operand slots.
    """
    for storage in storages:
        size = getattr(storage, "size", None)
        if size is not None:
            try:
                return max(1, int(size))
            except (TypeError, ValueError):
                continue
    return 4


def _constant_mop_value(mop: MopSnapshot | None) -> int | None:
    """Return the constant value of a portable (or rich) operand snapshot.

    Re-exported to the Hex-Rays backend prover, which hands it a live ``mop_t``
    while a constant operand is resolved by the engine, not here; for such a
    live operand this returns ``None`` (the ``varnode_from_mop_snapshot`` adapter
    yields no ``Space.CONST`` view and ``mop.value`` is not an ``int``), so the
    polymorphic ``getattr(mop, "value", ...)`` read on a non-portable snapshot
    is justified and is *not* an operand-slot read.
    """
    try:
        vn = varnode_from_mop_snapshot(mop)
    except (AttributeError, TypeError, ValueError):
        vn = None
    if vn is not None and vn.space is Space.CONST:
        return int(vn.offset)

    value = getattr(mop, "value", None)
    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return None


def _eval_conditional_tail(
    tail: InsnSnapshot,
    left: int,
    right: int,
    opcode_label_resolver: OpcodeLabelResolver | None = None,
    *,
    operand_size: int | None = None,
) -> bool | None:
    """Evaluate a conditional tail over already-folded ``left``/``right``.

    ``operand_size`` is the compare width: portable callers pass the canonical
    ``operand_storages`` view size (``_compare_operand_size``), and the Hex-Rays
    backend prover passes the live operand size; when ``None`` it defaults to
    dword semantics (the legacy ``conditional_operand_size`` default).
    """
    predicate = _predicate_kind(tail, opcode_label_resolver)
    size = operand_size if operand_size is not None else 4
    return predicate_jump_taken(predicate, left, right, operand_size=size)


def _predicate_kind(
    tail: InsnSnapshot,
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


def _opcode_name(
    tail: InsnSnapshot,
    opcode_label_resolver: OpcodeLabelResolver | None = None,
) -> str:
    # ``tail.opcode`` is the structural opcode integer (an ``InsnSnapshot`` field
    # / a live minsn opcode), not an operand slot.  The former ``opcode_name`` /
    # ``op`` text probes were dead: neither is a field on the portable or rich
    # ``InsnSnapshot``, on a live minsn, or on the fixture namespaces.
    opcode = getattr(tail, "opcode", None)
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


def _jump_target_block(tail: InsnSnapshot) -> int | None:
    """Return the conditional branch's explicit jump-target block serial.

    Read off the canonical ``Instruction.control.target`` (the projection
    populates it from the branch's block operand ``block_ref``), never from the
    raw ``tail.d`` operand slot.  The former ``_mop_block_ref`` text probes
    (``.b`` / ``.target``) were dead: neither is a field on the portable or rich
    ``MopSnapshot`` (which carry ``block_ref`` / ``block_num``).
    """
    control = project_instruction(tail).control
    if control is None or control.target is None:
        return None
    return int(control.target)


def _fallthrough_target(block: BlockSnapshot, jump_target: int | None) -> int | None:
    """Return the fall-through successor serial for a two-way block.

    Reads the portable :class:`~d810.ir.flowgraph.BlockSnapshot.succs` topology:
    the fall-through arm is the successor that is not the explicit jump target.
    """
    try:
        succ_serials = [int(s) for s in block.succs]
    except (TypeError, ValueError):
        succ_serials = []
    if len(succ_serials) == 2 and jump_target is not None:
        for serial in succ_serials:
            if serial != int(jump_target):
                return serial
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
    blocks = flow_graph.blocks
    qty = len(blocks)

    if qty and start_serial not in blocks:
        return "discarded_target_out_of_range"

    visited: set[int] = set()
    queue: list[tuple[int, int]] = [(int(start_serial), 0)]
    while queue:
        serial, depth = queue.pop(0)
        if serial in visited or serial == int(preserved_target):
            continue
        if serial not in blocks:
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
        for succ in block.succs:
            try:
                succ_serial = int(succ)
            except (TypeError, ValueError):
                return "discarded_successor_unavailable"
            if succ_serial not in visited:
                queue.append((succ_serial, depth + 1))
    return None


def _block_side_effect_reason(
    block: BlockSnapshot,
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


def _iter_block_insns(block: BlockSnapshot):
    """Iterate a portable block's instruction snapshots.

    ``block`` is always a :class:`~d810.ir.flowgraph.BlockSnapshot` here, so the
    legacy ``head`` / ``.next`` linked-list fallback (for live-fake blocks) was
    dead and is removed.
    """
    return block.iter_insns()


def _format_insn_text(insn: InsnSnapshot) -> str:
    """Return a portable instruction's rendered text, else its ``repr``.

    The former ``dstr`` / ``text`` / ``display`` probes were dead: none is a
    field on the portable or rich ``InsnSnapshot`` (which carries
    ``display_text``).
    """
    text = insn.display_text
    if text:
        return str(text)
    return repr(insn)


def _edge_kind_name(edge: object) -> str:
    # ``edge`` is a portable ``StateDagEdge`` in production (its ``kind`` is a
    # ``SemanticEdgeKind`` enum, read via ``.name``) and a duck-typed namespace
    # in fixtures; this structural, non-operand-slot read stays polymorphic.
    kind = getattr(edge, "kind", None)
    name = getattr(kind, "name", None)
    return str(name if name is not None else kind)


def _path_predecessor(edge: object, source_block: int) -> int | None:
    # ``edge.ordered_path`` is a portable ``StateDagEdge`` field in production
    # and a fixture-namespace attr in tests; structural, non-operand-slot read.
    path = tuple(getattr(edge, "ordered_path", ()) or ())
    try:
        index = path.index(int(source_block))
    except ValueError:
        return None
    if index <= 0:
        return None
    return int(path[index - 1])


def _block_nsucc(block: BlockSnapshot) -> int | None:
    return int(block.nsucc)


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
