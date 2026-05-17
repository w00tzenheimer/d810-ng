"""Microcode-backed branch ownership proof production.

This module stays in recon: it only classifies conditional state-machine branch
arms and emits :class:`BranchOwnershipProof` rows.  It does not plan or apply
CFG rewrites.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from enum import Enum
import re

from d810.core.typing import Callable
from d810.recon.flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
)

_MASK64 = 0xFFFFFFFFFFFFFFFF
_VAR_TOKEN_RE = re.compile(r"(?:%var_[0-9A-Fa-f]+|v\d+)")
_LOOP_BOUND_RE = re.compile(
    r"\bset[blge]+\s+\[ds[^\]]*:(?P<token>%var_[0-9A-Fa-f]+|v\d+)"
    r"\.8[^\]]*\]\.4,\s*#0x64\.4",
    re.IGNORECASE,
)


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


class OllvmCarrierBranchOwnershipOracle:
    """Classify OLLVM semantic branches from observed carrier facts.

    This oracle is intentionally conservative and read-only.  It upgrades an
    unresolved conditional edge only when the branch predicate text references a
    predicate token derived from OLLVM semantic carrier facts:

    * password compare result carriers become real password/input forks;
    * loop-index bound carriers become real loop-condition forks.

    The resulting proof is ``REAL_DATA_DEPENDENT``.  It may help preserve or
    bridge semantic control flow, but it never authorizes deleting a branch arm.
    """

    def __init__(
        self,
        *,
        mba: object | None,
        carrier_facts: tuple[object, ...] = (),
    ) -> None:
        self._mba = mba
        self._carrier_facts = tuple(carrier_facts or ())
        self._role_tokens = _carrier_role_tokens(self._carrier_facts)
        instruction_texts = tuple(_iter_mba_instruction_texts(mba))
        self._password_predicate_tokens = _derive_data_predicate_tokens(
            self._role_tokens.get("PASSWORD_COMPARE_RESULT", frozenset()),
            instruction_texts,
        )
        self._loop_predicate_tokens = _derive_loop_predicate_tokens(
            self._role_tokens.get("LOOP_INDEX_CARRIER", frozenset()),
            instruction_texts,
        )

    def refine(
        self,
        proof: BranchOwnershipProof,
        edge: object,
    ) -> BranchOwnershipProof | None:
        """Return a semantic branch proof for *edge*, or ``None``."""

        if not _carrier_oracle_may_refine(proof):
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

        tail_text = _format_insn_text(tail)
        tail_tokens = frozenset(_tokens(tail_text))
        if not tail_tokens:
            return None

        password_matches = tuple(
            sorted(tail_tokens & self._password_predicate_tokens)
        )
        if password_matches:
            return self._replace_proof(
                proof,
                reason="ollvm_carrier_password_compare_predicate",
                carrier_role="PASSWORD_COMPARE_RESULT",
                predicate_tokens=password_matches,
                tail_text=tail_text,
                edge=edge,
            )

        loop_matches = tuple(sorted(tail_tokens & self._loop_predicate_tokens))
        if loop_matches:
            return self._replace_proof(
                proof,
                reason="ollvm_carrier_loop_index_predicate",
                carrier_role="LOOP_INDEX_CARRIER",
                predicate_tokens=loop_matches,
                tail_text=tail_text,
                edge=edge,
            )

        return None

    def _replace_proof(
        self,
        proof: BranchOwnershipProof,
        *,
        reason: str,
        carrier_role: str,
        predicate_tokens: tuple[str, ...],
        tail_text: str,
        edge: object,
    ) -> BranchOwnershipProof:
        evidence = dict(proof.evidence)
        evidence.update({
            "predicate_ownership_kind": (
                PredicateOwnershipKind.REAL_DATA_DEPENDENT.value
            ),
            "predicate_ownership_reason": reason,
            "carrier_role": carrier_role,
            "predicate_tokens": predicate_tokens,
            "tail_text": tail_text,
            "via_pred": _path_predecessor(edge, proof.source_block),
        })
        return BranchOwnershipProof(
            proof_id=proof.proof_id,
            proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
            trusted=True,
            reason=reason,
            source_block=proof.source_block,
            branch_arm=proof.branch_arm,
            source_state=proof.source_state,
            target_state=proof.target_state,
            target_entry=proof.target_entry,
            predicate_block=proof.predicate_block,
            dispatcher_entry_block=proof.dispatcher_entry_block,
            oracle_kind="ollvm_carrier_branch_ownership",
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
    ) -> None:
        self._mba = mba
        self._prover_factory = prover_factory
        self._side_effect_guard = side_effect_guard
        self._discarded_side_effect_depth = max(0, int(discarded_side_effect_depth))
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
            return self._mba.get_mblock(int(serial))
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
            opcode=_opcode_name(tail),
            jump_target=int(jump_target),
            fallthrough_target=int(fallthrough_target),
            chosen_target=int(chosen_target),
            discarded_target=int(discarded_target),
            taken=bool(taken),
        )

    def _prove_jump_taken(self, block: object, tail: object) -> bool | None:
        opcode = _opcode_name(tail)
        if opcode in {"m_jcnd", "jcnd"}:
            return self._prove_jcnd_taken(block, tail)

        left = getattr(tail, "l", None)
        right = getattr(tail, "r", None)
        if left is None or right is None:
            return None
        direct = _eval_conditional_from_constants(tail, left, right)
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


def _carrier_role_tokens(
    facts: tuple[object, ...],
) -> dict[str, frozenset[str]]:
    role_tokens: dict[str, set[str]] = {}
    for fact in facts:
        payload = _fact_payload(fact)
        if not payload:
            continue
        if str(_fact_kind(fact) or "") != "OllvmSemanticCarrierFact":
            continue
        role = str(payload.get("role") or "")
        token = _canonical_token(payload.get("carrier_token"))
        if not role or token is None:
            continue
        role_tokens.setdefault(role, set()).add(token)
    return {
        role: frozenset(sorted(tokens))
        for role, tokens in role_tokens.items()
    }


def _carrier_oracle_may_refine(proof: BranchOwnershipProof) -> bool:
    if proof.proof_kind == BranchOwnershipProofKind.UNRESOLVED:
        return True
    if proof.proof_kind != BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER:
        return False
    return (
        str(proof.reason) == "target_state_terminal_return_frontier"
        and str(proof.evidence.get("edge_kind")) == "CONDITIONAL_TRANSITION"
    )


def _fact_kind(fact: object) -> object | None:
    if isinstance(fact, dict):
        return fact.get("kind")
    return getattr(fact, "kind", None)


def _fact_payload(fact: object) -> dict[str, object]:
    if isinstance(fact, dict):
        payload = fact.get("payload")
    else:
        payload = getattr(fact, "payload", None)
    return dict(payload or {}) if isinstance(payload, dict) else {}


def _derive_data_predicate_tokens(
    seed_tokens: frozenset[str],
    instruction_texts: tuple[str, ...],
) -> frozenset[str]:
    if not seed_tokens:
        return frozenset()

    derived: set[str] = set(seed_tokens)
    changed = True
    while changed:
        changed = False
        for text in instruction_texts:
            text_tokens = tuple(_tokens(text))
            if not text_tokens or not (set(text_tokens) & derived):
                continue
            dst = _dest_token(text)
            if dst is not None and dst not in derived:
                derived.add(dst)
                changed = True

    return frozenset(sorted(derived))


def _derive_loop_predicate_tokens(
    loop_carrier_tokens: frozenset[str],
    instruction_texts: tuple[str, ...],
) -> frozenset[str]:
    if not loop_carrier_tokens:
        return frozenset()

    predicate_tokens: set[str] = set(loop_carrier_tokens)
    for text in instruction_texts:
        match = _LOOP_BOUND_RE.search(text)
        if match is None:
            continue
        carrier = _canonical_token(match.group("token"))
        if carrier not in loop_carrier_tokens:
            continue
        dst = _dest_token(text)
        if dst is not None:
            predicate_tokens.add(dst)
    return frozenset(sorted(predicate_tokens))


def _iter_mba_instruction_texts(mba: object | None) -> tuple[str, ...]:
    if mba is None:
        return ()
    try:
        qty = int(getattr(mba, "qty", 0) or 0)
    except (TypeError, ValueError):
        qty = 0
    texts: list[str] = []
    for serial in range(max(0, qty)):
        try:
            block = mba.get_mblock(int(serial))
        except Exception:
            continue
        if block is None:
            continue
        for insn in _iter_block_insns(block):
            text = _format_insn_text(insn)
            if text:
                texts.append(text)
        tail = getattr(block, "tail", None)
        if tail is not None:
            text = _format_insn_text(tail)
            if text:
                texts.append(text)
    return tuple(texts)


def _tokens(text: str) -> tuple[str, ...]:
    return tuple(
        token for token in (
            _canonical_token(match.group(0)) for match in _VAR_TOKEN_RE.finditer(text)
        )
        if token is not None
    )


def _canonical_token(token: object | None) -> str | None:
    if token is None:
        return None
    text = str(token)
    if text.startswith("%var_"):
        return f"%var_{text[5:].upper()}"
    return text


def _dest_token(text: str) -> str | None:
    tokens = _tokens(text)
    if not tokens:
        return None
    return tokens[-1]


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


def _eval_conditional_from_constants(
    tail: object,
    left_mop: object,
    right_mop: object,
) -> bool | None:
    left = _constant_mop_value(left_mop)
    if left is None:
        return None
    right = _constant_mop_value(right_mop)
    if right is None:
        return None
    return _eval_conditional_tail(tail, int(left), int(right))


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
    if isinstance(opcode, str):
        return opcode
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
            "m_jcnd",
            "m_stx",
            "m_call",
            "m_icall",
        ):
            if opcode == getattr(ida_hexrays, name, None):
                return name
    return f"op_{opcode}"


def _opcode_sense(opcode: str) -> str:
    return {
        "m_jz": "jump_if_equal",
        "jz": "jump_if_equal",
        "m_jnz": "jump_if_not_equal",
        "jnz": "jump_if_not_equal",
        "m_jcnd": "jump_if_nonzero",
        "jcnd": "jump_if_nonzero",
        "m_jb": "jump_if_unsigned_below",
        "jb": "jump_if_unsigned_below",
        "m_jae": "jump_if_unsigned_above_or_equal",
        "jae": "jump_if_unsigned_above_or_equal",
        "m_ja": "jump_if_unsigned_above",
        "ja": "jump_if_unsigned_above",
        "m_jbe": "jump_if_unsigned_below_or_equal",
        "jbe": "jump_if_unsigned_below_or_equal",
        "m_jl": "jump_if_signed_less",
        "jl": "jump_if_signed_less",
        "m_jge": "jump_if_signed_greater_or_equal",
        "jge": "jump_if_signed_greater_or_equal",
        "m_jg": "jump_if_signed_greater",
        "jg": "jump_if_signed_greater",
        "m_jle": "jump_if_signed_less_or_equal",
        "jle": "jump_if_signed_less_or_equal",
    }.get(opcode, opcode)


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
) -> str | None:
    for insn in _iter_block_insns(block):
        opcode = _opcode_name(insn)
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
    "OllvmCarrierBranchOwnershipOracle",
    "PredicateOwnershipKind",
    "PredicateOwnershipResult",
    "Z3BranchOwnershipOracle",
]
