"""Read-only branch ownership proofs for state-machine reconstruction.

This module classifies conditional state-machine edges as semantic source
control flow, opaque/BCF residue, or unresolved evidence.  It deliberately
does not build graph modifications.  CFG lowering may consume trusted proof
rows later, but recon owns producing and explaining the proof.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from d810.recon.flow.dispatcher_map import StateDispatcherMap

_MASK64 = 0xFFFFFFFFFFFFFFFF


class BranchOwnershipProofKind(str, Enum):
    """Semantic ownership classification for one conditional branch arm.

    These values describe the *meaning of one observed branch arm*, not the
    graph edit to perform.  Keep that separation intact:

    - Semantic-edge authority means a consumer may preserve the arm as source
      program control flow or use it as an explicit state-DAG bridge.
    - Nonsemantic-rewrite authority means a consumer may remove, retarget, or
      bypass the arm after matching exact edge identity.
    - Diagnostic-only authority means the row explains why no mutation is
      allowed.

    ``REAL_DATA_DEPENDENT``
        The arm is controlled by real program data, such as password/input
        bytes, an API result, or another value that belongs to the source
        program.  This is semantic program structure.  A trusted proof may
        authorize explicit DAG bridging/preservation.  It must not authorize
        branch removal.

    ``OPAQUE_ALWAYS_TRUE`` / ``OPAQUE_ALWAYS_FALSE``
        The predicate outcome is proven constant under the relevant path
        constraints.  The proof describes the predicate, not just the target
        block shape.  A trusted proof may authorize eliminating or retargeting
        the non-taken arm.  It does not make either arm a semantic DAG edge by
        itself.

    ``EQUIVALENT_STATE_ARMS``
        Both conditional arms resolve to the same semantic state/handler, so
        the branch is not a meaningful source-level fork even if both CFG arms
        are reachable.  This is useful for simplification diagnostics and
        possible coalescing, but it is not enough by itself to delete one arm
        unless a later consumer also proves the exact rewrite shape.

    ``OBFUSCATION_RESIDUE_ARM``
        The arm reaches a state-machine state that exists only as obfuscation
        residue: for example a BCF false arm, selector backedge, dispatcher
        residue state, or opaque branch target that should not appear as
        recovered source control flow.  A trusted proof may authorize
        nonsemantic branch rewrite after exact edge matching.  It must not
        authorize semantic DAG bridging.

    ``TERMINAL_RETURN_FRONTIER``
        The arm identifies a return/exit frontier.  This is terminal ownership
        evidence for return-frontier handling.  It is not opaque-branch proof
        and does not authorize deleting a sibling arm.

    ``UNRESOLVED``
        Recon saw a conditional arm but no trusted oracle classified it.  This
        row is diagnostics only.  No CFG mutation or semantic bridge may be
        justified from it.
    """

    REAL_DATA_DEPENDENT = "REAL_DATA_DEPENDENT"
    OPAQUE_ALWAYS_TRUE = "OPAQUE_ALWAYS_TRUE"
    OPAQUE_ALWAYS_FALSE = "OPAQUE_ALWAYS_FALSE"
    EQUIVALENT_STATE_ARMS = "EQUIVALENT_STATE_ARMS"
    OBFUSCATION_RESIDUE_ARM = "OBFUSCATION_RESIDUE_ARM"
    TERMINAL_RETURN_FRONTIER = "TERMINAL_RETURN_FRONTIER"
    UNRESOLVED = "UNRESOLVED"


TRUSTED_OPAQUE_PROVENANCE_KINDS = frozenset({
    "ollvm_bcf_opaque_predicate",
    "opaque_bcf_branch",
    "proven_opaque_predicate",
})


@dataclass(frozen=True, slots=True)
class BranchOwnershipProof:
    """One diagnostic proof row for a conditional state-machine branch arm."""

    proof_id: str
    proof_kind: BranchOwnershipProofKind | str
    trusted: bool
    reason: str
    source_block: int | None = None
    branch_arm: int | None = None
    source_state: int | None = None
    target_state: int | None = None
    target_entry: int | None = None
    predicate_block: int | None = None
    dispatcher_entry_block: int | None = None
    oracle_kind: str = "recon_branch_ownership"
    evidence: dict[str, object] = field(default_factory=dict)
    payload: dict[str, object] = field(default_factory=dict)

    @property
    def proof_kind_name(self) -> str:
        kind = self.proof_kind
        if isinstance(kind, BranchOwnershipProofKind):
            return kind.value
        return str(kind)

    @property
    def authorizes_nonsemantic_branch_rewrite(self) -> bool:
        """Whether this proof can authorize removing/retargeting a branch arm.

        This is deliberately narrower than ``trusted``.  A trusted proof can be
        terminal evidence, semantic branch evidence, or diagnostics.  Only
        proof kinds that show an arm is nonsemantic may drive mutation that
        removes or bypasses that arm, and downstream consumers must still
        match exact edge identity before applying a rewrite.

        This property is semantic-edge authority, not raw CFG ownership
        authority.  A consumer that rewrites live/projected CFG must still prove
        the source block/arm is private to the edge, or lower through a
        clone/split primitive that makes it private first.
        """
        return bool(self.trusted) and self.proof_kind_name in {
            BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM.value,
            BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE.value,
            BranchOwnershipProofKind.OPAQUE_ALWAYS_FALSE.value,
        }

    @property
    def authorizes_semantic_branch_bridge(self) -> bool:
        """Whether this proof can authorize preserving a branch as semantic.

        Only real data-dependent branch ownership is semantic-edge authority.
        Opaque and obfuscation-residue proofs may be strong enough to remove a
        nonsemantic arm, but they are not proof that the arm should appear in
        the recovered state DAG.
        """

        return (
            bool(self.trusted)
            and self.proof_kind_name
            == BranchOwnershipProofKind.REAL_DATA_DEPENDENT.value
        )

    def to_diag_row(
        self,
        *,
        profile_name: str | None = None,
        maturity: str | None = None,
    ) -> dict[str, object]:
        payload = dict(self.payload)
        if profile_name is not None:
            payload.setdefault("profile_name", str(profile_name))
        if maturity is not None:
            payload.setdefault("maturity", str(maturity))
        return {
            "proof_id": self.proof_id,
            "proof_kind": self.proof_kind_name,
            "trusted": int(bool(self.trusted)),
            "reason": self.reason,
            "source_block": self.source_block,
            "branch_arm": self.branch_arm,
            "source_state": self.source_state,
            "target_state": self.target_state,
            "target_entry": self.target_entry,
            "predicate_block": self.predicate_block,
            "dispatcher_entry_block": self.dispatcher_entry_block,
            "oracle_kind": self.oracle_kind,
            "evidence": self.evidence,
            "payload": payload,
        }


def branch_ownership_proof_from_any(
    value: object | None,
) -> BranchOwnershipProof | None:
    """Coerce a proof object/dict into :class:`BranchOwnershipProof`."""
    if value is None:
        return None
    if isinstance(value, BranchOwnershipProof):
        return value
    if isinstance(value, dict):
        proof_id = value.get("proof_id")
        proof_kind = value.get("proof_kind")
        trusted = value.get("trusted")
        reason = value.get("reason")
    else:
        proof_id = getattr(value, "proof_id", None)
        proof_kind = getattr(value, "proof_kind", None)
        trusted = getattr(value, "trusted", None)
        reason = getattr(value, "reason", None)
    if proof_id is None or proof_kind is None or trusted is None or reason is None:
        return None

    def _field(name: str) -> object | None:
        if isinstance(value, dict):
            return value.get(name)
        return getattr(value, name, None)

    try:
        kind = (
            proof_kind
            if isinstance(proof_kind, BranchOwnershipProofKind)
            else BranchOwnershipProofKind(str(proof_kind))
        )
        return BranchOwnershipProof(
            proof_id=str(proof_id),
            proof_kind=kind,
            trusted=bool(trusted),
            reason=str(reason),
            source_block=_maybe_int(_field("source_block")),
            branch_arm=_maybe_int(_field("branch_arm")),
            source_state=_maybe_int(_field("source_state")),
            target_state=_maybe_int(_field("target_state")),
            target_entry=_maybe_int(_field("target_entry")),
            predicate_block=_maybe_int(_field("predicate_block")),
            dispatcher_entry_block=_maybe_int(_field("dispatcher_entry_block")),
            oracle_kind=str(_field("oracle_kind") or "recon_branch_ownership"),
            evidence=dict(_field("evidence") or {}),
            payload=dict(_field("payload") or {}),
        )
    except (TypeError, ValueError):
        return None


def collect_branch_ownership_proofs(
    *,
    dag: object,
    dispatch_map: StateDispatcherMap | None = None,
    dispatcher_entry_block: int | None = None,
    trusted_opaque_provenance_kinds: frozenset[str] = (
        TRUSTED_OPAQUE_PROVENANCE_KINDS
    ),
    proof_refiner: Callable[
        [BranchOwnershipProof, object],
        BranchOwnershipProof | None,
    ] | None = None,
) -> tuple[BranchOwnershipProof, ...]:
    """Collect diagnostics-only ownership proofs for conditional DAG edges.

    First slice: classify only evidence that is already explicit and cheap:
    trusted opaque/BCF provenance, terminal return frontier edges, equivalent
    conditional arms, and unresolved arms.  Future MopTracker/Z3/native oracles
    should add stronger producers here without changing cfg/hexrays layers.
    """
    edges = tuple(getattr(dag, "edges", ()) or ())
    conditional_edges: list[tuple[int, object]] = []
    outgoing_by_source: dict[int, list[object]] = {}
    for edge_index, edge in enumerate(edges):
        source_state = _edge_state(getattr(edge, "source_key", None))
        if source_state is not None:
            outgoing_by_source.setdefault(source_state, []).append(edge)
        if _edge_kind_name(edge) in {
            "CONDITIONAL_TRANSITION",
            "CONDITIONAL_RETURN",
            "EXIT_ROUTINE",
        }:
            conditional_edges.append((edge_index, edge))

    dispatcher_entry = dispatcher_entry_block
    if dispatcher_entry is None and dispatch_map is not None:
        dispatcher_entry = int(dispatch_map.dispatcher_entry_block)

    proofs: list[BranchOwnershipProof] = []
    for edge_index, edge in conditional_edges:
        source_state = _edge_state(getattr(edge, "source_key", None))
        target_state = _edge_state(getattr(edge, "target_key", None))
        source_block = _source_anchor_int(edge, "block_serial")
        branch_arm = _source_anchor_int(edge, "branch_arm")
        target_entry = _maybe_int(getattr(edge, "target_entry_anchor", None))
        edge_kind = _edge_kind_name(edge)
        provenance_kind = _edge_provenance_kind(edge)
        proof_kind = BranchOwnershipProofKind.UNRESOLVED
        trusted = False
        reason = "branch_ownership_unresolved"
        oracle_kind = "unresolved"

        if provenance_kind in trusted_opaque_provenance_kinds:
            proof_kind = BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM
            trusted = True
            reason = f"trusted_opaque_branch_provenance:{provenance_kind}"
            oracle_kind = "explicit_opaque_provenance"
        elif edge_kind in {"CONDITIONAL_RETURN", "EXIT_ROUTINE"}:
            proof_kind = BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER
            trusted = True
            reason = "edge_kind_terminal_return_frontier"
            oracle_kind = "dag_terminal_frontier"
        elif _has_equivalent_conditional_arm(
            edge,
            outgoing_by_source.get(source_state, ()),
        ):
            proof_kind = BranchOwnershipProofKind.EQUIVALENT_STATE_ARMS
            trusted = True
            reason = "conditional_arms_share_target_state"
            oracle_kind = "dag_edge_equivalence"

        proof = BranchOwnershipProof(
            proof_id=_proof_id(
                edge_index=edge_index,
                source_block=source_block,
                branch_arm=branch_arm,
                source_state=source_state,
                target_state=target_state,
                target_entry=target_entry,
            ),
            proof_kind=proof_kind,
            trusted=trusted,
            reason=reason,
            source_block=source_block,
            branch_arm=branch_arm,
            source_state=source_state,
            target_state=target_state,
            target_entry=target_entry,
            predicate_block=source_block,
            dispatcher_entry_block=dispatcher_entry,
            oracle_kind=oracle_kind,
            evidence={
                "edge_index": edge_index,
                "edge_kind": edge_kind,
                "provenance_kind": provenance_kind,
                "outgoing_count": len(
                    outgoing_by_source.get(source_state, ())
                ),
            },
        )
        if proof_refiner is not None:
            proof = proof_refiner(proof, edge) or proof
        proofs.append(proof)
    return tuple(proofs)


def _proof_id(
    *,
    edge_index: int,
    source_block: int | None,
    branch_arm: int | None,
    source_state: int | None,
    target_state: int | None,
    target_entry: int | None,
) -> str:
    return (
        f"branch_ownership:edge={edge_index}:"
        f"src_blk={source_block}:arm={branch_arm}:"
        f"src_state={_hex_state(source_state)}:"
        f"target_state={_hex_state(target_state)}:"
        f"target_entry={target_entry}"
    )


def _edge_kind_name(edge: object) -> str:
    kind = getattr(edge, "kind", None)
    name = getattr(kind, "name", None)
    return str(name if name is not None else kind)


def _edge_state(key: object | None) -> int | None:
    if key is None:
        return None
    state = getattr(key, "state_const", None)
    if state is None:
        return None
    try:
        return int(state) & _MASK64
    except (TypeError, ValueError):
        return None


def _source_anchor_int(edge: object, attr: str) -> int | None:
    anchor = getattr(edge, "source_anchor", None)
    if anchor is None:
        return None
    return _maybe_int(getattr(anchor, attr, None))


def _edge_provenance_kind(edge: object) -> str | None:
    candidates = [
        getattr(edge, "opaque_branch_provenance_kind", None),
        getattr(edge, "provenance_kind", None),
    ]
    metadata = getattr(edge, "metadata", None)
    if isinstance(metadata, dict):
        candidates.extend((
            metadata.get("opaque_branch_provenance_kind"),
            metadata.get("provenance_kind"),
        ))
    source_anchor = getattr(edge, "source_anchor", None)
    if source_anchor is not None:
        candidates.extend((
            getattr(source_anchor, "opaque_branch_provenance_kind", None),
            getattr(source_anchor, "provenance_kind", None),
        ))
    for candidate in candidates:
        if candidate is not None:
            return str(candidate)
    return None


def _has_equivalent_conditional_arm(
    edge: object,
    siblings: list[object] | tuple[object, ...],
) -> bool:
    target_state = _edge_state(getattr(edge, "target_key", None))
    if target_state is None:
        return False
    equivalent_count = 0
    for sibling in siblings:
        if _edge_kind_name(sibling) != "CONDITIONAL_TRANSITION":
            continue
        if _edge_state(getattr(sibling, "target_key", None)) == target_state:
            equivalent_count += 1
    return equivalent_count > 1


def _maybe_int(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (TypeError, ValueError):
        return None


def _hex_state(value: int | None) -> str | None:
    if value is None:
        return None
    return f"0x{int(value) & _MASK64:016x}"


def proof_json(value: object) -> str:
    """Stable JSON helper for debugging/tests."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


__all__ = [
    "BranchOwnershipProof",
    "BranchOwnershipProofKind",
    "TRUSTED_OPAQUE_PROVENANCE_KINDS",
    "branch_ownership_proof_from_any",
    "collect_branch_ownership_proofs",
    "proof_json",
]
