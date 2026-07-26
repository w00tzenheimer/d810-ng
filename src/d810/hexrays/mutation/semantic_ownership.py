"""Shared prewrite guard for committed semantic-fragment ownership."""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.native_preanalysis_session import (
    CommittedSemanticFragmentOwnership,
    SemanticFragmentBlockOwner,
)
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.ir.block_identity import (
    StableBlockIdentity,
    stable_block_identities_overlap,
    stable_block_identity_semantic_anchor,
)
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
from d810.transforms.plan import PatchPlan


@dataclass(frozen=True, slots=True)
class PatchPlanSemanticOwnershipOverlap:
    """Serial-free proof that an ordinary plan touches canonical ownership."""

    ref: NativeBlockRef | LogicalBlockRef
    identity: StableBlockIdentity
    publication: CommittedSemanticFragmentOwnership
    owner: SemanticFragmentBlockOwner

    def __post_init__(self) -> None:
        if not isinstance(self.ref, (NativeBlockRef, LogicalBlockRef)):
            raise TypeError("semantic overlap requires a portable block ref")
        if not isinstance(self.identity, StableBlockIdentity):
            raise TypeError("semantic overlap requires stable touched identity")
        if not isinstance(
            self.publication,
            CommittedSemanticFragmentOwnership,
        ):
            raise TypeError("semantic overlap requires committed publication")
        if not isinstance(self.owner, SemanticFragmentBlockOwner):
            raise TypeError("semantic overlap requires a typed block owner")
        if self.owner not in self.publication.owners:
            raise ValueError("semantic overlap owner belongs to another publication")
        if not stable_block_identities_overlap(
            self.owner.stable_identity,
            self.identity,
        ):
            raise ValueError("semantic overlap proof contains disjoint identities")

    @property
    def anchor_ea(self) -> int:
        """Return one deterministic native anchor for diagnostic correlation."""
        return stable_block_identity_semantic_anchor(self.identity)


def _portable_identity_for_ref(
    ref: NativeBlockRef | LogicalBlockRef,
    identity_index: MbaBlockIdentityIndex,
) -> StableBlockIdentity | None:
    if isinstance(ref, NativeBlockRef):
        return ref.identity
    if isinstance(ref, LogicalBlockRef):
        return identity_index.published_identity_for_logical_ref(ref)
    raise TypeError("semantic ownership preflight requires a portable block ref")


def find_patch_plan_semantic_ownership_overlap(
    plan: PatchPlan,
    identity_index: MbaBlockIdentityIndex,
    publications: tuple[CommittedSemanticFragmentOwnership, ...],
) -> PatchPlanSemanticOwnershipOverlap | None:
    """Find the first committed envelope touched by an ordinary PatchPlan."""
    if not isinstance(plan, PatchPlan):
        raise TypeError("semantic ownership guard requires a PatchPlan")
    if not isinstance(identity_index, MbaBlockIdentityIndex):
        raise TypeError("semantic ownership guard requires an identity index")
    publications = tuple(publications)
    if any(
        not isinstance(item, CommittedSemanticFragmentOwnership)
        for item in publications
    ):
        raise TypeError("semantic ownership guard requires typed publications")
    for ref, _coordinate in plan.source_coordinates:
        identity = _portable_identity_for_ref(ref, identity_index)
        if identity is None:
            continue
        for publication in publications:
            for owner in publication.owners:
                if stable_block_identities_overlap(owner.stable_identity, identity):
                    return PatchPlanSemanticOwnershipOverlap(
                        ref=ref,
                        identity=identity,
                        publication=publication,
                        owner=owner,
                    )
    return None


def format_patch_plan_semantic_ownership_overlap(
    overlap: PatchPlanSemanticOwnershipOverlap,
) -> str:
    """Describe an overlap without duplicating transaction-local plan identity."""
    if not isinstance(overlap, PatchPlanSemanticOwnershipOverlap):
        raise TypeError("semantic overlap formatting requires typed proof")
    return (
        "ordinary PatchPlan overlaps committed semantic plan "
        f"{overlap.publication.plan_id} atomic-group="
        f"{overlap.publication.atomic_group_id} operation "
        f"{overlap.owner.operation_id} source {overlap.owner.source_block_id} at "
        f"0x{overlap.anchor_ea:X}"
    )


__all__ = [
    "PatchPlanSemanticOwnershipOverlap",
    "find_patch_plan_semantic_ownership_overlap",
    "format_patch_plan_semantic_ownership_overlap",
]
