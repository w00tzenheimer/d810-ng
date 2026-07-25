"""Test-owned live MBA mutation gateways for system/runtime fixtures."""

from __future__ import annotations

from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.fragment_publication_lifecycle import (
    FragmentPublicationLifecycleAuthority,
)
from d810.hexrays.mutation.mba_mutation_events import MbaMutationGateway
from d810.manager.fragment_publication_lifecycle import (
    SessionFragmentPublicationLifecycleAuthority,
)
from d810.transforms.fragment_plan import FragmentPublicationPurpose
from tests.native_preanalysis import make_native_key


def _make_mutation_gateway(
    mba,
    *,
    generation: int,
    snapshot_id: str | None,
    maturity: int | None,
    lifecycle_authority: FragmentPublicationLifecycleAuthority | None,
    session_id: str | None = None,
) -> MbaMutationGateway:
    native_key = make_native_key()
    mba = object() if mba is None else mba
    session_id = session_id or f"test-mutation:{id(mba):x}"
    evidence_generation = (
        0
        if lifecycle_authority is None
        else int(lifecycle_authority.evidence_generation)
    )
    maturity = int(getattr(mba, "maturity", 0) or 0) if maturity is None else int(maturity)
    if callable(getattr(mba, "get_mblock", None)):
        index = MbaBlockIdentityIndex.from_mba(
            mba,
            generation=generation,
            evidence_generation=evidence_generation,
            maturity=maturity,
            snapshot_id=snapshot_id,
            native_key=native_key,
            session_id=session_id,
        )
    else:
        index = MbaBlockIdentityIndex.from_bindings(
            generation=generation,
            evidence_generation=evidence_generation,
            maturity=maturity,
            snapshot_id=snapshot_id,
            native_key=native_key,
            bindings=(),
            session_id=session_id,
        )
        index.ensure_serial_space(int(getattr(mba, "qty", 0) or 0))
    return MbaMutationGateway(
        native_key=native_key,
        generation=generation,
        session_id=session_id,
        function_ea=int(getattr(mba, "entry_ea", 0) or 0),
        maturity=maturity,
        identity_index=index,
        lifecycle_authority=lifecycle_authority,
    )


def make_mutation_gateway(
    mba=None,
    *,
    generation: int = 0,
    snapshot_id: str | None = None,
    maturity: int | None = None,
    session_id: str | None = None,
) -> MbaMutationGateway:
    """Build an explicit non-fragment gateway for a runtime-test MBA."""
    return _make_mutation_gateway(
        mba,
        generation=generation,
        snapshot_id=snapshot_id,
        maturity=maturity,
        lifecycle_authority=None,
        session_id=session_id,
    )


def make_fragment_publication_gateway(
    mba,
    *,
    publication_purpose: FragmentPublicationPurpose,
    generation: int = 0,
) -> MbaMutationGateway:
    """Build a gateway with a coherent lifecycle for fragment publication."""
    if not isinstance(publication_purpose, FragmentPublicationPurpose):
        raise TypeError("fragment publication purpose must be typed")
    lifecycle = NativePreanalysisSessionState(evidence_generation=1)
    if publication_purpose is FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING:
        lifecycle._fragment_publication_mark_normalization_staged()
        lifecycle._fragment_publication_mark_normalization_validated()
        lifecycle._fragment_publication_mark_normalization_published_and_postvalidated()
        lifecycle.mark_canonical_semantic_plan_ready()
    authority = SessionFragmentPublicationLifecycleAuthority(
        native_key=make_native_key(),
        state=lifecycle,
    )
    return _make_mutation_gateway(
        mba,
        generation=generation,
        snapshot_id=None,
        maturity=None,
        lifecycle_authority=authority,
    )


__all__ = ["make_fragment_publication_gateway", "make_mutation_gateway"]
