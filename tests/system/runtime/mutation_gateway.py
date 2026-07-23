"""Test-owned live MBA mutation gateways for system/runtime fixtures."""

from __future__ import annotations

from d810.analyses.control_flow.native_preanalysis_session import (
    FragmentPublicationLifecycleAuthority,
    NativePreanalysisSessionState,
)
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import MbaMutationGateway
from d810.transforms.fragment_plan import FragmentPublicationPurpose
from tests.native_preanalysis import make_native_key


def _make_mutation_gateway(
    mba,
    *,
    generation: int,
    lifecycle_authority: FragmentPublicationLifecycleAuthority | None,
) -> MbaMutationGateway:
    native_key = make_native_key()
    mba = object() if mba is None else mba
    session_id = f"test-mutation:{id(mba):x}"
    evidence_generation = (
        0
        if lifecycle_authority is None
        else int(lifecycle_authority.evidence_generation)
    )
    if callable(getattr(mba, "get_mblock", None)):
        index = MbaBlockIdentityIndex.from_mba(
            mba,
            generation=generation,
            evidence_generation=evidence_generation,
            native_key=native_key,
            session_id=session_id,
        )
    else:
        index = MbaBlockIdentityIndex.from_bindings(
            generation=generation,
            evidence_generation=evidence_generation,
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
        maturity=int(getattr(mba, "maturity", 0) or 0),
        identity_index=index,
        lifecycle_authority=lifecycle_authority,
    )


def make_mutation_gateway(mba=None, *, generation: int = 0) -> MbaMutationGateway:
    """Build an explicit non-fragment gateway for a runtime-test MBA."""
    return _make_mutation_gateway(
        mba,
        generation=generation,
        lifecycle_authority=None,
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
        lifecycle.mark_normalization_staged()
        lifecycle.mark_normalization_validated()
        lifecycle.mark_normalization_published_and_postvalidated()
        lifecycle.mark_canonical_semantic_plan_ready()
    return _make_mutation_gateway(
        mba,
        generation=generation,
        lifecycle_authority=lifecycle,
    )


__all__ = ["make_fragment_publication_gateway", "make_mutation_gateway"]
