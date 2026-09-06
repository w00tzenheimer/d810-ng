"""The resolver session releases the route arenas its lifecycle owns.

``NativePreanalysisSessionState`` mints one runtime authority arena per
canonical semantic bundle it projects.  Those bundles are consumed much later
than they are produced, so the arena cannot be owned by the region that mints
it -- it is owned by the session, and this is where the session ends.
"""

from __future__ import annotations

import pytest

from d810.analyses.control_flow.materialized_indirect_transfer import (
    PortableStateWriteRouteEvidence,
    StateWriteRouteDeliveryKind,
    StateWriteRouteProofKind,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.analyses.control_flow.semantic_route_evidence import route_join_binding
from d810.core.runtime_identity import RuntimeJoinRejected
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    ResolverSessionState,
)
from tests.native_preanalysis import make_native_key

NATIVE_KEY = make_native_key()


def _identity(start: int, end: int, ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(start, end),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(ea,),
    )


def _published_session() -> NativePreanalysisSessionState:
    route = PortableStateWriteRouteEvidence(
        write_identity=_identity(0x40A5A0, 0x40A5B8, 0x40A5B2),
        delivery_identity=_identity(0x40A5B8, 0x40A5CD, 0x40A5C8),
        source_write_ea=0x40A5B2,
        delivery_ea=0x40A5C8,
        delivery_region_start_ea=0x40A5B8,
        delivery_region_end_ea=0x40A5CD,
        corridor_instruction_eas=(0x40A5B2, 0x40A5B8, 0x40A5C2, 0x40A5C8),
        state_var_reg=16,
        state_constant=0xABB95547,
        target_identity=_identity(0x40BECC, 0x40BED0, 0x40BECC),
        target_ea=0x40BECC,
        authority_transfer_ea=None,
        preserved_call_instruction_eas=(),
        proof_kind=StateWriteRouteProofKind.STATE_ASSIGNMENT,
        delivery_kind=StateWriteRouteDeliveryKind.DIRECT_TARGET,
    )
    state = NativePreanalysisSessionState()
    assert state.merge_state_write_routes(NATIVE_KEY, (route,))
    assert state._fragment_publication_mark_normalization_staged()
    assert state._fragment_publication_mark_normalization_validated()
    assert state._fragment_publication_mark_normalization_published_and_postvalidated()
    return state


def test_releasing_live_bindings_ends_the_session_route_authority() -> None:
    native_preanalysis = _published_session()
    session = ResolverSessionState(
        native_preanalysis=native_preanalysis, native_key=NATIVE_KEY,
    )
    evidence = native_preanalysis.canonical_semantic_evidence_for(NATIVE_KEY)

    assert evidence is not None
    assert route_join_binding(evidence).is_live

    session.release_live_bindings()

    assert native_preanalysis._route_authority is None
    with pytest.raises(RuntimeJoinRejected, match="arena of this route bundle is closed"):
        route_join_binding(evidence)


def test_releasing_live_bindings_twice_is_idempotent() -> None:
    native_preanalysis = _published_session()
    session = ResolverSessionState(
        native_preanalysis=native_preanalysis, native_key=NATIVE_KEY,
    )
    assert native_preanalysis.canonical_semantic_evidence_for(NATIVE_KEY) is not None

    session.release_live_bindings()
    session.release_live_bindings()

    reopened = native_preanalysis.canonical_semantic_evidence_for(NATIVE_KEY)
    assert reopened is not None
    assert route_join_binding(reopened).is_live
