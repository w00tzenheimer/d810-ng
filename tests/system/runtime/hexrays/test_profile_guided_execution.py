"""Disposable-IDB proof that profile guidance has no native write authority."""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime, pytest.mark.hexrays]

ida_bytes = pytest.importorskip("ida_bytes")
idaapi = pytest.importorskip("idaapi")
idc = pytest.importorskip("idc")

from d810.core.execution_journal import (  # noqa: E402
    DecompilationSessionId,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    ExecutionDomain,
    ExecutionEffectRef,
)
from d810.core.execution_journal_store import ExecutionJournalStore  # noqa: E402
from d810.core.execution_profile import (  # noqa: E402
    ExecutionProfileKey,
    build_execution_profile_preview,
)
from d810.passes.profile_guidance import (  # noqa: E402
    ProfileCandidate,
    ProfileDecisionKind,
    ProfileGuidancePlanner,
    record_profile_guidance_preview,
)


def test_historical_native_success_and_user_opt_in_stay_preview_only(
    copy_of_idb, tmp_path
) -> None:
    function_ea = int(idc.get_name_ea_simple("single_iteration_simple"))
    assert function_ea != int(idaapi.BADADDR)
    before = bytes(ida_bytes.get_bytes(function_ea, 16) or b"")
    assert before

    key = ExecutionProfileKey(
        database_identity="disposable-idb-attestation",
        function_fingerprint="current-function-fingerprint",
        config_fingerprint="current-config-fingerprint",
        toolchain_fingerprint="ida-9.4+d810-runtime",
        maturity="MMAT_GLBOPT2",
        structural_shape="native-normalization-candidate",
    )
    historical = ExecutionAttempt(
        attempt_id=ExecutionAttemptId(
            DecompilationSessionId("historical-native-session"), 1
        ),
        parent_attempt_id=None,
        stage_id="native-normalize",
        domain=ExecutionDomain.NATIVE_NORMALIZATION,
        status=ExecutionAttemptStatus.COMPLETED,
        reason_code=None,
        effect_refs=(ExecutionEffectRef("native_transaction_receipt", "tx-old"),),
        elapsed_ms=1.0,
        details={
            "maturity": key.maturity,
            "structural_shape": key.structural_shape,
        },
    )
    history = build_execution_profile_preview(key, (historical,))
    preview = ProfileGuidancePlanner(enabled=True, budget_ms=1000.0).preview(
        key=key,
        candidates=(
            ProfileCandidate(
                candidate_id="native-normalize",
                stage_id="native-normalize",
                domain=ExecutionDomain.NATIVE_NORMALIZATION,
                estimated_cost_ms=1.0,
                explicit_user_selected=True,
                native_candidate=True,
            ),
        ),
        history=history,
    )

    decision = preview.decisions[0]
    assert decision.kind is ProfileDecisionKind.PREVIEW_ONLY
    assert decision.recommended is False
    assert decision.requires_live_preflight is True
    assert preview.has_execution_authority is False
    assert bytes(ida_bytes.get_bytes(function_ea, 16) or b"") == before

    session = DecompilationSessionId("live-profile-session")
    with ExecutionJournalStore(tmp_path / "execution.db") as journal:
        record_profile_guidance_preview(journal, session, preview)
        (attempt,) = journal.attempts_for_session(session)

    assert attempt.domain is ExecutionDomain.PROFILE_GUIDANCE
    assert attempt.status is ExecutionAttemptStatus.ABSTAINED
    assert attempt.reason_code == "profile_native_preview_only"
    assert attempt.effect_refs == ()
    assert bytes(ida_bytes.get_bytes(function_ea, 16) or b"") == before
