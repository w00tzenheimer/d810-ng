from __future__ import annotations

import pytest

from d810.core.deobfuscation_case import (
    CaseEvidenceLevel,
    CaseFinding,
    CaseFindingKind,
    CaseVerdict,
    DeobfuscationCaseEvidence,
)
from d810.diagnostics.deobfuscation_case_repository import (
    DeobfuscationCaseEvidenceError,
)
from d810.manager.deobfuscation_case_service import (
    DeobfuscationCaseCollectionError,
    DeobfuscationCaseService,
)
from d810.manager.workbench_models import FunctionRef, RuntimeConfigRef
from d810.manager.workbench_recipe_models import FunctionPipelineOverride


class _Repository:
    def __init__(
        self,
        evidence: DeobfuscationCaseEvidence | None = None,
        error: Exception | None = None,
    ) -> None:
        self.evidence = evidence
        self.error = error
        self.calls: list[tuple[int, str | None]] = []

    def load(
        self,
        function_ea: int,
        function_fingerprint: str | None,
    ) -> DeobfuscationCaseEvidence | None:
        self.calls.append((function_ea, function_fingerprint))
        if self.error is not None:
            raise self.error
        return self.evidence


def _function(*, fingerprint: str | None = "workbench:current") -> FunctionRef:
    return FunctionRef(
        ea=0x1800020F0,
        name="target",
        fingerprint=fingerprint,
        generation=4,
    )


def _runtime() -> RuntimeConfigRef:
    return RuntimeConfigRef(
        source_name="source.json",
        source_path="/source.json",
        runtime_name="runtime.json",
        runtime_path="/runtime.json",
        mode="config-v2",
        routed=True,
        hook_mode="config-v2",
        pass_ids=("recover_dispatcher",),
    )


def _evidence() -> DeobfuscationCaseEvidence:
    return DeobfuscationCaseEvidence(
        schema_version=1,
        function_fingerprint="native:producer",
        runtime_identity="native-profile:fixture",
        run_identity="diagnostic-session:fixture",
        findings=(
            CaseFinding(
                finding_id="observation:1",
                kind=CaseFindingKind.OBSERVATION,
                summary="Native evidence recorded.",
                detail="",
                native_ea=None,
                confidence=1.0,
                provenance=("diagnostic-session:fixture",),
            ),
        ),
        verdict=CaseVerdict(
            level=CaseEvidenceLevel.C1_DISCOVERY,
            summary="Discovery evidence recorded.",
            first_blocked_obligation=None,
        ),
    )


def _saved_recipe(*, fingerprint: str | None = "workbench:current") -> FunctionPipelineOverride:
    return FunctionPipelineOverride(
        schema_version=1,
        function_ea=0x1800020F0,
        function_fingerprint=fingerprint,
        source_path="/source.json",
        runtime_path="/runtime.json",
        pass_configs_json='[{"pass":"recover_dispatcher"}]',
        updated_at=1.0,
    )


def test_saved_current_recipe_permits_direct_run_without_overwriting_case_evidence() -> None:
    evidence = _evidence()
    repository = _Repository(evidence)

    snapshot = DeobfuscationCaseService(repository).collect(
        function=_function(),
        runtime=_runtime(),
        saved_recipe=_saved_recipe(),
    )

    assert snapshot.evidence is evidence
    assert snapshot.direct_run_permitted is True
    assert "saved function recipe" in snapshot.direct_run_reason
    # The Workbench byte fingerprint and native diagnostic fingerprint use
    # different algorithms, so only the producer's own reader may bind it.
    assert repository.calls == [(0x1800020F0, None)]


def test_unknown_function_requires_build_before_direct_run() -> None:
    repository = _Repository()

    snapshot = DeobfuscationCaseService(repository).collect(
        function=_function(),
        runtime=_runtime(),
        saved_recipe=None,
    )

    assert snapshot.evidence is None
    assert snapshot.direct_run_permitted is False
    assert snapshot.direct_run_reason == "Build a strategy before running it."


def test_stale_saved_recipe_does_not_permit_direct_run() -> None:
    snapshot = DeobfuscationCaseService(_Repository(_evidence())).collect(
        function=_function(),
        runtime=_runtime(),
        saved_recipe=_saved_recipe(fingerprint="workbench:stale"),
    )

    assert snapshot.direct_run_permitted is False
    assert "Build a strategy" in snapshot.direct_run_reason


def test_malformed_diagnostic_evidence_becomes_a_collection_error() -> None:
    service = DeobfuscationCaseService(
        _Repository(error=DeobfuscationCaseEvidenceError("bad diagnostic schema"))
    )

    with pytest.raises(DeobfuscationCaseCollectionError, match="bad diagnostic schema"):
        service.collect(
            function=_function(),
            runtime=_runtime(),
            saved_recipe=None,
        )
