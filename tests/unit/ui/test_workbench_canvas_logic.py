from __future__ import annotations

import json

from d810.core.deobfuscation_case import (
    CaseEvidenceLevel,
    CaseFinding,
    CaseFindingKind,
    CaseVerdict,
    DeobfuscationCaseEvidence,
    DeobfuscationCaseSnapshot,
)
from d810.manager.workbench_recipe_models import (
    PassCatalogEntry,
    PipelineRecipeDraft,
    RecipeDiagnostic,
    RecipePass,
    RecipeValidation,
)
from d810.manager.workbench_recipe_service import RecipeService
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pass_pipeline import PipelineConfig
from d810.ui.workbench_canvas_logic import project_maturity_canvas


def _entry(
    pass_id: str,
    maturity: str,
    *,
    requires: dict[str, object] | None = None,
    outputs: dict[str, object] | None = None,
) -> PassCatalogEntry:
    return PassCatalogEntry(
        pass_id=pass_id,
        display_name=pass_id.replace("-", " ").title(),
        contract_json=json.dumps(
            {
                "pass": pass_id,
                "requires": requires
                or {
                    "capabilities": [],
                    "analyses": [],
                    "evidence": [],
                    "facts": {"required": [], "optional": []},
                },
                "outputs": outputs or {"facts": [], "evidence": []},
            }
        ),
        option_template_json="{}",
        granularity="function",
        maturity=maturity,
        backend_route="mutation_backend",
        safety_policy="default",
        owned_rules=(),
        stage_ids=(),
        configured=True,
    )


def _draft(*passes: RecipePass) -> PipelineRecipeDraft:
    return PipelineRecipeDraft(
        draft_id="draft-1",
        schema_version=1,
        revision=1,
        function_ea=0x401000,
        function_fingerprint="sha256:canvas",
        workbench_generation=1,
        source_path="/source.json",
        runtime_path="/runtime.json",
        passes=passes,
    )


def _validation(*diagnostics: RecipeDiagnostic) -> RecipeValidation:
    return RecipeValidation(
        draft_id="draft-1",
        revision=1,
        satisfied=not diagnostics,
        diagnostics=diagnostics,
        manifest_json="[]",
    )


def _case(
    *,
    finding_id: str,
    finding_ea: int,
    blocked_obligation: str,
) -> DeobfuscationCaseSnapshot:
    return DeobfuscationCaseSnapshot(
        evidence=DeobfuscationCaseEvidence(
            schema_version=1,
            function_fingerprint="sha256:canvas",
            runtime_identity="ida:9.3",
            run_identity="run:canvas",
            findings=(
                CaseFinding(
                    finding_id=finding_id,
                    kind=CaseFindingKind.PORTABLE_EVIDENCE,
                    summary="Anchored branch-target evidence",
                    detail="Produced by the native evidence pass.",
                    native_ea=finding_ea,
                    confidence=1.0,
                    provenance=("run:canvas",),
                ),
            ),
            verdict=CaseVerdict(
                level=CaseEvidenceLevel.C1_DISCOVERY,
                summary="One finding is available.",
                first_blocked_obligation=blocked_obligation,
            ),
        ),
        strategy=None,
        direct_run_permitted=False,
        direct_run_reason="A required obligation is blocked.",
    )


def test_projection_carries_typed_output_into_later_maturity() -> None:
    draft = _draft(
        RecipePass("item-pre", "microcode", True, "{}"),
        RecipePass("item-locopt", "dispatcher", True, "{}"),
        RecipePass("item-glbopt", "regions", True, "{}"),
    )
    catalog = (
        _entry(
            "microcode",
            "ir.canonical",
            outputs={"facts": ["microcode"], "evidence": []},
        ),
        _entry(
            "dispatcher",
            "ir.local.optimized",
            requires={
                "capabilities": [],
                "analyses": [],
                "evidence": [],
                "facts": {"required": ["microcode"], "optional": []},
            },
            outputs={"facts": ["dispatcher"], "evidence": []},
        ),
        _entry(
            "regions",
            "ir.global.analyzed",
            requires={
                "capabilities": [],
                "analyses": [],
                "evidence": [],
                "facts": {"required": ["dispatcher"], "optional": []},
            },
            outputs={"facts": ["regions"], "evidence": []},
        ),
    )

    view = project_maturity_canvas(draft, catalog, _validation(), case=None)

    assert [stage.stage_id for stage in view.maturities] == [
        "ir.canonical",
        "ir.local.optimized",
        "ir.global.analyzed",
    ]
    assert not any(
        edge.source_node_id == "item-pre" and edge.target_node_id == "item-locopt"
        for edge in view.edges
    )
    assert {(edge.source_node_id, edge.target_node_id) for edge in view.edges} == {
        ("item-pre", "carry:item-pre:fact:microcode:ir.local.optimized"),
        ("carry:item-pre:fact:microcode:ir.local.optimized", "item-locopt"),
        ("item-locopt", "carry:item-locopt:fact:dispatcher:ir.global.analyzed"),
        ("carry:item-locopt:fact:dispatcher:ir.global.analyzed", "item-glbopt"),
    }
    assert view.nodes[1].inputs[0].artifact_type == "fact"
    assert view.nodes[1].outputs[0].artifact_type == "fact"
    carried = [node for node in view.nodes if node.state == "carried"]
    assert [(node.maturity.stage_id, node.inputs[0].label) for node in carried] == [
        ("ir.local.optimized", "microcode"),
        ("ir.global.analyzed", "dispatcher"),
    ]


def test_projection_reports_unknown_maturity_and_unresolved_requirement() -> None:
    draft = _draft(RecipePass("item-unknown", "unknown", True, "{}"))
    catalog = (
        _entry(
            "unknown",
            "NOT_A_MATURITY",
            requires={
                "capabilities": [],
                "analyses": [],
                "evidence": [],
                "facts": {"required": ["missing"], "optional": []},
            },
        ),
    )

    view = project_maturity_canvas(draft, catalog, _validation(), case=None)

    assert view.nodes[0].maturity.stage_id == "NOT_A_MATURITY"
    assert view.nodes[0].state == "blocked"
    assert any("unknown maturity" in diagnostic for diagnostic in view.diagnostics)
    assert any(
        "unresolved requirement: fact:missing" in diagnostic
        for diagnostic in view.diagnostics
    )


def test_projection_reports_incompatible_artifact_and_rejects_later_or_self_producers() -> (
    None
):
    draft = _draft(
        RecipePass("item-one", "one", True, "{}"),
        RecipePass("item-two", "two", True, "{}"),
        RecipePass("item-self", "self", True, "{}"),
    )
    catalog = (
        _entry(
            "one",
            "ir.canonical",
            requires={
                "capabilities": [],
                "analyses": [],
                "evidence": [],
                "facts": {"required": ["later"], "optional": []},
            },
            outputs={"facts": ["shared"], "evidence": []},
        ),
        _entry(
            "two",
            "ir.local.optimized",
            requires={
                "capabilities": [],
                "analyses": [],
                "evidence": ["shared"],
                "facts": {"required": ["shared"], "optional": []},
            },
            outputs={"facts": ["later"], "evidence": []},
        ),
        _entry(
            "self",
            "ir.global.analyzed",
            requires={
                "capabilities": [],
                "analyses": [],
                "evidence": [],
                "facts": {"required": ["self"], "optional": []},
            },
            outputs={"facts": ["self"], "evidence": []},
        ),
    )

    view = project_maturity_canvas(draft, catalog, _validation(), case=None)

    assert any(
        "incompatible artifact: evidence:shared" in diagnostic
        for diagnostic in view.diagnostics
    )
    assert any(
        "out-of-order requirement: fact:later" in diagnostic
        for diagnostic in view.diagnostics
    )
    assert any(
        "out-of-order requirement: fact:self" in diagnostic
        for diagnostic in view.diagnostics
    )
    assert not any(edge.source_node_id == edge.target_node_id for edge in view.edges)


def test_projection_accepts_actual_recipe_service_portable_maturity_values() -> None:
    service = RecipeService(operational_config_v2_pass_registry())
    draft = service.create_draft(
        function_ea=0x401000,
        function_fingerprint="sha256:canvas",
        workbench_generation=1,
        source_path="/source.json",
        runtime_path="/runtime.json",
        configs=(
            PipelineConfig(pass_id="jump-fixer", options={"legacy_rule": "JumpFixer"}),
            PipelineConfig(pass_id="recover_dispatcher"),
        ),
    )
    validation = RecipeValidation(
        draft_id=draft.draft_id,
        revision=draft.revision,
        satisfied=True,
        diagnostics=(),
        manifest_json="[]",
    )

    view = project_maturity_canvas(draft, service.catalog(), validation, case=None)

    assert [stage.stage_id for stage in view.maturities] == [
        "any",
        "ir.global.analyzed",
    ]
    assert not any("unknown maturity" in diagnostic for diagnostic in view.diagnostics)


def test_case_evidence_marks_only_the_exact_producer_and_blocked_consumer() -> None:
    finding_id = "ir.branch_target:0x401020"
    blocked_obligation = "semantic_output_verification:0x401080"
    draft = _draft(
        RecipePass("item-producer", "producer", True, "{}"),
        RecipePass("item-consumer", "consumer", True, "{}"),
        RecipePass("item-unrelated", "unrelated", True, "{}"),
    )
    catalog = (
        _entry(
            "producer",
            "ir.canonical",
            outputs={"facts": [], "evidence": [finding_id]},
        ),
        _entry(
            "consumer",
            "ir.global.analyzed",
            requires={
                "capabilities": [],
                "analyses": [],
                "evidence": [blocked_obligation],
                "facts": {"required": [], "optional": []},
            },
        ),
        _entry(
            "unrelated",
            "ir.global.analyzed",
            requires={
                "capabilities": [],
                "analyses": [],
                "evidence": ["different-obligation"],
                "facts": {"required": [], "optional": []},
            },
        ),
    )

    view = project_maturity_canvas(
        draft,
        catalog,
        _validation(),
        _case(
            finding_id=finding_id,
            finding_ea=0x401020,
            blocked_obligation=blocked_obligation,
        ),
    )

    nodes = {node.node_id: node for node in view.nodes}
    assert nodes["item-producer"].state == "evidence_produced"
    assert finding_id in nodes["item-producer"].detail
    assert "0x401020" in nodes["item-producer"].detail
    assert nodes["item-consumer"].state == "blocked"
    assert blocked_obligation in nodes["item-consumer"].detail
    assert nodes["item-unrelated"].state == "ready"
