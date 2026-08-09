from __future__ import annotations

import json

from d810.core.deobfuscation_case import (
    CaseEvidenceLevel,
    CaseFinding,
    CaseFindingKind,
    CaseVerdict,
    DeobfuscationCaseEvidence,
    DeobfuscationCaseSnapshot,
    StrategyWorkflowStage,
)
from d810.core.pass_editor_spec import PassEditorSpec
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
from d810.ui import workbench_canvas_logic as canvas_logic
from d810.ui.workbench_canvas_logic import project_maturity_canvas, typed_port_lines
from d810.ui.workbench_canvas_models import CanvasMaturity, CanvasNode, CanvasPort


def _entry(
    pass_id: str,
    maturity: str,
    *,
    requires: dict[str, object] | None = None,
    outputs: dict[str, object] | None = None,
    workflow_stage: StrategyWorkflowStage = StrategyWorkflowStage.CANONICAL_PIPELINE,
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
        transform_ids=(),
        stage_ids=(),
        configured=True,
        editor_spec=PassEditorSpec.summary(),
        workflow_stage=workflow_stage,
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
    blocked_obligation: str | None,
    pass_id: str | None = None,
    evidence_token: str | None = None,
) -> DeobfuscationCaseSnapshot:
    detail = "Produced by the native evidence pass."
    if pass_id is not None and evidence_token is not None:
        detail = json.dumps(
            {
                "pass_id": pass_id,
                "evidence_token": evidence_token,
                "maturity": "ir.canonical",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
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
                    detail=detail,
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


def test_typed_port_inspection_distinguishes_input_and_output_contracts() -> None:
    node = CanvasNode(
        node_id="resolve",
        pass_id="resolve-native-indirect-transfers",
        label="Resolve native indirect transfers",
        maturity=CanvasMaturity("ir.canonical", "Canonical", 0),
        inputs=(CanvasPort("capability:frontend", "frontend", "capability", "input"),),
        outputs=(
            CanvasPort("evidence:ir.branch_target", "ir.branch_target", "evidence", "output"),
            CanvasPort("fact:transfer", "transfer", "fact", "output"),
        ),
        state="ready",
        detail="{}",
    )

    assert typed_port_lines(node, "input") == ("capability: frontend",)
    assert typed_port_lines(node, "output") == (
        "evidence: ir.branch_target",
        "fact: transfer",
    )


def test_compact_node_inspection_summarizes_contract_and_hides_raw_json_by_default() -> (
    None
):
    node = CanvasNode(
        node_id="simplify",
        pass_id="constant-simplification",
        label="Simplify constants",
        maturity=CanvasMaturity("any", "Any maturity", -1),
        inputs=(CanvasPort("fact:memory", "memory", "fact", "input"),),
        outputs=(CanvasPort("fact:constant", "constant", "fact", "output"),),
        state="ready",
        detail=json.dumps(
            {
                "pass": "constant-simplification",
                "runtime": {
                    "backend_route": "mutation_backend",
                    "safety": {"policy": "default"},
                    "scope": "function",
                },
            },
            sort_keys=True,
        ),
        workflow_stage_label="Frontend normalization",
    )
    summarise = getattr(canvas_logic, "compact_canvas_node_inspection_lines", None)

    assert callable(summarise)
    compact = summarise(
        node,
        {"allow_executable_readonly": False},
        (),
    )
    raw = summarise(
        node,
        {"allow_executable_readonly": False},
        (),
        include_raw_contract=True,
    )

    assert "Purpose: Frontend normalization" in compact
    assert "Maturity: Any maturity" in compact
    assert "Inputs" in compact
    assert "Outputs" in compact
    assert "Safety: default" in compact
    assert "Raw contract" not in compact
    assert "Raw contract" in raw
    assert node.detail in raw


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
        edge.source_node_id == "item-pre"
        and edge.target_node_id == "item-locopt"
        and edge.relation == "contract"
        for edge in view.edges
    )
    assert {
        (edge.source_node_id, edge.target_node_id)
        for edge in view.edges
        if edge.relation == "contract"
    } == {
        ("item-pre", "carry:item-pre:fact:microcode:ir.local.optimized"),
        ("carry:item-pre:fact:microcode:ir.local.optimized", "item-locopt"),
        ("item-locopt", "carry:item-locopt:fact:dispatcher:ir.global.analyzed"),
        ("carry:item-locopt:fact:dispatcher:ir.global.analyzed", "item-glbopt"),
    }
    assert {
        (edge.source_node_id, edge.target_node_id)
        for edge in view.edges
        if edge.relation == "sequence"
    } == {
        ("item-pre", "item-locopt"),
        ("item-locopt", "item-glbopt"),
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
            PipelineConfig(pass_id="jump-fixer"),
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
            pass_id="producer",
            evidence_token=finding_id,
        ),
    )

    nodes = {node.node_id: node for node in view.nodes}
    assert nodes["item-producer"].state == "evidence_produced"
    assert finding_id in nodes["item-producer"].detail
    assert "0x401020" in nodes["item-producer"].detail
    assert nodes["item-consumer"].state == "blocked"
    assert blocked_obligation in nodes["item-consumer"].detail
    assert nodes["item-unrelated"].state == "ready"


def test_case_evidence_requires_exact_pass_and_output_token_provenance() -> None:
    evidence_token = "ir.branch_target"
    draft = _draft(
        RecipePass("item-producer", "producer", True, "{}"),
        RecipePass("item-same-token", "same-token", True, "{}"),
    )
    catalog = (
        _entry(
            "producer",
            "ir.canonical",
            outputs={"facts": [], "evidence": [evidence_token]},
        ),
        _entry(
            "same-token",
            "ir.canonical",
            outputs={"facts": [], "evidence": [evidence_token]},
        ),
    )
    case = DeobfuscationCaseSnapshot(
        evidence=DeobfuscationCaseEvidence(
            schema_version=1,
            function_fingerprint="sha256:canvas",
            runtime_identity="ida:9.3",
            run_identity="run:canvas",
            findings=(
                CaseFinding(
                    finding_id="pass-contract-evidence:7:0",
                    kind=CaseFindingKind.PORTABLE_EVIDENCE,
                    summary="Anchored branch-target evidence",
                    detail=json.dumps(
                        {
                            "pass_id": "producer",
                            "evidence_token": evidence_token,
                            "maturity": "ir.canonical",
                            "evidence_generation": 3,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    native_ea=0x401020,
                    confidence=1.0,
                    provenance=("lifecycle:7",),
                ),
            ),
            verdict=CaseVerdict(
                level=CaseEvidenceLevel.C1_DISCOVERY,
                summary="One finding is available.",
                first_blocked_obligation=None,
            ),
        ),
        strategy=None,
        direct_run_permitted=False,
        direct_run_reason="A required obligation is blocked.",
    )

    view = project_maturity_canvas(draft, catalog, _validation(), case)
    nodes = {node.node_id: node for node in view.nodes}

    assert nodes["item-producer"].state == "evidence_produced"
    assert nodes["item-same-token"].state == "ready"


def test_receipted_hook_evidence_is_a_readonly_automatic_canvas_node() -> None:
    evidence_token = "ir.branch_target"
    draft = _draft(RecipePass("item-consumer", "consumer", True, "{}"))
    catalog = (
        _entry(
            "consumer",
            "ir.local.optimized",
            requires={
                "capabilities": [],
                "analyses": [],
                "evidence": [evidence_token],
                "facts": {"required": [], "optional": []},
            },
        ),
    )
    case = _case(
        finding_id="pass-contract-evidence:7:0",
        finding_ea=0x401020,
        blocked_obligation=None,
        pass_id="resolve_native_indirect_transfers",
        evidence_token=evidence_token,
    )

    view = project_maturity_canvas(draft, catalog, _validation(), case)
    automatic = next(
        node
        for node in view.nodes
        if node.pass_id == "resolve_native_indirect_transfers"
    )

    assert automatic.node_id.startswith("automatic:ir.canonical:")
    assert automatic.state == "evidence_produced"
    assert automatic.inputs == ()
    assert [(port.artifact_type, port.label) for port in automatic.outputs] == [
        ("evidence", evidence_token)
    ]
    assert automatic.workflow_stage_label == "Automatic hook evidence"
    assert "read-only" in automatic.detail
    assert any(
        edge.source_node_id == automatic.node_id
        and edge.target_node_id.startswith("carry:")
        and edge.kind == "evidence"
        for edge in view.edges
    )


def test_projection_groups_nodes_by_display_only_strategy_stage_within_maturity() -> None:
    draft = _draft(
        RecipePass("recover", "recover-dispatcher", True, "{}"),
        RecipePass("lower", "lower-state-machine", True, "{}"),
    )
    catalog = (
        _entry(
            "recover-dispatcher",
            "ir.local.optimized",
            workflow_stage=StrategyWorkflowStage.CANONICAL_ANALYSIS,
        ),
        _entry(
            "lower-state-machine",
            "ir.local.optimized",
            workflow_stage=StrategyWorkflowStage.CANONICAL_TRANSFORM,
        ),
    )

    view = project_maturity_canvas(draft, catalog, _validation(), case=None)

    assert [
        (group.maturity_id, group.strategy_stage_id, group.node_ids)
        for group in view.subgraphs
    ] == [
        ("ir.local.optimized", "canonical_analysis", ("recover",)),
        ("ir.local.optimized", "canonical_transform", ("lower",)),
    ]
    assert view.nodes[0].workflow_stage_label == "Canonical analysis"
    assert [edge.relation for edge in view.edges] == ["sequence"]
    assert view.diagnostics == ()


def test_carried_artifacts_are_grouped_as_explanatory_nodes() -> None:
    draft = _draft(
        RecipePass("producer", "producer", True, "{}"),
        RecipePass("consumer", "consumer", True, "{}"),
    )
    catalog = (
        _entry(
            "producer",
            "ir.canonical",
            outputs={"facts": ["state"], "evidence": []},
        ),
        _entry(
            "consumer",
            "ir.global.analyzed",
            requires={
                "capabilities": [],
                "analyses": [],
                "evidence": [],
                "facts": {"required": ["state"], "optional": []},
            },
        ),
    )

    view = project_maturity_canvas(draft, catalog, _validation(), case=None)

    assert any(
        group.strategy_stage_id == "carried-artifacts"
        and group.label == "Carried artifacts"
        and group.node_ids == ("carry:producer:fact:state:ir.global.analyzed",)
        for group in view.subgraphs
    )


def test_projection_records_one_recipe_identity_for_an_any_maturity_pass() -> None:
    draft = _draft(RecipePass("item-any", "any-pass", True, "{}"))
    catalog = (_entry("any-pass", "any"),)

    view = project_maturity_canvas(draft, catalog, _validation(), case=None)

    recipe_nodes = [node for node in view.nodes if node.provenance == "recipe"]
    assert [node.recipe_item_id for node in recipe_nodes] == ["item-any"]
    assert recipe_nodes[0].execution_maturity_ids == ("any",)


def test_projection_marks_recipe_order_edges_separately_from_contract_edges() -> None:
    draft = _draft(
        RecipePass("item-first", "first", True, "{}"),
        RecipePass("item-second", "second", True, "{}"),
    )
    catalog = (
        _entry("first", "ir.canonical"),
        _entry("second", "ir.local.optimized"),
    )

    view = project_maturity_canvas(draft, catalog, _validation(), case=None)

    assert any(
        edge.source_node_id == "item-first"
        and edge.target_node_id == "item-second"
        and edge.relation == "sequence"
        for edge in view.edges
    )
