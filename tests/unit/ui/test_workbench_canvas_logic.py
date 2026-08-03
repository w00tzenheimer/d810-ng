from __future__ import annotations

import json

from d810.manager.workbench_recipe_models import (
    PassCatalogEntry,
    PipelineRecipeDraft,
    RecipeDiagnostic,
    RecipePass,
    RecipeValidation,
)
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
        transforms=(),
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


def test_projection_carries_typed_output_into_later_maturity() -> None:
    draft = _draft(
        RecipePass("item-pre", "microcode", True, "{}"),
        RecipePass("item-locopt", "dispatcher", True, "{}"),
        RecipePass("item-glbopt", "regions", True, "{}"),
    )
    catalog = (
        _entry("microcode", "MMAT_PREOPTIMIZED", outputs={"facts": ["microcode"], "evidence": []}),
        _entry(
            "dispatcher",
            "MMAT_LOCOPT",
            requires={"capabilities": [], "analyses": [], "evidence": [], "facts": {"required": ["microcode"], "optional": []}},
            outputs={"facts": ["dispatcher"], "evidence": []},
        ),
        _entry(
            "regions",
            "MMAT_GLBOPT1",
            requires={"capabilities": [], "analyses": [], "evidence": [], "facts": {"required": ["dispatcher"], "optional": []}},
            outputs={"facts": ["regions"], "evidence": []},
        ),
    )

    view = project_maturity_canvas(draft, catalog, _validation(), case=None)

    assert [stage.stage_id for stage in view.maturities] == [
        "MMAT_PREOPTIMIZED",
        "MMAT_LOCOPT",
        "MMAT_GLBOPT1",
    ]
    assert {(edge.source_node_id, edge.target_node_id) for edge in view.edges} == {
        ("item-pre", "item-locopt"),
        ("item-locopt", "item-glbopt"),
    }
    assert view.nodes[1].inputs[0].artifact_type == "fact"
    assert view.nodes[1].outputs[0].artifact_type == "fact"
    carried = [node for node in view.nodes if node.state == "carried"]
    assert [(node.maturity.stage_id, node.inputs[0].label) for node in carried] == [
        ("MMAT_LOCOPT", "microcode"),
        ("MMAT_GLBOPT1", "dispatcher"),
    ]


def test_projection_reports_unknown_maturity_and_unresolved_requirement() -> None:
    draft = _draft(RecipePass("item-unknown", "unknown", True, "{}"))
    catalog = (
        _entry(
            "unknown",
            "NOT_A_MATURITY",
            requires={"capabilities": [], "analyses": [], "evidence": [], "facts": {"required": ["missing"], "optional": []}},
        ),
    )

    view = project_maturity_canvas(draft, catalog, _validation(), case=None)

    assert view.nodes[0].maturity.stage_id == "NOT_A_MATURITY"
    assert view.nodes[0].state == "blocked"
    assert any("unknown maturity" in diagnostic for diagnostic in view.diagnostics)
    assert any("unresolved requirement: fact:missing" in diagnostic for diagnostic in view.diagnostics)


def test_projection_reports_incompatible_artifact_and_cycle() -> None:
    draft = _draft(
        RecipePass("item-one", "one", True, "{}"),
        RecipePass("item-two", "two", True, "{}"),
    )
    catalog = (
        _entry(
            "one",
            "MMAT_PREOPTIMIZED",
            requires={"capabilities": [], "analyses": [], "evidence": [], "facts": {"required": ["later"], "optional": []}},
            outputs={"facts": ["shared"], "evidence": []},
        ),
        _entry(
            "two",
            "MMAT_LOCOPT",
            requires={"capabilities": [], "analyses": [], "evidence": ["shared"], "facts": {"required": ["shared"], "optional": []}},
            outputs={"facts": ["later"], "evidence": []},
        ),
    )

    view = project_maturity_canvas(draft, catalog, _validation(), case=None)

    assert any("incompatible artifact: evidence:shared" in diagnostic for diagnostic in view.diagnostics)
    assert any("cycle: item-one -> item-two -> item-one" in diagnostic for diagnostic in view.diagnostics)
