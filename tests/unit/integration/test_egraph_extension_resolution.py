"""Declaration/activation boundary regressions for optional e-graph rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendManifest,
    BackendRegistry,
    BackendSpec,
)
from d810.passes.config_v2_hook_runtime import (
    compile_config_v2_hook_schedule as pipeline_v2_hook_activation,
)
from d810.passes.pass_pipeline import PipelineConfigError


def test_declaration_resolution_never_imports_runtime_or_rule_module(
    tmp_path, monkeypatch
):
    runtime_marker = tmp_path / "runtime.marker"
    rule_marker = tmp_path / "rule.marker"
    module_name = "task16_declaration_only_rule"
    (tmp_path / f"{module_name}.py").write_text(
        f"from pathlib import Path\nPath({str(rule_marker)!r}).write_text('imported')\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    def provides():
        runtime_marker.write_text("loaded", encoding="utf-8")
        return object()

    manifest = BackendManifest(
        name="egglog",
        api_version=PLUGIN_API_VERSION,
        provides=provides,
        implements={"mba-egraph": "EgglogOptimizer"},
    )
    registry = BackendRegistry(
        source=lambda: (
            BackendSpec(
                name="egglog",
                origin="declaration-only",
                load_manifest=lambda: manifest,
            ),
        ),
    )

    candidates = registry.implementation_candidates_for("mba-egraph")

    assert len(candidates) == 1
    assert candidates[0].backend_origin == "declaration-only"
    assert candidates[0].rule_modules == ()
    assert not runtime_marker.exists()
    assert not rule_marker.exists()


def test_mba_solve_rejects_ambiguous_compatible_declarations(monkeypatch):
    """The API-1 resolver rejects more than one compatible provider."""

    import d810.backends as backends

    first_manifest = BackendManifest(
        name="solver-a",
        api_version=PLUGIN_API_VERSION,
        provides=lambda: object(),
        implements={"mba-solve": "FirstSolver"},
    )
    second_manifest = BackendManifest(
        name="solver-b",
        api_version=PLUGIN_API_VERSION,
        provides=lambda: object(),
        implements={"mba-solve": "SecondSolver"},
    )
    registry = BackendRegistry(
        source=lambda: (
            BackendSpec(
                name="solver-a",
                origin="first-solver-origin",
                load_manifest=lambda: first_manifest,
            ),
            BackendSpec(
                name="solver-b",
                origin="second-solver-origin",
                load_manifest=lambda: second_manifest,
            ),
        ),
    )
    monkeypatch.setattr(backends, "registry", lambda: registry)

    with pytest.raises(PipelineConfigError, match="ambiguous"):
        pipeline_v2_hook_activation(
            ProjectConfiguration(
                path=Path("task16-mba-solve.json"),
                additional_configuration={
                    "pipeline_v2": [
                        {
                            "pass_id": "mba-solve",
                            "options": {"max_leaves": 4, "require_proof": True},
                        }
                    ],
                },
            )
        )
