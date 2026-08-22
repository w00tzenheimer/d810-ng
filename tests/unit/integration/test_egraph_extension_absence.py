"""Acceptance matrix for optional ``mba-egraph`` extension resolution.

These tests deliberately exercise the real declaration/probe/activation
boundaries.  The registry is injected with temporary ``BackendSpec``
declarations, rather than replacing the resolver's final answer, so each row
still proves the same path used by config-v2 startup.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.config import ProjectConfiguration
from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendManifest,
    BackendRegistry,
    BackendSpec,
    BackendStatus,
    PassImplementationAmbiguous,
    PassImplementationMissing,
    PassImplementationUnavailable,
)
from d810.passes.config_v2_hook_runtime import (
    compile_config_v2_hook_schedule as pipeline_v2_hook_activation,
)


MATRIX_ROWS = (
    "absent_unselected",
    "absent_selected",
    "incompatible_selected",
    "unavailable_selected",
    "broken_selected",
    "two_compatible_selected",
    "usable_unselected",
    "usable_selected",
)

_EGRAPH_OPTIONS = {
    "max_leaves": 4,
    "max_operator_nodes": 12,
    "max_degree": 2,
    "saturation_rounds": 5,
    "max_eclasses": 96,
    "max_enodes": 192,
    "max_rule_firings": 48,
    "cross_block_constant_preparation": True,
    "cross_block_def_use_preparation": True,
    "learned_replay_enabled": True,
    "learned_replay_max_entries": 64,
    "learned_replay_max_bytes": 1_048_576,
    "time_budget_ms": 9,
    "function_time_budget_ms": 1000,
    "residual_only": True,
    "require_proof": True,
    "collect_stage_timings": True,
    "execution_mode": "noninteractive",
    "native_proof_mode": "shadow",
    "families": ["xor", "add"],
    "maturities": ["GLOBAL_ANALYZED"],
}


def test_egglog_runtime_evidence_is_owned_by_the_extension_repository():
    """Core retains only provider-neutral hosts and extension contracts."""

    repository = Path(__file__).resolve().parents[3]
    provider_owned_paths = (
        repository / "samples/bins/hodur_egglog_probe.dll",
        repository
        / "samples/src/masm_probes/Hodur_ComplementMaskResidual.asm",
        repository / "tools/scripts/run_egglog_native_performance_ci.sh",
    )

    assert [
        path.relative_to(repository).as_posix()
        for path in provider_owned_paths
        if path.exists()
    ] == []

    assert "hodur-egglog-probe" not in (
        repository / "samples/Makefile"
    ).read_text(encoding="utf-8")
    assert "Hodur Egglog probe" not in (
        repository / "samples/src/masm/README.md"
    ).read_text(encoding="utf-8")


def _project(pass_id: str, options: dict[str, object]) -> ProjectConfiguration:
    return ProjectConfiguration(
        path=Path(f"task16-{pass_id}.json"),
        additional_configuration={
            "pipeline_v2": [{"pass_id": pass_id, "options": options}],
        },
    )


def _manifest(
    name: str,
    provides,
    *,
    origin: str,
    api_version: int = PLUGIN_API_VERSION,
    rule_modules: tuple[str, ...] = ("task16_extension_rule",),
    rule_name: str = "EgglogOptimizer",
    pass_id: str = "mba-egraph",
) -> BackendSpec:
    manifest = BackendManifest(
        name=name,
        api_version=api_version,
        provides=provides,
        rules=rule_modules,
        implements={pass_id: rule_name},
    )
    return BackendSpec(
        name=name,
        origin=origin,
        load_manifest=lambda: manifest,
    )


def _registry(specs, *, registration_lookup=None) -> BackendRegistry:
    return BackendRegistry(
        source=lambda: tuple(specs),
        registration_lookup=registration_lookup or (lambda _candidate: object()),
    )


def _rule_module(tmp_path: Path, monkeypatch, marker: Path) -> str:
    module_name = f"task16_extension_rule_{marker.stem.replace('-', '_')}"
    (tmp_path / f"{module_name}.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('imported')\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    return module_name


@pytest.mark.parametrize("row", MATRIX_ROWS, ids=MATRIX_ROWS)
def test_core_only_egraph_extension_resolution_matrix(row, tmp_path, monkeypatch):
    """Every selected/unselected extension state has an explicit outcome."""

    import d810.backends as backends

    runtime_calls: list[str] = []
    manifest_calls: list[str] = []
    marker = tmp_path / f"{row}.marker"
    module_name = _rule_module(tmp_path, monkeypatch, marker)

    def backend_object():
        runtime_calls.append(row)
        return object()

    def unavailable_backend():
        runtime_calls.append(row)

        class Unavailable:
            @staticmethod
            def d810_backend_probe():
                return "native Egglog binding is unavailable"

        return Unavailable()

    def broken_backend():
        runtime_calls.append(row)
        raise RuntimeError("native Egglog probe crashed")

    def spec(name: str, origin: str, *, api_version=PLUGIN_API_VERSION, provides=None):
        manifest_calls.append(origin)
        return BackendManifest(
            name=name,
            api_version=api_version,
            provides=backend_object if provides is None else provides,
            rules=(module_name,),
            implements={"mba-egraph": "EgglogOptimizer"},
        )

    if row in {"absent_unselected", "absent_selected"}:
        specs = ()
    elif row == "incompatible_selected":
        specs = (
            BackendSpec(
                name="egglog",
                origin="incompatible-origin",
                load_manifest=lambda: spec(
                    "egglog",
                    "incompatible-origin",
                    api_version=PLUGIN_API_VERSION + 99,
                ),
            ),
        )
    elif row == "unavailable_selected":
        specs = (
            BackendSpec(
                name="egglog",
                origin="unavailable-origin",
                load_manifest=lambda: spec(
                    "egglog", "unavailable-origin", provides=unavailable_backend
                ),
            ),
        )
    elif row == "broken_selected":
        specs = (
            BackendSpec(
                name="egglog",
                origin="broken-origin",
                load_manifest=lambda: spec(
                    "egglog", "broken-origin", provides=broken_backend
                ),
            ),
        )
    elif row == "two_compatible_selected":
        specs = (
            BackendSpec(
                name="egglog-a",
                origin="first-origin",
                load_manifest=lambda: spec("egglog-a", "first-origin"),
            ),
            BackendSpec(
                name="egglog-b",
                origin="second-origin",
                load_manifest=lambda: spec("egglog-b", "second-origin"),
            ),
        )
    else:
        specs = (
            BackendSpec(
                name="egglog",
                origin="usable-origin",
                load_manifest=lambda: spec("egglog", "usable-origin"),
            ),
        )

    registry = _registry(specs)
    monkeypatch.setattr(backends, "registry", lambda: registry)

    if row == "absent_unselected":
        activation = pipeline_v2_hook_activation(
            _project("constant-simplification", {"memory_policy": "strict"})
        )
        assert activation.configured_pass_ids == ("constant-simplification",)
        assert all(
            rule.name != "EgglogOptimizer" for rule in activation.instruction_rules
        )
        assert manifest_calls == []
        assert runtime_calls == []
        return

    if row == "absent_selected":
        with pytest.raises(PassImplementationMissing, match="install d810-egglog"):
            pipeline_v2_hook_activation(_project("mba-egraph", _EGRAPH_OPTIONS))
        assert runtime_calls == []
        return

    if row == "incompatible_selected":
        info = registry.probe("egglog")
        assert info.status is BackendStatus.INCOMPATIBLE
        assert "plugin API" in (info.reason or "")
        with pytest.raises(PassImplementationMissing, match="install d810-egglog"):
            pipeline_v2_hook_activation(_project("mba-egraph", _EGRAPH_OPTIONS))
        assert runtime_calls == []
        assert not marker.exists()
        return

    if row in {"unavailable_selected", "broken_selected"}:
        expected_status = (
            BackendStatus.UNAVAILABLE
            if row == "unavailable_selected"
            else BackendStatus.BROKEN
        )
        info = registry.probe("egglog")
        assert info.status is expected_status
        assert info.reason
        with pytest.raises(PassImplementationUnavailable):
            pipeline_v2_hook_activation(_project("mba-egraph", _EGRAPH_OPTIONS))
        assert not marker.exists()
        assert runtime_calls == [row]
        return

    if row == "two_compatible_selected":
        with pytest.raises(PassImplementationAmbiguous) as error:
            pipeline_v2_hook_activation(_project("mba-egraph", _EGRAPH_OPTIONS))
        message = str(error.value)
        assert "first-origin" in message
        assert "second-origin" in message
        assert runtime_calls == []
        assert not marker.exists()
        return

    if row == "usable_unselected":
        activation = pipeline_v2_hook_activation(
            _project("constant-simplification", {"memory_policy": "strict"})
        )
        assert activation.configured_pass_ids == ("constant-simplification",)
        assert all(
            rule.name != "EgglogOptimizer" for rule in activation.instruction_rules
        )
        assert manifest_calls == ["usable-origin", "usable-origin"]
        assert runtime_calls == []
        assert not marker.exists()
        return

    assert row == "usable_selected"
    activation = pipeline_v2_hook_activation(_project("mba-egraph", _EGRAPH_OPTIONS))
    assert activation.configured_pass_ids == ("mba-egraph",)
    assert len(activation.instruction_rules) == 1
    rule = activation.instruction_rules[0]
    assert rule.name == "EgglogOptimizer"
    assert rule.config == {
        **_EGRAPH_OPTIONS,
    }
    assert manifest_calls == ["usable-origin"] * 4
    assert runtime_calls == [row]
    assert marker.read_text(encoding="utf-8") == "imported"
