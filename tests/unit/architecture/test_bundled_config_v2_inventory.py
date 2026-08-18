"""Repository inventory for bundled config-v2 project presets.

This test deliberately keeps the bundled JSON policy explicit.  The top-level
``conf`` directory contains both project presets and research data; a broad
``*.json`` exclusion would allow a new project to escape the v2 gate.  The
allowlist below is therefore the reviewable boundary for runtime projects,
fixture-only projects, and files that are intentionally not projects.
"""

from __future__ import annotations

import json
from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.passes.config_v2_hook_runtime import compile_config_v2_hook_schedule
from d810.passes.pipeline_config_parser import require_config_v2_project


CONF_DIR = Path(__file__).resolve().parents[3] / "src" / "d810" / "conf"

# These are the exact canonical project basenames from the migration matrix.
MAPPED_BUNDLED_PROJECTS = frozenset(
    {
        "bogus_loops.json",
        "default.json",
        "default_indirect_resolution.json",
        "default_instruction_only.json",
        "default_unflattening_approov.json",
        "default_unflattening_approov_s1a.json",
        "default_unflattening_ollvm.json",
        "default_unflattening_tigress_engine.json",
        "default_unflattening_tigress_engine_transition_facts.json",
        "default_unflattening_tigress_indirect.json",
        "eidolon.json",
        "example_hodur.json",
        "example_libobfuscated.json",
        "example_libobfuscated_abc.json",
        "example_libobfuscated_no_fixprecedessor.json",
        "flatfold.json",
        "hodur_flag2.json",
        "hodur_flag2_s1a.json",
        "hodur_flag2_with_fcp.json",
        "hodur_glbopt2_only.json",
        "identity_call.json",
    }
)

STANDALONE_BUNDLED_PROJECTS = frozenset(
    {
        "eidolon_v3_const_solve.json",
        "eidolon_v4_const_simplify_solve.json",
    }
)

FIXTURE_ONLY_BUNDLED_PROJECTS = frozenset(
    {
        "dead_store_elimination_fixture.json",
        "hodur_flag2_s1a_fixture_constant_simplification.json",
    }
)

CANONICAL_BUNDLED_PROJECTS = (
    MAPPED_BUNDLED_PROJECTS
    | STANDALONE_BUNDLED_PROJECTS
    | FIXTURE_ONLY_BUNDLED_PROJECTS
)

# Research/configuration data is intentionally not a runtime project preset.
# Each entry is named here rather than hidden behind a prefix/glob so adding a
# new JSON file requires an explicit inventory decision.
EXCLUDED_NON_PROJECT_JSON = frozenset(
    {
        "options.json",
        "egglog_add_spike.json",
        "egglog_mba_families_spike.json",
        "mba_compiler_shape_catalogue.json",
        "mba_compiler_shape_egglog.json",
        "mba_compiler_shape_egglog_degree2.json",
        "mba_compiler_shape_egglog_profile.json",
        "mba_portfolio_deep.json",
        "mba_portfolio_spike.json",
        "mba_portfolio_telemetry_3ms.json",
    }
)


def bundled_runtime_projects() -> tuple[Path, ...]:
    """Return every checked-in top-level bundled runtime project.

    Any top-level JSON file must be classified explicitly above or this
    inventory fails closed.
    """

    excluded = EXCLUDED_NON_PROJECT_JSON
    actual = frozenset(path.name for path in CONF_DIR.glob("*.json") if path.name not in excluded)
    assert actual == CANONICAL_BUNDLED_PROJECTS, (
        "bundled conf inventory changed; classify every top-level JSON file "
        f"explicitly (missing={sorted(CANONICAL_BUNDLED_PROJECTS - actual)}, "
        f"unexpected={sorted(actual - CANONICAL_BUNDLED_PROJECTS)})"
    )
    return tuple(CONF_DIR / name for name in sorted(actual))


def test_bundled_runtime_projects_are_canonical_v2() -> None:
    for path in bundled_runtime_projects():
        document = json.loads(path.read_text(encoding="utf-8"))
        assert "canary" not in path.name
        description = str(document.get("description", "")).lower()
        assert not any(
            marker in description
            for marker in ("canary", "shadow", "legacy source", "alternate runtime")
        )
        assert not document.get("ins_rules")
        assert not document.get("blk_rules")
        additional = document.get("additional_configuration")
        assert isinstance(additional, dict)
        assert "pipeline_v2_mode" not in additional
        assert "config_v2_" + "canary" not in additional
        assert additional.get("pipeline_v2")

        project = ProjectConfiguration.from_file(path)
        configs = require_config_v2_project(project)
        assert configs
        schedule = compile_config_v2_hook_schedule(project)
        assert schedule.configured_pass_ids == tuple(config.pass_id for config in configs)
