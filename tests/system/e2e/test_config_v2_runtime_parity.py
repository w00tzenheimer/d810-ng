"""Runtime parity evidence for supported config-v2 generated shadows."""
from __future__ import annotations

import contextlib
import os
import platform
from pathlib import Path

import pytest

import idaapi
import idc

from d810.core.config import ProjectConfiguration


_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONF_DIR = _REPO_ROOT / "src" / "d810" / "conf"
_HODUR_LEGACY_CONFIG = "hodur_glbopt2_only.json"
_HODUR_CONFIG_V2_PROJECT = "hodur_glbopt2_only.config_v2_runtime.json"
_HODUR_SPINE_PASS_IDS = (
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
)
_REQUIRED_DIAG_TABLES = frozenset(("blocks", "snapshots"))
_STABLE_DIAG_COUNT_TABLES = (
    "snapshots",
    "blocks",
    "cfg_provenance",
    "state_dispatcher_rows",
    "state_transition_dispatch_resolutions",
    "rendered_programs",
    "rendered_program_lines",
    "instructions",
    "block_observations",
    "fact_mappings",
)
_KNOWN_DIAG_COUNT_DRIFT_TABLES = frozenset(("fact_observations",))
_FINAL_POST_D810_SNAPSHOT_LABEL = "maturity_MMAT_GLBOPT1_post_d810"


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _get_func_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def _config_v2_project() -> ProjectConfiguration:
    legacy = ProjectConfiguration.from_file(_CONF_DIR / _HODUR_LEGACY_CONFIG)
    shadow = ProjectConfiguration.from_file(
        _CONF_DIR / "hodur_glbopt2_only.pipeline_v2.json"
    )
    additional_configuration = dict(legacy.additional_configuration)
    additional_configuration.update(dict(shadow.additional_configuration))
    additional_configuration["pipeline_v2_mode"] = "config-v2"
    return ProjectConfiguration(
        path=Path(_HODUR_CONFIG_V2_PROJECT),
        description=(
            "Runtime parity test project for hodur_glbopt2_only generated "
            "config-v2 shadow"
        ),
        ins_rules=list(legacy.ins_rules),
        blk_rules=list(legacy.blk_rules),
        additional_configuration=additional_configuration,
    )


@contextlib.contextmanager
def _temporary_project(state, project: ProjectConfiguration):
    """Register ``project`` in memory only; do not write user options/configs."""
    manager = state.project_manager
    name = project.path.name
    with manager._lock:
        previous = manager._projects.get(name)
        manager._projects[name] = project
    try:
        yield name
    finally:
        with manager._lock:
            if previous is None:
                manager._projects.pop(name, None)
            else:
                manager._projects[name] = previous


def _active_state_machine_rule(state):
    for rule in state.current_blk_rules:
        if getattr(rule, "name", None) == "StateMachineCffUnflattener":
            return rule
    raise AssertionError("StateMachineCffUnflattener is not active")


def _diag_db_path(diag_conn, *, func_ea: int) -> Path:
    diag_conn.commit()
    for row in diag_conn.execute("PRAGMA database_list"):
        if row[1] == "main" and row[2]:
            return Path(row[2])

    from d810.core.diag import find_latest_diag_db_path

    latest = find_latest_diag_db_path(func_ea)
    assert latest is not None, "config-v2 runtime parity requires a diag DB path"
    return latest


def _quoted_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _diag_summary(func_ea: int) -> dict[str, object]:
    from d810.core.diag import get_diag_conn

    diag_conn = get_diag_conn(func_ea)
    assert diag_conn is not None, "config-v2 runtime parity requires a diag DB"
    path = _diag_db_path(diag_conn, func_ea=func_ea)
    tables = tuple(
        row[0]
        for row in diag_conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        )
        if not str(row[0]).startswith("sqlite_")
    )
    counts: dict[str, int] = {}
    for table in tables:
        count = diag_conn.execute(
            f"SELECT COUNT(*) FROM {_quoted_identifier(str(table))}"
        ).fetchone()[0]
        counts[str(table)] = int(count)
    snapshot_labels = tuple(
        row[0]
        for row in diag_conn.execute("SELECT label FROM snapshots ORDER BY id")
    )
    return {
        "path": str(path),
        "tables": tables,
        "counts": counts,
        "snapshot_labels": snapshot_labels,
    }


def _stable_diag_counts(summary: dict[str, object]) -> dict[str, int]:
    counts = summary["counts"]
    assert isinstance(counts, dict)
    return {
        table: int(counts[table])
        for table in _STABLE_DIAG_COUNT_TABLES
        if table in counts
    }


def _diag_count_deltas(
    legacy_summary: dict[str, object], config_v2_summary: dict[str, object]
) -> dict[str, tuple[int | None, int | None]]:
    legacy_counts = legacy_summary["counts"]
    config_v2_counts = config_v2_summary["counts"]
    assert isinstance(legacy_counts, dict)
    assert isinstance(config_v2_counts, dict)
    tables = set(legacy_counts) | set(config_v2_counts)
    return {
        table: (legacy_counts.get(table), config_v2_counts.get(table))
        for table in sorted(tables)
        if legacy_counts.get(table) != config_v2_counts.get(table)
    }


def _decompile_with_project(
    *,
    state,
    project_name: str,
    func_ea: int,
    pseudocode_to_string,
) -> tuple[str, tuple[str, ...], str | None, dict[str, object]]:
    with state.for_project(project_name):
        state.stats.reset()
        state.start_d810()
        cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert cfunc is not None, f"decompilation failed under {project_name}"
        text = pseudocode_to_string(cfunc.get_pseudocode())
        rule = _active_state_machine_rule(state)
        return (
            text,
            tuple(getattr(rule, "_last_config_v2_pass_ids", ())),
            getattr(rule, "_last_pipeline_v2_mode", None),
            _diag_summary(func_ea),
        )


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestConfigV2RuntimeParity:
    """Config-v2 opt-in execution must match the legacy runtime source."""

    binary_name = _get_default_binary()

    def test_hodur_glbopt2_only_config_v2_matches_legacy(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        request,
    ):
        func_ea = _get_func_ea("hodur_func")
        if func_ea == idaapi.BADADDR:
            pytest.skip("hodur_func not found")
        assert code_comparator is not None, "libclang required for parity metrics"

        from d810.core.settings import configure_settings, reset_settings

        configure_settings(
            diag_snapshots=True,
            capture_post_maturity=idaapi.MMAT_GLBOPT1,
        )
        request.addfinalizer(reset_settings)

        with d810_state() as state:
            legacy_text, legacy_pass_ids, legacy_mode, legacy_diag = (
                _decompile_with_project(
                    state=state,
                    project_name=_HODUR_LEGACY_CONFIG,
                    func_ea=func_ea,
                    pseudocode_to_string=pseudocode_to_string,
                )
            )

        # The unflattener records per-ea convergence to avoid reprocessing the same
        # function inside one session. Use a fresh D810State lifetime so the config-v2
        # run proves runtime parity rather than exercising the convergence cache.
        with d810_state() as state:
            with _temporary_project(state, _config_v2_project()) as project_name:
                (
                    config_v2_text,
                    config_v2_pass_ids,
                    config_v2_mode,
                    config_v2_diag,
                ) = _decompile_with_project(
                    state=state,
                    project_name=project_name,
                    func_ea=func_ea,
                    pseudocode_to_string=pseudocode_to_string,
                )

        legacy_stats = code_comparator.count_ast_statements(legacy_text)
        config_v2_stats = code_comparator.count_ast_statements(config_v2_text)
        print("\n=== CONFIG-V2 RUNTIME PARITY: hodur_glbopt2_only ===")
        print(f"legacy_mode={legacy_mode!r} legacy_pass_ids={legacy_pass_ids!r}")
        print(
            f"config_v2_mode={config_v2_mode!r} "
            f"config_v2_pass_ids={config_v2_pass_ids!r}"
        )
        print(f"legacy_stats={legacy_stats}")
        print(f"config_v2_stats={config_v2_stats}")
        print(f"legacy_diag={legacy_diag}")
        print(f"config_v2_diag={config_v2_diag}")
        diag_count_deltas = _diag_count_deltas(legacy_diag, config_v2_diag)
        print(f"diag_count_deltas={diag_count_deltas}")

        assert legacy_pass_ids == ()
        assert config_v2_mode == "config-v2"
        assert config_v2_pass_ids == _HODUR_SPINE_PASS_IDS
        assert config_v2_stats == legacy_stats
        assert config_v2_text == legacy_text
        assert legacy_diag["tables"] == config_v2_diag["tables"]
        assert _REQUIRED_DIAG_TABLES <= set(legacy_diag["tables"])
        assert _stable_diag_counts(config_v2_diag) == _stable_diag_counts(
            legacy_diag
        )
        assert set(diag_count_deltas) <= _KNOWN_DIAG_COUNT_DRIFT_TABLES
        assert legacy_diag["snapshot_labels"] == config_v2_diag["snapshot_labels"]
        assert _FINAL_POST_D810_SNAPSHOT_LABEL in legacy_diag["snapshot_labels"]
