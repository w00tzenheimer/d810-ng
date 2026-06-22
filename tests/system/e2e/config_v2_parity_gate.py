"""Reusable runtime parity gate for explicit config-v2 projects."""
from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

import idaapi
import idc

from d810.core.config import ProjectConfiguration
from d810.core.config_v2_defaults import CONFIG_V2_SUPPORTED_DEFAULTS_ENV


REPO_ROOT = Path(__file__).resolve().parents[3]
CONF_DIR = REPO_ROOT / "src" / "d810" / "conf"
REQUIRED_DIAG_TABLES = frozenset(("blocks", "snapshots"))
STABLE_DIAG_COUNT_TABLES = (
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
KNOWN_DIAG_COUNT_DRIFT_TABLES = frozenset(("fact_observations",))
FINAL_POST_D810_SNAPSHOT_LABEL = "maturity_MMAT_GLBOPT1_post_d810"


@dataclass(frozen=True)
class ConfigV2ParityRow:
    row_id: str
    legacy_config: str
    shadow_config: str
    function_name: str
    expected_pass_ids: tuple[str, ...]
    expects_state_machine: bool
    required_snapshot_label: str | None
    runtime_config: str | None = None


@dataclass(frozen=True)
class ConfigV2RunResult:
    text: str
    hook_pass_ids: tuple[str, ...]
    hook_mode: str | None
    state_machine_pass_ids: tuple[str, ...]
    state_machine_mode: str | None
    active_instruction_rules: tuple[str, ...]
    active_block_rules: tuple[str, ...]
    diag: dict[str, object]


def get_func_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def config_v2_project_from_shadow(row: ConfigV2ParityRow) -> ProjectConfiguration:
    legacy = ProjectConfiguration.from_file(CONF_DIR / row.legacy_config)
    shadow = ProjectConfiguration.from_file(CONF_DIR / row.shadow_config)
    additional_configuration = dict(legacy.additional_configuration)
    additional_configuration.update(dict(shadow.additional_configuration))
    additional_configuration["pipeline_v2_mode"] = "config-v2"
    return ProjectConfiguration(
        path=Path(f"{Path(row.shadow_config).stem}.runtime.json"),
        description=(
            f"Runtime parity test project for {row.shadow_config} generated "
            "config-v2 shadow; legacy hook rules are derived from pipeline_v2"
        ),
        ins_rules=[],
        blk_rules=[],
        additional_configuration=additional_configuration,
    )


@contextlib.contextmanager
def temporary_project(state, project: ProjectConfiguration):
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


@contextlib.contextmanager
def supported_defaults_disabled_for_baseline():
    """Collect the existing-project baseline without supported-default routing."""
    previous = os.environ.get(CONFIG_V2_SUPPORTED_DEFAULTS_ENV)
    os.environ[CONFIG_V2_SUPPORTED_DEFAULTS_ENV] = "0"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(CONFIG_V2_SUPPORTED_DEFAULTS_ENV, None)
        else:
            os.environ[CONFIG_V2_SUPPORTED_DEFAULTS_ENV] = previous


def find_state_machine_rule(state):
    for rule in state.current_blk_rules:
        if getattr(rule, "name", None) == "StateMachineCffUnflattener":
            return rule
    return None


def diag_db_path(diag_conn, *, func_ea: int) -> Path:
    diag_conn.commit()
    for row in diag_conn.execute("PRAGMA database_list"):
        if row[1] == "main" and row[2]:
            return Path(row[2])

    from d810.core.diag import find_latest_diag_db_path

    latest = find_latest_diag_db_path(func_ea)
    assert latest is not None, "config-v2 runtime parity requires a diag DB path"
    return latest


def clear_diag_dbs(func_ea: int) -> None:
    log_dir = Path("~/.idapro/logs/d810_logs").expanduser()
    if not log_dir.exists():
        return
    for path in log_dir.glob(f"{int(func_ea):016x}_*.diag.sqlite3"):
        path.unlink(missing_ok=True)


def quoted_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def diag_summary(func_ea: int) -> dict[str, object]:
    from d810.core.diag import get_diag_conn

    diag_conn = get_diag_conn(func_ea)
    assert diag_conn is not None, "config-v2 runtime parity requires a diag DB"
    path = diag_db_path(diag_conn, func_ea=func_ea)
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
            f"SELECT COUNT(*) FROM {quoted_identifier(str(table))}"
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


def stable_diag_counts(summary: dict[str, object]) -> dict[str, int]:
    counts = summary["counts"]
    assert isinstance(counts, dict)
    return {
        table: int(counts[table])
        for table in STABLE_DIAG_COUNT_TABLES
        if table in counts
    }


def diag_count_deltas(
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


def decompile_with_project(
    *,
    state,
    project_name: str,
    func_ea: int,
    pseudocode_to_string,
) -> ConfigV2RunResult:
    clear_diag_dbs(func_ea)
    with state.for_project(project_name):
        state.stats.reset()
        state.start_d810()
        cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert cfunc is not None, f"decompilation failed under {project_name}"
        text = pseudocode_to_string(cfunc.get_pseudocode())
        rule = find_state_machine_rule(state)
        return ConfigV2RunResult(
            text=text,
            hook_pass_ids=tuple(getattr(state, "last_pipeline_v2_hook_pass_ids", ())),
            hook_mode=getattr(state, "last_pipeline_v2_hook_mode", None),
            state_machine_pass_ids=(
                tuple(getattr(rule, "_last_config_v2_pass_ids", ())) if rule else ()
            ),
            state_machine_mode=(
                getattr(rule, "_last_pipeline_v2_mode", None) if rule else None
            ),
            active_instruction_rules=tuple(
                str(getattr(rule, "name", ""))
                for rule in state.current_ins_rules
            ),
            active_block_rules=tuple(
                str(getattr(rule, "name", ""))
                for rule in state.current_blk_rules
            ),
            diag=diag_summary(func_ea),
        )


def assert_diag_parity(
    *,
    legacy_diag: dict[str, object],
    config_v2_diag: dict[str, object],
    required_snapshot_label: str | None,
) -> dict[str, tuple[int | None, int | None]]:
    diag_count_delta_map = diag_count_deltas(legacy_diag, config_v2_diag)

    assert legacy_diag["tables"] == config_v2_diag["tables"]
    assert REQUIRED_DIAG_TABLES <= set(legacy_diag["tables"])
    assert stable_diag_counts(config_v2_diag) == stable_diag_counts(legacy_diag)
    assert set(diag_count_delta_map) <= KNOWN_DIAG_COUNT_DRIFT_TABLES
    assert legacy_diag["snapshot_labels"] == config_v2_diag["snapshot_labels"]
    if required_snapshot_label is not None:
        assert required_snapshot_label in legacy_diag["snapshot_labels"]
    return diag_count_delta_map


def assert_config_v2_runtime_parity(
    *,
    row: ConfigV2ParityRow,
    d810_state,
    pseudocode_to_string,
    code_comparator,
):
    func_ea = get_func_ea(row.function_name)
    if func_ea == idaapi.BADADDR:
        pytest.skip(f"{row.function_name} not found")
    assert code_comparator is not None, "libclang required for parity metrics"

    # The unflattener records per-ea convergence while decompiling a function.
    # Run each side in a fresh D810State lifetime and execute config-v2 first so
    # the opt-in path cannot benefit from any legacy recovery side effects.
    with d810_state() as state:
        if row.runtime_config is None:
            config_v2_project = config_v2_project_from_shadow(row)
            assert config_v2_project.ins_rules == []
            assert config_v2_project.blk_rules == []
            with temporary_project(state, config_v2_project) as project_name:
                config_v2_result = decompile_with_project(
                    state=state,
                    project_name=project_name,
                    func_ea=func_ea,
                    pseudocode_to_string=pseudocode_to_string,
                )
        else:
            config_v2_project = ProjectConfiguration.from_file(
                CONF_DIR / row.runtime_config
            )
            assert config_v2_project.ins_rules == []
            assert config_v2_project.blk_rules == []
            assert (
                config_v2_project.additional_configuration["pipeline_v2_mode"]
                == "config-v2"
            )
            config_v2_result = decompile_with_project(
                state=state,
                project_name=row.runtime_config,
                func_ea=func_ea,
                pseudocode_to_string=pseudocode_to_string,
            )

    with d810_state() as state, supported_defaults_disabled_for_baseline():
        legacy_result = decompile_with_project(
            state=state,
            project_name=row.legacy_config,
            func_ea=func_ea,
            pseudocode_to_string=pseudocode_to_string,
        )

    legacy_stats = code_comparator.count_ast_statements(legacy_result.text)
    config_v2_stats = code_comparator.count_ast_statements(config_v2_result.text)
    diag_count_delta_map = diag_count_deltas(
        legacy_result.diag,
        config_v2_result.diag,
    )

    print(f"\n=== CONFIG-V2 RUNTIME PARITY: {row.row_id} ===")
    print(f"legacy_config={row.legacy_config!r} shadow={row.shadow_config!r}")
    if row.runtime_config is not None:
        print(f"runtime_config={row.runtime_config!r}")
    print(
        f"legacy_hook_mode={legacy_result.hook_mode!r} "
        f"legacy_hook_pass_ids={legacy_result.hook_pass_ids!r}"
    )
    print(
        f"config_v2_hook_mode={config_v2_result.hook_mode!r} "
        f"config_v2_hook_pass_ids={config_v2_result.hook_pass_ids!r}"
    )
    print(
        f"config_v2_state_machine_mode={config_v2_result.state_machine_mode!r} "
        "config_v2_state_machine_pass_ids="
        f"{config_v2_result.state_machine_pass_ids!r}"
    )
    print(f"legacy_stats={legacy_stats}")
    print(f"config_v2_stats={config_v2_stats}")
    print(f"legacy_active_instruction_rules={legacy_result.active_instruction_rules}")
    print(f"legacy_active_block_rules={legacy_result.active_block_rules}")
    print(
        "config_v2_active_instruction_rules="
        f"{config_v2_result.active_instruction_rules}"
    )
    print(f"config_v2_active_block_rules={config_v2_result.active_block_rules}")
    print(f"legacy_diag={legacy_result.diag}")
    print(f"config_v2_diag={config_v2_result.diag}")
    print(f"diag_count_deltas={diag_count_delta_map}")

    assert_diag_parity(
        legacy_diag=legacy_result.diag,
        config_v2_diag=config_v2_result.diag,
        required_snapshot_label=row.required_snapshot_label,
    )
    assert legacy_result.hook_pass_ids == ()
    assert legacy_result.hook_mode is None
    assert legacy_result.state_machine_pass_ids == ()
    assert config_v2_result.hook_mode == "config-v2"
    assert config_v2_result.hook_pass_ids == row.expected_pass_ids
    if row.expects_state_machine:
        assert config_v2_result.state_machine_mode == "config-v2"
        assert config_v2_result.state_machine_pass_ids == row.expected_pass_ids
    else:
        assert config_v2_result.state_machine_mode is None
        assert config_v2_result.state_machine_pass_ids == ()
    assert config_v2_stats == legacy_stats
    assert config_v2_result.text == legacy_result.text
