"""Static ownership guard for live Hex-Rays structural mutation."""

from __future__ import annotations

import ast
from pathlib import Path


SRC_ROOT = Path(__file__).parents[3] / "src" / "d810"
SDK_MUTATION_METHODS = frozenset(
    {
        "split_block",
        "copy_block",
        "insert_block",
        "remove_block",
        "delete_block",
        "clone_block",
    }
)
SDK_EXECUTORS = frozenset(
    {
        "hexrays/mutation/cfg_mutations.py",
        "hexrays/mutation/deferred_modifier.py",
    }
)
GATEWAY_CONSTRUCTORS = frozenset(
    {
        "hexrays/mutation/mba_mutation_events.py",
        "manager/manager.py",
    }
)
GATEWAY_REQUIRED_ENTRYPOINTS = {
    "hexrays/mutation/detached_handler_island.py": frozenset(
        {
            "_apply_boundary_port_batch",
            "_materialize_detached_snippet_templates",
            "materialize_detached_snippet_templates",
            "materialize_preopt_union_snippet_templates",
            "materialize_detached_replacement_snippet_templates",
            "redirect_live_target_predecessors",
            "materialize_detached_handler_island",
        }
    ),
    "optimizers/microcode/flow/jumps/materialized_computed_goto_island.py": (
        frozenset(
            {
                "_apply_residual_state_route_bridges",
                "_apply_detached_snippet_terminal_routes",
                "_apply_live_resolver_cut_counterparts",
                "_materialize_missing_detached_snippets",
                "_materialize_live_handler_replacements",
                "_apply_conditional_bridge_plans",
            }
        )
    ),
}


def _production_calls():
    for path in SRC_ROOT.rglob("*.py"):
        relative = path.relative_to(SRC_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                yield relative, node


def test_sdk_structural_writes_stay_in_the_gateway_backend() -> None:
    violations = []
    for relative, call in _production_calls():
        function = call.func
        if (
            isinstance(function, ast.Attribute)
            and function.attr in SDK_MUTATION_METHODS
            and relative not in SDK_EXECUTORS
        ):
            violations.append(f"{relative}:{call.lineno}:{function.attr}")
        if (
            isinstance(function, ast.Attribute)
            and function.attr in {"push_back", "_del", "remove", "clear"}
            and isinstance(function.value, ast.Attribute)
            and function.value.attr in {"succset", "predset"}
            and relative not in SDK_EXECUTORS
        ):
            violations.append(
                f"{relative}:{call.lineno}:{function.value.attr}.{function.attr}"
            )
    assert violations == []


def test_only_manager_and_gateway_create_mutation_gateways() -> None:
    violations = []
    for relative, call in _production_calls():
        if (
            isinstance(call.func, ast.Name)
            and call.func.id == "MbaMutationGateway"
            and relative not in GATEWAY_CONSTRUCTORS
        ):
            violations.append(f"{relative}:{call.lineno}")
    assert violations == []


def test_production_has_no_adapter_local_serial_maps() -> None:
    forbidden = {"serial_map", "serial_remap", "ea_to_serial"}
    violations = []
    for path in SRC_ROOT.rglob("*.py"):
        relative = path.relative_to(SRC_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in forbidden:
                violations.append(f"{relative}:{node.lineno}:{node.id}")
    assert violations == []


def test_migrated_structural_entrypoints_require_the_gateway_port() -> None:
    violations = []
    for relative, names in GATEWAY_REQUIRED_ENTRYPOINTS.items():
        path = SRC_ROOT / relative
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        found = set()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name not in names:
                continue
            found.add(node.name)
            keyword_defaults = dict(
                zip(
                    (argument.arg for argument in node.args.kwonlyargs),
                    node.args.kw_defaults,
                    strict=True,
                )
            )
            if (
                "mutation_gateway" in keyword_defaults
                and keyword_defaults["mutation_gateway"] is None
            ):
                continue
            violations.append(f"{relative}:{node.lineno}:{node.name}")
        for missing in sorted(names - found):
            violations.append(f"{relative}:missing:{missing}")
    assert violations == []
