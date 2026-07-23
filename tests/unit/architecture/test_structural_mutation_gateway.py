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
    "hexrays/mutation/dispatcher_materialization.py": frozenset(
        {
            "apply_scheduled_deferred_modifications",
            "apply_dispatcher_deferred_modifier",
            "_downgrade_nway_goto_blocks",
        }
    ),
    "hexrays/mutation/dispatcher_residue_cleanup.py": frozenset(
        {
            "apply_dispatcher_residue_cleanup_plan",
            "apply_unreachable_region_cleanup_plan",
        }
    ),
    "hexrays/mutation/ir_translator.py": frozenset({"lower"}),
    "passes/pipeline.py": frozenset({"run"}),
    "passes/transaction_engine.py": frozenset({"apply"}),
    "backends/hexrays/mutation/backend.py": frozenset({"__init__"}),
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
}
GATEWAYLESS_NONSTRUCTURAL_ENTRYPOINTS = {
    "hexrays/mutation/detached_handler_island.py": frozenset(
        {
            "reconcile_imported_callinfo_with_live_native_calls",
            "restore_terminal_return_carriers",
            "restore_call_result_carriers",
            "restore_detached_call_result_definitions",
        }
    ),
    "hexrays/mutation/byte_emit_tail_isolation_runtime.py": frozenset(
        {"_rewrite_terminal_return_block_to_literal"}
    ),
    "optimizers/microcode/flow/flattening/engine/executor.py": frozenset(
        {"_filter_backend_unsupported_modifications"}
    ),
}


def _production_calls():
    for path in SRC_ROOT.rglob("*.py"):
        relative = path.relative_to(SRC_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                yield relative, node


def _production_calls_in_functions():
    for path in SRC_ROOT.rglob("*.py"):
        relative = path.relative_to(SRC_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        class FunctionCallVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.function_names: list[str] = []

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self.function_names.append(node.name)
                self.generic_visit(node)
                self.function_names.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Call(self, node: ast.Call) -> None:
                function_name = self.function_names[-1] if self.function_names else None
                calls.append((relative, function_name, node))
                self.generic_visit(node)

        calls: list[tuple[str, str | None, ast.Call]] = []
        FunctionCallVisitor().visit(tree)
        yield from calls


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


def test_only_nonstructural_probes_construct_gatewayless_modifiers() -> None:
    violations = []
    for relative, function_name, call in _production_calls_in_functions():
        constructor = call.func
        constructor_name = (
            constructor.id
            if isinstance(constructor, ast.Name)
            else constructor.attr
            if isinstance(constructor, ast.Attribute)
            else None
        )
        if constructor_name != "DeferredGraphModifier":
            continue
        if any(keyword.arg == "mutation_gateway" for keyword in call.keywords):
            continue
        if function_name in GATEWAYLESS_NONSTRUCTURAL_ENTRYPOINTS.get(
            relative,
            (),
        ):
            continue
        violations.append(f"{relative}:{call.lineno}:{function_name}")
    assert violations == []


def test_low_level_cfg_mutation_helpers_are_private_to_the_gateway_backend() -> None:
    violations = []
    for path in SRC_ROOT.rglob("*.py"):
        relative = path.relative_to(SRC_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "d810.hexrays.mutation.cfg_mutations"
                and relative != "hexrays/mutation/deferred_modifier.py"
            ):
                violations.append(f"{relative}:{node.lineno}")
    assert violations == []


def test_production_has_no_adapter_local_serial_maps() -> None:
    forbidden = {"serial_map", "serial_remap", "ea_to_serial"}
    violations = []
    for path in SRC_ROOT.rglob("*.py"):
        relative = path.relative_to(SRC_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            name = (
                node.id
                if isinstance(node, ast.Name)
                else node.attr
                if isinstance(node, ast.Attribute)
                else None
            )
            if name is not None and name.lstrip("_") in forbidden:
                violations.append(f"{relative}:{node.lineno}:{name}")
    assert violations == []


def test_deferred_gateway_batches_close_on_exception_and_implicit_insert() -> None:
    path = SRC_ROOT / "hexrays/mutation/deferred_modifier.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modifier_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "DeferredGraphModifier"
    )
    functions = {
        node.name: node
        for node in modifier_class.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    apply = functions["apply"]
    apply_calls = {
        node.func.attr
        for node in ast.walk(apply)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    insertion = functions["_record_serial_insertion"]
    insertion_calls = {
        node.func.attr
        for node in ast.walk(insertion)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }

    assert "_apply" in apply_calls
    assert "_abort_open_mutation_batch" in apply_calls
    assert "commit" in insertion_calls

    apply_impl = functions["_apply"]
    receipt_lines = [
        node.lineno
        for node in ast.walk(apply_impl)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_finish_mutation_batch"
    ]
    post_loop_snapshot_lines = [
        node.lineno
        for node in ast.walk(apply_impl)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_capture_phase_snapshot"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "post_loop"
    ]
    assert min(receipt_lines) < min(post_loop_snapshot_lines)
    rollback = functions["_record_snapshot_rollback"]
    rollback_calls = {
        node.func.attr
        for node in ast.walk(rollback)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert {"abort", "begin_batch", "record_unknown_sdk_operation", "commit"} <= (
        rollback_calls
    )


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
