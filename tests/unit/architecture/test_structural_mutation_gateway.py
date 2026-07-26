"""Static ownership guard for live Hex-Rays structural mutation."""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

from d810.core import typing


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


def test_patch_plan_has_no_transitional_or_raw_block_references() -> None:
    """The executable IR contains only nominal block references."""
    from d810.transforms import cfg_transaction
    from d810.transforms import plan as patch_plan

    assert not hasattr(cfg_transaction, "Snapshot" + "BlockRef")

    block_field_tokens = (
        "block",
        "serial",
        "source",
        "target",
        "pred",
        "succ",
        "anchor",
        "entry",
        "dispatcher",
    )

    def contains_raw_int(annotation: object) -> bool:
        if annotation is int:
            return True
        return any(contains_raw_int(arg) for arg in typing.get_args(annotation))

    violations: list[str] = []
    for operation_type in typing.get_args(patch_plan.PatchOperation):
        if not dataclasses.is_dataclass(operation_type):
            continue
        annotations = typing.get_type_hints(operation_type)
        for field_name, annotation in annotations.items():
            if (
                field_name != "pred_arm"
                and any(token in field_name for token in block_field_tokens)
                and contains_raw_int(annotation)
            ):
                violations.append(f"{operation_type.__name__}.{field_name}")
    assert violations == []


def test_every_plan_created_block_requires_a_plan_ref_creation_witness() -> None:
    """Creation identity is allocated by the plan, never inferred after SDK work."""
    from d810.transforms.cfg_transaction import PlanBlockRef
    from d810.transforms.plan import PatchBlockSpec

    block_id_annotation = typing.get_type_hints(PatchBlockSpec)["block_id"]
    assert block_id_annotation is PlanBlockRef

    source = (SRC_ROOT / "hexrays/ir/mba_identity_index.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    index_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "MbaBlockIdentityIndex"
    )
    reserve = next(
        node
        for node in index_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "reserve_plan_block"
    )
    reserve_calls = {
        node.func.attr
        for node in ast.walk(reserve)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert {"_create_plan_handle", "_reserve_new_proxy"} <= reserve_calls
    bind = next(
        node
        for node in index_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "bind_reserved_plan_block"
    )
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "PlanBlockCreationReceipt"
        for node in ast.walk(bind)
    )

    plan_source = (SRC_ROOT / "transforms/plan.py").read_text(encoding="utf-8")
    assert "PlanBlockRef lacks a creation specification" in (
        SRC_ROOT / "hexrays/mutation/patch_binding.py"
    ).read_text(encoding="utf-8")
    assert "block_id: PlanBlockRef" in plan_source


def test_every_production_patch_plan_compiler_call_names_exact_block_authority() -> (
    None
):
    """Executable compilation cannot degrade when serial authority is absent."""
    violations: list[str] = []
    for relative, call in _production_calls():
        function = call.func
        if not isinstance(function, ast.Name) or function.id != "compile_patch_plan":
            continue
        if relative == "transforms/plan.py":
            continue
        if not any(keyword.arg == "block_refs_by_serial" for keyword in call.keywords):
            violations.append(f"{relative}:{call.lineno}")
    assert violations == []


def test_every_production_minimal_unflatten_emit_names_complete_source_authority() -> (
    None
):
    """Minimal unflattening must preserve complete source authority."""
    required = {
        "block_refs_by_serial",
        "snapshot_id",
        "source_generation",
        "source_maturity",
    }
    violations: list[str] = []
    for relative, call in _production_calls():
        function = call.func
        if (
            not isinstance(function, ast.Name)
            or function.id != "emit_minimal_unflatten"
        ):
            continue
        if relative == "transforms/minimal_unflatten_emit.py":
            continue
        named = {keyword.arg for keyword in call.keywords}
        if missing := sorted(required - named):
            violations.append(f"{relative}:{call.lineno}:{','.join(missing)}")
    assert violations == []


def test_semantic_sdk_creation_sites_are_exhaustive_and_receipt_backed() -> None:
    """Every semantic SDK allocation is named and bound to planned authority."""
    path = SRC_ROOT / "hexrays/mutation/deferred_modifier.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modifier = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "DeferredGraphModifier"
    )
    methods = {
        node.name: node for node in modifier.body if isinstance(node, ast.FunctionDef)
    }
    sdk_names = {"copy_block_keep", "create_standalone_block"}
    creation_sites: set[tuple[str, str]] = set()
    for method_name, method in methods.items():
        if (
            "semantic" not in method_name
            and method_name != "_build_fallthrough_goto_helper"
        ):
            continue
        for call in ast.walk(method):
            if not isinstance(call, ast.Call):
                continue
            called = (
                call.func.id
                if isinstance(call.func, ast.Name)
                else call.func.attr
                if isinstance(call.func, ast.Attribute)
                else None
            )
            if called in sdk_names or called == "insert_block":
                creation_sites.add((method_name, str(called)))
    assert creation_sites == {
        ("_stage_detached_semantic_replacement", "copy_block_keep"),
        ("_stage_empty_semantic_block", "create_standalone_block"),
        ("_stage_imported_native_semantic_block", "create_standalone_block"),
        ("_build_fallthrough_goto_helper", "insert_block"),
    }

    def called_methods(name: str) -> set[str]:
        return {
            call.func.attr
            for call in ast.walk(methods[name])
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
        }

    for method_name in {
        "_stage_detached_semantic_replacement",
        "_stage_empty_semantic_block",
        "_stage_imported_native_semantic_block",
    }:
        assert {"reserve_plan_block", "bind_reserved_plan_block"} <= called_methods(
            method_name
        )
    assert "bind_reserved_plan_block" in called_methods(
        "_build_fallthrough_goto_helper"
    )
    assert "reserve_plan_block" in called_methods("_stage_semantic_fallthrough_helper")


def test_synthetic_identity_is_nominal_not_derived_from_live_coordinates() -> None:
    """Synthetic handle constructors receive only external nominal authority."""
    path = SRC_ROOT / "ir/block_identity.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    handle_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "MbaBlockHandle"
    )
    constructors = {
        node.name: node
        for node in handle_class.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"created_synthetic", "observed_ephemeral"}
    }
    assert set(constructors) == {"created_synthetic", "observed_ephemeral"}
    forbidden = {"ea", "badaddr", "hash", "content", "serial"}
    violations: list[str] = []
    for name, function in constructors.items():
        parameter_names = {
            argument.arg
            for argument in (*function.args.args, *function.args.kwonlyargs)
            if argument.arg not in {"cls", "self"}
        }
        for parameter in parameter_names:
            if any(token in parameter.lower() for token in forbidden):
                violations.append(f"{name}:{parameter}")
    assert violations == []
