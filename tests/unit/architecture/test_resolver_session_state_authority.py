"""Static ownership guard for resolver evidence and live session state."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


REPO_ROOT = Path(__file__).parents[3]
RESOLVER_STATE_PATH = (
    REPO_ROOT
    / "src"
    / "d810"
    / "optimizers"
    / "microcode"
    / "flow"
    / "jumps"
    / "resolver_session_state.py"
)
LIFECYCLE_PATH = (
    REPO_ROOT
    / "src"
    / "d810"
    / "manager"
    / "decompilation_lifecycle.py"
)
COMPUTED_GOTO_RESOLVER_PATH = (
    REPO_ROOT
    / "src"
    / "d810"
    / "optimizers"
    / "microcode"
    / "flow"
    / "jumps"
    / "computed_goto_resolver.py"
)
NATIVE_PREANALYSIS_SESSION_PATH = (
    REPO_ROOT
    / "src"
    / "d810"
    / "analyses"
    / "control_flow"
    / "native_preanalysis_session.py"
)
MATERIALIZED_COMPUTED_GOTO_ISLAND_PATH = (
    REPO_ROOT
    / "src"
    / "d810"
    / "optimizers"
    / "microcode"
    / "flow"
    / "jumps"
    / "materialized_computed_goto_island.py"
)
MANAGER_PATH = REPO_ROOT / "src" / "d810" / "manager" / "manager.py"
LEGACY_ISLAND_REFERENCE_PATHS = (
    REPO_ROOT / "src" / "d810" / "conf" / "default_unflattening_ollvm.json",
    REPO_ROOT
    / "src"
    / "d810"
    / "conf"
    / "default_unflattening_ollvm_config_v2_canary.json",
    REPO_ROOT / "src" / "d810" / "core" / "config_v2_defaults.py",
    REPO_ROOT / "src" / "d810" / "passes" / "legacy_flow_rules.py",
    REPO_ROOT / "tools" / "scripts" / "rhad_investigation" / "README.md",
)
LEGACY_PREOPT_PROBE_PATH = (
    REPO_ROOT
    / "tools"
    / "scripts"
    / "rhad_investigation"
    / "probe_preopt_snippet_import.py"
)


def _referenced_identifiers(tree: ast.AST) -> set[str]:
    identifiers = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    }
    identifiers.update(
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    )
    identifiers.update(
        alias.name.rsplit(".", 1)[-1]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    )
    return identifiers


class FieldLifetime(Enum):
    """Architectural lifetime of one ResolverSessionState field."""

    LIFECYCLE_BINDING = "lifecycle_binding"
    CALLBACK_LOCAL = "callback_local"
    TRANSIENT_MATERIALIZATION = "transient_materialization"
    PORTABLE_CROSS_REDO = "portable_cross_redo"


@dataclass(frozen=True, slots=True)
class FieldInventory:
    lifetime: FieldLifetime
    rationale: str


# Field-by-field live inventory required by dsf-katd. Keep this exhaustive.
RESOLVER_SESSION_FIELD_INVENTORY = {
    "native_preanalysis": FieldInventory(
        FieldLifetime.LIFECYCLE_BINDING,
        "typed reference to the lifecycle-owned portable authority",
    ),
    "native_key": FieldInventory(
        FieldLifetime.LIFECYCLE_BINDING,
        "portable owner key used to reject cross-session evidence",
    ),
    "identity_index": FieldInventory(
        FieldLifetime.CALLBACK_LOCAL,
        "current-MBA bindings invalidated on mutation or regeneration",
    ),
    "materialization": FieldInventory(
        FieldLifetime.TRANSIENT_MATERIALIZATION,
        "bounded in-progress resolver materialization state",
    ),
    "materialized": FieldInventory(
        FieldLifetime.TRANSIENT_MATERIALIZATION,
        "session-local completion guard, not semantic evidence",
    ),
    "indirect_label_materialized": FieldInventory(
        FieldLifetime.TRANSIENT_MATERIALIZATION,
        "one-session label materialization guard",
    ),
    "indirect_dispatcher_materialized": FieldInventory(
        FieldLifetime.TRANSIENT_MATERIALIZATION,
        "one-session dispatcher materialization guard",
    ),
    "snippet_capture_active": FieldInventory(
        FieldLifetime.CALLBACK_LOCAL,
        "live detached-snippet capture section guard",
    ),
    "snippet_capture_profile_ea": FieldInventory(
        FieldLifetime.CALLBACK_LOCAL,
        "native owner of the active live capture callback",
    ),
    "preopt_union_import_active": FieldInventory(
        FieldLifetime.CALLBACK_LOCAL,
        "live import reentrancy guard",
    ),
    "pending_preopt_reimport": FieldInventory(
        FieldLifetime.TRANSIENT_MATERIALIZATION,
        "one-shot import control flag",
    ),
    "pending_prepatch_materialization": FieldInventory(
        FieldLifetime.TRANSIENT_MATERIALIZATION,
        "resolution awaiting the next bounded materialization step",
    ),
    "preopt_union_imported_mbas": FieldInventory(
        FieldLifetime.CALLBACK_LOCAL,
        "live MBA identity and generation guards",
    ),
    "preopt_union_mutated_mbas": FieldInventory(
        FieldLifetime.CALLBACK_LOCAL,
        "live MBA identity and generation guards",
    ),
    "attempted_mbas": FieldInventory(
        FieldLifetime.CALLBACK_LOCAL,
        "live MBA attempt deduplication coordinates",
    ),
    "current_mba_token": FieldInventory(
        FieldLifetime.CALLBACK_LOCAL,
        "current MBA generation token for imported instruction provenance",
    ),
    "current_imported_instruction_origins": FieldInventory(
        FieldLifetime.CALLBACK_LOCAL,
        "current MBA synthetic-to-native instruction provenance",
    ),
    "current_imported_root_handles": FieldInventory(
        FieldLifetime.CALLBACK_LOCAL,
        "importer-selected roots bound through the live MBA identity index",
    ),
}


MOVED_PORTABLE_FIELDS = frozenset(
    {
        "resolution",
        "portable_state_routes",
        "portable_dispatcher_region_identity",
        "terminal_return_carrier_requests",
        "terminal_return_carriers",
        "call_result_carriers",
        "call_abi_proofs",
        "preopt_union_preparation",
        "prepatch_preopt_union_source",
        "bootstrap_route_bindings",
    }
)


DIRECT_EVIDENCE_MUTATIONS = frozenset(
    {
        "mark_evidence_changed",
        "merge_bootstrap_route",
        "merge_call_abi_proof",
        "merge_facts",
        "merge_portable_dispatcher_region_identity",
        "merge_portable_state_routes",
        "merge_terminal_return_carrier_requests",
        "merge_terminal_return_carriers",
        "request_controlled_redo",
        "request_generated_restart",
    }
)

LEGACY_FINAL_ROUTE_FUNCTIONS = frozenset(
    {
        "_build_residual_state_route_evidence",
        "_choose_dispatch_patch_region",
        "_entry_bridge_ready",
        "_exact_register_state_write_sites",
        "_materialize_residual_entry_bridge",
        "_materialize_residual_fragment_from_mba",
        "_materialize_residual_state_routes",
        "_materialize_residual_state_routes_from_mba",
        "_native_dispatch_branch_site",
        "_native_equality_state_target_rows",
        "_native_post_state_write_indirect_site",
        "_native_predicate_reaches_route_site",
        "_native_register_immediate_write_matches",
        "_native_register_immediate_write_near_block",
        "_native_residual_route_patch_site",
        "_partition_residual_route_branches",
        "_plan_all_residual_state_route_patches",
        "_plan_exact_state_write_route_patches",
        "_plan_misrouted_exact_state_route_patches",
        "_plan_residual_state_route_patches",
        "_plan_unseen_residual_state_route_patches",
        "_residual_patch_site_is_path_local",
        "_residual_predicate_inherited_states",
        "_select_register_indirect_patch_region",
        "_unique_equality_state_targets",
    }
)


def _resolver_state_class() -> ast.ClassDef:
    tree = ast.parse(
        RESOLVER_STATE_PATH.read_text(encoding="utf-8"),
        filename=str(RESOLVER_STATE_PATH),
    )
    return next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ResolverSessionState"
    )


def _resolver_state_fields() -> frozenset[str]:
    return frozenset(
        node.target.id
        for node in _resolver_state_class().body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    )


def _class(path: Path, name: str) -> ast.ClassDef:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == name
    )


def _function(node: ast.ClassDef | ast.Module, name: str) -> ast.FunctionDef:
    return next(
        child
        for child in node.body
        if isinstance(child, ast.FunctionDef) and child.name == name
    )


def test_resolver_session_state_lifetime_inventory_is_exhaustive() -> None:
    assert _resolver_state_fields() == frozenset(RESOLVER_SESSION_FIELD_INVENTORY)


def test_resolver_session_state_contains_no_portable_cross_redo_evidence() -> None:
    assert _resolver_state_fields().isdisjoint(MOVED_PORTABLE_FIELDS)
    assert all(
        inventory.lifetime is not FieldLifetime.PORTABLE_CROSS_REDO
        for inventory in RESOLVER_SESSION_FIELD_INVENTORY.values()
    )


def test_resolver_session_state_cannot_advance_lifecycle_evidence() -> None:
    violations = []
    for node in ast.walk(_resolver_state_class()):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        owner = node.func.value
        if (
            isinstance(owner, ast.Attribute)
            and isinstance(owner.value, ast.Name)
            and owner.value.id == "self"
            and owner.attr == "native_preanalysis"
            and node.func.attr in DIRECT_EVIDENCE_MUTATIONS
        ):
            violations.append(f"{node.lineno}:{node.func.attr}")
    assert violations == []


def test_lifecycle_uses_a_named_resolver_attachment_not_generic_extensions() -> None:
    context = _class(LIFECYCLE_PATH, "DecompilationSessionContext")
    fields = {
        node.target.id
        for node in context.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    assert "resolver_attachment" in fields
    assert "extensions" not in fields


def test_known_resolver_lifecycle_boundaries_do_not_use_getattr() -> None:
    resolver_module = ast.parse(
        RESOLVER_STATE_PATH.read_text(encoding="utf-8"),
        filename=str(RESOLVER_STATE_PATH),
    )
    lifecycle = _class(LIFECYCLE_PATH, "DecompilationLifecycleCoordinator")
    boundaries = (
        _function(resolver_module, "resolver_session_state"),
        _function(lifecycle, "mark_preopt_ready_emitted"),
        _function(lifecycle, "finish_hexrays_session"),
    )
    violations = [
        f"{boundary.name}:{node.lineno}"
        for boundary in boundaries
        for node in ast.walk(boundary)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
    ]
    assert violations == []


def test_production_terminal_carrier_capture_has_no_legacy_template_authority() -> None:
    resolver_tree = ast.parse(
        COMPUTED_GOTO_RESOLVER_PATH.read_text(encoding="utf-8"),
        filename=str(COMPUTED_GOTO_RESOLVER_PATH),
    )
    assert _referenced_identifiers(resolver_tree).isdisjoint(
        {
            "capture_terminal_return_carrier_template",
            "has_terminal_return_carrier_template",
            "prepare_terminal_return_carrier_templates",
        }
    )

    manager_tree = ast.parse(
        MANAGER_PATH.read_text(encoding="utf-8"),
        filename=str(MANAGER_PATH),
    )
    assert (
        "prepare_terminal_return_carrier_templates"
        not in _referenced_identifiers(manager_tree)
    )


def test_computed_goto_resolver_has_no_direct_final_state_route_authority() -> None:
    resolver_tree = ast.parse(
        COMPUTED_GOTO_RESOLVER_PATH.read_text(encoding="utf-8"),
        filename=str(COMPUTED_GOTO_RESOLVER_PATH),
    )
    resolver_functions = {
        node.name for node in resolver_tree.body if isinstance(node, ast.FunctionDef)
    }
    assert "rebind_live_preopt_routes" not in resolver_functions
    assert resolver_functions.isdisjoint(LEGACY_FINAL_ROUTE_FUNCTIONS)
    assert _referenced_identifiers(resolver_tree).isdisjoint(
        {
            "DeferredGraphModifier",
            "queue_conditional_target_change",
            "queue_goto_change",
            "queue_lower_conditional_state_transition",
            "queue_materialize_zero_way_conditional",
            "queue_materialize_zero_way_goto",
            "queue_terminal_goto_change",
        }
    )
    calls_done = _function(resolver_tree, "_on_calls_done_preanalysis")
    assert _referenced_identifiers(calls_done).isdisjoint(
        {
            "_entry_bridge_ready",
            "_materialize_residual_entry_bridge",
            "_materialize_residual_state_routes_from_mba",
            "entry_bridge_materialized",
            "state_route_rounds",
        }
    )

    resolver_state_tree = ast.parse(
        RESOLVER_STATE_PATH.read_text(encoding="utf-8"),
        filename=str(RESOLVER_STATE_PATH),
    )
    materialization_state = next(
        node
        for node in resolver_state_tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "ResolverMaterializationState"
    )
    materialization_fields = {
        node.target.id
        for node in materialization_state.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    assert materialization_fields.isdisjoint(
        {"entry_bridge_materialized", "state_route_rounds"}
    )


def test_computed_goto_resolver_has_no_provider_specific_route_authority() -> None:
    resolver_source = COMPUTED_GOTO_RESOLVER_PATH.read_text(encoding="utf-8")

    assert "_discover_reference_style_immediate_flow_routes" not in resolver_source
    assert "reference_style_immediate_flow_route" not in resolver_source


def test_portable_session_has_no_profile_specific_trace_switches() -> None:
    session_source = NATIVE_PREANALYSIS_SESSION_PATH.read_text(encoding="utf-8")

    assert "RHAD_" not in session_source


def test_legacy_materialized_island_lowering_is_removed() -> None:
    assert not MATERIALIZED_COMPUTED_GOTO_ISLAND_PATH.exists()
    assert not LEGACY_PREOPT_PROBE_PATH.exists()
    for path in LEGACY_ISLAND_REFERENCE_PATHS:
        text = path.read_text(encoding="utf-8")
        assert "MaterializedComputedGotoIslandRule" not in text
        assert "materialized-computed-goto-island" not in text
        assert "probe_preopt_snippet_import.py" not in text
