"""Static ownership guard for resolver evidence and live session state."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


RESOLVER_STATE_PATH = (
    Path(__file__).parents[3]
    / "src"
    / "d810"
    / "optimizers"
    / "microcode"
    / "flow"
    / "jumps"
    / "resolver_session_state.py"
)
LIFECYCLE_PATH = (
    Path(__file__).parents[3]
    / "src"
    / "d810"
    / "manager"
    / "decompilation_lifecycle.py"
)


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
