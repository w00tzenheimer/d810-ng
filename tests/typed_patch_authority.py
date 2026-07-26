"""Explicit logical source witnesses for portable compiler-only tests."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from types import SimpleNamespace

from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.plan import compile_patch_plan as _compile_patch_plan


def _integer_coordinates(value: object) -> set[int]:
    coordinates: set[int] = set()
    if isinstance(value, bool):
        return coordinates
    if isinstance(value, int):
        if value >= 0:
            coordinates.add(value)
        return coordinates
    if is_dataclass(value):
        for field in fields(value):
            coordinates.update(_integer_coordinates(getattr(value, field.name)))
        return coordinates
    if isinstance(value, Mapping):
        for key, item in value.items():
            coordinates.update(_integer_coordinates(key))
            coordinates.update(_integer_coordinates(item))
        return coordinates
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            coordinates.update(_integer_coordinates(item))
    return coordinates


def compile_patch_plan(*args, **kwargs):
    """Compile with explicit test-session witnesses for every fixture integer."""
    if "block_refs_by_serial" not in kwargs:
        coordinates = _integer_coordinates((args, kwargs))
        kwargs["block_refs_by_serial"] = {
            coordinate: LogicalBlockRef(
                session_id="unit-test-source-authority",
                proxy_token=f"fixture-coordinate:{coordinate}",
                version=0,
            )
            for coordinate in coordinates
        }
    return _compile_patch_plan(*args, **kwargs)


def emit_minimal_unflatten(flow_graph, dispatcher, **kwargs):
    """Emit with explicit test-session authority for every fixture block."""
    from d810.transforms.minimal_unflatten_emit import (
        emit_minimal_unflatten as _emit_minimal_unflatten,
    )

    kwargs.setdefault(
        "block_refs_by_serial",
        block_refs_by_serial(*flow_graph.blocks),
    )
    return _emit_minimal_unflatten(flow_graph, dispatcher, **kwargs)


def graph_modifications(patch_plan) -> list[object]:
    """Project simple typed patch steps back into planner values for assertions."""
    from d810.transforms import graph_modification as graph_modification_module
    from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef, PlanBlockRef

    coordinates = dict(patch_plan.source_coordinates)

    def project(value):
        if isinstance(value, (NativeBlockRef, LogicalBlockRef)):
            return coordinates[value]
        if isinstance(value, PlanBlockRef):
            raise TypeError("test projection cannot assign a serial to a planned block")
        if isinstance(value, tuple):
            return tuple(project(item) for item in value)
        return value

    projected = []
    for step in patch_plan.steps:
        modification_type = getattr(
            graph_modification_module,
            type(step).__name__.removeprefix("Patch"),
            None,
        )
        if modification_type is None:
            raise TypeError(f"test projection does not support {type(step).__name__}")
        projected.append(
            modification_type(
                **{
                    item.name: project(getattr(step, item.name))
                    for item in fields(modification_type)
                    if not item.name.startswith("_") and hasattr(step, item.name)
                }
            )
        )
    return projected


def block_refs_by_serial(*values: object) -> dict[int, LogicalBlockRef]:
    """Return explicit observed-source witnesses for test fixture coordinates."""
    return {
        coordinate: LogicalBlockRef(
            session_id="unit-test-source-authority",
            proxy_token=f"fixture-coordinate:{coordinate}",
            version=0,
        )
        for coordinate in _integer_coordinates(values)
    }


def mutation_gateway_for(*values: object) -> object:
    refs = block_refs_by_serial(*values)
    index = SimpleNamespace(
        snapshot_id="unit-test-source-snapshot",
        generation=0,
        plan_refs_by_serial=lambda: refs,
    )
    return SimpleNamespace(identity_index=index)
