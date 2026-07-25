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
