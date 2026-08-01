"""Schema-derived ownership metadata for diagnostic snapshot cleanup."""

from __future__ import annotations

from d810.core.diag.models import MODELS
from d810.core.diag.schema import _LEGACY_DAG_TABLE_RENAMES

SNAPSHOT_PARENT_TABLE = "snapshots"


def _model_has_snapshot_id(model: type) -> bool:
    return any(
        field.column_name == "snapshot_id"
        for field in model._meta.sorted_fields
    )


def snapshot_owned_tables() -> tuple[str, ...]:
    """Return modeled base tables whose rows belong to one snapshot."""

    return tuple(
        sorted(
            model._meta.table_name
            for model in MODELS
            if model._meta.table_name != SNAPSHOT_PARENT_TABLE
            and _model_has_snapshot_id(model)
        )
    )


def legacy_snapshot_owned_tables() -> tuple[str, ...]:
    """Return the equivalent registry for supported pre-rename databases."""

    current = set(snapshot_owned_tables())
    for old, new in _LEGACY_DAG_TABLE_RENAMES.items():
        if new in current:
            current.remove(new)
            current.add(old)
    return tuple(sorted(current))
