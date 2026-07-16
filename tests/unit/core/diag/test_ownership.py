from d810.core.diag.ownership import (
    SNAPSHOT_PARENT_TABLE,
    legacy_snapshot_owned_tables,
    snapshot_owned_tables,
)
from d810.core.diag.schema import _LEGACY_DAG_TABLE_RENAMES


def test_snapshot_owned_tables_are_derived_from_modeled_snapshot_id_columns():
    tables = snapshot_owned_tables()

    assert tables == tuple(sorted(tables))
    assert SNAPSHOT_PARENT_TABLE == "snapshots"
    assert SNAPSHOT_PARENT_TABLE not in tables
    assert "blocks" in tables
    assert "instructions" in tables
    assert "rendered_programs" in tables
    assert "terminal_tail_dce_causes" not in tables


def test_legacy_snapshot_owned_tables_substitute_supported_dag_names():
    current = set(snapshot_owned_tables())
    legacy = set(legacy_snapshot_owned_tables())

    for old, new in _LEGACY_DAG_TABLE_RENAMES.items():
        if new in current:
            assert old in legacy
            assert new not in legacy


def test_snapshot_owned_registry_is_immutable():
    assert isinstance(snapshot_owned_tables(), tuple)
    assert isinstance(legacy_snapshot_owned_tables(), tuple)
