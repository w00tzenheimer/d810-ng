"""Persistence tests for the region oracle.

Verifies that re-running --persist does NOT wipe rows scoped to other
sources or snapshot ids. The existing schema's primary keys constrain
upsert scope; the helpers must use INSERT OR REPLACE, never a global
DELETE WHERE func_ea_hex = ?.
"""
from __future__ import annotations

import inspect
import json
import re
import sqlite3
import textwrap

import pytest

from d810.cfg.ref_region_oracle import (
    FeatureRegion,
    FeatureSource,
    RegionFeature,
    spec_for,
)
from d810.core.diag.__main__ import (
    _oracle_persist_dce_causes,
    _oracle_persist_features,
)
from d810.core.diag.schema import create_tables


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    return conn


def test_persist_features_inserts_rows():
    conn = _conn()
    feat = RegionFeature(
        source=FeatureSource.D810_SNAPSHOT,
        region=FeatureRegion.TERMINAL_TAIL,
        feature="byte_emit_3_present",
        value=True,
        evidence={"side": "d810", "block_serial": 161, "snapshot_id": 17},
        snapshot_id=17,
    )
    _oracle_persist_features(
        conn,
        func_ea_hex="0x0000000180012df0",
        func_ea_i64=0x180012df0,
        features=[feat],
    )
    rows = conn.execute("SELECT COUNT(*) FROM region_shape_features").fetchone()
    assert rows[0] == 1


def test_persist_features_is_idempotent():
    conn = _conn()
    feat = RegionFeature(
        source=FeatureSource.D810_SNAPSHOT,
        region=FeatureRegion.TERMINAL_TAIL,
        feature="byte_emit_3_present",
        value=True,
        evidence={"snapshot_id": 17},
        snapshot_id=17,
    )
    for _ in range(3):
        _oracle_persist_features(
            conn, func_ea_hex="0x0000000180012df0",
            func_ea_i64=0x180012df0, features=[feat],
        )
    n = conn.execute("SELECT COUNT(*) FROM region_shape_features").fetchone()[0]
    assert n == 1


def test_persist_features_does_not_wipe_other_sources():
    conn = _conn()
    ref_feat = RegionFeature(
        source=FeatureSource.REF, region=FeatureRegion.TERMINAL_TAIL,
        feature="byte_emit_3_present", value=True, evidence={"side": "ref"},
        snapshot_id=None,
    )
    snap17_feat = RegionFeature(
        source=FeatureSource.D810_SNAPSHOT, region=FeatureRegion.TERMINAL_TAIL,
        feature="byte_emit_3_present", value=True,
        evidence={"side": "d810", "snapshot_id": 17}, snapshot_id=17,
    )
    snap18_feat = RegionFeature(
        source=FeatureSource.D810_SNAPSHOT, region=FeatureRegion.TERMINAL_TAIL,
        feature="byte_emit_3_present", value=False,
        evidence={"side": "d810", "snapshot_id": 18}, snapshot_id=18,
    )

    _oracle_persist_features(
        conn, func_ea_hex="0x0000000180012df0", func_ea_i64=0x180012df0,
        features=[ref_feat, snap17_feat, snap18_feat],
    )
    assert conn.execute("SELECT COUNT(*) FROM region_shape_features").fetchone()[0] == 3

    # Re-run for snap17 only. Other rows must survive.
    _oracle_persist_features(
        conn, func_ea_hex="0x0000000180012df0", func_ea_i64=0x180012df0,
        features=[snap17_feat],
    )
    assert conn.execute("SELECT COUNT(*) FROM region_shape_features").fetchone()[0] == 3

    sources = sorted(
        r[0] for r in conn.execute("SELECT source FROM region_shape_features")
    )
    assert sources == ["D810_SNAPSHOT", "D810_SNAPSHOT", "REF"]


def test_persist_dce_causes_is_idempotent():
    conn = _conn()
    cause = {
        "byte_index": 3,
        "last_present_snapshot_id": 17,
        "first_missing_snapshot_id": 18,
        "last_block_serial": 161,
        "last_ea_hex": "0x0000000180012df0",
        "cause": "FOLDED_INTO_SURVIVING_BYTE_EMIT",
        "recommended_action": "STRUCTURER_SHAPING",
        "rationale": "tail-equivalent fold",
        "evidence": {"side": "d810"},
    }
    for _ in range(2):
        _oracle_persist_dce_causes(
            conn, func_ea_hex="0x0000000180012df0",
            func_ea_i64=0x180012df0, causes=[cause],
        )
    assert conn.execute("SELECT COUNT(*) FROM terminal_tail_dce_causes").fetchone()[0] == 1


def test_persistence_does_not_use_global_delete_where_func_ea():
    """Regression guard: scoped upsert only.

    The persist helpers must NOT contain a `DELETE FROM <oracle_table>
    WHERE func_ea_hex = ?` without additional scope conditions.
    """
    src = inspect.getsource(_oracle_persist_features)
    src += "\n" + inspect.getsource(_oracle_persist_dce_causes)
    pat = re.compile(
        r"DELETE\s+FROM\s+region_shape_features\s+WHERE\s+func_ea_hex",
        re.IGNORECASE,
    )
    assert pat.search(src) is None, (
        "Found unscoped DELETE in persistence helper:\n"
        f"{textwrap.indent(src, '  ')}"
    )
    pat2 = re.compile(
        r"DELETE\s+FROM\s+terminal_tail_dce_causes\s+WHERE\s+func_ea_hex",
        re.IGNORECASE,
    )
    assert pat2.search(src) is None, (
        "Found unscoped DELETE in persistence helper:\n"
        f"{textwrap.indent(src, '  ')}"
    )
