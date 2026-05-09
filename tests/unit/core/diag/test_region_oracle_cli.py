"""Unit tests for python -m d810.core.diag region-* subcommands."""
from __future__ import annotations

import sqlite3

import pytest

from d810.core.diag.__main__ import _resolve_oracle_snap_ids


def _make_conn_with_snaps(snaps: list[tuple[int, str]]) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE snapshots (id INTEGER PRIMARY KEY, label TEXT NOT NULL)"
    )
    conn.executemany("INSERT INTO snapshots (id, label) VALUES (?, ?)", snaps)
    conn.commit()
    return conn


def test_resolver_picks_highest_id_for_primary_label():
    conn = _make_conn_with_snaps([
        (3, "post_bundle_stabilize"),
        (5, "post_bundle_stabilize"),
        (4, "post_pipeline"),
        (10, "GLBOPT1_post_d810"),
    ])
    snap17, snap18 = _resolve_oracle_snap_ids(
        conn,
        snap17_labels=("post_bundle_stabilize", "post_pipeline"),
        snap18_labels=("GLBOPT1_post_d810",),
    )
    assert snap17 == 5
    assert snap18 == 10


def test_resolver_falls_back_through_label_list():
    conn = _make_conn_with_snaps([
        (4, "post_pipeline"),
        (10, "post_d810"),
    ])
    snap17, snap18 = _resolve_oracle_snap_ids(
        conn,
        snap17_labels=("post_bundle_stabilize", "post_pipeline"),
        snap18_labels=("maturity_MMAT_GLBOPT1_post_d810", "GLBOPT1_post_d810", "post_d810"),
    )
    assert snap17 == 4
    assert snap18 == 10


def test_resolver_returns_none_when_unresolvable():
    conn = _make_conn_with_snaps([(1, "irrelevant")])
    snap17, snap18 = _resolve_oracle_snap_ids(
        conn,
        snap17_labels=("post_bundle_stabilize",),
        snap18_labels=("GLBOPT1_post_d810",),
    )
    assert snap17 is None
    assert snap18 is None


def test_resolver_returns_partial_results():
    conn = _make_conn_with_snaps([(7, "post_pipeline")])
    snap17, snap18 = _resolve_oracle_snap_ids(
        conn,
        snap17_labels=("post_bundle_stabilize", "post_pipeline"),
        snap18_labels=("GLBOPT1_post_d810",),
    )
    assert snap17 == 7
    assert snap18 is None
