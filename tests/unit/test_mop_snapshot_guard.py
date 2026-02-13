"""Guard test: ensures MopSnapshot class body is complete (catches indentation regressions)."""
from d810.hexrays.mop_snapshot import MopSnapshot


def test_mop_snapshot_has_all_fields():
    """MopSnapshot must expose expected field surface across backends."""
    # Compatibility hack:
    # MopSnapshot is either:
    # - pure Python @dataclass (has __dataclass_fields__), or
    # - Cython extension class (no dataclass internals).
    # Import order can select either backend in a given process.
    expected_fields = (
        "t",
        "size",
        "valnum",
        "value",
        "reg",
        "stkoff",
        "gaddr",
        "lvar_idx",
        "lvar_off",
        "block_num",
        "helper_name",
        "const_str",
        "pair_lo_t",
        "pair_hi_t",
    )

    dataclass_fields = getattr(MopSnapshot, "__dataclass_fields__", None)
    if dataclass_fields is not None:
        # Pure Python backend: keep original indentation-regression guard.
        assert len(dataclass_fields) >= len(expected_fields), (
            f"MopSnapshot has only {len(dataclass_fields)} fields, expected >= {len(expected_fields)}. "
            "Check indentation in mop_snapshot.py — fields may have fallen outside class body."
        )
        return

    # Cython backend: validate equivalent public field surface.
    snap = MopSnapshot(t=0, size=0)
    missing = [name for name in expected_fields if not hasattr(snap, name)]
    assert not missing, (
        f"MopSnapshot (Cython backend) missing fields: {missing}. "
        "Keep Cython MopSnapshot aligned with pure-Python MopSnapshot fields."
    )


def test_mop_snapshot_has_from_mop():
    """MopSnapshot.from_mop must be a classmethod."""
    assert hasattr(MopSnapshot, "from_mop"), "MopSnapshot.from_mop is missing"
    assert callable(MopSnapshot.from_mop), "MopSnapshot.from_mop is not callable"


def test_mop_snapshot_has_to_cache_key():
    """MopSnapshot.to_cache_key must be a method."""
    assert hasattr(MopSnapshot, "to_cache_key"), "MopSnapshot.to_cache_key is missing"
