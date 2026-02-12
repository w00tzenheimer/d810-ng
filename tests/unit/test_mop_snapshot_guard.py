"""Guard test: ensures MopSnapshot class body is complete (catches indentation regressions)."""
from d810.hexrays.mop_snapshot import MopSnapshot


def test_mop_snapshot_has_all_fields():
    """MopSnapshot must have all 14 dataclass fields."""
    assert len(MopSnapshot.__dataclass_fields__) >= 14, (
        f"MopSnapshot has only {len(MopSnapshot.__dataclass_fields__)} fields, expected 14. "
        "Check indentation in mop_snapshot.py — fields may have fallen outside class body."
    )


def test_mop_snapshot_has_from_mop():
    """MopSnapshot.from_mop must be a classmethod."""
    assert hasattr(MopSnapshot, "from_mop"), "MopSnapshot.from_mop is missing"
    assert callable(MopSnapshot.from_mop), "MopSnapshot.from_mop is not callable"


def test_mop_snapshot_has_to_cache_key():
    """MopSnapshot.to_cache_key must be a method."""
    assert hasattr(MopSnapshot, "to_cache_key"), "MopSnapshot.to_cache_key is missing"
