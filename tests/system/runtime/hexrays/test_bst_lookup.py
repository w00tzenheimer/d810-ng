import pytest
from d810.hexrays.bst_analysis import BSTAnalysisResult, resolve_target_via_bst


def _make_bst_result(exact_map, range_map=None):
    """Build a minimal BSTAnalysisResult for testing."""
    r = BSTAnalysisResult()
    r.handler_state_map = exact_map
    r.handler_range_map = range_map or {}
    return r


class TestResolveTargetViaBst:
    def test_exact_match(self):
        bst = _make_bst_result({10: 0xAABBCCDD, 20: 0x11223344})
        assert resolve_target_via_bst(bst, 0xAABBCCDD) == 10
        assert resolve_target_via_bst(bst, 0x11223344) == 20

    def test_range_match(self):
        bst = _make_bst_result(
            {10: 0x100},
            range_map={20: (0x200, 0x300), 30: (0x400, 0x500)},
        )
        assert resolve_target_via_bst(bst, 0x250) == 20
        assert resolve_target_via_bst(bst, 0x450) == 30

    def test_range_boundary(self):
        bst = _make_bst_result({}, range_map={20: (0x200, 0x300)})
        assert resolve_target_via_bst(bst, 0x200) == 20
        assert resolve_target_via_bst(bst, 0x300) == 20

    def test_no_match_returns_none(self):
        bst = _make_bst_result({10: 0x100}, range_map={20: (0x200, 0x300)})
        assert resolve_target_via_bst(bst, 0x999) is None

    def test_exact_takes_priority_over_range(self):
        bst = _make_bst_result({10: 0x250}, range_map={20: (0x200, 0x300)})
        assert resolve_target_via_bst(bst, 0x250) == 10

    def test_open_range_low_none(self):
        bst = _make_bst_result({}, range_map={20: (None, 0x300)})
        assert resolve_target_via_bst(bst, 0x100) == 20
        assert resolve_target_via_bst(bst, 0x400) is None

    def test_open_range_high_none(self):
        bst = _make_bst_result({}, range_map={20: (0x200, None)})
        assert resolve_target_via_bst(bst, 0x999) == 20
        assert resolve_target_via_bst(bst, 0x100) is None
