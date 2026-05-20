"""Regression coverage for MopSnapshot inputs to def_search."""

from types import SimpleNamespace

import ida_hexrays

from d810.evaluator.hexrays_microcode import def_search


class FakeSnapshot:
    def __init__(self, *, t, size, reg=None, stkoff=None, owned_mop=None):
        self.t = t
        self.size = size
        self.reg = reg
        self.r = reg
        self.stkoff = stkoff
        self.owned_mop = owned_mop

    def to_mop(self):
        return SimpleNamespace(t=self.t, size=self.size, r=self.reg)


def test_resolve_mop_to_ast_materializes_snapshot_before_tracker(monkeypatch):
    class RecordingTracker:
        seen_mop = None

        @staticmethod
        def reset():
            return None

        def __init__(self, searched_mop_list, **_kwargs):
            self.__class__.seen_mop = searched_mop_list[0]

        def search_backward(self, _blk, _ins):
            return []

    tracker_module = SimpleNamespace(MopTracker=RecordingTracker)
    monkeypatch.setattr(def_search, "MopSnapshot", FakeSnapshot)
    monkeypatch.setitem(
        def_search.sys.modules,
        "d810.evaluator.hexrays_microcode.tracker",
        tracker_module,
    )
    monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", False)

    snapshot = FakeSnapshot(t=ida_hexrays.mop_r, size=4, reg=0)
    result = def_search.resolve_mop_to_ast(
        snapshot,
        blk=object(),
        ins=SimpleNamespace(ea=0x1000),
    )

    assert result is None
    assert RecordingTracker.seen_mop is not None
    assert not isinstance(RecordingTracker.seen_mop, FakeSnapshot)
    assert RecordingTracker.seen_mop.t == ida_hexrays.mop_r
    assert RecordingTracker.seen_mop.r == 0
    assert RecordingTracker.seen_mop.size == 4


def test_resolve_mop_to_ast_fails_closed_for_unowned_stack_snapshot(monkeypatch):
    class ExplodingTracker:
        @staticmethod
        def reset():
            raise AssertionError("tracker should not run for unowned stack snapshots")

    tracker_module = SimpleNamespace(MopTracker=ExplodingTracker)
    monkeypatch.setattr(def_search, "MopSnapshot", FakeSnapshot)
    monkeypatch.setitem(
        def_search.sys.modules,
        "d810.evaluator.hexrays_microcode.tracker",
        tracker_module,
    )
    monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", False)

    snapshot = FakeSnapshot(t=ida_hexrays.mop_S, size=4, stkoff=0x10)
    result = def_search.resolve_mop_to_ast(
        snapshot,
        blk=object(),
        ins=SimpleNamespace(ea=0x1000),
    )

    assert result is None
