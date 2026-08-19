"""Regression coverage for MopSnapshot inputs to def_search."""

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.evaluator.hexrays_microcode import def_search


class FakeSnapshot:
    def __init__(self, *, t, size, reg=None, stkoff=None, owned_mop=None):
        self.t = t
        self.size = size
        self.reg = reg
        self.r = reg
        self.stkoff = stkoff
        self.owned_mop = owned_mop
        self.materialized_mba = None

    def to_mop(self, mba=None):
        self.materialized_mba = mba
        return SimpleNamespace(t=self.t, size=self.size, r=self.reg)


def test_materialize_stack_snapshot_rebinds_to_destination_mba(monkeypatch):
    monkeypatch.setattr(def_search, "MopSnapshot", FakeSnapshot)
    destination_mba = object()
    snapshot = FakeSnapshot(
        t=ida_hexrays.mop_S,
        size=4,
        stkoff=0xA4,
    )

    materialized = def_search._materialize_mop_for_tracking(
        snapshot,
        "test",
        mba=destination_mba,
    )

    assert materialized is not None
    assert snapshot.materialized_mba is destination_mba


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


def test_resolve_mop_to_ast_forwards_explicit_cross_block_tracker_budget(monkeypatch):
    class RecordingTracker:
        received_budget = None

        @staticmethod
        def reset():
            return None

        def __init__(self, _searched_mop_list, *, max_nb_block, max_path):
            self.__class__.received_budget = (max_nb_block, max_path)

        def search_backward(self, _blk, _ins):
            return []

    monkeypatch.setitem(
        def_search.sys.modules,
        "d810.evaluator.hexrays_microcode.tracker",
        SimpleNamespace(MopTracker=RecordingTracker),
    )
    monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", False)

    result = def_search.resolve_mop_to_ast(
        SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=0),
        blk=object(),
        ins=SimpleNamespace(ea=0x1000),
        max_predecessor_blocks=2,
        max_paths=3,
    )

    assert result is None
    assert RecordingTracker.received_budget == (2, 3)


def test_resolve_mop_to_ast_forwards_native_def_search_budget(monkeypatch):
    received_budgets = []

    def native_resolver(
        _mop,
        _blk,
        _ins,
        *,
        max_predecessor_blocks,
        max_paths,
        node_budget=None,
    ):
        received_budgets.append((max_predecessor_blocks, max_paths))
        return None

    monkeypatch.setattr(def_search, "resolve_mop_via_predecessors", native_resolver)
    monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", True)
    monkeypatch.setitem(
        def_search.sys.modules,
        "d810.evaluator.hexrays_microcode.tracker",
        SimpleNamespace(),
    )
    mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=0)
    block = object()
    instruction = SimpleNamespace(ea=0x1000)

    assert def_search.resolve_mop_to_ast(mop, block, instruction) is None
    assert (
        def_search.resolve_mop_to_ast(
            mop,
            block,
            instruction,
            max_predecessor_blocks=2,
            max_paths=3,
        )
        is None
    )

    assert received_budgets == [(1, 1), (2, 3)]


def test_native_predecessor_walk_honors_predecessor_budget(monkeypatch):
    searched_blocks = []
    predecessor_lookups = []

    class Block:
        def __init__(self, serial, predecessor):
            self.serial = serial
            self._predecessor = predecessor
            self.mba = None

        def npred(self):
            return 0 if self._predecessor is None else 1

        def pred(self, index):
            assert index == 0
            return self._predecessor

    blocks = {
        serial: Block(serial, serial + 1 if serial < 2 else None)
        for serial in range(3)
    }

    class Mba:
        def get_mblock(self, serial):
            predecessor_lookups.append(serial)
            return blocks[serial]

    mba = Mba()
    for block in blocks.values():
        block.mba = mba

    monkeypatch.setattr(
        def_search,
        "find_def_in_block",
        lambda _mop, block, _before: searched_blocks.append(block.serial) or None,
    )
    mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=0)

    assert (
        def_search.resolve_mop_via_predecessors(
            mop,
            blocks[0],
            SimpleNamespace(ea=0x1000),
            max_predecessor_blocks=2,
            max_paths=1,
        )
        is None
    )
    assert searched_blocks == [0, 1, 2]
    assert predecessor_lookups == [1, 2]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_predecessor_blocks": 0},
        {"max_predecessor_blocks": 9},
        {"max_predecessor_blocks": True},
        {"max_paths": 0},
        {"max_paths": 33},
        {"max_paths": True},
    ],
)
def test_native_predecessor_walk_rejects_invalid_budget(monkeypatch, kwargs):
    monkeypatch.setattr(
        def_search,
        "find_def_in_block",
        lambda *_args: pytest.fail("invalid budget must fail before searching"),
    )
    mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=0)
    block = SimpleNamespace(serial=0)

    assert (
        def_search.resolve_mop_via_predecessors(
            mop,
            block,
            SimpleNamespace(ea=0x1000),
            **kwargs,
        )
        is None
    )


def test_recursive_cache_distinguishes_same_ea_microinstructions(monkeypatch):
    class Leaf:
        def __init__(self):
            self.mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=0)

        @staticmethod
        def is_leaf():
            return True

    calls = []

    def unresolved(_mop, _blk, ins, **_kwargs):
        calls.append(ins)
        return None

    monkeypatch.setattr(def_search, "get_mop_key", lambda _mop: ("reg", 0))
    monkeypatch.setattr(def_search, "resolve_mop_to_ast", unresolved)
    block = SimpleNamespace(serial=7)
    first = SimpleNamespace(ea=0x401000, this=object())
    second = SimpleNamespace(ea=0x401000, this=object())
    cache = {}

    for resolver in (
        def_search._py_slow_recursively_resolve_ast,
        def_search.recursively_resolve_ast,
    ):
        calls.clear()
        cache.clear()
        resolver(Leaf(), block, first, cache=cache)
        resolver(Leaf(), block, second, cache=cache)
        assert calls == [first, second]


def _resolver_width_test_leaf(name: str, size: int):
    """Build a register AST leaf with an explicit Hex-Rays byte width."""

    from d810.hexrays.expr.ast import AstLeaf

    leaf = AstLeaf(name)
    leaf.mop = SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=size,
        r=1,
        valnum=0,
    )
    leaf.dest_size = size
    return leaf


def _resolver_width_test_definition(size: int):
    """Build a definition AST whose result width is *size* bytes."""

    from d810.hexrays.expr.ast import AstLeaf, AstNode

    definition = AstNode(
        ida_hexrays.m_add,
        AstLeaf("definition_left"),
        AstLeaf("definition_right"),
    )
    definition.dest_size = size
    return definition


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_truncates_wider_definition_to_use_width(
    monkeypatch, resolver_name
):
    """A wider producer must be explicitly narrowed at a narrower use site."""

    from d810.hexrays.expr.ast import AstNode

    replacement = _resolver_width_test_definition(8)
    use = _resolver_width_test_leaf("use", 4)

    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: replacement,
    )
    result = getattr(def_search, resolver_name)(
        use,
        SimpleNamespace(serial=7),
        SimpleNamespace(this=1),
        cache={},
    )

    assert isinstance(result, AstNode)
    assert result.opcode == ida_hexrays.m_low
    assert result.left is replacement
    assert result.right is None
    assert result.dest_size == 4


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_keeps_equal_width_definition_unchanged(
    monkeypatch, resolver_name
):
    """Equal-width replacement keeps the original definition shape."""

    replacement = _resolver_width_test_definition(4)
    use = _resolver_width_test_leaf("use", 4)

    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: replacement,
    )
    result = getattr(def_search, resolver_name)(
        use,
        SimpleNamespace(serial=7),
        SimpleNamespace(this=1),
        cache={},
    )

    assert result is replacement


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_rejects_narrower_definition_for_wider_use(
    monkeypatch, resolver_name
):
    """A partial-register definition is never widened by recursive resolution."""

    replacement = _resolver_width_test_definition(4)
    use = _resolver_width_test_leaf("use", 8)

    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: replacement,
    )
    result = getattr(def_search, resolver_name)(
        use,
        SimpleNamespace(serial=7),
        SimpleNamespace(this=1),
        cache={},
    )

    assert result is use


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_cache_includes_use_width(monkeypatch, resolver_name):
    """One storage identity cannot reuse a replacement at another width."""

    replacement = _resolver_width_test_definition(8)
    narrow_use = _resolver_width_test_leaf("narrow_use", 4)
    wide_use = _resolver_width_test_leaf("wide_use", 8)
    calls = []

    def resolve(*_args, **_kwargs):
        calls.append(1)
        return replacement

    monkeypatch.setattr(def_search, "get_mop_key", lambda _mop: ("r", 1))
    monkeypatch.setattr(def_search, "resolve_mop_to_ast", resolve)
    block = SimpleNamespace(serial=7)
    instruction = SimpleNamespace(this=1)
    cache = {}
    resolver = getattr(def_search, resolver_name)

    narrow_result = resolver(narrow_use, block, instruction, cache=cache)
    wide_result = resolver(wide_use, block, instruction, cache=cache)

    assert len(calls) == 2
    assert narrow_result.opcode == ida_hexrays.m_low
    assert wide_result is replacement


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_fails_closed_when_definition_width_unknown(
    monkeypatch, resolver_name
):
    """Unknown producer width must not be guessed from the use site."""

    from d810.hexrays.expr.ast import AstLeaf, AstNode

    replacement = AstNode(
        ida_hexrays.m_add,
        AstLeaf("definition_left"),
        AstLeaf("definition_right"),
    )
    use = _resolver_width_test_leaf("use", 4)

    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: replacement,
    )
    result = getattr(def_search, resolver_name)(
        use,
        SimpleNamespace(serial=7),
        SimpleNamespace(this=1),
        cache={},
    )

    assert result is use


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_charges_synthetic_truncation(
    monkeypatch, resolver_name
):
    """The inserted low-part node participates in the caller's node budget."""

    replacement = _resolver_width_test_definition(8)
    use = _resolver_width_test_leaf("use", 4)

    class Budget:
        def __init__(self):
            self.consumed = 0
            self.charged = []

        def consume(self):
            self.consumed += 1

        def mark_charged(self, occurrence):
            self.charged.append(occurrence)

    monkeypatch.setattr(
        def_search,
        "resolve_mop_to_ast",
        lambda *_args, **_kwargs: replacement,
    )
    budget = Budget()
    result = getattr(def_search, resolver_name)(
        use,
        SimpleNamespace(serial=7),
        SimpleNamespace(this=1),
        cache={},
        node_budget=budget,
    )

    assert result.opcode == ida_hexrays.m_low
    assert budget.consumed == 1
    assert budget.charged == [result]


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


def test_find_def_in_block_uses_destination_owned_stack_operand(monkeypatch):
    calls = []

    class ImportedBlock:
        mba = object()
        tail = None

        def append_use_list(self, _ml, mop, _access):
            calls.append(mop)

    monkeypatch.setattr(
        def_search.ida_hexrays,
        "mlist_t",
        lambda: SimpleNamespace(empty=lambda: True),
    )

    assert (
        def_search.find_def_in_block(
            SimpleNamespace(t=ida_hexrays.mop_r),
            ImportedBlock(),
            None,
        )
        is None
    )
    assert len(calls) == 1
