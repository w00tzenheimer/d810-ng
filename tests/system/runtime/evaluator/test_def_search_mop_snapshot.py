"""Regression coverage for MopSnapshot inputs to def_search."""

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.evaluator.hexrays_microcode import def_search


def test_terminal_origin_rejects_non_native_before_mlist(monkeypatch):
    def explode():
        raise AssertionError("native mlist must not be constructed")

    monkeypatch.setattr(ida_hexrays, "mlist_t", explode)
    mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=1, valnum=0, this=1)
    block = SimpleNamespace(serial=1, start=0, end=1, this=2, mba=None)
    assert not def_search._proof_operand_has_location(mop, block)


def test_proof_mba_identity_rejects_missing_mba():
    assert def_search._proof_mba_identity(None) is None


def test_terminal_origin_materializes_real_snapshot_before_location_check(monkeypatch):
    """A real snapshot must be materialized before native location validation."""

    from d810.hexrays.ir.mop_snapshot import MopSnapshot

    class FakeLocations:
        def __init__(self):
            self._empty = True

        def empty(self):
            return self._empty

    class Mba:
        this = 0x1234

    class Block:
        serial = 7
        start = 0x4000
        end = 0x4020
        this = 0x5678
        mba = Mba()

        def npred(self):
            return 0

        def append_use_list(self, locations, mop, _access):
            assert hasattr(mop, "this")
            assert not isinstance(mop, MopSnapshot)
            locations._empty = False

    snapshot = MopSnapshot(
        t=ida_hexrays.mop_r,
        size=4,
        reg=1,
        valnum=0,
    )
    assert not hasattr(snapshot, "this")

    live_mop = SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=4,
        r=1,
        valnum=0,
        this=0xDEAD,
    )
    materialization_calls = []

    def materialize(mop, context, *, mba):
        materialization_calls.append((mop, context, mba))
        return live_mop

    # Constructing a native mop_t without an active microcode arena can fault
    # inside IDA.  Keep this regression focused on the proof gate's ordering:
    # a real snapshot must reach the materializer before the native location
    # API sees the returned live mop.
    monkeypatch.setattr(def_search, "_materialize_mop_for_tracking", materialize)
    monkeypatch.setattr(def_search.ida_hexrays, "mlist_t", FakeLocations)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)

    origin = def_search._terminal_proof_origin(
        snapshot,
        Block(),
        SimpleNamespace(this=0x9ABC),
        max_predecessor_blocks=1,
        scope=object(),
    )

    assert origin is not None
    assert materialization_calls == [(snapshot, "_terminal_proof_origin", Block.mba)]


@pytest.mark.parametrize(
    "snapshot",
    [
        # Complex snapshots without an owned native operand are not safe to
        # materialize for a proof-location query.
        lambda MopSnapshot: MopSnapshot(
            t=ida_hexrays.mop_d,
            size=4,
            valnum=0,
        ),
        lambda MopSnapshot: MopSnapshot(
            t=ida_hexrays.mop_l,
            size=4,
            lvar_idx=1,
            lvar_off=0,
            valnum=0,
        ),
    ],
    ids=["missing-owned-complex-mop", "missing-owned-local-mop"],
)
def test_terminal_origin_fails_closed_for_unmaterializable_snapshot(
    monkeypatch, snapshot
):
    """A snapshot that cannot become a live mop must not create proof input."""

    from d810.hexrays.ir.mop_snapshot import MopSnapshot

    class Mba:
        this = 0x1234

    class Block:
        serial = 7
        start = 0x4000
        end = 0x4020
        this = 0x5678
        mba = Mba()

        def npred(self):
            return 0

        def append_use_list(self, *_args):
            raise AssertionError("unmaterializable snapshot reached native mlist")

    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)

    assert (
        def_search._terminal_proof_origin(
            snapshot(MopSnapshot),
            Block(),
            SimpleNamespace(this=0x9ABC),
            max_predecessor_blocks=1,
            scope=object(),
        )
        is None
    )


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


class _ProofOriginBlock:
    """Minimal single-entry block model for proof-origin tests."""

    def __init__(self, serial, *, start=0x4000):
        self.serial = serial
        self.start = start
        self.end = start + 0x20
        self.mba = object()

    def npred(self):
        return 0


def _proof_origin_leaf(name, *, register=1, size=4, valnum=0):
    from d810.hexrays.expr.ast import AstLeaf

    leaf = AstLeaf(name)
    leaf.mop = SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=size,
        r=register,
        valnum=valnum,
    )
    leaf.dest_size = size
    return leaf


@pytest.mark.parametrize(
    "resolver_name",
    ["_py_slow_recursively_resolve_ast", "recursively_resolve_ast"],
)
def test_recursive_resolver_attaches_same_origin_to_rebuilt_entry_leaves(
    monkeypatch, resolver_name
):
    """One proof-root register rebuilt through separate chains shares one token."""

    monkeypatch.setattr(def_search, "resolve_mop_to_ast", lambda *_a, **_k: None)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)
    monkeypatch.setattr(def_search, "_proof_operand_has_location", lambda *_a: True)
    block = _ProofOriginBlock(7)
    cache = {}
    resolver = getattr(def_search, resolver_name)

    first = resolver(
        _proof_origin_leaf("first"),
        block,
        SimpleNamespace(ea=0x5000, this=object()),
        cache=cache,
    )
    second = resolver(
        _proof_origin_leaf("second"),
        block,
        SimpleNamespace(ea=0x5000, this=object()),
        cache=cache,
    )

    assert first.proof_origin is not None
    assert second.proof_origin == first.proof_origin


def test_proof_origins_separate_distinct_entry_blocks(monkeypatch):
    """An unversioned register at different block entries stays distinct."""

    from d810.backends.ast.z3 import create_z3_vars

    monkeypatch.setattr(def_search, "resolve_mop_to_ast", lambda *_a, **_k: None)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)
    monkeypatch.setattr(def_search, "_proof_operand_has_location", lambda *_a: True)
    cache = {}
    first = _proof_origin_leaf("first")
    second = _proof_origin_leaf("second")
    resolver = def_search._py_slow_recursively_resolve_ast

    resolver(first, _ProofOriginBlock(7), SimpleNamespace(this=object()), cache=cache)
    resolver(second, _ProofOriginBlock(8), SimpleNamespace(this=object()), cache=cache)

    assert first.proof_origin is not None
    assert second.proof_origin is not None
    assert first.proof_origin != second.proof_origin
    assert len(create_z3_vars([first, second])) == 2


def test_terminal_origin_normalizes_distinct_mba_wrappers(monkeypatch):
    """Equivalent SWIG MBA wrappers use their native pointer identity."""

    monkeypatch.setattr(def_search, "_proof_operand_has_location", lambda *_a: True)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)
    first_block = _ProofOriginBlock(7)
    second_block = _ProofOriginBlock(7)

    class MbaWrapper:
        this = 0x1234

    first_block.mba = MbaWrapper()
    second_block.mba = MbaWrapper()
    leaf = _proof_origin_leaf("entry")
    scope = object()
    first = def_search._terminal_proof_origin(
        leaf.mop,
        first_block,
        SimpleNamespace(this=object()),
        max_predecessor_blocks=1,
        scope=scope,
    )
    second = def_search._terminal_proof_origin(
        leaf.mop,
        second_block,
        SimpleNamespace(this=object()),
        max_predecessor_blocks=1,
        scope=scope,
    )

    assert first is not None
    assert second == first


@pytest.mark.parametrize("predecessor_location", ["empty", "raises"])
def test_terminal_origin_validates_location_in_each_walk_block(
    monkeypatch, predecessor_location
):
    """A use-site location cannot certify an invalid predecessor location."""

    calls = []

    class FakeLocations:
        def __init__(self):
            self._empty = True

        def empty(self):
            return self._empty

    class Mba:
        this = 0x1234

        def __init__(self):
            self.blocks = {}

        def get_mblock(self, serial):
            return self.blocks[serial]

    class Block:
        def __init__(self, serial, *, predecessor=None, location="valid"):
            self.serial = serial
            self.start = 0x4000 + serial * 0x20
            self.end = self.start + 0x20
            self.this = object()
            self.mba = mba
            self.predecessor = predecessor
            self.location = location

        def append_use_list(self, locations, _mop, _access):
            calls.append(self.serial)
            if self.location == "raises":
                raise RuntimeError("predecessor location failed")
            locations._empty = self.location == "empty"

        def npred(self):
            return 0 if self.predecessor is None else 1

        def pred(self, index):
            assert index == 0
            return self.predecessor.serial

    mba = Mba()
    predecessor = Block(11, location=predecessor_location)
    use_block = Block(10, predecessor=predecessor, location="valid")
    mba.blocks[use_block.serial] = use_block
    mba.blocks[predecessor.serial] = predecessor

    monkeypatch.setattr(def_search.ida_hexrays, "mlist_t", FakeLocations)
    monkeypatch.setattr(
        def_search,
        "_materialize_mop_for_tracking",
        lambda mop, *_a, **_k: mop,
    )
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)

    mop = SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=4,
        r=1,
        valnum=0,
        this=object(),
    )
    origin = def_search._terminal_proof_origin(
        mop,
        use_block,
        SimpleNamespace(this=object()),
        max_predecessor_blocks=1,
        scope=object(),
    )

    assert origin is None
    assert calls == [use_block.serial, predecessor.serial]


def test_resolver_move_ast_preserves_source_operand(monkeypatch):
    """Resolver definitions must not overwrite a move's source with its dst."""

    from d810.hexrays.expr.ast import AstLeaf

    source = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=16, valnum=0)
    destination = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=8, valnum=0)
    source_ast = AstLeaf("source")
    source_ast.mop = source
    monkeypatch.setattr(def_search, "mop_to_ast", lambda mop, **_kwargs: source_ast)
    instruction = SimpleNamespace(
        opcode=ida_hexrays.m_mov,
        l=source,
        d=destination,
        ea=0x401000,
    )

    result = def_search._minsn_to_ast_with_budget(instruction, None)

    assert result is source_ast
    assert result.mop is source


def test_resolver_move_ast_preserves_source_width_anchor_and_budget(monkeypatch):
    """Resolver-only moves use the source value, width, anchors, and budget."""

    from d810.hexrays.expr.ast import AstLeaf

    source = SimpleNamespace(t=ida_hexrays.mop_r, size=2, r=16, valnum=0)
    destination = SimpleNamespace(t=ida_hexrays.mop_r, size=8, r=8, valnum=0)
    instruction = SimpleNamespace(
        opcode=ida_hexrays.m_mov,
        l=source,
        d=destination,
        ea=0x401234,
    )

    class Budget:
        def __init__(self):
            self.consumed = 0
            self.charged = []

        def consume(self):
            self.consumed += 1

        def mark_charged(self, occurrence):
            self.charged.append(occurrence)

    budget = Budget()
    seen = []

    def build_source(mop, *, node_budget):
        seen.append((mop, node_budget))
        node_budget.consume()
        ast = AstLeaf("source")
        ast.mop = mop
        ast.dest_size = mop.size
        node_budget.mark_charged(ast)
        return ast

    monkeypatch.setattr(def_search, "mop_to_ast", build_source)
    result = def_search._minsn_to_ast_with_budget(instruction, budget)

    assert result.mop is source
    assert result.dest_size == source.size
    assert result.ea == instruction.ea
    assert result.ins is instruction
    assert seen == [(source, budget)]
    assert budget.consumed == 1
    assert budget.charged == [result]


def test_ast_leaf_update_clears_stale_origin_without_replacement():
    """A failed binding cannot retain provenance from a previous AST."""

    from d810.hexrays.expr.ast import AstLeaf, AstNode

    target = AstLeaf("x")
    target.proof_origin = ("stale",)
    source = AstLeaf("x")
    candidate = AstNode(ida_hexrays.m_add, source, None)
    candidate._check_implicit_equalities()

    assert target.update_leafs_mop(candidate) is False
    assert target.proof_origin is None


def test_ast_leaf_update_copies_only_source_origin_with_source_mop():
    """A successful binding takes provenance from its matching source leaf."""

    from d810.hexrays.expr.ast import AstLeaf, AstNode

    source_mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=16, valnum=0)
    target = AstLeaf("x")
    target.proof_origin = ("stale",)
    source = AstLeaf("x")
    source.mop = source_mop
    source.proof_origin = ("source",)
    candidate = AstNode(ida_hexrays.m_add, source, None)
    candidate._check_implicit_equalities()

    assert target.update_leafs_mop(candidate) is True
    assert target.mop is source_mop
    assert target.proof_origin == source.proof_origin


def test_recursive_origin_fixture_uses_compiled_backend_when_enabled():
    """The parity fixture must not silently exercise Python in Cython mode."""

    from d810.core.cymode import CythonMode

    if CythonMode().is_enabled():
        assert def_search.get_recursive_resolver_backend() == "cython"


def test_terminal_origin_fails_closed_for_ambiguous_or_exhausted_paths(monkeypatch):
    """Joins and depth cutoffs are not unique block-entry proofs."""

    monkeypatch.setattr(def_search, "_proof_operand_has_location", lambda *_a: True)
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)
    leaf = _proof_origin_leaf("entry")

    class JoinBlock(_ProofOriginBlock):
        def npred(self):
            return 2

    assert (
        def_search._terminal_proof_origin(
            leaf.mop,
            JoinBlock(7),
            SimpleNamespace(this=object()),
            max_predecessor_blocks=1,
            scope=object(),
        )
        is None
    )

    class ChainBlock(_ProofOriginBlock):
        def __init__(self, serial, predecessor):
            super().__init__(serial)
            self._predecessor = predecessor

        def npred(self):
            return 1

        def pred(self, index):
            assert index == 0
            return self._predecessor.serial

    terminal = _ProofOriginBlock(9)

    class Mba:
        def get_mblock(self, serial):
            assert serial == terminal.serial
            return terminal

    chain = ChainBlock(8, terminal)
    chain.mba = Mba()
    assert (
        def_search._terminal_proof_origin(
            leaf.mop,
            chain,
            SimpleNamespace(this=object()),
            max_predecessor_blocks=0,
            scope=object(),
        )
        is None
    )


def test_terminal_origin_fails_closed_for_reaching_definition_or_location_error(
    monkeypatch,
):
    """A definition, empty location, or API error cannot create provenance."""

    leaf = _proof_origin_leaf("entry")
    block = _ProofOriginBlock(7)
    ins = SimpleNamespace(this=object())
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: object())
    monkeypatch.setattr(def_search, "_proof_operand_has_location", lambda *_a: True)
    assert (
        def_search._terminal_proof_origin(
            leaf.mop, block, ins, max_predecessor_blocks=1, scope=object()
        )
        is None
    )

    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_a: None)
    monkeypatch.setattr(def_search, "_proof_operand_has_location", lambda *_a: False)
    assert (
        def_search._terminal_proof_origin(
            leaf.mop, block, ins, max_predecessor_blocks=1, scope=object()
        )
        is None
    )

    monkeypatch.setattr(
        def_search,
        "_proof_operand_has_location",
        lambda *_a: (_ for _ in ()).throw(RuntimeError("location")),
    )
    assert (
        def_search._terminal_proof_origin(
            leaf.mop, block, ins, max_predecessor_blocks=1, scope=object()
        )
        is None
    )


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
