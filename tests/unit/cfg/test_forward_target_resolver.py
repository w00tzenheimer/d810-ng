"""Tests for the forward-target resolver."""
from __future__ import annotations

from d810.cfg.dispatcher_aware_classifier import (
    DispatcherAwareClassification,
    DispatcherAwareEdgeClass,
)
from d810.cfg.forward_target_resolver import (
    PredicateInfo,
    ResolvedTarget,
    resolve_forward_target,
)


def _mk_classification(
    cls: DispatcherAwareEdgeClass,
    *,
    src: int = 42,
    tgt: int = 2,
) -> DispatcherAwareClassification:
    return DispatcherAwareClassification(
        src_serial=src,
        tgt_serial=tgt,
        classification=cls,
        src_writes=frozenset(),
        tgt_predicate_reads=frozenset(),
        overlap=frozenset(),
        state_var_overlap=frozenset(),
        reason="x",
    )


class TestDispatcherRoundTrip:
    def test_const_state_with_bst_match_resolves(self) -> None:
        # Classic OLLVM trampoline: handler at blk[42] writes
        # %state_var = 0x6b588048; dispatcher BST resolves to handler 11.
        bst_table = {0x6B588048: 11, 0x37B42A3F: 7}
        c = _mk_classification(
            DispatcherAwareEdgeClass.DISPATCHER_ROUND_TRIP, src=42, tgt=2
        )
        result = resolve_forward_target(
            c,
            src_reaching_const={"%var_3C": 0x6B588048},
            bst_resolver=lambda k: bst_table.get(k),
        )
        assert isinstance(result, ResolvedTarget)
        assert result.src_serial == 42
        assert result.old_target == 2
        assert result.new_target == 11
        assert result.resolution_kind == "bst_const_resolved"
        assert "0x6b588048" in result.reason
        assert "blk[11]" in result.reason

    def test_const_state_via_range_row(self) -> None:
        # BST row encodes a range: any value in [0x000..0x100] -> 7.
        # The resolver doesn't know about ranges; it delegates to the
        # bst_resolver callable. This test documents that contract.
        def bst(k: int) -> int | None:
            if 0 <= k <= 0x100:
                return 7
            return None

        c = _mk_classification(DispatcherAwareEdgeClass.DISPATCHER_ROUND_TRIP)
        result = resolve_forward_target(
            c, src_reaching_const={"%var_3C": 0x42}, bst_resolver=bst
        )
        assert result is not None
        assert result.new_target == 7

    def test_missing_state_def_returns_none(self) -> None:
        c = _mk_classification(DispatcherAwareEdgeClass.DISPATCHER_ROUND_TRIP)
        result = resolve_forward_target(
            c,
            src_reaching_const={"%var_3C": None},
            bst_resolver=lambda k: 99,
        )
        assert result is None

    def test_no_bst_resolver_returns_none(self) -> None:
        c = _mk_classification(DispatcherAwareEdgeClass.DISPATCHER_ROUND_TRIP)
        result = resolve_forward_target(
            c, src_reaching_const={"%var_3C": 0x42}, bst_resolver=None,
        )
        assert result is None

    def test_bst_returns_none_keeps_unresolved(self) -> None:
        # State const exists but BST has no row for it (e.g. value
        # outside dispatcher's known range).
        c = _mk_classification(DispatcherAwareEdgeClass.DISPATCHER_ROUND_TRIP)
        result = resolve_forward_target(
            c,
            src_reaching_const={"%var_3C": 0xDEADBEEF},
            bst_resolver=lambda k: None,
        )
        assert result is None

    def test_bst_resolver_exception_treated_as_unresolved(self) -> None:
        def boom(k: int) -> int | None:
            raise RuntimeError("BST not built")

        c = _mk_classification(DispatcherAwareEdgeClass.DISPATCHER_ROUND_TRIP)
        result = resolve_forward_target(
            c, src_reaching_const={"%var_3C": 0x42}, bst_resolver=boom,
        )
        assert result is None

    def test_multiple_reaching_consts_uses_first_resolvable(self) -> None:
        # If src has multiple known consts (e.g. a temp + state var),
        # the resolver tries each via the BST callable. Sort order is
        # alphabetical to keep behavior deterministic.
        bst = lambda k: 11 if k == 0x6B588048 else None  # noqa: E731
        c = _mk_classification(DispatcherAwareEdgeClass.DISPATCHER_ROUND_TRIP)
        result = resolve_forward_target(
            c,
            src_reaching_const={
                "%var_178": 0x12345678,    # not a state value
                "%var_3C": 0x6B588048,     # the state value
            },
            bst_resolver=bst,
        )
        assert result is not None
        assert result.new_target == 11


class TestPredicateEdge:
    def test_jge_taken_branch(self) -> None:
        c = _mk_classification(DispatcherAwareEdgeClass.SPURIOUS, src=18, tgt=2)
        pred = PredicateInfo(
            opcode="jge", read_var="%var_1C8", test_const=0x80,
            taken_succ=19, fallthrough_succ=3,
        )
        result = resolve_forward_target(
            c,
            src_reaching_const={"%var_1C8": 0x100},  # >= 0x80 -> taken
            target_predicate=pred,
        )
        assert result is not None
        assert result.new_target == 19
        assert result.resolution_kind == "predicate_simulated"

    def test_jge_fallthrough_branch(self) -> None:
        c = _mk_classification(DispatcherAwareEdgeClass.SPURIOUS, src=18, tgt=2)
        pred = PredicateInfo(
            opcode="jge", read_var="%var_1C8", test_const=0x80,
            taken_succ=19, fallthrough_succ=3,
        )
        result = resolve_forward_target(
            c,
            src_reaching_const={"%var_1C8": 0x10},  # < 0x80 -> fallthrough
            target_predicate=pred,
        )
        assert result is not None
        assert result.new_target == 3

    def test_jz_equal_branches_to_taken(self) -> None:
        c = _mk_classification(DispatcherAwareEdgeClass.SPURIOUS)
        pred = PredicateInfo(
            opcode="jz", read_var="%var_X", test_const=0,
            taken_succ=10, fallthrough_succ=20,
        )
        result = resolve_forward_target(
            c, src_reaching_const={"%var_X": 0}, target_predicate=pred,
        )
        assert result is not None and result.new_target == 10

    def test_jz_unequal_branches_to_fallthrough(self) -> None:
        c = _mk_classification(DispatcherAwareEdgeClass.SPURIOUS)
        pred = PredicateInfo(
            opcode="jz", read_var="%var_X", test_const=0,
            taken_succ=10, fallthrough_succ=20,
        )
        result = resolve_forward_target(
            c, src_reaching_const={"%var_X": 5}, target_predicate=pred,
        )
        assert result is not None and result.new_target == 20

    def test_jcnd_zero_falls_through(self) -> None:
        c = _mk_classification(DispatcherAwareEdgeClass.SPURIOUS)
        pred = PredicateInfo(
            opcode="jcnd", read_var="%var_X", test_const=None,
            taken_succ=10, fallthrough_succ=20,
        )
        result = resolve_forward_target(
            c, src_reaching_const={"%var_X": 0}, target_predicate=pred,
        )
        assert result is not None and result.new_target == 20

    def test_jcnd_nonzero_takes_branch(self) -> None:
        c = _mk_classification(DispatcherAwareEdgeClass.SPURIOUS)
        pred = PredicateInfo(
            opcode="jcnd", read_var="%var_X", test_const=None,
            taken_succ=10, fallthrough_succ=20,
        )
        result = resolve_forward_target(
            c, src_reaching_const={"%var_X": 0x42}, target_predicate=pred,
        )
        assert result is not None and result.new_target == 10

    def test_unsigned_vs_signed_comparison(self) -> None:
        # ja is unsigned: -1 (0xFFF...FF) > 0.  jg is signed: -1 < 0.
        c = _mk_classification(DispatcherAwareEdgeClass.SPURIOUS)
        ja = PredicateInfo(
            opcode="ja", read_var="%var_X", test_const=0,
            taken_succ=1, fallthrough_succ=2,
        )
        jg = PredicateInfo(
            opcode="jg", read_var="%var_X", test_const=0,
            taken_succ=1, fallthrough_succ=2,
        )
        ja_result = resolve_forward_target(
            c, src_reaching_const={"%var_X": -1}, target_predicate=ja,
        )
        jg_result = resolve_forward_target(
            c, src_reaching_const={"%var_X": -1}, target_predicate=jg,
        )
        assert ja_result is not None and ja_result.new_target == 1   # unsigned: taken
        assert jg_result is not None and jg_result.new_target == 2   # signed: fallthrough

    def test_ambiguous_predicate_input_returns_none(self) -> None:
        c = _mk_classification(DispatcherAwareEdgeClass.SPURIOUS)
        pred = PredicateInfo(
            opcode="jge", read_var="%var_X", test_const=10,
            taken_succ=1, fallthrough_succ=2,
        )
        # Reaching def for %var_X is non-constant.
        result = resolve_forward_target(
            c, src_reaching_const={"%var_X": None}, target_predicate=pred,
        )
        assert result is None

    def test_unknown_opcode_returns_none(self) -> None:
        c = _mk_classification(DispatcherAwareEdgeClass.SPURIOUS)
        pred = PredicateInfo(
            opcode="jweird", read_var="%var_X", test_const=10,
            taken_succ=1, fallthrough_succ=2,
        )
        result = resolve_forward_target(
            c, src_reaching_const={"%var_X": 5}, target_predicate=pred,
        )
        assert result is None

    def test_missing_predicate_returns_none(self) -> None:
        c = _mk_classification(DispatcherAwareEdgeClass.SPURIOUS)
        result = resolve_forward_target(
            c,
            src_reaching_const={"%var_X": 5},
            target_predicate=None,
        )
        assert result is None


class TestRefuseToRewriteRealLoops:
    def test_real_loop_classification_returns_none(self) -> None:
        # Even with a perfectly resolvable reaching def, refuse to
        # rewrite a back-edge classified as REAL_LOOP.
        c = _mk_classification(DispatcherAwareEdgeClass.REAL_LOOP)
        pred = PredicateInfo(
            opcode="jge", read_var="%var_178", test_const=10,
            taken_succ=1, fallthrough_succ=2,
        )
        result = resolve_forward_target(
            c,
            src_reaching_const={"%var_178": 5},
            bst_resolver=lambda k: 99,
            target_predicate=pred,
        )
        assert result is None

    def test_unknown_classification_returns_none(self) -> None:
        c = _mk_classification(DispatcherAwareEdgeClass.UNKNOWN)
        result = resolve_forward_target(
            c,
            src_reaching_const={"%var_X": 5},
            bst_resolver=lambda k: 11,
        )
        assert result is None
