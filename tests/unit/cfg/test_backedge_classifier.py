"""Tests for back-edge classification."""
from __future__ import annotations

from d810.cfg.backedge_classifier import (
    BackedgeClass,
    BackedgeClassification,
    classify_backedge,
    classify_backedges,
    parse_var_tokens,
)


class TestParseVarTokens:
    def test_empty_string(self) -> None:
        assert parse_var_tokens("") == frozenset()

    def test_none_input(self) -> None:
        assert parse_var_tokens(None) == frozenset()

    def test_single_token(self) -> None:
        assert parse_var_tokens("mov %var_178.8, rax.8") == frozenset({"%var_178"})

    def test_multiple_tokens(self) -> None:
        text = "add    %var_178.8, #1.8, %var_170.8"
        assert parse_var_tokens(text) == frozenset({"%var_178", "%var_170"})

    def test_hex_digits(self) -> None:
        text = "sub %var_3A8.8, %var_F0.8, %var_100.8"
        assert parse_var_tokens(text) == frozenset(
            {"%var_3A8", "%var_F0", "%var_100"}
        )

    def test_dedupes_repeats(self) -> None:
        text = "add %var_50.8, %var_50.8, %var_50.8"
        assert parse_var_tokens(text) == frozenset({"%var_50"})

    def test_no_tokens_in_unrelated_text(self) -> None:
        assert parse_var_tokens("rax.8 + #0xD.8") == frozenset()


class TestClassifyBackedge:
    def test_empty_tgt_predicate_returns_unknown(self) -> None:
        result = classify_backedge(
            src_serial=10,
            tgt_serial=4,
            src_writes=frozenset({"%var_178"}),
            tgt_predicate_reads=frozenset(),
        )
        assert result.classification is BackedgeClass.UNKNOWN
        assert result.is_real_loop is False
        assert result.is_spurious is False
        assert result.overlap == frozenset()
        assert "no readable tail predicate" in result.reason

    def test_overlap_classifies_real_loop(self) -> None:
        result = classify_backedge(
            src_serial=18,
            tgt_serial=2,
            src_writes=frozenset({"%var_1C8", "%var_310"}),
            tgt_predicate_reads=frozenset({"%var_1C8"}),
        )
        assert result.classification is BackedgeClass.REAL_LOOP
        assert result.is_real_loop is True
        assert result.is_spurious is False
        assert result.overlap == frozenset({"%var_1C8"})
        assert "%var_1C8" in result.reason

    def test_disjoint_sets_classify_spurious(self) -> None:
        result = classify_backedge(
            src_serial=15,
            tgt_serial=13,
            src_writes=frozenset({"%var_F0"}),
            tgt_predicate_reads=frozenset({"%var_330"}),
        )
        assert result.classification is BackedgeClass.SPURIOUS
        assert result.is_spurious is True
        assert result.is_real_loop is False
        assert result.overlap == frozenset()
        assert "does not write any var" in result.reason

    def test_multiple_overlap_all_reported(self) -> None:
        result = classify_backedge(
            src_serial=10,
            tgt_serial=4,
            src_writes=frozenset({"%var_178", "%var_180", "%var_188"}),
            tgt_predicate_reads=frozenset({"%var_180", "%var_188", "%var_200"}),
        )
        assert result.classification is BackedgeClass.REAL_LOOP
        assert result.overlap == frozenset({"%var_180", "%var_188"})

    def test_empty_writes_with_nonempty_reads_is_spurious(self) -> None:
        # Source mutates nothing; back-edge must be spurious.
        result = classify_backedge(
            src_serial=44,
            tgt_serial=33,
            src_writes=frozenset(),
            tgt_predicate_reads=frozenset({"%var_F0"}),
        )
        assert result.classification is BackedgeClass.SPURIOUS

    def test_serials_preserved_in_result(self) -> None:
        result = classify_backedge(
            src_serial=42,
            tgt_serial=7,
            src_writes=frozenset(),
            tgt_predicate_reads=frozenset({"%var_50"}),
        )
        assert result.src_serial == 42
        assert result.tgt_serial == 7


class TestClassifyBackedges:
    def test_empty_input_returns_empty_tuple(self) -> None:
        result = classify_backedges([], block_writes={}, block_predicate_reads={})
        assert result == ()

    def test_preserves_input_order(self) -> None:
        edges = [(18, 2), (15, 13), (10, 4)]
        block_writes = {
            18: frozenset({"%var_1C8"}),
            15: frozenset({"%var_F0"}),
            10: frozenset({"%var_178"}),
        }
        block_predicate_reads = {
            2: frozenset({"%var_1C8"}),
            13: frozenset({"%var_330"}),
            4: frozenset({"%var_178"}),
        }
        result = classify_backedges(
            edges,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )
        assert len(result) == 3
        assert (result[0].src_serial, result[0].tgt_serial) == (18, 2)
        assert (result[1].src_serial, result[1].tgt_serial) == (15, 13)
        assert (result[2].src_serial, result[2].tgt_serial) == (10, 4)
        assert result[0].is_real_loop
        assert result[1].is_spurious
        assert result[2].is_real_loop

    def test_missing_keys_treated_as_empty(self) -> None:
        # Edge references blocks not present in either map.
        result = classify_backedges(
            [(99, 100)],
            block_writes={},
            block_predicate_reads={},
        )
        assert len(result) == 1
        # Empty tgt predicate reads → UNKNOWN.
        assert result[0].classification is BackedgeClass.UNKNOWN

    def test_mixed_classification_summary(self) -> None:
        # Models the sub_7FFD shape: some real loops, some spurious.
        edges = [(10, 4), (12, 5), (14, 6), (15, 13), (18, 2),
                 (32, 29), (35, 4), (44, 33), (46, 15), (47, 27)]
        # Carrier in source → real loop. None → spurious or unknown.
        block_writes = {
            10: frozenset({"%var_178"}),     # head-byte stride update
            12: frozenset({"%var_330"}),
            14: frozenset(),                 # no writes
            15: frozenset({"%var_5B8"}),     # opaque MBA carrier write
            18: frozenset({"%var_1C8"}),     # chunk-emit carrier
            32: frozenset({"%var_198"}),     # block-emit counter
            35: frozenset({"%var_178"}),     # secondary head-byte
            44: frozenset(),                 # tail iter — no carrier
            46: frozenset(),                 # tail redo — no carrier
            47: frozenset(),                 # tail iter — no carrier
        }
        block_predicate_reads = {
            4: frozenset({"%var_178"}),       # head-byte test
            5: frozenset({"%var_330"}),
            6: frozenset({"%var_F0"}),
            13: frozenset({"%var_F0"}),
            2: frozenset({"%var_1C8"}),       # chunk-size test
            29: frozenset({"%var_198"}),      # counter test
            33: frozenset({"%var_F0"}),
            15: frozenset({"%var_5B8"}),      # multi-pred test
            27: frozenset({"%var_F0"}),
        }
        result = classify_backedges(
            edges,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )
        real = [c for c in result if c.is_real_loop]
        spurious = [c for c in result if c.is_spurious]
        # Expected: 5 real-loop edges, 5 spurious.
        assert len(real) == 5
        assert len(spurious) == 5
        real_pairs = {(c.src_serial, c.tgt_serial) for c in real}
        spurious_pairs = {(c.src_serial, c.tgt_serial) for c in spurious}
        assert real_pairs == {(10, 4), (12, 5), (18, 2), (32, 29), (35, 4)}
        assert spurious_pairs == {(14, 6), (15, 13), (44, 33), (46, 15), (47, 27)}


class TestBackedgeClassificationDataclass:
    def test_real_loop_shortcuts(self) -> None:
        c = BackedgeClassification(
            src_serial=18, tgt_serial=2,
            classification=BackedgeClass.REAL_LOOP,
            src_writes=frozenset({"%var_1C8"}),
            tgt_predicate_reads=frozenset({"%var_1C8"}),
            overlap=frozenset({"%var_1C8"}),
            reason="x",
        )
        assert c.is_real_loop
        assert not c.is_spurious

    def test_spurious_shortcuts(self) -> None:
        c = BackedgeClassification(
            src_serial=44, tgt_serial=33,
            classification=BackedgeClass.SPURIOUS,
            src_writes=frozenset(),
            tgt_predicate_reads=frozenset({"%var_F0"}),
            overlap=frozenset(),
            reason="x",
        )
        assert c.is_spurious
        assert not c.is_real_loop

    def test_unknown_shortcuts(self) -> None:
        c = BackedgeClassification(
            src_serial=99, tgt_serial=100,
            classification=BackedgeClass.UNKNOWN,
            src_writes=frozenset(),
            tgt_predicate_reads=frozenset(),
            overlap=frozenset(),
            reason="x",
        )
        assert not c.is_real_loop
        assert not c.is_spurious
