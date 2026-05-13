"""Unit tests for ModificationBuilder's intra-fragment RedirectGoto ledger.

Covers the Mode 1 bug pattern: a single strategy's ``plan()`` call emitting
two RedirectGoto mods on the same source_block with different new_targets.
The ledger lives on the builder instance (per-strategy-pass scope), so a
new builder constructed via ``from_snapshot`` starts with a clean ledger.

Only the ``RedirectGoto`` emission paths are tracked:

- ``goto_redirect`` (1-way source)
- ``edge_redirect`` (1-way source, no ``via_pred``)

``ConvertToGoto``, ``RedirectBranch``, and ``EdgeRedirectViaPredSplit`` are
explicitly out of scope for this ledger.
"""
from __future__ import annotations

import logging
import re

import pytest

from d810.cfg.graph_modification import (
    ConvertToGoto,
    EdgeRedirectViaPredSplit,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.modification_builder import ModificationBuilder


MODULE_LOGGER_NAME = "d810.cfg.modification_builder"


def _make_builder(
    *,
    nsucc: dict[int, int] | None = None,
    succs: dict[int, tuple[int, ...]] | None = None,
) -> ModificationBuilder:
    return ModificationBuilder(
        block_nsucc_map=dict(nsucc or {}),
        block_succ_map=dict(succs or {}),
    )


def _override_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        record
        for record in caplog.records
        if "INTRA_FRAGMENT_REDIRECT_OVERRIDE" in record.getMessage()
    ]


class TestGotoRedirectLedger:
    def test_no_conflict_different_sources(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        builder = _make_builder(
            nsucc={76: 1, 77: 1},
            succs={76: (2,), 77: (11,)},
        )
        with caplog.at_level(logging.WARNING, logger=MODULE_LOGGER_NAME):
            mod_a = builder.goto_redirect(76, 11)
            mod_b = builder.goto_redirect(77, 2)

        assert isinstance(mod_a, RedirectGoto)
        assert isinstance(mod_b, RedirectGoto)
        assert mod_a.from_serial == 76 and mod_a.new_target == 11
        assert mod_b.from_serial == 77 and mod_b.new_target == 2
        assert _override_records(caplog) == []

    def test_consistent_repeat_same_new_target_no_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        builder = _make_builder(
            nsucc={76: 1},
            succs={76: (2,)},
        )
        with caplog.at_level(logging.WARNING, logger=MODULE_LOGGER_NAME):
            mod_1 = builder.goto_redirect(76, 11)
            # Second emission with the SAME new_target — not a conflict.
            mod_2 = builder.goto_redirect(76, 11)

        assert isinstance(mod_1, RedirectGoto)
        assert isinstance(mod_2, RedirectGoto)
        assert mod_1.new_target == mod_2.new_target == 11
        assert _override_records(caplog) == []

    def test_same_source_different_new_target_emits_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Reproduces the Mode 1 bug pattern observed on sub_7FFD3338C040:
        # mod[26]: RedirectGoto src=76 tgt=11 old=2
        # mod[75]: RedirectGoto src=76 tgt=2  old=11
        builder = _make_builder(
            nsucc={76: 1},
            succs={76: (2,)},
        )

        with caplog.at_level(logging.WARNING, logger=MODULE_LOGGER_NAME):
            first = builder.goto_redirect(76, 11, old_target=2)
            second = builder.goto_redirect(76, 2, old_target=11)

        assert isinstance(first, RedirectGoto)
        assert isinstance(second, RedirectGoto)

        override_records = _override_records(caplog)
        assert len(override_records) == 1, (
            f"expected exactly one override warning, got {len(override_records)}: "
            f"{[r.getMessage() for r in override_records]}"
        )

        record = override_records[0]
        assert record.levelno == logging.WARNING
        message = record.getMessage()
        assert "src=76" in message
        assert "prior=(new_target=11, old_target=2)" in message
        assert "now=(new_target=2, old_target=11)" in message
        assert "origin=goto_redirect" in message

    def test_three_distinct_new_targets_emit_two_warnings(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Each new (src, new_target) that conflicts with ANY prior emission
        # on the same src must log. With three distinct new_targets, the
        # second emission conflicts with the first, and the third conflicts
        # with the first (loop breaks on first mismatch), giving 2 warnings.
        builder = _make_builder(
            nsucc={10: 1},
            succs={10: (99,)},
        )

        with caplog.at_level(logging.WARNING, logger=MODULE_LOGGER_NAME):
            builder.goto_redirect(10, 100)
            builder.goto_redirect(10, 200)
            builder.goto_redirect(10, 300)

        override_records = _override_records(caplog)
        assert len(override_records) == 2
        # Both should cite src=10
        assert all("src=10" in r.getMessage() for r in override_records)

    def test_ledger_is_builder_instance_scoped(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        builder_a = _make_builder(nsucc={76: 1}, succs={76: (2,)})
        builder_b = _make_builder(nsucc={76: 1}, succs={76: (2,)})

        with caplog.at_level(logging.WARNING, logger=MODULE_LOGGER_NAME):
            builder_a.goto_redirect(76, 11)
            # A different builder instance must NOT see builder_a's history.
            builder_b.goto_redirect(76, 22)

        assert _override_records(caplog) == []

        # Now confirm builder_a still has its own history and flags a conflict.
        with caplog.at_level(logging.WARNING, logger=MODULE_LOGGER_NAME):
            builder_a.goto_redirect(76, 22)

        override_records = _override_records(caplog)
        assert len(override_records) == 1
        assert "src=76" in override_records[0].getMessage()
        assert "prior=(new_target=11" in override_records[0].getMessage()
        assert "now=(new_target=22" in override_records[0].getMessage()

    def test_convert_to_goto_path_is_not_tracked(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # ConvertToGoto (2-way source) is explicitly out of scope.
        builder = _make_builder(nsucc={42: 2}, succs={42: (7, 9)})
        with caplog.at_level(logging.WARNING, logger=MODULE_LOGGER_NAME):
            first = builder.goto_redirect(42, 100)
            second = builder.goto_redirect(42, 200)

        assert isinstance(first, ConvertToGoto)
        assert isinstance(second, ConvertToGoto)
        assert _override_records(caplog) == []
        # Ensure nothing was recorded in the ledger for the 2-way source.
        assert 42 not in builder._redirect_ledger


class TestEdgeRedirectLedger:
    def test_same_source_different_new_target_via_edge_redirect_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        builder = _make_builder(nsucc={76: 1}, succs={76: (2,)})

        with caplog.at_level(logging.WARNING, logger=MODULE_LOGGER_NAME):
            first = builder.edge_redirect(76, 11, old_target=2)
            second = builder.edge_redirect(76, 22, old_target=11)

        assert isinstance(first, RedirectGoto)
        assert isinstance(second, RedirectGoto)

        override_records = _override_records(caplog)
        assert len(override_records) == 1
        message = override_records[0].getMessage()
        assert "src=76" in message
        assert "origin=edge_redirect" in message

    def test_ledger_shared_across_goto_redirect_and_edge_redirect(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Both methods emit RedirectGoto on 1-way sources. A conflict across
        # the two API surfaces within the same builder must still be caught.
        builder = _make_builder(nsucc={76: 1}, succs={76: (2,)})

        with caplog.at_level(logging.WARNING, logger=MODULE_LOGGER_NAME):
            builder.goto_redirect(76, 11)
            builder.edge_redirect(76, 22)

        override_records = _override_records(caplog)
        assert len(override_records) == 1
        message = override_records[0].getMessage()
        assert "src=76" in message
        assert "prior=(new_target=11" in message
        assert "now=(new_target=22" in message
        # The overriding emission is the one via edge_redirect.
        assert "origin=edge_redirect" in message

    def test_redirect_branch_path_is_not_tracked(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # edge_redirect on a 2-way source returns RedirectBranch — out of scope.
        builder = _make_builder(nsucc={50: 2}, succs={50: (60, 70)})
        with caplog.at_level(logging.WARNING, logger=MODULE_LOGGER_NAME):
            first = builder.edge_redirect(50, 100, old_target=60)
            second = builder.edge_redirect(50, 200, old_target=60)

        assert isinstance(first, RedirectBranch)
        assert isinstance(second, RedirectBranch)
        assert _override_records(caplog) == []
        assert 50 not in builder._redirect_ledger

    def test_edge_redirect_via_pred_split_is_not_tracked(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # via_pred path returns EdgeRedirectViaPredSplit — out of scope.
        builder = _make_builder(nsucc={50: 1}, succs={50: (60,)})
        with caplog.at_level(logging.WARNING, logger=MODULE_LOGGER_NAME):
            first = builder.edge_redirect(50, 100, old_target=60, via_pred=42)
            second = builder.edge_redirect(50, 200, old_target=60, via_pred=42)

        assert isinstance(first, EdgeRedirectViaPredSplit)
        assert isinstance(second, EdgeRedirectViaPredSplit)
        assert _override_records(caplog) == []
        assert 50 not in builder._redirect_ledger


class TestLedgerLogFormat:
    def test_log_message_has_stable_grep_format(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Pin the format so log-analyst and grep-based tooling can rely on it.
        builder = _make_builder(nsucc={76: 1}, succs={76: (2,)})
        with caplog.at_level(logging.WARNING, logger=MODULE_LOGGER_NAME):
            builder.goto_redirect(76, 11, old_target=2)
            builder.goto_redirect(76, 2, old_target=11)

        records = _override_records(caplog)
        assert len(records) == 1
        pattern = re.compile(
            r"^INTRA_FRAGMENT_REDIRECT_OVERRIDE "
            r"src=76 "
            r"prior=\(new_target=11, old_target=2\) "
            r"now=\(new_target=2, old_target=11\) "
            r"origin=goto_redirect$"
        )
        message = records[0].getMessage()
        assert pattern.match(message), f"log format drift: {message!r}"
