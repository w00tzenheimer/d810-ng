"""Pure-logic tests for the Extensions listing (ticket d81-zijs).

The listing is fed by the real ``BackendRegistry.report()``, so it shows
load-bearing state -- including *why* an optional extension like ``d810-cobra``
is not doing anything, which nothing else in the plugin surfaces today.
"""

from __future__ import annotations

import pytest

from d810.core.plugins import BackendInfo, BackendStatus
from d810.ui.extensions_logic import (
    EXTENSION_COLUMNS,
    ExtensionRow,
    extension_rows,
    has_defects,
    summarize,
)


def _info(name: str, status: BackendStatus, **kw) -> BackendInfo:
    return BackendInfo(
        name=name,
        status=status,
        origin=kw.pop("origin", "built-in"),
        **kw,
    )


class TestColumns:
    def test_columns_match_the_row_fields(self) -> None:
        assert EXTENSION_COLUMNS == ("Name", "Origin", "API", "Status", "Detail")

    def test_every_row_yields_one_cell_per_column(self) -> None:
        rows = extension_rows([_info("cobra", BackendStatus.AVAILABLE)])
        assert len(rows[0].cells()) == len(EXTENSION_COLUMNS)


class TestRowMapping:
    def test_available_backend_reads_cleanly(self) -> None:
        row = extension_rows(
            [_info("z3", BackendStatus.AVAILABLE, api_version=1)]
        )[0]
        assert row.name == "z3"
        assert row.api_version == "1"
        assert row.status == "available"
        assert row.detail == ""

    def test_missing_api_version_renders_as_a_dash(self) -> None:
        row = extension_rows([_info("cobra", BackendStatus.UNAVAILABLE)])[0]
        assert row.api_version == "-"

    def test_reason_becomes_the_detail_cell(self) -> None:
        row = extension_rows(
            [
                _info(
                    "cobra",
                    BackendStatus.UNAVAILABLE,
                    reason="No module named 'd810_cobra'",
                )
            ]
        )[0]
        assert "d810_cobra" in row.detail

    def test_shadowed_candidates_are_surfaced(self) -> None:
        """Running on a fallback is exactly what a user needs told."""
        row = extension_rows(
            [_info("cobra", BackendStatus.AVAILABLE, shadowed=("pypi:d810-cobra",))]
        )[0]
        assert "pypi:d810-cobra" in row.detail

    def test_rows_preserve_registry_order(self) -> None:
        rows = extension_rows(
            [
                _info("b", BackendStatus.AVAILABLE),
                _info("a", BackendStatus.UNAVAILABLE),
            ]
        )
        assert [row.name for row in rows] == ["b", "a"]

    def test_empty_registry_yields_no_rows(self) -> None:
        assert extension_rows([]) == ()


class TestDefectSignalling:
    """UNAVAILABLE is a deployment fact; BROKEN is someone's bug."""

    @pytest.mark.parametrize(
        "status", [BackendStatus.BROKEN, BackendStatus.INCOMPATIBLE]
    )
    def test_defective_statuses_are_flagged(self, status: BackendStatus) -> None:
        row = extension_rows([_info("cobra", status)])[0]
        assert row.is_defect is True

    @pytest.mark.parametrize(
        "status",
        [
            BackendStatus.AVAILABLE,
            BackendStatus.UNAVAILABLE,
            BackendStatus.NOT_LOADED,
        ],
    )
    def test_normal_statuses_are_not_defects(self, status: BackendStatus) -> None:
        row = extension_rows([_info("z3", status)])[0]
        assert row.is_defect is False

    def test_has_defects_reports_across_the_listing(self) -> None:
        rows = extension_rows(
            [
                _info("z3", BackendStatus.AVAILABLE),
                _info("cobra", BackendStatus.BROKEN),
            ]
        )
        assert has_defects(rows) is True

    def test_no_defects_when_everything_is_normal(self) -> None:
        rows = extension_rows(
            [
                _info("z3", BackendStatus.AVAILABLE),
                _info("cobra", BackendStatus.UNAVAILABLE),
            ]
        )
        assert has_defects(rows) is False


class TestSummary:
    def test_counts_available_out_of_total(self) -> None:
        rows = extension_rows(
            [
                _info("z3", BackendStatus.AVAILABLE),
                _info("llvm", BackendStatus.AVAILABLE),
                _info("cobra", BackendStatus.UNAVAILABLE),
            ]
        )
        assert summarize(rows) == "2 of 3 available"

    def test_empty_listing_says_so(self) -> None:
        assert summarize(()) == "no extensions registered"

    def test_unprobed_registry_does_not_read_as_nothing_works(self) -> None:
        """Backends load lazily; a fresh session is all NOT_LOADED.

        Reporting that as "0 of 6 available" would tell a user everything is
        broken when nothing has been asked yet.
        """
        rows = extension_rows(
            [
                _info("z3", BackendStatus.NOT_LOADED),
                _info("llvm", BackendStatus.NOT_LOADED),
            ]
        )
        assert summarize(rows) == "2 registered, none loaded yet"

    def test_partially_probed_registry_counts_availability(self) -> None:
        rows = extension_rows(
            [
                _info("z3", BackendStatus.AVAILABLE),
                _info("llvm", BackendStatus.NOT_LOADED),
            ]
        )
        assert summarize(rows) == "1 of 2 available"

    def test_defects_are_called_out(self) -> None:
        rows = extension_rows(
            [
                _info("z3", BackendStatus.AVAILABLE),
                _info("cobra", BackendStatus.BROKEN),
            ]
        )
        assert "1 broken" in summarize(rows)


class TestImmutability:
    def test_row_is_frozen(self) -> None:
        row = extension_rows([_info("z3", BackendStatus.AVAILABLE)])[0]
        with pytest.raises((AttributeError, TypeError)):
            row.name = "nope"  # type: ignore[misc]

    def test_is_an_extension_row(self) -> None:
        assert isinstance(
            extension_rows([_info("z3", BackendStatus.AVAILABLE)])[0], ExtensionRow
        )
