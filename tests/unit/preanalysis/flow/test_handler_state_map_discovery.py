from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.handler_state_map_discovery import (
    collect_unique_interval_handler_backfills,
)


class TestCollectUniqueIntervalHandlerBackfills:
    def test_collects_unique_non_existing_targets(self) -> None:
        dispatcher = SimpleNamespace(
            _rows=(
                SimpleNamespace(target=24, lo=0x11, hi=0x12),
                SimpleNamespace(target=25, lo=0x22, hi=0x23),
            )
        )

        backfills = collect_unique_interval_handler_backfills(
            {24: 0x10},
            dispatcher,
        )

        assert [(b.target, b.lo, b.hi) for b in backfills] == [(25, 0x22, 0x23)]

    def test_skips_multi_row_targets(self) -> None:
        dispatcher = SimpleNamespace(
            _rows=(
                SimpleNamespace(target=24, lo=0x11, hi=0x20),
                SimpleNamespace(target=24, lo=0x20, hi=0x30),
                SimpleNamespace(target=25, lo=0x30, hi=0x31),
            )
        )

        backfills = collect_unique_interval_handler_backfills({}, dispatcher)

        assert [(b.target, b.lo, b.hi) for b in backfills] == [(25, 0x30, 0x31)]
