"""Tests for scc_analysis's INFO/DEBUG log split (slice 3 of
unflat-diagnostics-legibility, ticket d81-ymrt).

log_sccs()/classify_loop_regions() already emit one summary INFO line;
the per-component/per-region detail loop was also firing at INFO
(17,474 lines in the 8-day sample). It moves to DEBUG here without
touching the summary line.
"""

import logging

from d810.analyses.control_flow.scc_analysis import (
    LoopRegion,
    StateSCC,
    classify_loop_regions,
    log_sccs,
)
from d810.core.logging import LevelFlag


def _at_level(caplog, level, logger_name):
    """caplog.set_level() sets the stdlib logger's .level directly, but
    D810Logger.debug_on is a cached LevelFlag (src/d810/core/logging.py)
    that only recomputes when LevelFlag.bump_config_version() is called.
    Without the bump, a level change made outside configure_loggers()'s
    dictConfig would not be observed by the cached flag.
    """
    caplog.set_level(level, logger=logger_name)
    LevelFlag.bump_config_version()


def _scc(scc_id, states, has_self_loop=False, is_trivial=False):
    return StateSCC(
        scc_id=scc_id,
        states=frozenset(states),
        nodes=frozenset({scc_id}),
        has_self_loop=has_self_loop,
        is_trivial=is_trivial,
    )


class TestLogSccs:
    def test_info_has_one_summary_line_no_per_component_detail(self, caplog):
        sccs = (
            _scc(0, {0x1000, 0x2000}),
            _scc(1, {0x3000}, has_self_loop=True),
        )
        _at_level(caplog, logging.INFO, "d810.analyses.control_flow.scc_analysis")
        log_sccs(sccs)

        summary = [r for r in caplog.records if "cyclic component(s)" in r.message]
        detail = [r for r in caplog.records if "cycle id=" in r.message]
        assert len(summary) == 1
        assert detail == []

    def test_debug_has_per_component_detail(self, caplog):
        sccs = (_scc(0, {0x1000}),)
        _at_level(caplog, logging.DEBUG, "d810.analyses.control_flow.scc_analysis")
        log_sccs(sccs)

        detail = [r for r in caplog.records if "cycle id=0" in r.message]
        assert len(detail) == 1

    def test_no_cyclic_sccs_emits_nothing(self, caplog):
        sccs = (_scc(0, set(), is_trivial=True),)
        _at_level(caplog, logging.INFO, "d810.analyses.control_flow.scc_analysis")
        log_sccs(sccs)

        assert caplog.records == []


class TestClassifyLoopRegions:
    class _FakeDag:
        def __init__(self, sccs):
            self.sccs = sccs

    def test_info_has_one_summary_line_no_per_region_detail(self, caplog):
        scc = _scc(0, {0x1000})
        dag = self._FakeDag((scc,))
        _at_level(caplog, logging.INFO, "d810.analyses.control_flow.scc_analysis")
        regions = classify_loop_regions(dag, dispatcher_region=set())

        assert len(regions) == 1
        summary = [r for r in caplog.records if "classified" in r.message]
        detail = [r for r in caplog.records if "loop region: id=" in r.message]
        assert len(summary) == 1
        assert detail == []

    def test_debug_has_per_region_detail(self, caplog):
        scc = _scc(0, {0x1000})
        dag = self._FakeDag((scc,))
        _at_level(caplog, logging.DEBUG, "d810.analyses.control_flow.scc_analysis")
        classify_loop_regions(dag, dispatcher_region=set())

        detail = [r for r in caplog.records if "loop region: id=0" in r.message]
        assert len(detail) == 1
