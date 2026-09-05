"""The generic optblock ``except`` must name the exception (ticket d81-aw7v).

``BlockOptimizerManager._func`` funnels every non-``RuntimeError`` /
non-``D810Exception`` / non-``DatabaseError`` failure into one generic handler
that used to log ``"Exception in block optimizer on blk %d: %s" % (serial, e)``.
For an exception built with no arguments that renders as a bare trailing
colon: no type, no traceback, nothing. A Target A preflight rejection produced
exactly that line -- the sole trace of the defect in a 245 MB DEBUG log.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import ida_hexrays

from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager


class _EmptyMessageError(Exception):
    """Any exception raised with no arguments has an empty ``str()``."""


def _manager(raising: Exception) -> BlockOptimizerManager:
    manager = object.__new__(BlockOptimizerManager)
    manager._decompilation_lifecycle = None
    manager._pipeline_just_fired = False
    manager._pass_count = 0
    manager._max_passes_current = BlockOptimizerManager._BASE_PASSES_PER_MATURITY
    manager.current_maturity = int(ida_hexrays.MMAT_GLBOPT1)
    manager.log_info_on_input = lambda blk: False

    def _optimize(blk):
        raise raising

    manager.optimize = _optimize
    return manager


def _blk() -> SimpleNamespace:
    return SimpleNamespace(serial=1, mba=SimpleNamespace(qty=10))


def test_generic_optblock_exception_logs_type_and_traceback(caplog) -> None:
    manager = _manager(_EmptyMessageError())

    with caplog.at_level(logging.WARNING, logger="d810.optimizer"):
        assert manager._func(_blk()) == 0

    records = [
        record
        for record in caplog.records
        if "in block optimizer on blk" in record.getMessage()
    ]
    assert len(records) == 1
    record = records[0]
    assert record.levelno == logging.WARNING
    assert "_EmptyMessageError" in record.getMessage()
    assert record.exc_info is not None
    assert record.exc_info[0] is _EmptyMessageError


def test_generic_optblock_exception_message_is_never_a_bare_colon(caplog) -> None:
    manager = _manager(AssertionError())

    with caplog.at_level(logging.WARNING, logger="d810.optimizer"):
        manager._func(_blk())

    messages = [
        record.getMessage()
        for record in caplog.records
        if "in block optimizer on blk" in record.getMessage()
    ]
    assert messages
    for message in messages:
        assert not message.rstrip().endswith(":")
        assert "AssertionError" in message


def test_generic_optblock_exception_suppresses_the_rest_of_the_maturity() -> None:
    manager = _manager(_EmptyMessageError())

    manager._func(_blk())

    assert manager._pass_count > manager._max_passes_current
