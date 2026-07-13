from __future__ import annotations

from d810.hexrays.hooks.optimization_suppression import (
    d810_optimization_is_suppressed,
    suppress_d810_optimization,
)


def test_optimization_suppression_is_scoped_and_nested() -> None:
    assert d810_optimization_is_suppressed() is False
    with suppress_d810_optimization():
        assert d810_optimization_is_suppressed() is True
        with suppress_d810_optimization():
            assert d810_optimization_is_suppressed() is True
        assert d810_optimization_is_suppressed() is True
    assert d810_optimization_is_suppressed() is False
