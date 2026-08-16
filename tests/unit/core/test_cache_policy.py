"""Tests for the process-wide MOP cache replay policy."""

from __future__ import annotations

import pytest

from d810.core import (
    MOP_CONSTANT_CACHE,
    MOP_TO_AST_CACHE,
    temporary_mop_cache_policy,
)


@pytest.fixture(autouse=True)
def _clear_global_caches():
    original_constant = MOP_CONSTANT_CACHE.stats.configured_max_size
    original_ast = MOP_TO_AST_CACHE.stats.configured_max_size
    MOP_CONSTANT_CACHE.clear(reset_stats=True)
    MOP_TO_AST_CACHE.clear(reset_stats=True)
    yield
    MOP_CONSTANT_CACHE.reconfigure_capacity(original_constant)
    MOP_TO_AST_CACHE.reconfigure_capacity(original_ast)


def test_selected_capacity_constants() -> None:
    assert MOP_CONSTANT_CACHE.stats.configured_max_size == 4096
    assert MOP_TO_AST_CACHE.stats.configured_max_size == 40960


def test_policy_reconfigures_existing_caches_and_clears_session_stats() -> None:
    constant_object = MOP_CONSTANT_CACHE
    ast_object = MOP_TO_AST_CACHE
    MOP_CONSTANT_CACHE["old"] = 1
    MOP_TO_AST_CACHE["old"] = 1
    MOP_CONSTANT_CACHE.lookup("old")
    MOP_TO_AST_CACHE.lookup("old")

    with temporary_mop_cache_policy(17, 19):
        assert MOP_CONSTANT_CACHE is constant_object
        assert MOP_TO_AST_CACHE is ast_object
        assert len(MOP_CONSTANT_CACHE) == 0
        assert len(MOP_TO_AST_CACHE) == 0
        assert MOP_CONSTANT_CACHE.stats.lookups == 0
        assert MOP_TO_AST_CACHE.stats.lookups == 0
        assert MOP_CONSTANT_CACHE.stats.configured_max_size == 17
        assert MOP_TO_AST_CACHE.stats.configured_max_size == 19

    assert MOP_CONSTANT_CACHE is constant_object
    assert MOP_TO_AST_CACHE is ast_object
    assert MOP_CONSTANT_CACHE.stats.configured_max_size == 4096
    assert MOP_TO_AST_CACHE.stats.configured_max_size == 40960
    assert MOP_CONSTANT_CACHE.stats.lookups == 0
    assert MOP_TO_AST_CACHE.stats.lookups == 0


def test_nested_policy_restores_the_outer_limits() -> None:
    with temporary_mop_cache_policy(17, 19):
        with temporary_mop_cache_policy(23, 29):
            assert MOP_CONSTANT_CACHE.stats.configured_max_size == 23
            assert MOP_TO_AST_CACHE.stats.configured_max_size == 29
        assert MOP_CONSTANT_CACHE.stats.configured_max_size == 17
        assert MOP_TO_AST_CACHE.stats.configured_max_size == 19
    assert MOP_CONSTANT_CACHE.stats.configured_max_size == 4096
    assert MOP_TO_AST_CACHE.stats.configured_max_size == 40960


def test_policy_restores_nondefault_configured_limits() -> None:
    MOP_CONSTANT_CACHE.reconfigure_capacity(7)
    MOP_TO_AST_CACHE.reconfigure_capacity(11)

    with temporary_mop_cache_policy(17, 19):
        assert MOP_CONSTANT_CACHE.stats.configured_max_size == 17
        assert MOP_TO_AST_CACHE.stats.configured_max_size == 19

    assert MOP_CONSTANT_CACHE.stats.configured_max_size == 7
    assert MOP_TO_AST_CACHE.stats.configured_max_size == 11


def test_policy_restores_limits_after_body_error() -> None:
    constant_object = MOP_CONSTANT_CACHE
    ast_object = MOP_TO_AST_CACHE
    with pytest.raises(RuntimeError, match="replay failed"):
        with temporary_mop_cache_policy(17, 19):
            raise RuntimeError("replay failed")

    assert MOP_CONSTANT_CACHE is constant_object
    assert MOP_TO_AST_CACHE is ast_object
    assert MOP_CONSTANT_CACHE.stats.configured_max_size == 4096
    assert MOP_TO_AST_CACHE.stats.configured_max_size == 40960


def test_policy_rolls_back_first_cache_if_second_setup_fails(monkeypatch) -> None:
    def fail_ast_setup(capacity: int) -> None:
        raise RuntimeError(f"AST setup failed for {capacity}")

    monkeypatch.setattr(MOP_TO_AST_CACHE, "reconfigure_capacity", fail_ast_setup)

    with pytest.raises(RuntimeError, match="AST setup failed"):
        with temporary_mop_cache_policy(17, 19):
            raise AssertionError("context body must not run")

    assert MOP_CONSTANT_CACHE.stats.configured_max_size == 4096
    assert MOP_TO_AST_CACHE.stats.configured_max_size == 40960


@pytest.mark.parametrize("bad_capacity", [0, -1, True, 1.5])
def test_policy_rejects_invalid_capacities_without_mutating_globals(
    bad_capacity,
) -> None:
    with pytest.raises(ValueError):
        with temporary_mop_cache_policy(bad_capacity, 19):
            pass

    assert MOP_CONSTANT_CACHE.stats.configured_max_size == 4096
    assert MOP_TO_AST_CACHE.stats.configured_max_size == 40960
