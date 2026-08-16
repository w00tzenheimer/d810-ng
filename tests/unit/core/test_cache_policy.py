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


def test_same_capacity_policy_clears_at_entry_and_exit() -> None:
    MOP_CONSTANT_CACHE["before"] = 1
    MOP_TO_AST_CACHE["before"] = 1
    MOP_CONSTANT_CACHE.lookup("before")
    MOP_TO_AST_CACHE.lookup("before")

    with temporary_mop_cache_policy(4096, 40960):
        assert len(MOP_CONSTANT_CACHE) == 0
        assert len(MOP_TO_AST_CACHE) == 0
        assert MOP_CONSTANT_CACHE.stats.lookups == 0
        assert MOP_TO_AST_CACHE.stats.lookups == 0
        MOP_CONSTANT_CACHE["inside"] = 1
        MOP_TO_AST_CACHE["inside"] = 1
        MOP_CONSTANT_CACHE.lookup("inside")
        MOP_TO_AST_CACHE.lookup("inside")

    assert len(MOP_CONSTANT_CACHE) == 0
    assert len(MOP_TO_AST_CACHE) == 0
    assert MOP_CONSTANT_CACHE.stats.lookups == 0
    assert MOP_TO_AST_CACHE.stats.lookups == 0


def test_nested_same_capacity_policy_clears_at_each_boundary() -> None:
    with temporary_mop_cache_policy(4096, 40960):
        MOP_CONSTANT_CACHE["outer"] = 1
        MOP_TO_AST_CACHE["outer"] = 1
        MOP_CONSTANT_CACHE.lookup("outer")
        MOP_TO_AST_CACHE.lookup("outer")

        with temporary_mop_cache_policy(4096, 40960):
            assert len(MOP_CONSTANT_CACHE) == 0
            assert len(MOP_TO_AST_CACHE) == 0
            MOP_CONSTANT_CACHE["inner"] = 1
            MOP_TO_AST_CACHE["inner"] = 1

        assert len(MOP_CONSTANT_CACHE) == 0
        assert len(MOP_TO_AST_CACHE) == 0
        assert MOP_CONSTANT_CACHE.stats.lookups == 0
        assert MOP_TO_AST_CACHE.stats.lookups == 0

    assert len(MOP_CONSTANT_CACHE) == 0
    assert len(MOP_TO_AST_CACHE) == 0
    assert MOP_CONSTANT_CACHE.stats.lookups == 0
    assert MOP_TO_AST_CACHE.stats.lookups == 0


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


def test_policy_restores_after_first_setup_mutates_then_raises(monkeypatch) -> None:
    constant_object = MOP_CONSTANT_CACHE
    ast_object = MOP_TO_AST_CACHE
    original_reconfigure = MOP_CONSTANT_CACHE.reconfigure_capacity
    state = {"raise": True}

    def mutate_then_raise(capacity: int) -> None:
        original_reconfigure(capacity)
        if state["raise"]:
            state["raise"] = False
            raise RuntimeError("constant setup failed after mutation")

    monkeypatch.setattr(MOP_CONSTANT_CACHE, "reconfigure_capacity", mutate_then_raise)

    with pytest.raises(RuntimeError, match="constant setup failed"):
        with temporary_mop_cache_policy(17, 19):
            pass

    assert MOP_CONSTANT_CACHE is constant_object
    assert MOP_TO_AST_CACHE is ast_object
    assert MOP_CONSTANT_CACHE.stats.configured_max_size == 4096
    assert MOP_TO_AST_CACHE.stats.configured_max_size == 40960


def test_policy_restores_after_second_setup_mutates_then_raises(monkeypatch) -> None:
    constant_object = MOP_CONSTANT_CACHE
    ast_object = MOP_TO_AST_CACHE
    original_reconfigure = MOP_TO_AST_CACHE.reconfigure_capacity
    state = {"raise": True}

    def mutate_then_raise(capacity: int) -> None:
        original_reconfigure(capacity)
        if state["raise"]:
            state["raise"] = False
            raise RuntimeError("AST setup failed after mutation")

    monkeypatch.setattr(MOP_TO_AST_CACHE, "reconfigure_capacity", mutate_then_raise)

    with pytest.raises(RuntimeError, match="AST setup failed"):
        with temporary_mop_cache_policy(17, 19):
            pass

    assert MOP_CONSTANT_CACHE is constant_object
    assert MOP_TO_AST_CACHE is ast_object
    assert MOP_CONSTANT_CACHE.stats.configured_max_size == 4096
    assert MOP_TO_AST_CACHE.stats.configured_max_size == 40960


def test_policy_preserves_body_error_when_first_restore_mutates_then_raises(
    monkeypatch,
) -> None:
    original_reconfigure = MOP_CONSTANT_CACHE.reconfigure_capacity
    original_capacity = MOP_CONSTANT_CACHE.stats.configured_max_size
    state = {"raise": False}

    def mutate_then_raise_on_restore(capacity: int) -> None:
        original_reconfigure(capacity)
        if capacity == original_capacity and not state["raise"]:
            state["raise"] = True
            raise RuntimeError("constant restore failed after mutation")

    monkeypatch.setattr(
        MOP_CONSTANT_CACHE,
        "reconfigure_capacity",
        mutate_then_raise_on_restore,
    )

    with pytest.raises(RuntimeError, match="body failure") as raised:
        with temporary_mop_cache_policy(17, 19):
            raise RuntimeError("body failure")

    assert raised.value.__notes__
    assert "constant restore failed" in raised.value.__notes__[0]
    assert MOP_CONSTANT_CACHE.stats.configured_max_size == original_capacity


def test_policy_preserves_body_error_when_second_restore_mutates_then_raises(
    monkeypatch,
) -> None:
    original_reconfigure = MOP_TO_AST_CACHE.reconfigure_capacity
    original_capacity = MOP_TO_AST_CACHE.stats.configured_max_size
    state = {"raise": False}

    def mutate_then_raise_on_restore(capacity: int) -> None:
        original_reconfigure(capacity)
        if capacity == original_capacity and not state["raise"]:
            state["raise"] = True
            raise RuntimeError("AST restore failed after mutation")

    monkeypatch.setattr(
        MOP_TO_AST_CACHE,
        "reconfigure_capacity",
        mutate_then_raise_on_restore,
    )

    with pytest.raises(RuntimeError, match="body failure") as raised:
        with temporary_mop_cache_policy(17, 19):
            raise RuntimeError("body failure")

    assert raised.value.__notes__
    assert "AST restore failed" in raised.value.__notes__[0]
    assert MOP_TO_AST_CACHE.stats.configured_max_size == original_capacity


def test_policy_retries_first_restore_failure_before_mutation(monkeypatch) -> None:
    original_reconfigure = MOP_CONSTANT_CACHE.reconfigure_capacity
    original_capacity = MOP_CONSTANT_CACHE.stats.configured_max_size
    state = {"failed": False}

    def fail_once_before_mutation(capacity: int) -> None:
        if capacity == original_capacity and not state["failed"]:
            state["failed"] = True
            raise RuntimeError("transient constant restore failure")
        original_reconfigure(capacity)

    monkeypatch.setattr(
        MOP_CONSTANT_CACHE,
        "reconfigure_capacity",
        fail_once_before_mutation,
    )

    with temporary_mop_cache_policy(17, 19):
        pass

    assert MOP_CONSTANT_CACHE.stats.configured_max_size == original_capacity
    assert MOP_TO_AST_CACHE.stats.configured_max_size == 40960
    assert MOP_CONSTANT_CACHE.stats.lookups == 0
    assert MOP_TO_AST_CACHE.stats.lookups == 0


def test_policy_retries_second_restore_failure_before_mutation(monkeypatch) -> None:
    original_reconfigure = MOP_TO_AST_CACHE.reconfigure_capacity
    original_capacity = MOP_TO_AST_CACHE.stats.configured_max_size
    state = {"failed": False}

    def fail_once_before_mutation(capacity: int) -> None:
        if capacity == original_capacity and not state["failed"]:
            state["failed"] = True
            raise RuntimeError("transient AST restore failure")
        original_reconfigure(capacity)

    monkeypatch.setattr(
        MOP_TO_AST_CACHE,
        "reconfigure_capacity",
        fail_once_before_mutation,
    )

    with temporary_mop_cache_policy(17, 19):
        pass

    assert MOP_CONSTANT_CACHE.stats.configured_max_size == 4096
    assert MOP_TO_AST_CACHE.stats.configured_max_size == original_capacity
    assert MOP_CONSTANT_CACHE.stats.lookups == 0
    assert MOP_TO_AST_CACHE.stats.lookups == 0


def test_policy_reports_restore_failure_without_body_error(monkeypatch) -> None:
    original_reconfigure = MOP_CONSTANT_CACHE.reconfigure_capacity
    original_capacity = MOP_CONSTANT_CACHE.stats.configured_max_size

    def fail_restore(capacity: int) -> None:
        if capacity == original_capacity:
            raise RuntimeError("constant restore failed permanently")
        original_reconfigure(capacity)

    monkeypatch.setattr(MOP_CONSTANT_CACHE, "reconfigure_capacity", fail_restore)

    with pytest.raises(RuntimeError, match="constant restore failed permanently"):
        with temporary_mop_cache_policy(17, 19):
            pass

    assert MOP_CONSTANT_CACHE.stats.configured_max_size == 17
    monkeypatch.undo()
    MOP_CONSTANT_CACHE.reconfigure_capacity(original_capacity)


@pytest.mark.parametrize("bad_capacity", [0, -1, True, 1.5])
def test_policy_rejects_invalid_capacities_without_mutating_globals(
    bad_capacity,
) -> None:
    with pytest.raises(ValueError):
        with temporary_mop_cache_policy(bad_capacity, 19):
            pass

    assert MOP_CONSTANT_CACHE.stats.configured_max_size == 4096
    assert MOP_TO_AST_CACHE.stats.configured_max_size == 40960
