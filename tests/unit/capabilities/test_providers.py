"""Unit tests for the composition-root provider registry (LS10 C1).

Pure-Python, no IDA: the registry holds opaque callables, so it is fully
unit-testable. Backends supply real Hex-Rays callables at runtime.
"""
from __future__ import annotations

import dataclasses

import pytest

from d810.capabilities.providers import (
    ConditionChainWalkerProvider,
    get_condition_chain_walkers,
    register_condition_chain_walkers,
    reset_providers_for_tests,
)


def _fake_provider() -> ConditionChainWalkerProvider:
    return ConditionChainWalkerProvider(
        detect_state_var_stkoff=lambda *a, **k: ("detect", a, k),
        dump_dispatcher_node=lambda *a, **k: "dump",
        find_pre_header_state=lambda *a, **k: "preheader",
        walk_handler_chain=lambda *a, **k: "walk",
        forward_eval_insn=lambda *a, **k: "eval",
        resolve_via_condition_chain_walk=lambda *a, **k: "resolve",
        get_block=lambda mba, serial: ("block", serial),
        block_successors=lambda block: ("succs", block),
    )


@pytest.fixture(autouse=True)
def _isolate_registry():
    reset_providers_for_tests()
    yield
    reset_providers_for_tests()


class TestConditionChainWalkerRegistry:
    def test_register_then_get_roundtrip(self) -> None:
        provider = _fake_provider()
        register_condition_chain_walkers(provider)
        assert get_condition_chain_walkers() is provider
        assert get_condition_chain_walkers().forward_eval_insn() == "eval"

    def test_get_before_register_raises_loud(self) -> None:
        with pytest.raises(LookupError, match="not registered"):
            get_condition_chain_walkers()

    def test_reset_clears_registration(self) -> None:
        register_condition_chain_walkers(_fake_provider())
        reset_providers_for_tests()
        with pytest.raises(LookupError):
            get_condition_chain_walkers()

    def test_re_register_overrides(self) -> None:
        first, second = _fake_provider(), _fake_provider()
        register_condition_chain_walkers(first)
        register_condition_chain_walkers(second)
        assert get_condition_chain_walkers() is second


class TestConditionChainWalkerProvider:
    def test_is_frozen(self) -> None:
        provider = _fake_provider()
        with pytest.raises(dataclasses.FrozenInstanceError):
            provider.forward_eval_insn = None  # type: ignore[misc]

    def test_exposes_all_seams(self) -> None:
        fields = {f.name for f in dataclasses.fields(ConditionChainWalkerProvider)}
        assert fields == {
            "detect_state_var_stkoff",
            "dump_dispatcher_node",
            "find_pre_header_state",
            "walk_handler_chain",
            "forward_eval_insn",
            "resolve_via_condition_chain_walk",
            "get_block",
            "block_successors",
            "fetch_idb_value",
        }
