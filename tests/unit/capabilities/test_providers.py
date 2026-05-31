"""Unit tests for the composition-root provider registry (LS10 C1).

Pure-Python, no IDA: the registry holds opaque callables, so it is fully
unit-testable. Backends supply real Hex-Rays callables at runtime.
"""
from __future__ import annotations

import dataclasses

import pytest

from d810.capabilities.providers import (
    BstWalkerProvider,
    get_bst_walkers,
    register_bst_walkers,
    reset_providers_for_tests,
)


def _fake_provider() -> BstWalkerProvider:
    return BstWalkerProvider(
        detect_state_var_stkoff=lambda *a, **k: ("detect", a, k),
        dump_dispatcher_node=lambda *a, **k: "dump",
        find_pre_header_state=lambda *a, **k: "preheader",
        walk_handler_chain=lambda *a, **k: "walk",
        forward_eval_insn=lambda *a, **k: "eval",
        resolve_via_bst_walk=lambda *a, **k: "resolve",
        get_block=lambda mba, serial: ("block", serial),
        block_successors=lambda block: ("succs", block),
    )


@pytest.fixture(autouse=True)
def _isolate_registry():
    reset_providers_for_tests()
    yield
    reset_providers_for_tests()


class TestBstWalkerRegistry:
    def test_register_then_get_roundtrip(self) -> None:
        provider = _fake_provider()
        register_bst_walkers(provider)
        assert get_bst_walkers() is provider
        assert get_bst_walkers().forward_eval_insn() == "eval"

    def test_get_before_register_raises_loud(self) -> None:
        with pytest.raises(LookupError, match="not registered"):
            get_bst_walkers()

    def test_reset_clears_registration(self) -> None:
        register_bst_walkers(_fake_provider())
        reset_providers_for_tests()
        with pytest.raises(LookupError):
            get_bst_walkers()

    def test_re_register_overrides(self) -> None:
        first, second = _fake_provider(), _fake_provider()
        register_bst_walkers(first)
        register_bst_walkers(second)
        assert get_bst_walkers() is second


class TestBstWalkerProvider:
    def test_is_frozen(self) -> None:
        provider = _fake_provider()
        with pytest.raises(dataclasses.FrozenInstanceError):
            provider.forward_eval_insn = None  # type: ignore[misc]

    def test_exposes_all_seams(self) -> None:
        fields = {f.name for f in dataclasses.fields(BstWalkerProvider)}
        assert fields == {
            "detect_state_var_stkoff",
            "dump_dispatcher_node",
            "find_pre_header_state",
            "walk_handler_chain",
            "forward_eval_insn",
            "resolve_via_bst_walk",
            "get_block",
            "block_successors",
        }
