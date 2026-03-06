"""Unit tests for the read-only chain-backed evaluator helpers.

These tests verify module structure, signatures, and the DefSite NamedTuple.
No IDA dependency required -- chains.py uses lazy imports.
"""
from __future__ import annotations

import inspect

import pytest

from d810.evaluator.hexrays_microcode.chains import (
    DefSite,
    collect_pred_defs_for_block,
    ensure_graph_and_lists_ready,
    find_reaching_defs_for_reg,
    find_reaching_defs_for_stkvar,
    get_ud_du_chains,
    is_passthru_chain,
    is_phi_like_merge,
)


# ---------------------------------------------------------------------------
# DefSite NamedTuple
# ---------------------------------------------------------------------------


class TestDefSite:
    """Verify DefSite is a proper NamedTuple with expected fields."""

    def test_def_site_is_namedtuple(self) -> None:
        """DefSite must be a NamedTuple with block_serial, ins_ea, ins_opcode."""
        ds = DefSite(block_serial=3, ins_ea=0x1000, ins_opcode=7)
        assert ds.block_serial == 3
        assert ds.ins_ea == 0x1000
        assert ds.ins_opcode == 7

    def test_def_site_fields(self) -> None:
        assert DefSite._fields == ("block_serial", "ins_ea", "ins_opcode")

    def test_def_site_is_hashable(self) -> None:
        ds1 = DefSite(1, 0x2000, 5)
        ds2 = DefSite(1, 0x2000, 5)
        assert hash(ds1) == hash(ds2)
        assert ds1 == ds2
        assert len({ds1, ds2}) == 1

    def test_def_site_tuple_unpacking(self) -> None:
        blk, ea, opc = DefSite(2, 0x3000, 9)
        assert blk == 2
        assert ea == 0x3000
        assert opc == 9

    def test_def_site_different_values_not_equal(self) -> None:
        ds1 = DefSite(1, 0x1000, 5)
        ds2 = DefSite(1, 0x1000, 6)
        assert ds1 != ds2


# ---------------------------------------------------------------------------
# Module importability
# ---------------------------------------------------------------------------


class TestImportability:
    """Verify the module and all public symbols are importable without IDA."""

    def test_ensure_graph_stubs_importable(self) -> None:
        assert callable(ensure_graph_and_lists_ready)

    def test_all_public_symbols_importable(self) -> None:
        from d810.evaluator.hexrays_microcode import chains

        for name in chains.__all__:
            assert hasattr(chains, name), f"Missing public symbol: {name}"


# ---------------------------------------------------------------------------
# Function signatures
# ---------------------------------------------------------------------------


class TestSignatures:
    """Verify that all chain functions have the expected parameter names."""

    def test_ensure_graph_and_lists_ready_signature(self) -> None:
        sig = inspect.signature(ensure_graph_and_lists_ready)
        assert "mba" in sig.parameters

    def test_get_ud_du_chains_signature(self) -> None:
        sig = inspect.signature(get_ud_du_chains)
        params = list(sig.parameters.keys())
        assert "mba" in params
        assert "gctype" in params

    def test_find_reaching_defs_for_reg_signature(self) -> None:
        sig = inspect.signature(find_reaching_defs_for_reg)
        params = list(sig.parameters.keys())
        assert params == ["mba", "blk_serial", "reg_mreg", "size"]

    def test_find_reaching_defs_for_stkvar_signature(self) -> None:
        sig = inspect.signature(find_reaching_defs_for_stkvar)
        params = list(sig.parameters.keys())
        assert params == ["mba", "blk_serial", "stkoff", "size"]

    def test_is_passthru_chain_signature(self) -> None:
        sig = inspect.signature(is_passthru_chain)
        assert "chain" in sig.parameters

    def test_collect_pred_defs_for_block_signature(self) -> None:
        sig = inspect.signature(collect_pred_defs_for_block)
        params = list(sig.parameters.keys())
        assert "mba" in params
        assert "blk_serial" in params
        assert "target_mreg" in params

    def test_is_phi_like_merge_signature(self) -> None:
        sig = inspect.signature(is_phi_like_merge)
        params = list(sig.parameters.keys())
        assert params == ["mba", "blk_serial", "mreg"]


# ---------------------------------------------------------------------------
# Stub behavior (no IDA available)
# ---------------------------------------------------------------------------


class TestStubBehavior:
    """Verify graceful stub returns when IDA is not available."""

    def test_get_ud_du_chains_returns_none_pair(self) -> None:
        """Without IDA, get_ud_du_chains returns (None, None)."""
        ud, du = get_ud_du_chains(object())
        assert ud is None
        assert du is None

    def test_find_reaching_defs_for_reg_returns_empty(self) -> None:
        result = find_reaching_defs_for_reg(object(), blk_serial=0, reg_mreg=0, size=8)
        assert result == []

    def test_find_reaching_defs_for_stkvar_returns_empty(self) -> None:
        result = find_reaching_defs_for_stkvar(object(), blk_serial=0, stkoff=0, size=8)
        assert result == []

    def test_is_passthru_chain_returns_false(self) -> None:
        assert is_passthru_chain(object()) is False

    def test_collect_pred_defs_returns_empty_dict(self) -> None:
        result = collect_pred_defs_for_block(object(), blk_serial=0)
        assert result == {}

    def test_is_phi_like_merge_returns_false(self) -> None:
        assert is_phi_like_merge(object(), blk_serial=0, mreg=0) is False
