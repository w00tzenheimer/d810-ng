"""Tests for mba_serializer module (IDA-free unit tests).

Since ``mba_to_block_snapshots`` requires ``ida_hexrays`` at runtime,
unit tests focus on the import guard behavior and the module-level
contract.  Full integration tests that exercise the serializer with
a real MBA belong in ``tests/system/``.
"""
from __future__ import annotations

import importlib
import json
import sys
from types import SimpleNamespace
from unittest import mock

import pytest


class TestMbaSerializerImportGuard:
    """Verify that the module handles missing ida_hexrays gracefully."""

    def test_module_importable_without_ida(self) -> None:
        """The module must be importable even when ida_hexrays is not available."""
        # Force ida_hexrays to be absent for the duration of this test
        saved = sys.modules.get("ida_hexrays")
        try:
            sys.modules["ida_hexrays"] = None  # type: ignore[assignment]
            # Remove cached module if it was already imported
            sys.modules.pop("d810.hexrays.mba_serializer", None)
            mod = importlib.import_module("d810.hexrays.mba_serializer")
            assert mod._ihr is None
        finally:
            if saved is not None:
                sys.modules["ida_hexrays"] = saved
            else:
                sys.modules.pop("ida_hexrays", None)
            # Restore cached module
            sys.modules.pop("d810.hexrays.mba_serializer", None)

    def test_mba_to_block_snapshots_raises_without_ida(self) -> None:
        """Calling mba_to_block_snapshots without IDA raises RuntimeError."""
        saved = sys.modules.get("ida_hexrays")
        try:
            sys.modules["ida_hexrays"] = None  # type: ignore[assignment]
            sys.modules.pop("d810.hexrays.mba_serializer", None)
            mod = importlib.import_module("d810.hexrays.mba_serializer")
            with pytest.raises(RuntimeError, match="requires ida_hexrays"):
                mod.mba_to_block_snapshots(mock.MagicMock())
        finally:
            if saved is not None:
                sys.modules["ida_hexrays"] = saved
            else:
                sys.modules.pop("ida_hexrays", None)
            sys.modules.pop("d810.hexrays.mba_serializer", None)


class TestMbaSerializerExports:
    """Verify public API surface of the module."""

    def test_public_function_exists(self) -> None:
        from d810.hexrays.mba_serializer import mba_to_block_snapshots

        assert callable(mba_to_block_snapshots)

    def test_snapshot_types_reexported(self) -> None:
        """BlockSnapshot and InstructionSnapshot should be accessible."""
        from d810.hexrays.mba_serializer import BlockSnapshot, InstructionSnapshot

        assert BlockSnapshot is not None
        assert InstructionSnapshot is not None


class _FakeMop:
    def __init__(self, mop_type: int, size: int = 0, text: str = "", **attrs: object):
        self.t = mop_type
        self.size = size
        self._text = text
        for key, value in attrs.items():
            setattr(self, key, value)

    def dstr(self) -> str:
        return self._text


class _FakeInsn:
    def __init__(
        self,
        *,
        opcode: int,
        ea: int,
        text: str,
        l: _FakeMop,
        r: _FakeMop,
        d: _FakeMop,
    ):
        self.opcode = opcode
        self.ea = ea
        self._text = text
        self.l = l
        self.r = r
        self.d = d

    def dstr(self) -> str:
        return self._text


class _FakeIhr:
    mop_z = 0
    mop_r = 1
    mop_n = 2
    mop_d = 4
    mop_S = 5
    mop_v = 6
    mop_b = 7
    mop_f = 8
    mop_l = 9
    mop_a = 10
    mop_h = 11
    mop_str = 12
    mop_c = 13
    mop_fn = 14
    mop_p = 15
    mop_sc = 16
    m_mov = 4
    m_call = 56
    m_icall = 57

    @staticmethod
    def get_mreg_name(register: int, size: int) -> str:
        if size == 0:
            return {4: "m_mov", 56: "m_call", 57: "m_icall"}.get(register, "")
        return {16: "rdx", 24: "rcx", 72: "r8"}.get(register, f"r{register}")


class TestMbaSerializerInstructionMeta:
    def test_call_meta_includes_block_local_argument_register_setup(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import d810.hexrays.mba_serializer as serializer

        monkeypatch.setattr(serializer, "_ihr", _FakeIhr)

        z = _FakeMop(_FakeIhr.mop_z)
        register_defs: dict[int, dict[str, object]] = {}
        setup = (
            _FakeInsn(
                opcode=_FakeIhr.m_mov,
                ea=0x1800175E3,
                text="mov &($off_180019F10).8, rdx.8",
                l=_FakeMop(
                    _FakeIhr.mop_a,
                    8,
                    "&($off_180019F10).8",
                    a=_FakeMop(
                        _FakeIhr.mop_v,
                        -1,
                        "$off_180019F10",
                        g=0x180019F10,
                    ),
                ),
                r=z,
                d=_FakeMop(_FakeIhr.mop_r, 8, "rdx.8", r=16),
            ),
            _FakeInsn(
                opcode=_FakeIhr.m_mov,
                ea=0x1800175EA,
                text="mov &(%var_1A8).8, rcx.8",
                l=_FakeMop(
                    _FakeIhr.mop_a,
                    8,
                    "&(%var_1A8).8",
                    a=_FakeMop(
                        _FakeIhr.mop_S,
                        -1,
                        "%var_1A8",
                        s=SimpleNamespace(off=0x70),
                    ),
                ),
                r=z,
                d=_FakeMop(_FakeIhr.mop_r, 8, "rcx.8", r=24),
            ),
            _FakeInsn(
                opcode=_FakeIhr.m_mov,
                ea=0x1800175EF,
                text="mov #0x128.8, r8.8",
                l=_FakeMop(
                    _FakeIhr.mop_n,
                    8,
                    "#0x128.8",
                    nnn=SimpleNamespace(value=0x128),
                ),
                r=z,
                d=_FakeMop(_FakeIhr.mop_r, 8, "r8.8", r=72),
            ),
        )
        for index, insn in enumerate(setup, start=7):
            serializer._record_register_definition(
                register_defs,
                insn_index=index,
                insn=insn,
            )

        call = _FakeInsn(
            opcode=_FakeIhr.m_call,
            ea=0x1800175F5,
            text="call $0x180000000",
            l=_FakeMop(_FakeIhr.mop_v, -1, "$0x180000000", g=0x180000000),
            r=z,
            d=z,
        )
        meta_json = serializer._instruction_snapshot_meta(
            call,
            insn_index=10,
            block_register_defs=register_defs,
        )
        assert meta_json is not None

        meta = json.loads(meta_json)
        setup_by_name = {
            record["register_name"]: record
            for record in meta["call_setup_registers"]
        }
        assert setup_by_name["rcx"]["source"]["sub_operand"]["stkoff"] == 0x70
        assert setup_by_name["rdx"]["source"]["sub_operand"]["global_ea"] == (
            "0x180019f10"
        )
        assert setup_by_name["r8"]["source"]["value"] == 0x128
