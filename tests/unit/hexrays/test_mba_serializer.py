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
from dataclasses import replace
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
        left: _FakeMop,
        right: _FakeMop,
        dest: _FakeMop,
        iprops: int = 0,
    ):
        self.opcode = opcode
        self.ea = ea
        self._text = text
        self.l = left
        self.r = right
        self.d = dest
        self.iprops = iprops
        self.next = None

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
    mop_str = 3
    mop_c = 12
    mop_fn = 13
    mop_p = 14
    mop_sc = 15
    m_mov = 4
    m_nop = 1
    m_goto = 55
    m_call = 56
    m_icall = 57
    m_jz = 58
    m_jcnd = 59
    m_ret = 60
    m_jtbl = 61
    m_sub = 62
    IPROP_ASSERT = 0x80
    BLT_NONE = 0
    BLT_STOP = 1
    BLT_1WAY = 2
    BLT_2WAY = 3
    BLT_NWAY = 4
    BLT_XTRN = 5

    @staticmethod
    def get_mreg_name(register: int, size: int) -> str:
        if size == 0:
            return {
                4: "m_mov",
                55: "fps^3",
                56: "m_call",
                57: "m_icall",
                58: "m_jz",
                59: "m_jcnd",
                60: "m_ret",
                61: "m_jtbl",
                62: "m_sub",
            }.get(register, "")
        return {16: "rdx", 24: "rcx", 72: "r8"}.get(register, f"r{register}")


class TestMbaSerializerInstructionMeta:
    @pytest.mark.parametrize(
        "opcode_name",
        (
            "m_nop", "m_ret", "m_goto", "m_ijmp", "m_jtbl", "m_jcnd",
            "m_jnz", "m_jz", "m_jae", "m_jb", "m_ja", "m_jbe", "m_jg",
            "m_jge", "m_jl", "m_jle", "m_call", "m_icall", "m_mov",
            "m_ldx", "m_stx", "m_xdu", "m_xds", "m_add", "m_sub", "m_mul",
            "m_and",
        ),
    )
    def test_closed_operand_vocabulary_accepts_valid_layout_and_rejects_missing(
        self, opcode_name: str,
    ) -> None:
        from d810.hexrays.instruction_vocabulary import (
            operand_shape_for_opcode_name,
            validate_operand_shape,
        )
        from d810.ir.flowgraph import MopSnapshot, OperandKind

        stack = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,))
        number = MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7)
        block = MopSnapshot(kind=OperandKind.BLOCK, size=0, block_ref=2)
        register = MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=1)
        global_target = MopSnapshot(kind=OperandKind.GLOBAL, size=8, gaddr=0x5000)
        arg_list = MopSnapshot(kind=OperandKind.ARG_LIST, size=8, args=())
        cases = MopSnapshot(kind=OperandKind.CASE_LIST, size=0)
        shape = operand_shape_for_opcode_name(opcode_name)
        assert shape is not None
        if opcode_name in {"m_nop", "m_ret"}:
            operands = (None, None, None)
        elif opcode_name == "m_goto":
            operands = (block, None, None)
        elif opcode_name == "m_ijmp":
            operands = (register, None, None)
        elif opcode_name == "m_jtbl":
            operands = (register, cases, None)
        elif opcode_name == "m_jcnd":
            operands = (stack, None, block)
        elif opcode_name in {
            "m_jnz", "m_jz", "m_jae", "m_jb", "m_ja", "m_jbe",
            "m_jg", "m_jge", "m_jl", "m_jle",
        }:
            operands = (stack, number, block)
        elif opcode_name == "m_call":
            operands = (global_target, None, arg_list)
        elif opcode_name == "m_icall":
            operands = (register, number, arg_list)
        elif opcode_name in {"m_mov", "m_xdu", "m_xds"}:
            operands = (stack, None, register)
        else:
            operands = (stack, number, register)
        assert validate_operand_shape(opcode_name, l=operands[0], r=operands[1], d=operands[2]) is shape
        invalid = list(operands)
        invalid[0] = stack if opcode_name in {"m_nop", "m_ret"} else None
        with pytest.raises(ValueError, match="operand shape"):
            validate_operand_shape(opcode_name, l=invalid[0], r=invalid[1], d=invalid[2])

    def test_all_sdk_rows_have_independent_shapes_and_reject_slot_mutations(self) -> None:
        from d810.hexrays.instruction_vocabulary import (
            OperandShape,
            live_known_opcode_names,
            validate_operand_shape,
            vocabulary_entry_for_opcode_name,
        )
        from d810.ir.flowgraph import MopSnapshot, OperandKind
        from d810.ir.semantics import CallKind, ControlTransferKind

        zero = {"m_nop", "m_ret"}
        unary_ld = {
            "m_ldc", "m_mov", "m_neg", "m_lnot", "m_bnot", "m_xds", "m_xdu",
            "m_low", "m_high", "m_f2i", "m_f2u", "m_i2f", "m_u2f", "m_f2f",
            "m_fneg",
        }
        unary_l = {"m_push"}
        unary_d = {"m_pop", "m_und"}
        binary = {
            "m_add", "m_sub", "m_mul", "m_udiv", "m_sdiv", "m_umod", "m_smod",
            "m_or", "m_and", "m_xor", "m_shl", "m_shr", "m_sar", "m_cfadd",
            "m_ofadd", "m_cfshl", "m_cfshr", "m_seto", "m_setp", "m_fadd",
            "m_fsub", "m_fmul", "m_fdiv",
        }
        ternary = {
            "m_ldx", "m_stx", "m_setz", "m_setnz", "m_setae", "m_setb", "m_seta",
            "m_setbe", "m_setg", "m_setge", "m_setl", "m_setle",
        }
        special = {
            "m_sets": OperandShape(True, False, True),
            "m_goto": OperandShape(True, False, False),
            "m_jtbl": OperandShape(True, True, False),
            "m_ijmp": OperandShape(True, None, False),
            "m_jcnd": OperandShape(True, False, True),
            "m_jz": OperandShape(True, True, True),
            "m_jnz": OperandShape(True, True, True),
            "m_jae": OperandShape(True, True, True),
            "m_jb": OperandShape(True, True, True),
            "m_ja": OperandShape(True, True, True),
            "m_jbe": OperandShape(True, True, True),
            "m_jg": OperandShape(True, True, True),
            "m_jge": OperandShape(True, True, True),
            "m_jl": OperandShape(True, True, True),
            "m_jle": OperandShape(True, True, True),
            "m_call": OperandShape(True, False, None),
            "m_icall": OperandShape(True, True, None),
            "m_ext": OperandShape(None, None, None),
        }
        expected: dict[str, OperandShape] = {}
        expected.update({name: OperandShape(False, False, False) for name in zero})
        expected.update({name: OperandShape(True, False, True) for name in unary_ld})
        expected.update({name: OperandShape(True, False, False) for name in unary_l})
        expected.update({name: OperandShape(False, False, True) for name in unary_d})
        expected.update({name: OperandShape(True, True, True) for name in binary})
        expected.update({name: OperandShape(True, True, True) for name in ternary})
        expected.update(special)
        names = set(live_known_opcode_names())
        assert set(expected) == names

        stack = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,))
        number = MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7)
        register = MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=1)
        block = MopSnapshot(kind=OperandKind.BLOCK, size=0, block_ref=2)
        cases = MopSnapshot(kind=OperandKind.CASE_LIST, size=0)
        global_target = MopSnapshot(kind=OperandKind.GLOBAL, size=8, gaddr=0x5000)
        arg_list = MopSnapshot(kind=OperandKind.ARG_LIST, size=8, args=())
        for name in sorted(names):
            entry = vocabulary_entry_for_opcode_name(name)
            assert entry is not None
            assert entry.shape == expected[name]
            if name == "m_goto":
                operands = (block, None, None)
            elif name == "m_jtbl":
                operands = (register, cases, None)
            elif name == "m_ijmp":
                operands = (register, None, None)
            elif name == "m_jcnd":
                operands = (stack, None, block)
            elif entry.control_transfer_kind is ControlTransferKind.CONDITIONAL_BRANCH:
                operands = (stack, number, block)
            elif entry.call_kind is CallKind.DIRECT:
                operands = (global_target, None, arg_list)
            elif entry.call_kind is CallKind.INDIRECT:
                operands = (register, number, arg_list)
            else:
                operands = tuple(
                    operand if required else None
                    for required, operand in zip(
                        (entry.shape.l, entry.shape.r, entry.shape.d),
                        (stack, number, register),
                    )
                )
            assert validate_operand_shape(name, l=operands[0], r=operands[1], d=operands[2]) is entry.shape

            required_slots = [index for index, required in enumerate((entry.shape.l, entry.shape.r, entry.shape.d)) if required is True]
            if required_slots:
                invalid = list(operands)
                invalid[required_slots[0]] = None
            else:
                forbidden_slots = [index for index, required in enumerate((entry.shape.l, entry.shape.r, entry.shape.d)) if required is False]
                if not forbidden_slots:
                    continue
                invalid = list(operands)
                invalid[forbidden_slots[0]] = stack
            with pytest.raises(ValueError, match="operand shape"):
                validate_operand_shape(name, l=invalid[0], r=invalid[1], d=invalid[2])

    def test_ijmp_accepts_exact_ida94_right_and_destination_layout(self) -> None:
        """IDA 9.4 can expose early-maturity m_ijmp as z,r,d."""
        from d810.hexrays.instruction_vocabulary import validate_operand_shape
        from d810.ir.flowgraph import MopSnapshot, OperandKind

        register = MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=1)
        target = MopSnapshot(kind=OperandKind.GLOBAL, size=8, gaddr=0x5000)

        validate_operand_shape("m_ijmp", l=None, r=register, d=target)
        with pytest.raises(ValueError, match="operand shape"):
            validate_operand_shape("m_ijmp", l=None, r=register, d=None)

    def test_ext_accepts_destination_only_external_instruction(self) -> None:
        """m_ext has opcode-specific optional slots, including live z,z,d."""
        from d810.hexrays.instruction_vocabulary import validate_operand_shape
        from d810.ir.flowgraph import MopSnapshot, OperandKind

        destination = MopSnapshot(kind=OperandKind.REGISTER, size=1, reg=0)

        validate_operand_shape("m_ext", l=None, r=None, d=destination)

    def test_conditional_normalizer_keeps_jcnd_unary_and_only_canonicalizes_eq(
        self,
    ) -> None:
        from d810.hexrays.instruction_vocabulary import normalize_conditional_operands
        from d810.ir.flowgraph import MopSnapshot, OperandKind

        stack = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,))
        number = MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7)
        block = MopSnapshot(kind=OperandKind.BLOCK, size=0, block_ref=2)

        left, right, width = normalize_conditional_operands(
            "m_jcnd", l=stack, r=None, d=block,
        )
        assert (left, right, width) == (stack, None, 4)

        left, right, width = normalize_conditional_operands(
            "m_jz", l=number, r=stack, d=block,
        )
        assert (left, right, width) == (stack, number, 4)

        with pytest.raises(ValueError, match="operand shape"):
            normalize_conditional_operands(
                "m_jz", l=stack, r=number,
                d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=1),
            )

        register = MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=2)
        left, right, width = normalize_conditional_operands(
            "m_jz", l=register, r=register, d=block,
        )
        assert (left, right, width) == (register, register, 4)
        left, right, width = normalize_conditional_operands(
            "m_jz", l=register, r=number, d=block,
        )
        assert (left, right, width) == (register, number, 4)

    @pytest.mark.parametrize(
        ("opcode_name", "target_slot"),
        (("m_jcnd", "d"), ("m_goto", "l")),
    )
    def test_direct_branch_targets_accept_sdk_global_and_block_forms(
        self, opcode_name: str, target_slot: str,
    ) -> None:
        """Hex-Rays permits ``mop_v`` as well as ``mop_b`` direct targets."""
        from d810.hexrays.instruction_vocabulary import validate_operand_shape
        from d810.ir.flowgraph import MopSnapshot, OperandKind

        condition = MopSnapshot(kind=OperandKind.REGISTER, size=1, reg=1)
        block_target = MopSnapshot(kind=OperandKind.BLOCK, size=0, block_ref=2)
        global_target = MopSnapshot(
            kind=OperandKind.GLOBAL, size=0, gaddr=0x7801,
        )
        register_target = MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=2)

        def operands(target: MopSnapshot) -> tuple[MopSnapshot, None, MopSnapshot | None]:
            return (
                (condition if target_slot == "d" else target),
                None,
                (target if target_slot == "d" else None),
        )

        for target in (block_target, global_target):
            left, right, dest = operands(target)
            assert validate_operand_shape(
                opcode_name, l=left, r=right, d=dest,
            ) is not None
        with pytest.raises(ValueError, match="non-block target"):
            left, right, dest = operands(register_target)
            validate_operand_shape(
                opcode_name, l=left, r=right, d=dest,
            )

    def test_direct_call_accepts_target_only_but_rejects_non_argument_destination(
        self,
    ) -> None:
        """SDK 9.4 can omit m_call.d when the direct call has no call-info."""
        from d810.hexrays.instruction_vocabulary import validate_operand_shape
        from d810.ir.flowgraph import MopSnapshot, OperandKind

        target = MopSnapshot(kind=OperandKind.GLOBAL, size=0, gaddr=0xB290)
        args = MopSnapshot(kind=OperandKind.ARG_LIST, size=0, args=())
        invalid_dest = MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=1)

        assert validate_operand_shape("m_call", l=target, r=None, d=None) is not None
        assert validate_operand_shape("m_call", l=target, r=None, d=args) is not None
        with pytest.raises(ValueError, match="incomplete call"):
            validate_operand_shape("m_call", l=target, r=None, d=invalid_dest)

    def test_indirect_call_accepts_target_only_but_rejects_non_argument_destination(
        self,
    ) -> None:
        """SDK 9.4 can omit m_icall.d when the indirect call has no call-info."""
        from d810.hexrays.instruction_vocabulary import validate_operand_shape
        from d810.ir.flowgraph import MopSnapshot, OperandKind

        selector = MopSnapshot(kind=OperandKind.REGISTER, size=2, reg=240)
        offset = MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=8)
        args = MopSnapshot(kind=OperandKind.ARG_LIST, size=0, args=())
        invalid_dest = MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=1)

        assert validate_operand_shape(
            "m_icall", l=selector, r=offset, d=None,
        ) is not None
        assert validate_operand_shape(
            "m_icall", l=selector, r=offset, d=args,
        ) is not None
        with pytest.raises(ValueError, match="incomplete call"):
            validate_operand_shape(
                "m_icall", l=selector, r=offset, d=invalid_dest,
            )

    def test_opcode_name_comes_from_sdk_opcode_constants(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import d810.hexrays.mba_serializer as serializer

        monkeypatch.setattr(serializer, "_ihr", _FakeIhr)
        serializer._OPCODE_NAME_CACHE.clear()

        assert serializer._opcode_name(_FakeIhr.m_goto) == "m_goto"

    def test_live_shape_uses_canonical_sdk_mop_kinds_for_jtbl(self, monkeypatch) -> None:
        import d810.hexrays.mba_serializer as serializer
        from d810.hexrays.instruction_vocabulary import validate_live_operand_shape

        monkeypatch.setattr(serializer, "_ihr", _FakeIhr)
        z = _FakeMop(_FakeIhr.mop_z)
        selector = _FakeMop(_FakeIhr.mop_r, 4, "r0", r=0)
        cases = _FakeMop(_FakeIhr.mop_c, 0, "cases", c=SimpleNamespace(values=(), targets=()))
        fp_const = _FakeMop(_FakeIhr.mop_fn, 8, "fn", f=SimpleNamespace())
        assert validate_live_operand_shape(
            "m_jtbl", l=selector, r=cases, d=z,
            kind_classifier=serializer._live_operand_kind,
        ) is not None
        with pytest.raises(ValueError, match="case-list"):
            validate_live_operand_shape(
                "m_jtbl", l=selector, r=fp_const, d=z,
                kind_classifier=serializer._live_operand_kind,
            )
        assert validate_live_operand_shape(
            "m_nop", l=z, r=z, d=z,
            kind_classifier=serializer._live_operand_kind,
        ) is not None
        unknown = _FakeMop(999, 4, "unknown")
        with pytest.raises(ValueError, match="operand shape"):
            validate_live_operand_shape(
                "m_nop", l=unknown, r=z, d=z,
                kind_classifier=serializer._live_operand_kind,
            )
        with pytest.raises(ValueError, match="unknown operand kind"):
            validate_live_operand_shape(
                "m_mov", l=unknown, r=z, d=selector,
                kind_classifier=serializer._live_operand_kind,
            )

    def test_live_shape_accepts_icall_selector_offset_and_arguments(self, monkeypatch) -> None:
        """m_icall records its selector, offset, and argument-list mops."""
        import d810.hexrays.mba_serializer as serializer
        from d810.hexrays.instruction_vocabulary import validate_live_operand_shape

        monkeypatch.setattr(serializer, "_ihr", _FakeIhr)
        selector = _FakeMop(_FakeIhr.mop_r, 8, "rcx", r=24)
        offset = _FakeMop(_FakeIhr.mop_a, 8, "#0x10", a=SimpleNamespace())
        arguments = _FakeMop(_FakeIhr.mop_f, 8, "()", args=())

        assert validate_live_operand_shape(
            "m_icall", l=selector, r=offset, d=arguments,
            kind_classifier=serializer._live_operand_kind,
        ) is not None

    def test_live_shape_accepts_call_info_omitted_as_mop_z(self, monkeypatch) -> None:
        """Live mop_z call-info is absent, not an invalid non-argument mop."""
        import d810.hexrays.mba_serializer as serializer
        from d810.hexrays.instruction_vocabulary import validate_live_operand_shape

        monkeypatch.setattr(serializer, "_ihr", _FakeIhr)
        empty = _FakeMop(_FakeIhr.mop_z)
        direct_target = _FakeMop(_FakeIhr.mop_v, 8, "target", g=0xB290)
        selector = _FakeMop(_FakeIhr.mop_r, 2, "selector", r=240)
        offset = _FakeMop(_FakeIhr.mop_r, 8, "offset", r=8)

        assert validate_live_operand_shape(
            "m_call", l=direct_target, r=empty, d=empty,
            kind_classifier=serializer._live_operand_kind,
        ) is not None
        assert validate_live_operand_shape(
            "m_icall", l=selector, r=offset, d=empty,
            kind_classifier=serializer._live_operand_kind,
        ) is not None

    def test_nested_known_subinstruction_preserves_closed_semantics(self) -> None:
        from d810.backends.hexrays.diag_lifter import parse_diag_meta_operand
        from d810.ir.expressions import ValueOpKind
        from d810.ir.flowgraph import InsnKind, OperandKind

        operand = parse_diag_meta_operand({
            "type": "mop_d", "type_num": 4, "size": 4,
            "sub_instruction": {
                "opcode": 7,
                "opcode_name": "m_bnot",
                "l": {
                    "type": "mop_S", "type_num": 5, "size": 4,
                    "stkoff": 4,
                },
                "d": {
                    "type": "mop_r", "type_num": 1, "size": 4,
                    "register": 1,
                },
            },
        })

        assert operand is not None and operand.kind is OperandKind.SUBINSN
        assert operand.sub_kind is InsnKind.VALUE
        assert operand.sub_value_op_kind is ValueOpKind.NOT
        assert operand.sub_raw_opcode == 7

    def test_nested_unknown_subinstruction_is_rejected(self) -> None:
        from d810.backends.hexrays.diag_lifter import parse_diag_meta_operand

        with pytest.raises(ValueError, match="subinstruction|opcode"):
            parse_diag_meta_operand({
                "type": "mop_d", "type_num": 4, "size": 4,
                "sub_instruction": {
                    "opcode": 7,
                    "opcode_name": "m_invented",
                    "l": {
                        "type": "mop_S", "type_num": 5, "size": 4,
                        "stkoff": 4,
                    },
                    "d": {
                        "type": "mop_r", "type_num": 1, "size": 4,
                        "register": 1,
                    },
                },
            })

    @pytest.mark.parametrize("sub_opcode", [None, "7"])
    def test_nested_subinstruction_requires_exact_raw_opcode(self, sub_opcode) -> None:
        from d810.backends.hexrays.diag_lifter import parse_diag_meta_operand

        sub = {
            "opcode_name": "m_bnot",
            "l": {"type": "mop_S", "type_num": 5, "size": 4, "stkoff": 4},
            "d": {"type": "mop_r", "type_num": 1, "size": 4, "register": 1},
        }
        if sub_opcode is not None:
            sub["opcode"] = sub_opcode
        with pytest.raises(ValueError, match="exact integer"):
            parse_diag_meta_operand({"type": "mop_d", "type_num": 4, "sub_instruction": sub})

    @pytest.mark.parametrize("sub_name", ["bnot", "op_7"])
    def test_nested_subinstruction_requires_canonical_known_name(self, sub_name: str) -> None:
        from d810.backends.hexrays.diag_lifter import parse_diag_meta_operand

        with pytest.raises(ValueError, match="canonical|closed"):
            parse_diag_meta_operand({
                "type": "mop_d", "type_num": 4,
                "sub_instruction": {
                    "opcode": 7,
                    "opcode_name": sub_name,
                    "l": {"type": "mop_S", "type_num": 5, "size": 4, "stkoff": 4},
                    "d": {"type": "mop_r", "type_num": 1, "size": 4, "register": 1},
                },
            })

    def test_set_predicate_replays_as_value_materialization_not_control_flow(self) -> None:
        from d810.backends.hexrays.diag_lifter import project_diag_instruction
        from d810.ir.flowgraph import InsnKind, OperandKind
        from d810.ir.semantics import PredicateKind

        row = SimpleNamespace(
            opcode=90,
            opcode_name="m_setz",
            raw_opcode=90,
            provenance_version=1,
            ea=0x404010,
            dstr="setz %var_4.4, #0, %zf.1",
            meta=json.dumps({
                "l": {"type": "mop_S", "type_num": 5, "size": 4, "stkoff": 4},
                "r": {"type": "mop_n", "type_num": 2, "size": 4, "value": 0},
                "d": {"type": "mop_r", "type_num": 1, "size": 1, "register": 9},
            }),
        )

        instruction = project_diag_instruction(row)

        assert instruction.attrs["snapshot_kind"] == InsnKind.SET.value
        assert instruction.operation is PredicateKind.EQ
        assert instruction.control is None
        assert instruction.result is not None
        assert instruction.result.space.value == "r"

    def test_diag_replay_preserves_assertion_identity(self) -> None:
        from d810.backends.hexrays.diag_lifter import project_diag_instruction

        row = SimpleNamespace(
            opcode=1,
            opcode_name="m_mov",
            raw_opcode=1,
            provenance_version=1,
            ea=0x7FFB0DE936BC,
            dstr="mov #0x5CD7812F.4, %var_2C4.4{2}",
            is_assert=1,
            meta=json.dumps(
                {
                    "l": {
                        "type": "mop_n",
                        "type_num": 2,
                        "size": 4,
                        "value": 0x5CD7812F,
                    },
                    "d": {
                        "type": "mop_S",
                        "type_num": 5,
                        "size": 4,
                        "stkoff": 0x2C4,
                    },
                }
            ),
        )

        instruction = project_diag_instruction(row)

        assert instruction.attrs["is_assert"] is True

    def test_persisted_replay_rejects_portable_opcode_aliases(self) -> None:
        from d810.backends.hexrays.diag_lifter import project_diag_instruction

        row = SimpleNamespace(
            opcode=2,
            opcode_name="add",
            raw_opcode=2,
            provenance_version=1,
            ea=0x404020,
            meta=json.dumps({
                "l": {"type": "mop_S", "type_num": 5, "size": 4, "stkoff": 4},
                "r": {"type": "mop_n", "type_num": 2, "size": 4, "value": 1},
                "d": {"type": "mop_r", "type_num": 1, "size": 4, "register": 9},
            }),
        )

        with pytest.raises(ValueError, match="canonical"):
            project_diag_instruction(row)

    def test_live_assertion_state_is_first_class(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import d810.hexrays.mba_serializer as serializer

        monkeypatch.setattr(serializer, "_ihr", _FakeIhr)
        z = _FakeMop(_FakeIhr.mop_z)
        insn = _FakeInsn(
            opcode=_FakeIhr.m_mov,
            ea=0x401234,
            text="mov #1, r0",
            left=_FakeMop(_FakeIhr.mop_n, 4, "#1", nnn=SimpleNamespace(value=1)),
            right=z,
            dest=_FakeMop(_FakeIhr.mop_r, 4, "r0", r=0),
            iprops=_FakeIhr.IPROP_ASSERT,
        )
        block = SimpleNamespace(
            head=insn,
            tail=insn,
            type=_FakeIhr.BLT_STOP,
            start=0x401234,
            end=0x401235,
            nsucc=lambda: 0,
            npred=lambda: 0,
            succ=lambda _index: 0,
            pred=lambda _index: 0,
        )
        mba = SimpleNamespace(qty=1, get_mblock=lambda _index: block)

        snapshot = serializer.mba_to_block_snapshots(mba)[0].instructions[0]

        assert snapshot.iprops == _FakeIhr.IPROP_ASSERT
        assert snapshot.is_assert is True
        assert snapshot.raw_opcode == _FakeIhr.m_mov
        assert snapshot.provenance_version == 1
        lifted_block = serializer.mba_to_block_snapshots(mba)[0]
        assert lifted_block.tail_opcode == _FakeIhr.m_mov
        assert lifted_block.raw_tail_opcode == _FakeIhr.m_mov
        assert lifted_block.tail_kind == "mov"
        assert lifted_block.provenance_version == 1

    def test_serializer_dataclasses_replay_through_diag_lifter(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import d810.hexrays.mba_serializer as serializer
        from d810.backends.hexrays.diag_lifter import DiagSourceLifter

        monkeypatch.setattr(serializer, "_ihr", _FakeIhr)
        z = _FakeMop(_FakeIhr.mop_z)
        insn = _FakeInsn(
            opcode=_FakeIhr.m_mov,
            ea=0x401234,
            text="mov #1, r0",
            left=_FakeMop(_FakeIhr.mop_n, 4, "#1", nnn=SimpleNamespace(value=1)),
            right=z,
            dest=_FakeMop(_FakeIhr.mop_r, 4, "r0", r=0),
        )
        block = SimpleNamespace(
            head=insn,
            tail=insn,
            type=_FakeIhr.BLT_STOP,
            start=0x401234,
            end=0x401235,
            nsucc=lambda: 0,
            npred=lambda: 0,
            succ=lambda _index: 0,
            pred=lambda _index: 0,
        )
        snapshot = serializer.mba_to_block_snapshots(
            SimpleNamespace(qty=1, get_mblock=lambda _index: block)
        )[0]

        replay = DiagSourceLifter().lift(
            SimpleNamespace(blocks=(snapshot,), entry_serial=0, func_ea=0x401234)
        )
        replayed = replay.blocks[0]
        assert replayed.insn_snapshots[0].raw_opcode == _FakeIhr.m_mov
        assert replayed.tail_opcode == _FakeIhr.m_mov
        assert replayed.raw_tail_opcode == _FakeIhr.m_mov

    def test_serializer_sqlite_v12_decoder_lifter_preserves_block_only_tail_mismatch(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import d810.hexrays.mba_serializer as serializer
        from d810.backends.hexrays.diag_lifter import DiagSourceLifter
        from d810.core.diag import create_diag_database
        from d810.core.diag.semantic_route_oracle import load_snapshot_blocks
        from d810.core.diag.snapshot import snapshot_mba
        from d810.transforms.unflatten_authority import producer_api

        monkeypatch.setattr(serializer, "_ihr", _FakeIhr)
        z = _FakeMop(_FakeIhr.mop_z)
        insn = _FakeInsn(
            opcode=_FakeIhr.m_mov,
            ea=0x401234,
            text="mov #1, r0",
            left=_FakeMop(_FakeIhr.mop_n, 4, "#1", nnn=SimpleNamespace(value=1)),
            right=z,
            dest=_FakeMop(_FakeIhr.mop_r, 4, "r0", r=0),
        )
        block = SimpleNamespace(
            head=insn,
            tail=insn,
            type=_FakeIhr.BLT_STOP,
            start=0x401234,
            end=0x401235,
            nsucc=lambda: 0,
            npred=lambda: 0,
            succ=lambda _index: 0,
            pred=lambda _index: 0,
        )
        snapshot = serializer.mba_to_block_snapshots(
            SimpleNamespace(qty=1, get_mblock=lambda _index: block)
        )[0]
        mismatched = replace(
            snapshot,
            serial=1,
            tail_opcode=99,
            raw_tail_opcode=990,
            tail_kind="unknown",
            meta=json.dumps(
                {
                    "provenance_version": 1,
                    "tail_opcode": 99,
                    "raw_tail_opcode": 990,
                    "tail_kind": "unknown",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        db = create_diag_database(":memory:")
        try:
            snapshot_id = snapshot_mba(
                db.connection(), [snapshot, mismatched], "round5", 0x401234,
            )
            decoded = load_snapshot_blocks(db.connection(), snapshot_id)
            assert (decoded[0].tail_opcode, decoded[0].raw_tail_opcode) == (4, 4)
            assert (decoded[1].tail_opcode, decoded[1].raw_tail_opcode) == (99, 990)
            source = SimpleNamespace(blocks=decoded, entry_serial=0, func_ea=0x401234)
            lifted = DiagSourceLifter().lift(source)
            assert lifted.blocks[1].tail_opcode == 99
            with pytest.raises(ValueError, match="raw tail provenance"):
                producer_api.observe_inventory_block(
                    lifted.blocks[1], owner_ref=None, owner_anchor_ea=0x401234,
                )
        finally:
            db.close()

    def test_serializer_sqlite_v12_lifter_preserves_conditional_nop_call_roles(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The persisted exact F/R/T/L shape remains authority-eligible."""
        import d810.hexrays.mba_serializer as serializer
        from d810.backends.hexrays.diag_lifter import DiagSourceLifter
        from d810.core.diag import create_diag_database
        from d810.core.diag.semantic_route_oracle import load_snapshot_blocks
        from d810.core.diag.snapshot import snapshot_mba
        from d810.ir.flowgraph import InsnKind, OperandKind
        from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
        from d810.transforms.unflatten_authority import producer_api

        monkeypatch.setattr(serializer, "_ihr", _FakeIhr)
        z = _FakeMop(_FakeIhr.mop_z)
        def _block(serial, insn, *, succs, preds, block_type, tail=None):
            return SimpleNamespace(
                head=insn,
                tail=insn if tail is None else tail,
                type=block_type,
                start=0x401000 + serial * 0x10,
                end=0x401001 + serial * 0x10,
                nsucc=lambda: len(succs),
                npred=lambda: len(preds),
                succ=lambda index: succs[index],
                pred=lambda index: preds[index],
            )

        r = _FakeInsn(
            opcode=_FakeIhr.m_jz,
            ea=0x401010,
            text="jz %var_4.4, #7.4, @2",
            left=_FakeMop(_FakeIhr.mop_S, 4, "%var_4.4", s=SimpleNamespace(off=4)),
            right=_FakeMop(_FakeIhr.mop_n, 4, "#7.4", nnn=SimpleNamespace(value=7)),
            dest=_FakeMop(_FakeIhr.mop_b, 0, "@2", b=2),
        )
        t = _FakeInsn(
            opcode=_FakeIhr.m_nop, ea=0x401020, text="nop",
            left=z, right=z, dest=z,
        )
        l = _FakeInsn(
            opcode=_FakeIhr.m_call, ea=0x401030, text="call foo",
            left=_FakeMop(_FakeIhr.mop_v, 8, "foo", g=0x5000),
            right=z, dest=_FakeMop(_FakeIhr.mop_f, 8, "()", args=()),
        )
        f_write = _FakeInsn(
            opcode=_FakeIhr.m_mov, ea=0x401000, text="mov #7, %var_4.4",
            left=_FakeMop(_FakeIhr.mop_n, 4, "#7.4", nnn=SimpleNamespace(value=7)),
            right=z,
            dest=_FakeMop(_FakeIhr.mop_S, 4, "%var_4.4", s=SimpleNamespace(off=4)),
        )
        f_goto = _FakeInsn(
            opcode=_FakeIhr.m_goto, ea=0x401001, text="goto @1",
            left=_FakeMop(_FakeIhr.mop_b, 0, "@1", b=1), right=z, dest=z,
        )
        f_write.next = f_goto
        blocks = (
            _block(0, f_write, tail=f_goto, succs=(1,), preds=(), block_type=_FakeIhr.BLT_1WAY),
            _block(1, r, succs=(3, 2), preds=(0,), block_type=_FakeIhr.BLT_2WAY),
            # This is the source authority shape: T is the terminal selected
            # arm and L is the private effect arm.  The projected helper's
            # H->L edge is a later realization fact, not a source edge; adding
            # T->L here would make the exact effect branch reachable.
            _block(2, t, succs=(), preds=(1,), block_type=_FakeIhr.BLT_STOP),
            _block(3, l, succs=(), preds=(1,), block_type=_FakeIhr.BLT_STOP),
        )
        snapshots = serializer.mba_to_block_snapshots(
            SimpleNamespace(qty=len(blocks), get_mblock=lambda index: blocks[index])
        )
        db = create_diag_database(":memory:")
        try:
            snapshot_id = snapshot_mba(db.connection(), snapshots, "round7", 0x401000)
            decoded = load_snapshot_blocks(db.connection(), snapshot_id)
            lifted = DiagSourceLifter().lift(
                SimpleNamespace(blocks=decoded, entry_serial=0, func_ea=0x401000)
            )
            observed = dict(lifted.blocks)
            branch = observed[1].insn_snapshots[0]
            assert observed[1].succs == (3, 2)
            assert branch.kind is InsnKind.EQUALITY_JUMP
            assert branch.branch_predicate is PredicateKind.EQ
            assert branch.predicate_kind is PredicateKind.EQ
            assert branch.control_transfer_kind is ControlTransferKind.CONDITIONAL_BRANCH
            assert branch.compare_width == 4
            assert branch.l is not None and branch.l.kind is OperandKind.STACK
            assert branch.l.stkoff == 4 and branch.l.size == 4
            assert branch.r is not None and branch.r.kind is OperandKind.NUMBER
            assert branch.r.value == 7 and branch.r.size == 4
            assert branch.d is not None and branch.d.kind is OperandKind.BLOCK
            assert branch.d.block_ref == 2
            assert (observed[1].tail_opcode, observed[1].raw_tail_opcode, observed[1].tail_kind) == (
                _FakeIhr.m_jz, _FakeIhr.m_jz, InsnKind.EQUALITY_JUMP,
            )
            assert observed[2].insn_snapshots[0].kind is InsnKind.NOP
            assert (observed[2].tail_opcode, observed[2].raw_tail_opcode, observed[2].tail_kind) == (
                _FakeIhr.m_nop, _FakeIhr.m_nop, InsnKind.NOP,
            )
            assert observed[3].insn_snapshots[0].call_kind is CallKind.DIRECT
            assert observed[3].insn_snapshots[0].is_call is True
            assert (observed[3].tail_opcode, observed[3].raw_tail_opcode, observed[3].tail_kind) == (
                _FakeIhr.m_call, _FakeIhr.m_call, InsnKind.CALL,
            )
            # The persisted semantic rows now feed the same inventory and
            # source-authority path used by production; there is no unrelated
            # fixture graph in this assertion.
            from d810.analyses.control_flow import semantic_route_evidence as route_model
            from d810.transforms.unflatten_authority import bind, model, transaction_api
            from d810.transforms.graph_modification import CreateConditionalRedirect
            from tests.typed_patch_authority import compile_patch_plan
            from d810.analyses.control_flow.effect_branch_exclusion import (
                build_exact_state_branch_effect_exclusion,
            )
            from d810.analyses.control_flow.semantic_route_evidence import (
                SemanticCarrierProof, SemanticCorridorPoint,
                canonical_semantic_evidence_from_proofs,
                SemanticPredicateKind, SemanticPredicateProof,
                SemanticRouteDestination, SemanticRouteProof,
                SemanticRouteProofKind, SemanticRouteShape,
                SemanticStateWriteDeliveryKind, SemanticStateWriteProof,
            )
            from d810.core.native_preanalysis_key import NativePreanalysisKey
            from d810.ir.block_identity import StableBlockIdentity
            from d810.ir.flowgraph import FlowGraph
            from d810.ir.semantic_edge import SemanticEdgeRole
            from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
            from d810.transforms.cfg_transaction import NativeBlockRef
            from d810.transforms.unflatten_authority.ids import authority_id
            from d810.transforms.unflatten_authority.model import UseDefFragmentWitness

            # Build the route proposal from the graph that just traversed
            # serializer -> SQLite v12 -> decoder -> DiagSourceLifter.  Using
            # an unrelated hand-built fixture here would reintroduce the
            # producer/replay authority split that this test is meant to pin.
            source = lifted
            key = NativePreanalysisKey(
                "input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64,
            )
            refs = {
                serial: NativeBlockRef(
                    StableBlockIdentity.from_instruction_eas(
                        [instruction.ea for instruction in block.insn_snapshots],
                        native_key=key,
                    )
                )
                for serial, block in observed.items()
            }
            state = StorageIdentity(StorageIdentityKind.STACK, 4)
            state_number = observed[0].insn_snapshots[0].l
            state_stack = observed[0].insn_snapshots[0].d
            assert state_number is not None and state_stack is not None
            assert state_number.value == 7 and state_stack.stkoff == 4
            predicate_instruction = observed[1].insn_snapshots[0]
            assert predicate_instruction.ea == 0x401010
            source_point = SemanticCorridorPoint(refs[0].identity, 0x401000)
            predicate_point = SemanticCorridorPoint(refs[1].identity, predicate_instruction.ea)
            state_write = SemanticStateWriteProof(
                refs[0].identity, 0x401000, state, 4, 7,
                (0x401000, 0x401010), None, (),
                SemanticStateWriteDeliveryKind.CONDITIONAL,
            )
            predicate = SemanticPredicateProof(
                SemanticPredicateKind.STORAGE_EQUALS, predicate_point,
                predicate_point, (predicate_point,), state, 4, 7, None, (),
            )
            carrier = SemanticCarrierProof(
                authority_id("persisted-carrier"), source_point,
                (predicate_point,), (source_point, predicate_point), state,
                4, (7, 8), (0x401000,),
            )
            route = SemanticRouteProof(
                authority_id("persisted-route"), authority_id("persisted-group"),
                SemanticRouteProofKind.STATE_CHOICE, SemanticRouteShape.CONDITIONAL,
                refs[1].identity, predicate_instruction.ea,
                (
                    SemanticRouteDestination(
                        SemanticEdgeRole.CONDITIONAL_TAKEN, 7,
                        refs[2].identity, observed[2].start_ea,
                    ),
                    SemanticRouteDestination(
                        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH, 8,
                        refs[3].identity, observed[3].start_ea,
                    ),
                ),
                source_owner_identity=refs[0].identity,
                source_owner_anchor_ea=0x401000,
                state_write=state_write, predicate=predicate, carriers=(carrier,),
                diagnostic_provenance=(("provider_proof_kind", "state_choice"),),
            )
            evidence = canonical_semantic_evidence_from_proofs(
                native_key=key, generation=1, proofs=(route,),
            )
            exclusion = build_exact_state_branch_effect_exclusion(
                source, source, normalized_state=7, source_serial=0,
                predicate_serial=1, selected_target_serial=2,
                discarded_effect_serial=3, state_identity=state,
            )
            assert exclusion is not None
            witness = UseDefFragmentWitness(
                authority_id("persisted-fragment"), state, (refs[0],),
                authority_id("persisted-redirect"), True, True, 0, (),
            )
            base = producer_api.build_proposal(
                plan_id=authority_id("persisted-plan"), source=source,
                block_refs_by_serial=refs, source_generation=1,
                canonical_route_evidence=evidence,
                exact_state_effect_exclusions=(exclusion,),
                dispatcher_entry_serial=1, dispatcher_member_serials=(0, 1),
                authoritative_handler_serials=(2,), state_identity=state,
                use_def_witness=witness,
            )
            claims = producer_api.build_equivalent_route_claims(
                source=source,
                source_catalog=base.source_identity_catalog,
                route_evidence=base.route_evidence,
                selected_proof_ids=(base.route_evidence.route_proofs[0].proof_id,),
            )
            proposal = replace(base, claims=claims, plan_inputs=replace(
                base.plan_inputs, shape=model.UnflattenPlanShape.PARTIAL_REWRITE,
            ))
            plan = compile_patch_plan(
                [CreateConditionalRedirect(
                    source_block=0, ref_block=1, conditional_target=2,
                    fallthrough_target=3,
                )],
                source,
                plan_id=proposal.plan_id,
                source_generation=1,
                block_refs_by_serial=refs,
            )
            plan = replace(plan, unflatten_proposal=proposal)
            materialization = route_model.CanonicalRouteMaterialization.capture(
                source, generation=1, phase=route_model.CanonicalRouteAssessmentPhase.SOURCE,
            )
            source_inventory = transaction_api._build_semantic_graph_inventory(
                source, proposal, plan, source=True,
                phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
                materialization=materialization,
            )
            assert source_inventory.graph_fingerprint == materialization.graph_fingerprint
            assert source_inventory.inventory_digest
            with mock.patch.object(
                route_model,
                "bind_canonical_semantic_evidence_result",
                wraps=route_model.bind_canonical_semantic_evidence_result,
            ) as source_binder:
                authority = bind.bind_source_route_authority(
                    proposal=proposal,
                    source_inventory=source_inventory,
                    source_materialization=materialization,
                )
            assert type(authority) is model.SourceBoundRouteAuthorityAccepted
            assert source_binder.call_count == 1
            assert authority.authority.source_fingerprint == source_inventory.graph_fingerprint
            assert authority.authority.source_inventory_digest == source_inventory.inventory_digest
        finally:
            db.close()

    def test_diag_lifter_rejects_unrecorded_nested_conditional_expression(
        self,
    ) -> None:
        from d810.backends.hexrays.diag_lifter import _diag_row_to_insn_snapshot

        def mop_stack() -> dict[str, object]:
            return {
                "type": "mop_S", "type_num": 5, "size": 4, "stkoff": 4,
            }

        def mop_number() -> dict[str, object]:
            return {
                "type": "mop_n", "type_num": 2, "size": 4, "value": 7,
            }

        row = SimpleNamespace(
            opcode=_FakeIhr.m_jz,
            opcode_name="m_jz",
            raw_opcode=_FakeIhr.m_jz,
            provenance_version=1,
            ea=0x403010,
            dstr="jz (%var_4.4 - #7.4), @2",
            meta=json.dumps({
                "l": {
                    "type": "mop_d", "type_num": 4, "size": 4,
                    "sub_instruction": {
                        "opcode": _FakeIhr.m_sub,
                        "opcode_name": "m_sub",
                        "l": mop_stack(), "r": mop_number(),
                    },
                },
                "d": {"type": "mop_b", "type_num": 7, "size": 0, "block_num": 2},
                "provenance_version": 1,
            }),
        )

        with pytest.raises(ValueError, match="operand shape|opaque"):
            _diag_row_to_insn_snapshot(row)

    def test_diag_operand_kind_comes_from_canonical_name_not_invented_type_number(
        self,
    ) -> None:
        from d810.backends.hexrays.diag_lifter import parse_diag_meta_operand
        from d810.ir.flowgraph import OperandKind

        stack = parse_diag_meta_operand({
            "type": "mop_S", "type_num": 999, "size": 4, "stkoff": 4,
        })
        assert stack is not None and stack.kind is OperandKind.STACK

        args = parse_diag_meta_operand({
            "type": "mop_f", "type_num": 8, "size": 8,
            "args": [{"type": "mop_S", "type_num": 5, "size": 4, "stkoff": 4}],
        })
        assert args is not None and args.kind is OperandKind.ARG_LIST
        assert args.args[0].kind is OperandKind.STACK

        cases = parse_diag_meta_operand({
            "type": "mop_c", "type_num": 12, "size": 0, "values": [],
        })
        assert cases is not None and cases.kind is OperandKind.CASE_LIST

        with pytest.raises(ValueError, match="canonical type name"):
            parse_diag_meta_operand({"type_num": 5, "size": 4, "stkoff": 4})
        with pytest.raises(ValueError, match="type number"):
            parse_diag_meta_operand({"type": "mop_S", "size": 4, "stkoff": 4})
        with pytest.raises(ValueError, match="outside the closed vocabulary"):
            parse_diag_meta_operand({"type": "mop_invented", "type_num": 5, "size": 4})

    def test_diag_lifter_rejects_impossible_operandless_call(self) -> None:
        from d810.backends.hexrays.diag_lifter import _diag_row_to_insn_snapshot

        row = SimpleNamespace(
            opcode=_FakeIhr.m_call,
            opcode_name="m_call",
            raw_opcode=_FakeIhr.m_call,
            provenance_version=1,
            ea=0x403020,
            dstr="call",
            meta=json.dumps({"provenance_version": 1}),
        )

        with pytest.raises(ValueError, match="operand shape"):
            _diag_row_to_insn_snapshot(row)

    @pytest.mark.parametrize("mutation", ("missing_l", "missing_r", "missing_d", "wrong_target", "wrong_width"))
    def test_diag_conditional_replay_rejects_incomplete_recorded_operands(
        self, mutation: str, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import d810.hexrays.mba_serializer as serializer
        from d810.backends.hexrays.diag_lifter import DiagSourceLifter
        from d810.core.diag import create_diag_database
        from d810.core.diag.semantic_route_oracle import load_snapshot_blocks
        from d810.core.diag.snapshot import snapshot_mba

        monkeypatch.setattr(serializer, "_ihr", _FakeIhr)
        z = _FakeMop(_FakeIhr.mop_z)
        branch = _FakeInsn(
            opcode=_FakeIhr.m_jz, ea=0x402010, text="jz",
            left=_FakeMop(_FakeIhr.mop_S, 4, s=SimpleNamespace(off=0x20)),
            right=_FakeMop(_FakeIhr.mop_n, 4, nnn=SimpleNamespace(value=0)),
            dest=_FakeMop(_FakeIhr.mop_b, 0, b=2),
        )
        block = SimpleNamespace(
            head=branch, tail=branch, type=_FakeIhr.BLT_2WAY,
            start=0x402000, end=0x402011,
            nsucc=lambda: 2, npred=lambda: 0,
            succ=lambda index: (2, 3)[index], pred=lambda _index: 0,
        )
        snapshot = serializer.mba_to_block_snapshots(
            SimpleNamespace(qty=1, get_mblock=lambda _index: block)
        )[0]
        db = create_diag_database(":memory:")
        try:
            snapshot_id = snapshot_mba(db.connection(), [snapshot], "round7-negative", 0x402000)
            decoded = load_snapshot_blocks(db.connection(), snapshot_id)
            row = decoded[0].instructions[0]
            meta = json.loads(row.meta or "{}")
            if mutation == "missing_l":
                meta.pop("l", None)
            elif mutation == "missing_r":
                meta.pop("r", None)
            elif mutation == "missing_d":
                meta.pop("d", None)
            elif mutation == "wrong_target":
                meta["d"]["block_num"] = 99
            else:
                meta["l"]["size"] = 0
            bad_row = replace(row, meta=json.dumps(meta, sort_keys=True, separators=(",", ":")))
            bad_block = replace(decoded[0], instructions=[bad_row])
            with pytest.raises(ValueError, match="conditional|operand shape"):
                DiagSourceLifter().lift(
                    SimpleNamespace(blocks={0: bad_block}, entry_serial=0, func_ea=0x402000)
                )
        finally:
            db.close()

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
                left=_FakeMop(
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
                right=z,
                dest=_FakeMop(_FakeIhr.mop_r, 8, "rdx.8", r=16),
            ),
            _FakeInsn(
                opcode=_FakeIhr.m_mov,
                ea=0x1800175EA,
                text="mov &(%var_1A8).8, rcx.8",
                left=_FakeMop(
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
                right=z,
                dest=_FakeMop(_FakeIhr.mop_r, 8, "rcx.8", r=24),
            ),
            _FakeInsn(
                opcode=_FakeIhr.m_mov,
                ea=0x1800175EF,
                text="mov #0x128.8, r8.8",
                left=_FakeMop(
                    _FakeIhr.mop_n,
                    8,
                    "#0x128.8",
                    nnn=SimpleNamespace(value=0x128),
                ),
                right=z,
                dest=_FakeMop(_FakeIhr.mop_r, 8, "r8.8", r=72),
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
            left=_FakeMop(_FakeIhr.mop_v, -1, "$0x180000000", g=0x180000000),
            right=z,
            dest=z,
        )
        meta_json = serializer._instruction_snapshot_meta(
            call,
            insn_index=10,
            block_register_defs=register_defs,
        )
        assert meta_json is not None

        meta = json.loads(meta_json)
        setup_by_name = {
            record["register_name"]: record for record in meta["call_setup_registers"]
        }
        assert setup_by_name["rcx"]["source"]["sub_operand"]["stkoff"] == 0x70
        assert setup_by_name["rdx"]["source"]["sub_operand"]["global_ea"] == (
            "0x180019f10"
        )
        assert setup_by_name["r8"]["source"]["value"] == 0x128
