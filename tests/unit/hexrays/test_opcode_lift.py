"""Equivalence tests for the Hex-Rays SDK adapter and semantic vocabulary."""

from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace

import pytest


def _load_opcode_lift(monkeypatch: pytest.MonkeyPatch):
    from d810.hexrays import instruction_vocabulary as vocabulary

    names = vocabulary.live_known_opcode_names()
    fake_sdk = SimpleNamespace(**{name: index + 1 for index, name in enumerate(names)})
    monkeypatch.setitem(sys.modules, "ida_hexrays", fake_sdk)
    module = importlib.import_module("d810.hexrays.opcode_lift")
    return importlib.reload(module), vocabulary, fake_sdk


def test_sdk_adapter_delegates_every_known_name_to_instruction_vocabulary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opcode_lift, vocabulary, sdk = _load_opcode_lift(monkeypatch)

    for name in vocabulary.live_known_opcode_names():
        opcode = getattr(sdk, name)
        assert opcode_lift.opcode_name(opcode) == name
        assert opcode_lift.value_op_from_opcode(opcode) is vocabulary.value_op_kind_for_opcode_name(name)
        assert opcode_lift.branch_predicate_from_opcode(opcode) is vocabulary.branch_predicate_for_opcode_name(name)
        assert opcode_lift.set_predicate_from_opcode(opcode) is vocabulary.set_predicate_for_opcode_name(name)
        assert opcode_lift.control_transfer_from_opcode(opcode) is vocabulary.control_transfer_kind_for_opcode_name(name)
        assert opcode_lift.call_kind_from_opcode(opcode) is vocabulary.call_kind_for_opcode_name(name)


def test_branch_predicate_reverse_lookup_is_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opcode_lift, vocabulary, sdk = _load_opcode_lift(monkeypatch)

    for name, predicate in vocabulary.live_branch_predicates():
        assert vocabulary.branch_opcode_name_for_predicate(predicate) == name
        assert opcode_lift.branch_opcode_for_predicate(predicate) == getattr(sdk, name)


def test_replay_subset_is_closed_intersection_of_kind_and_operand_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opcode_lift, vocabulary, sdk = _load_opcode_lift(monkeypatch)

    for name in vocabulary.live_known_opcode_names():
        supported = vocabulary.replay_supported_opcode_name(name)
        if supported:
            assert opcode_lift.opcode_name(getattr(sdk, name)) == name
            assert vocabulary.insn_kind_for_opcode_name(name) is not None
            assert vocabulary.operand_shape_for_opcode_name(name) is not None
        else:
            assert vocabulary.insn_kind_for_opcode_name(name) is None or vocabulary.operand_shape_for_opcode_name(name) is None


def test_every_live_known_opcode_has_closed_replay_semantics_and_shape() -> None:
    from d810.hexrays import instruction_vocabulary as vocabulary

    for name in vocabulary.live_known_opcode_names():
        assert vocabulary.replay_supported_opcode_name(name), name
        assert vocabulary.insn_kind_for_opcode_name(name) is not None, name
        assert vocabulary.operand_shape_for_opcode_name(name) is not None, name
        assert (
            vocabulary.value_op_kind_for_opcode_name(name) is not None
            or vocabulary.predicate_for_opcode_name(name) is not None
            or vocabulary.call_kind_for_opcode_name(name) is not None
            or vocabulary.control_transfer_kind_for_opcode_name(name) is not None
            or name == "m_nop"
        ), name


def test_replay_preserves_exact_unary_value_and_set_predicate_semantics() -> None:
    from d810.hexrays import instruction_vocabulary as vocabulary
    from d810.ir.expressions import ValueOpKind
    from d810.ir.semantics import PredicateKind

    assert vocabulary.insn_kind_for_opcode_name("m_bnot") is not None
    assert vocabulary.value_op_kind_for_opcode_name("m_bnot") is ValueOpKind.NOT
    assert vocabulary.operand_shape_for_opcode_name("m_bnot") == (
        vocabulary.OperandShape(True, False, True)
    )
    assert vocabulary.insn_kind_for_opcode_name("m_setz") is not None
    assert vocabulary.set_predicate_for_opcode_name("m_setz") is PredicateKind.EQ


def test_unknown_and_numeric_aliases_remain_fail_closed() -> None:
    from d810.hexrays import instruction_vocabulary as vocabulary

    for name in ("m_invented", "op_123", "m_op_123"):
        assert vocabulary.insn_kind_for_opcode_name(name) is None
        assert vocabulary.operand_shape_for_opcode_name(name) is None
        assert not vocabulary.replay_supported_opcode_name(name)


def test_live_known_names_cover_complete_sdk_mcode_vocabulary() -> None:
    from d810.hexrays import instruction_vocabulary as vocabulary
    from d810.ir.expressions import ValueOpKind
    from d810.ir.flowgraph import InsnKind

    expected = {
        "m_nop", "m_stx", "m_ldx", "m_ldc", "m_mov", "m_neg", "m_lnot",
        "m_bnot", "m_xds", "m_xdu", "m_low", "m_high", "m_add", "m_sub",
        "m_mul", "m_udiv", "m_sdiv", "m_umod", "m_smod", "m_or", "m_and",
        "m_xor", "m_shl", "m_shr", "m_sar", "m_cfadd", "m_ofadd", "m_cfshl",
        "m_cfshr", "m_sets", "m_seto", "m_setp", "m_setnz", "m_setz", "m_setae",
        "m_setb", "m_seta", "m_setbe", "m_setg", "m_setge", "m_setl", "m_setle",
        "m_jcnd", "m_jnz", "m_jz", "m_jae", "m_jb", "m_ja", "m_jbe", "m_jg",
        "m_jge", "m_jl", "m_jle", "m_jtbl", "m_ijmp", "m_goto", "m_call",
        "m_icall", "m_ret", "m_push", "m_pop", "m_und", "m_ext", "m_f2i",
        "m_f2u", "m_i2f", "m_u2f", "m_f2f", "m_fneg", "m_fadd", "m_fsub",
        "m_fmul", "m_fdiv",
    }
    assert set(vocabulary.live_known_opcode_names()) == expected
    for name in expected:
        assert vocabulary.replay_supported_opcode_name(name)
        assert vocabulary.operand_shape_for_opcode_name(name) is not None
    assert vocabulary.insn_kind_for_opcode_name("m_fdiv") is InsnKind.UNKNOWN
    assert vocabulary.value_op_kind_for_opcode_name("m_fdiv") is ValueOpKind.VENDOR
