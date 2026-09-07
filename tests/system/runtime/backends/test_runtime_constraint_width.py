"""Matched-expression width survives defining constraints and IDA emission."""

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.backends.mba.ida import IDAPatternAdapter
from d810.hexrays.expr.ast import AstConstant
from d810.mba.rules.cst import (
    CstSimplificationRule3,
    CstSimplificationRule4,
    CstSimplificationRule7,
    CstSimplificationRule17,
)


def candidate(size, **values):
    return SimpleNamespace(
        size=size,
        dest_size=size,
        dst_mop=SimpleNamespace(size=size),
        leafs_by_name={
            name: AstConstant(name, value, size) for name, value in values.items()
        },
    )


@pytest.mark.usefixtures("ida_database")
class TestRuntimeConstraintWidth:
    binary_name = "libobfuscated.dll"

    @pytest.mark.parametrize("size", [1, 2, 4, 8])
    @pytest.mark.parametrize(
        "rule_type,values,expected",
        [
            (
                CstSimplificationRule17,
                {"c_1": 0x0051C78825B4E571},
                {"bnot_c_1": ~0x0051C78825B4E571},
            ),
            (
                CstSimplificationRule4,
                {"c_1": 0x0051C78825B4E571},
                {"c_res": -0x0051C78825B4E571},
            ),
            (
                CstSimplificationRule3,
                {"c_0": 3, "c_1": 0x100000001, "c_2": 7},
                {"c_coeff": 0x100000002, "c_sub": 0x70000000A},
            ),
        ],
    )
    def test_computed_constant_emission(self, size, rule_type, values, expected):
        mask = (1 << (size * 8)) - 1
        matched = candidate(
            size, **{name: value & mask for name, value in values.items()}
        )
        rule = rule_type()
        assert rule.check_candidate(matched)
        assert matched.leafs_by_name["_width"] == size * 8
        adapter = IDAPatternAdapter(rule)
        for name, value in expected.items():
            computed = matched.leafs_by_name[name]
            assert computed.value == value & mask
            assert computed.expected_size == size
            leaf = AstConstant(name)
            replacement = SimpleNamespace(get_leaf_list=lambda: [leaf])
            assert adapter._materialize_replacement_constants(replacement, matched)
            assert leaf.mop.size == size
            assert leaf.mop.nnn.value == value & mask

    @pytest.mark.parametrize(
        "size,dest_size,dst_size,width",
        [(0, 0, 0, None), (8, 4, 8, None), (8, 8, 4, None), (8, 8, 8, 32)],
    )
    def test_missing_or_conflicting_candidate_width_rejects(
        self, size, dest_size, dst_size, width
    ):
        matched = candidate(size, c_1=1)
        matched.dest_size = dest_size
        matched.dst_mop.size = dst_size
        if width is not None:
            matched.leafs_by_name["_width"] = width
        assert not CstSimplificationRule17().check_candidate(matched)
        assert "bnot_c_1" not in matched.leafs_by_name

    def test_computed_emission_requires_explicit_consistent_size(self):
        adapter = IDAPatternAdapter(CstSimplificationRule17())
        matched = candidate(8)
        matched.leafs_by_name["bnot_c_1"] = AstConstant("bnot_c_1", 0xDA4B1A8E)
        leaf = AstConstant("bnot_c_1")
        assert not adapter._materialize_replacement_constants(
            SimpleNamespace(get_leaf_list=lambda: [leaf]), matched
        )
        matched.leafs_by_name["bnot_c_1"].expected_size = 4
        assert not adapter._materialize_replacement_constants(
            SimpleNamespace(get_leaf_list=lambda: [leaf]), matched
        )

    def test_shift_rule_accepts_one_byte_count_for_eight_byte_data(self):
        matched = candidate(8, c_1=0x8000000000000000)
        matched.leafs_by_name["c_2"] = AstConstant("c_2", 32, 1)
        assert CstSimplificationRule7().check_candidate(matched)
        assert matched.leafs_by_name["c_res"].value == 0x80000000
        assert matched.leafs_by_name["c_res"].expected_size == 8

    @pytest.mark.parametrize("size", [1, 2, 4, 8])
    def test_rule17_final_instruction_mask(self, size):
        from d810.hexrays.ir.number_operand import safe_make_number

        mask = (1 << (size * 8)) - 1
        value = 0x0051C78825B4E571 & mask
        nested = ida_hexrays.minsn_t(0x401000)
        nested.opcode = ida_hexrays.m_or
        nested.l.make_reg(1, size)
        assert safe_make_number(nested.r, value, size)
        nested.d.make_reg(2, size)
        original = ida_hexrays.minsn_t(0x401000)
        original.opcode = ida_hexrays.m_bnot
        original.l.create_from_insn(nested)
        original.l.size = size
        original.d.make_reg(2, size)
        result = IDAPatternAdapter(CstSimplificationRule17()).check_and_replace(
            None, original
        )
        assert result is not None
        assert result.opcode == ida_hexrays.m_and
        assert result.d.size == size
        assert result.r.t == ida_hexrays.mop_n
        assert result.r.size == size
        assert result.r.nnn.value == (~value & mask)

    def test_shadow_binding_preserves_constraint_width(self):
        from d810.backends.mba.ida import _ShadowBindingCandidate

        matched = candidate(8, c_1=0x0051C78825B4E571)
        matched.ea = 0x401000
        rule = CstSimplificationRule17()
        assert rule.check_candidate(matched)
        shadow = _ShadowBindingCandidate(matched.leafs_by_name, matched)
        rebound = IDAPatternAdapter(rule)._shadow_binding_context(shadow)
        assert rebound.leafs_by_name["_width"] == 64
        assert rebound.dest_size == 8

    def test_rule_rejects_narrow_arithmetic_leaf_without_raising(self):
        matched = candidate(8)
        matched.leafs_by_name["c_1"] = AstConstant("c_1", 1, 4)
        assert not CstSimplificationRule17().check_candidate(matched)
