"""Runtime boundary tests for constant propagation and memory resolution."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.ir.lattice import TOP, Const
from d810.hexrays.ir.mop_utils import constant_propagation_var_name
from d810.optimizers.microcode.flow.constant_prop.forward_const_prop import (
    ForwardConstantPropagationRule,
)


def test_mba_function_ea_accepts_valid_entry_ea():
    rule = ForwardConstantPropagationRule()
    mba = SimpleNamespace(entry_ea=0x401000)

    assert rule._mba_function_ea(mba) == 0x401000


def test_unmaterialized_ldx_kills_destination(monkeypatch):
    """FCP must not independently manufacture a constant from memory."""
    rule = ForwardConstantPropagationRule()
    instruction = SimpleNamespace(
        opcode=ida_hexrays.m_ldx,
        l=None,
        has_side_effects=lambda: False,
    )
    monkeypatch.setattr(rule, "_get_written_var_name", lambda _ins: "dst")
    environment = {"dst": Const(0xDEADBEEF, 4)}

    rule._slow_transfer_single(None, instruction, environment)

    assert environment["dst"] is TOP
    assert not hasattr(rule, "_try_resolve_readonly_ldx")


def test_forward_fcp_can_be_scheduled_only_after_cfg_recovery():
    rule = ForwardConstantPropagationRule()
    rule.configure({"maturities": ["MMAT_GLBOPT2"], "cython_enabled": False})

    assert rule.maturities == [ida_hexrays.MMAT_GLBOPT2]
    assert rule.cython_enabled is False


def test_constprop_stack_key_ignores_ssa_version_but_register_key_does_not(
    monkeypatch,
):
    """A stack location survives SSA and width changes across recovered blocks."""
    stack_definition = SimpleNamespace(t=ida_hexrays.mop_S, valnum=0)
    stack_use = SimpleNamespace(t=ida_hexrays.mop_S, valnum=78)
    register_definition = SimpleNamespace(t=ida_hexrays.mop_r, valnum=0)
    register_use = SimpleNamespace(t=ida_hexrays.mop_r, valnum=78)

    def render_name(mop):
        if mop.t == ida_hexrays.mop_S:
            prefix = "%var_2E0.8" if mop.valnum == 0 else "%var_2E0.4"
        else:
            prefix = "rax"
        return f"{prefix}{{{mop.valnum}}}"

    monkeypatch.setattr(
        "d810.hexrays.ir.mop_utils.get_stack_var_name",
        render_name,
    )

    assert constant_propagation_var_name(stack_definition) == "%var_2E0"
    assert constant_propagation_var_name(stack_use) == "%var_2E0"
    assert constant_propagation_var_name(register_definition) == "rax{0}"
    assert constant_propagation_var_name(register_use) == "rax{78}"


def test_constprop_does_not_widen_a_known_stack_value(monkeypatch):
    """A four-byte store never authorizes an eight-byte read rewrite."""
    rule = ForwardConstantPropagationRule()
    rewritten = []
    stack_use = SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=8,
        make_number=lambda value, size: rewritten.append((value, size)),
    )

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.constant_prop.forward_const_prop.constant_propagation_var_name",
        lambda _mop: "%var_2E0",
    )

    assert not rule._slow_process_operand(
        stack_use,
        {"%var_2E0": Const(0x89ABCDEF, 4)},
    )
    assert rewritten == []
