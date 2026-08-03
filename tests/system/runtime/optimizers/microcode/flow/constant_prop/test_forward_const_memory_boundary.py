"""Runtime boundary tests for constant propagation and memory resolution."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.ir.lattice import TOP, Const
from d810.optimizers.microcode.flow.constant_prop.forward_const_prop import (
    ForwardConstantPropagationRule,
)


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
