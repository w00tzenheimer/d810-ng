from __future__ import annotations

import pytest

from d810.analyses.control_flow import guarded_state_machine
from d810.analyses.control_flow import local_select_loop
from d810.analyses.control_flow import selector_shell
from d810.analyses.control_flow import side_effect_select_loop
from d810.ir.flowgraph import MopSnapshot, OperandKind


class _ConstWithoutRawNnn:
    kind = OperandKind.NUMBER
    size = 4
    value = 0x2A

    @property
    def nnn(self):  # pragma: no cover - test fails if accessed
        raise AssertionError("selector helper read raw .nnn")


class _LvarWithoutRawIdx:
    kind = OperandKind.LVAR
    size = 4
    lvar_off = 0x38

    @property
    def lvar_idx(self):  # pragma: no cover - test fails if accessed
        raise AssertionError("selector helper read raw .lvar_idx")


@pytest.mark.parametrize(
    "module",
    (
        guarded_state_machine,
        local_select_loop,
        selector_shell,
        side_effect_select_loop,
    ),
)
def test_selector_const_helpers_use_canonical_varnode_value(module) -> None:
    assert module._const_value(_ConstWithoutRawNnn()) == 0x2A


@pytest.mark.parametrize(
    "module",
    (
        local_select_loop,
        selector_shell,
        side_effect_select_loop,
    ),
)
def test_selector_var_ids_use_canonical_storage_identity(module) -> None:
    assert module._var_id(MopSnapshot(kind=OperandKind.REGISTER, reg=7, size=8)) == (
        "reg",
        7,
    )
    assert module._var_id(MopSnapshot(kind=OperandKind.STACK, stkoff=0x80, size=1)) == (
        "stack",
        0x80,
    )
    assert module._var_id(_LvarWithoutRawIdx()) == ("lvar", 0x38)


def test_guarded_state_machine_var_key_uses_canonical_storage_identity() -> None:
    assert guarded_state_machine._var_key(
        MopSnapshot(kind=OperandKind.REGISTER, reg=7, size=8)
    ) == ("reg", 7, 8)
    assert guarded_state_machine._var_key(
        MopSnapshot(kind=OperandKind.STACK, stkoff=0x80, size=1)
    ) == ("stack", 0x80, 1)
    assert guarded_state_machine._var_key(_LvarWithoutRawIdx()) == ("lvar", 0x38, 4)
