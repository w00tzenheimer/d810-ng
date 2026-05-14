from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.optimizers.microcode.flow.flattening.hodur.profile_gate import (
    AttributeHodurProfileGate,
    accepts_exact_sub7ffd_glbopt1,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies import (
    exact_conditional_alias,
    exact_conditional_fork,
    exact_conditional_node,
    exact_node_frontier_bypass,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_alias import (
    ExactConditionalAliasNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_fork import (
    ExactConditionalForkNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_node import (
    ExactConditionalNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_node_frontier_bypass import (
    ExactNodeFrontierBypassStrategy,
)


_SUB7FFD_FUNC_EA = 0x180012B60
_MMAT_GLBOPT1 = AttributeHodurProfileGate().maturity_name_to_int["global_opt_1"]


def _snapshot(
    *,
    entry_ea: int = _SUB7FFD_FUNC_EA,
    maturity: int = _MMAT_GLBOPT1,
    state_machine: object | None = object(),
    bst_result: object | None = object(),
    flow_graph: object | None = object(),
    bst_dispatcher_serial: int = 2,
):
    return SimpleNamespace(
        mba=SimpleNamespace(entry_ea=entry_ea, maturity=maturity),
        state_machine=state_machine,
        bst_result=bst_result,
        flow_graph=flow_graph,
        bst_dispatcher_serial=bst_dispatcher_serial,
    )


def test_attribute_profile_gate_accepts_named_glbopt1() -> None:
    gate = AttributeHodurProfileGate()
    live_function = SimpleNamespace(entry_ea=_SUB7FFD_FUNC_EA, maturity=_MMAT_GLBOPT1)

    assert gate.accepts_function(
        live_function,
        expected_entry_ea=_SUB7FFD_FUNC_EA,
        required_maturity="global_opt_1",
    )
    assert gate.accepts_function(
        live_function,
        expected_entry_ea=_SUB7FFD_FUNC_EA,
        required_maturity="MMAT_GLBOPT1",
    )


@pytest.mark.parametrize(
    ("live_function", "expected_entry_ea", "required_maturity"),
    (
        (None, _SUB7FFD_FUNC_EA, "global_opt_1"),
        (SimpleNamespace(entry_ea=0x1111, maturity=_MMAT_GLBOPT1), _SUB7FFD_FUNC_EA, "global_opt_1"),
        (SimpleNamespace(entry_ea=_SUB7FFD_FUNC_EA, maturity=3), _SUB7FFD_FUNC_EA, "global_opt_1"),
        (SimpleNamespace(entry_ea=_SUB7FFD_FUNC_EA, maturity=_MMAT_GLBOPT1), _SUB7FFD_FUNC_EA, "unknown"),
    ),
)
def test_attribute_profile_gate_rejects_mismatches(
    live_function,
    expected_entry_ea: int,
    required_maturity: str,
) -> None:
    gate = AttributeHodurProfileGate()

    assert not gate.accepts_function(
        live_function,
        expected_entry_ea=expected_entry_ea,
        required_maturity=required_maturity,
    )


def test_exact_sub7ffd_gate_reads_snapshot_mba() -> None:
    snapshot = _snapshot()

    assert accepts_exact_sub7ffd_glbopt1(
        snapshot,
        expected_entry_ea=_SUB7FFD_FUNC_EA,
    )
    assert not accepts_exact_sub7ffd_glbopt1(
        _snapshot(maturity=3),
        expected_entry_ea=_SUB7FFD_FUNC_EA,
    )


@pytest.mark.parametrize(
    ("module", "strategy_cls"),
    (
        (exact_conditional_node, ExactConditionalNodeLoweringStrategy),
        (exact_conditional_fork, ExactConditionalForkNodeLoweringStrategy),
        (exact_conditional_alias, ExactConditionalAliasNodeLoweringStrategy),
        (exact_node_frontier_bypass, ExactNodeFrontierBypassStrategy),
    ),
)
def test_exact_strategy_admission_delegates_to_profile_gate(
    monkeypatch,
    module,
    strategy_cls,
) -> None:
    calls: list[int] = []

    def fake_gate(snapshot, *, expected_entry_ea):
        calls.append(int(expected_entry_ea))
        return True

    monkeypatch.setattr(module, "accepts_exact_sub7ffd_glbopt1", fake_gate)

    assert strategy_cls().is_applicable(_snapshot())
    assert calls == [_SUB7FFD_FUNC_EA]


@pytest.mark.parametrize(
    ("module", "strategy_cls"),
    (
        (exact_conditional_node, ExactConditionalNodeLoweringStrategy),
        (exact_conditional_fork, ExactConditionalForkNodeLoweringStrategy),
        (exact_conditional_alias, ExactConditionalAliasNodeLoweringStrategy),
        (exact_node_frontier_bypass, ExactNodeFrontierBypassStrategy),
    ),
)
def test_exact_strategy_admission_rejects_when_profile_gate_rejects(
    monkeypatch,
    module,
    strategy_cls,
) -> None:
    monkeypatch.setattr(
        module,
        "accepts_exact_sub7ffd_glbopt1",
        lambda _snapshot, *, expected_entry_ea: False,
    )

    assert not strategy_cls().is_applicable(_snapshot())
