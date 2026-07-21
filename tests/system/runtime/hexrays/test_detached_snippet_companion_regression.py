"""Regression contracts for detached PREOPT/CALLS companion templates."""

from __future__ import annotations

import os
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.hexrays.mutation import detached_handler_island
from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from tests.native_preanalysis import make_native_key
from tests.system.runtime.hexrays.test_detached_snippet_import import (
    _Block,
    _install_runtime_fakes,
    _Instruction,
    _MBA,
    _Operand,
)


_TRUE_ENV_VALUES = frozenset({"1", "true", "yes", "on"})


def _env_enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUE_ENV_VALUES


def _companion_pair(
    *,
    target_ea: int,
    call_ea: int,
    callee_ea: int,
    preopt_root_ea: int | None = None,
) -> tuple[_MBA, _MBA]:
    preopt = _MBA(
        (
            _Block(
                0,
                target_ea if preopt_root_ea is None else preopt_root_ea,
                (
                    _Instruction(
                        ida_hexrays.m_call,
                        call_ea,
                        left=_Operand(
                            ida_hexrays.mop_v,
                            target_ea=callee_ea,
                        ),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    calls = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_call,
                        call_ea,
                        left=_Operand(
                            ida_hexrays.mop_v,
                            target_ea=callee_ea,
                        ),
                        dest=_Operand(ida_hexrays.mop_f),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_CALLS,
    )
    return preopt, calls


@pytest.mark.skipif(
    not _env_enabled("D810_NO_SPEEDUPS"),
    reason="acceptance contract runs with D810_NO_SPEEDUPS=1",
)
def test_companion_capture_is_correct_without_optional_speedups(
    monkeypatch,
) -> None:
    """Companion correctness must not require any optional speedup backend."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    call_ea = 0x40BA56
    preopt, calls = _companion_pair(
        target_ea=target_ea,
        call_ea=call_ea,
        callee_ea=0x40F830,
    )

    result = detached_handler_island.capture_detached_snippet_companion_templates(
        function_ea,
        target_ea,
        preopt,
        calls,
        ((target_ea, call_ea + 1),),
    )

    assert result.captured is True
    assert result.call_eas == (call_ea,)
    assert detached_handler_island.has_detached_snippet_template(
        function_ea,
        target_ea,
    )
    assert detached_handler_island.has_detached_replacement_snippet_template(
        function_ea,
        target_ea,
    )


def test_companion_abstention_restores_existing_pair_atomically(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    call_ea = 0x40BA56
    key = (function_ea, target_ea)
    old_primary = object()
    old_replacement = object()
    detached_handler_island._DETACHED_SNIPPET_TEMPLATES[key] = old_primary
    detached_handler_island._DETACHED_REPLACEMENT_SNIPPET_TEMPLATES[key] = (
        old_replacement
    )
    detached_handler_island._DETACHED_SNIPPET_GENERATIONS[function_ea] = 7
    preopt, calls = _companion_pair(
        target_ea=target_ea,
        call_ea=call_ea,
        callee_ea=0x40F830,
        preopt_root_ea=target_ea + 1,
    )

    result = detached_handler_island.capture_detached_snippet_companion_templates(
        function_ea,
        target_ea,
        preopt,
        calls,
        ((target_ea, call_ea + 1),),
    )

    assert result.captured is False
    assert result.reason == "primary_capture_failed"
    assert detached_handler_island._DETACHED_SNIPPET_TEMPLATES[key] is old_primary
    assert (
        detached_handler_island._DETACHED_REPLACEMENT_SNIPPET_TEMPLATES[key]
        is old_replacement
    )
    assert (
        detached_handler_island.detached_snippet_template_generation(function_ea) == 7
    )


def test_companion_preparer_is_inert_without_profile_evidence(monkeypatch) -> None:
    from d810.optimizers.microcode.flow.jumps import computed_goto_resolver

    session = SimpleNamespace(
        native_key=make_native_key(),
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
    )
    state = computed_goto_resolver.resolver_session_state(session)

    def unexpected_capture(*_args: object, **_kwargs: object) -> object:
        pytest.fail("unowned function reached companion capture")

    monkeypatch.setattr(
        detached_handler_island,
        "capture_detached_snippet_companion_templates",
        unexpected_capture,
    )

    assert computed_goto_resolver.prepare_detached_handler_snippets(state) == 0


def test_companion_cache_clear_removes_primary_replacement_and_generation(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    monkeypatch.setattr(detached_handler_island, "_ANALYZED_CALL_TEMPLATES", {})
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    key = (function_ea, target_ea)
    detached_handler_island._DETACHED_SNIPPET_TEMPLATES[key] = object()
    detached_handler_island._DETACHED_REPLACEMENT_SNIPPET_TEMPLATES[key] = object()
    detached_handler_island._DETACHED_SNIPPET_GENERATIONS[function_ea] = 3

    detached_handler_island.clear_detached_handler_call_templates()

    assert not detached_handler_island.has_detached_snippet_template(
        function_ea,
        target_ea,
    )
    assert not detached_handler_island.has_detached_replacement_snippet_template(
        function_ea,
        target_ea,
    )
    assert (
        detached_handler_island.detached_snippet_template_generation(function_ea) == 0
    )


def _analyzed_call_mba(
    *,
    call_ea: int,
    callee_ea: int,
    arguments: tuple[_Operand, ...],
    call_spd: int = 0,
    stkargs_top: int = 0,
) -> _MBA:
    arglist = _Operand(ida_hexrays.mop_f, arguments=arguments)
    arglist.f.call_spd = int(call_spd)
    arglist.f.stkargs_top = int(stkargs_top)
    return _MBA(
        (
            _Block(
                0,
                call_ea,
                (
                    _Instruction(
                        ida_hexrays.m_call,
                        call_ea,
                        left=_Operand(
                            ida_hexrays.mop_v,
                            target_ea=callee_ea,
                        ),
                        dest=arglist,
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_CALLS,
    )


def test_route_callinfo_capture_merges_unique_native_call_eas(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    monkeypatch.setattr(detached_handler_island, "_DETACHED_CALLINFO_TEMPLATES", {})
    monkeypatch.setattr(detached_handler_island, "_DETACHED_CALLINFO_CONFLICTS", set())
    function_ea = 0x401000
    first_call_ea = 0x402010
    second_call_ea = 0x403020

    first = detached_handler_island.capture_detached_callinfo_templates(
        function_ea,
        _analyzed_call_mba(
            call_ea=first_call_ea,
            callee_ea=0x500000,
            arguments=(_Operand(ida_hexrays.mop_n, value=0x7F00),),
            call_spd=0,
            stkargs_top=4,
        ),
    )
    second = detached_handler_island.capture_detached_callinfo_templates(
        function_ea,
        _analyzed_call_mba(
            call_ea=second_call_ea,
            callee_ea=0x500100,
            arguments=(
                _Operand(ida_hexrays.mop_n, value=1),
                _Operand(ida_hexrays.mop_n, value=0x7538),
            ),
            call_spd=0,
            stkargs_top=8,
        ),
    )

    assert first == (first_call_ea,)
    assert second == (second_call_ea,)
    assert set(detached_handler_island._DETACHED_CALLINFO_TEMPLATES) == {
        (function_ea, first_call_ea),
        (function_ea, second_call_ea),
    }


def test_route_callinfo_capture_rejects_mba_relative_arguments(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    monkeypatch.setattr(detached_handler_island, "_DETACHED_CALLINFO_TEMPLATES", {})
    monkeypatch.setattr(detached_handler_island, "_DETACHED_CALLINFO_CONFLICTS", set())
    function_ea = 0x401000
    call_ea = 0x402010
    mba = _analyzed_call_mba(
        call_ea=call_ea,
        callee_ea=0x500000,
        arguments=(
            _Operand(
                ida_hexrays.mop_a,
                address=_Operand(ida_hexrays.mop_S, stack_offset=0x80),
            ),
        ),
        call_spd=0,
        stkargs_top=4,
    )

    assert (
        detached_handler_island.capture_detached_callinfo_templates(
            function_ea,
            mba,
        )
        == ()
    )
    assert (function_ea, call_ea) not in (
        detached_handler_island._DETACHED_CALLINFO_TEMPLATES
    )


def test_route_callinfo_conflict_abstains_atomically(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    monkeypatch.setattr(detached_handler_island, "_DETACHED_CALLINFO_TEMPLATES", {})
    monkeypatch.setattr(detached_handler_island, "_DETACHED_CALLINFO_CONFLICTS", set())
    function_ea = 0x401000
    call_ea = 0x402010
    first = _analyzed_call_mba(
        call_ea=call_ea,
        callee_ea=0x500000,
        arguments=(_Operand(ida_hexrays.mop_n, value=1),),
        call_spd=0,
        stkargs_top=4,
    )
    conflicting = _analyzed_call_mba(
        call_ea=call_ea,
        callee_ea=0x500000,
        arguments=(_Operand(ida_hexrays.mop_n, value=2),),
        call_spd=0,
        stkargs_top=4,
    )

    assert detached_handler_island.capture_detached_callinfo_templates(
        function_ea,
        first,
    ) == (call_ea,)
    assert (
        detached_handler_island.capture_detached_callinfo_templates(
            function_ea,
            conflicting,
        )
        == ()
    )
    assert (function_ea, call_ea) not in (
        detached_handler_island._DETACHED_CALLINFO_TEMPLATES
    )
    assert (function_ea, call_ea) in (
        detached_handler_island._DETACHED_CALLINFO_CONFLICTS
    )


def test_route_callinfo_rebases_analyzed_stack_window(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    monkeypatch.setattr(detached_handler_island, "_DETACHED_CALLINFO_TEMPLATES", {})
    monkeypatch.setattr(detached_handler_island, "_DETACHED_CALLINFO_CONFLICTS", set())
    function_ea = 0x401000
    call_ea = 0x402010
    analyzed = _analyzed_call_mba(
        call_ea=call_ea,
        callee_ea=0x500000,
        arguments=(
            _Operand(ida_hexrays.mop_n, value=0),
            _Operand(ida_hexrays.mop_n, value=0x7F00),
        ),
        call_spd=0x80,
        stkargs_top=0x88,
    )
    detached_handler_island.capture_detached_callinfo_templates(
        function_ea,
        analyzed,
    )
    raw_call = _Instruction(
        ida_hexrays.m_call,
        call_ea,
        left=_Operand(ida_hexrays.mop_v, target_ea=0x500000),
    )
    destination = _MBA(
        (_Block(0, function_ea, (raw_call,)),),
        ida_to_vd_delta=0x30,
    )

    class Callinfo:
        def __init__(self) -> None:
            self.args: list[object] = []
            self.call_spd = 0
            self.stkargs_top = 0

    monkeypatch.setattr(
        detached_handler_island.ida_hexrays,
        "mcallinfo_t",
        Callinfo,
    )

    def copy_callinfo(destination_callinfo: object, source_callinfo: object) -> bool:
        destination_callinfo.args = list(source_callinfo.args)
        destination_callinfo.call_spd = int(source_callinfo.call_spd)
        destination_callinfo.stkargs_top = int(source_callinfo.stkargs_top)
        return True

    prepared = detached_handler_island.prepare_detached_callinfo_template(
        function_ea,
        call_ea,
        raw_call,
        destination,
        copy_callinfo=copy_callinfo,
    )

    assert prepared is not None
    assert len(prepared.args) == 2
    assert prepared.call_spd == 0x28
    assert prepared.stkargs_top == 0x30
