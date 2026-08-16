"""Fail-closed SCCP projections at the definition and state-write seams."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.backends.hexrays.evidence.bad_while_loop_dependency_diagnostics import (
    build_bad_while_loop_dependency_diagnostic,
)
from d810.evaluator.hexrays_microcode import (
    definition_rescue_backend as definition_backend_module,
)
from d810.evaluator.hexrays_microcode import (
    dynamic_state_write_backend as dynamic_backend_module,
)
from d810.evaluator.hexrays_microcode import sccp as sccp_module
from d810.evaluator.hexrays_microcode.definition_rescue_backend import (
    HexRaysDefinitionRescueBackend,
)
from d810.evaluator.hexrays_microcode.sccp_model import SccpResult, SccpStatus


NON_CONVERGED_STATUSES = (
    SccpStatus.WORK_LIMIT,
    SccpStatus.BLOCK_LIMIT,
    SccpStatus.ERROR,
)


def _stack_mop(stkoff: int, size: int = 4):
    return SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=size,
        s=SimpleNamespace(off=stkoff),
        dstr=lambda: f"S{stkoff:#x}",
    )


def _dynamic_mba():
    source = _stack_mop(0x24)
    destination = _stack_mop(0x20)
    instruction = SimpleNamespace(
        opcode=ida_hexrays.m_mov,
        ea=0x401000,
        l=source,
        r=None,
        d=destination,
        next=None,
        dstr=lambda: "mov source, state",
    )
    block = SimpleNamespace(head=instruction, succset=(), predset=())
    return SimpleNamespace(
        qty=1,
        get_mblock=lambda serial: block if int(serial) == 0 else None,
    )


@pytest.mark.parametrize("status", NON_CONVERGED_STATUSES)
def test_nonconverged_public_projection_is_proof_empty(
    monkeypatch: pytest.MonkeyPatch,
    status: SccpStatus,
) -> None:
    """Every bounded/error status exposes no constants or edge proof."""

    result = SccpResult.empty(
        status=status,
        program_fingerprint=f"consumer-{status.value}",
        fallback_reason="test non-convergence",
    )
    monkeypatch.setattr(sccp_module, "run_sccp_ex", lambda _mba: result)

    assert sccp_module.run_sccp(object()) == {}
    assert result.constants == {}
    assert result.executable_edges == frozenset()
    assert result.reachable_blocks == frozenset()
    assert result.is_edge_executable(0, 1) is False
    assert result.is_edge_dead(0, 1) is False
    assert result.dead_edges_among(((0, 1),)) == frozenset()


@pytest.mark.parametrize("status", NON_CONVERGED_STATUSES)
def test_nonconverged_overlay_stops_definition_and_dynamic_rescue(
    monkeypatch: pytest.MonkeyPatch,
    status: SccpStatus,
) -> None:
    """Empty SCCP overlays cannot authorize definition rescue or state rewrites."""

    result = SccpResult.empty(
        status=status,
        program_fingerprint=f"consumer-{status.value}",
        fallback_reason="test non-convergence",
    )
    sccp_requests: list[object] = []

    def run_sccp_ex(current_mba: object) -> SccpResult:
        sccp_requests.append(current_mba)
        return result

    monkeypatch.setattr(sccp_module, "run_sccp_ex", run_sccp_ex)
    # The definition backend imported this public function at module load time;
    # patch that public seam to the same projection used by live consumers.
    monkeypatch.setattr(definition_backend_module, "run_sccp", sccp_module.run_sccp)

    mba = _dynamic_mba()
    definition_backend = HexRaysDefinitionRescueBackend()
    assert definition_backend.run_sccp_overlay(mba) == {}
    assert (
        definition_backend.lookup_sccp_stkvar(
            {},
            stkoff=0x20,
            size=4,
        )
        is None
    )

    # Exercise the real diagnostic consumer through its public backend seam.
    missing_source = _stack_mop(0x24)
    copied_instruction = SimpleNamespace(
        opcode=0x77,
        ea=0x401000,
        uses=(missing_source,),
        defs=(),
        dstr=lambda: "copy",
    )
    diagnostic = build_bad_while_loop_dependency_diagnostic(
        mba=mba,
        rule=SimpleNamespace(),
        source_blk=SimpleNamespace(liveins=(), defs=(), predset=()),
        dispatcher_entry=2,
        source_serial=5,
        target_serial=7,
        category="test",
        reason="non-converged SCCP",
        copied_instructions=(copied_instruction,),
        dependency_safe_copies=(),
        definition_backend=definition_backend,
    )
    missing_row = diagnostic["missing_uses"][0]
    assert missing_row["sccp_value"] is None

    # The dynamic-state consumer uses the same public run_sccp projection to
    # build its resolver.  With no proof, an unresolved write must not produce
    # transition evidence or a rewrite target.
    resolver = dynamic_backend_module.make_cross_block_resolver(mba)
    assert resolver(_stack_mop(0x24), 0) is None
    assert (
        dynamic_backend_module.recognize_constant_folded_state_write(
            mba=mba,
            handler_serial=0,
            state_var_stkoff=0x20,
            known_states=(0x1234,),
            cross_block_resolver=resolver,
        )
        is None
    )
    # Direct backend projection, definition diagnostics, and dynamic-state
    # resolver each reached the public SCCP gate exactly once.
    assert sccp_requests == [mba, mba, mba]
