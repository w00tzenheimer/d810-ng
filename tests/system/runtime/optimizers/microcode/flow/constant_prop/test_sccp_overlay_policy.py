"""Runtime coverage for the explicit FCP SCCP overlay policy."""

from __future__ import annotations

import hashlib
import json
import os
import platform
from types import SimpleNamespace

import ida_hexrays
import idaapi
import pytest

from d810.core import CythonMode
from d810.ir.lattice import BOTTOM, TOP, Const
from d810.evaluator.hexrays_microcode.sccp import (
    SccpStatus,
    reset_sccp_session,
    run_sccp_ex,
)
from d810.hexrays.diagnostics.microcode_capture import dump_mba_json
from d810.optimizers.microcode.flow.constant_prop.forward_const_prop import (
    ForwardConstantPropagationRule,
)


def test_modes_are_declared_and_validated():
    params = {item.name: item for item in ForwardConstantPropagationRule.CONFIG_SCHEMA}
    assert params["sccp_overlay"].choices == ("on", "off", "auto")

    rule = ForwardConstantPropagationRule()
    rule.configure({"sccp_overlay": "off"})
    assert rule.sccp_overlay == "off"
    with pytest.raises(ValueError, match="sccp_overlay must be one of"):
        rule.configure({"sccp_overlay": "partial"})


def test_off_and_auto_gate_solver_requests():
    rule = ForwardConstantPropagationRule()
    calls: list[object] = []

    def get_overlay(mba: object) -> dict[tuple[str, int], int]:
        calls.append(mba)
        return {("s", 1): 7}

    rule._get_sccp_overlay = get_overlay
    rule.sccp_overlay = "off"
    assert rule._requested_sccp_overlay(object(), {}) is None
    assert calls == []

    rule.sccp_overlay = "auto"
    rule._sccp_demand_present = lambda _mba: False
    assert rule._requested_sccp_overlay(object(), {}) is None
    assert calls == []

    rule._sccp_demand_present = lambda _mba: True
    assert rule._requested_sccp_overlay(object(), {}) == {("s", 1): 7}
    assert len(calls) == 1


def test_cython_mode_does_not_bypass_requested_overlay(monkeypatch):
    rule = ForwardConstantPropagationRule()
    rule.cython_enabled = True
    rule.sccp_overlay = "on"
    demand_calls: list[object] = []

    def record_demand(mba: object) -> bool:
        demand_calls.append(mba)
        return True

    rule._sccp_demand_present = record_demand
    rule._slow_run_on_function = lambda _mba, **_kwargs: 4

    def forbidden_full_pass(_mba: object) -> int:
        raise AssertionError("overlay bypass")

    rule._run_cython_full_pass = forbidden_full_pass
    assert rule._run_on_function(object()) == 4
    assert demand_calls == []


def test_off_cython_path_does_not_scan_for_sccp_demand():
    rule = ForwardConstantPropagationRule()
    rule.cython_enabled = True
    rule.sccp_overlay = "off"
    rule._sccp_demand_present = lambda _mba: pytest.fail("off policy scanned")
    rule._run_cython_full_pass = lambda _mba: 0

    assert rule._run_on_function(object()) == 0


def test_auto_demand_is_scanned_once_and_passed_to_shared_path():
    rule = ForwardConstantPropagationRule()
    rule.cython_enabled = True
    rule.sccp_overlay = "auto"
    demand_calls: list[object] = []

    def record_demand(mba: object) -> bool:
        demand_calls.append(mba)
        return True

    rule._sccp_demand_present = record_demand
    rule._get_sccp_overlay = lambda _mba: {}

    def shared_path(mba: object, **kwargs: object) -> int:
        rule._requested_sccp_overlay(mba, {}, **kwargs)
        return 4

    rule._slow_run_on_function = shared_path
    rule._run_cython_full_pass = lambda _mba: pytest.fail("auto demand bypass")

    mba = object()
    assert rule._run_on_function(mba) == 4
    assert demand_calls == [mba]


def test_empty_overlay_does_not_merge_or_call_rewrite(monkeypatch):
    rule = ForwardConstantPropagationRule()
    rule.sccp_overlay = "on"
    rule._get_sccp_overlay = lambda _mba: {}
    block = SimpleNamespace(
        head=SimpleNamespace(
            l=SimpleNamespace(t=ida_hexrays.mop_S),
            r=None,
            d=None,
            next=None,
        )
    )
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        rule,
        "_try_sccp_merge_op",
        lambda *args: calls.append(args),
    )
    consts = {}

    overlay = rule._get_sccp_overlay(object())
    assert overlay == {}
    rule._merge_sccp_into_constmap(consts, overlay, block)

    assert consts == {}
    assert calls == []


def test_sccp_overlay_does_not_refine_classic_top_conflict(monkeypatch):
    """SCCP may fill a missing fact, but must not erase a path conflict."""
    from d810.optimizers.microcode.flow.constant_prop import forward_const_prop

    op = SimpleNamespace(size=4)
    monkeypatch.setattr(
        forward_const_prop,
        "constant_propagation_var_name",
        lambda _op: "state",
    )
    overlay = {"state-key": 0x13FA9E5}

    conflicted = {"state": TOP}
    ForwardConstantPropagationRule._try_sccp_merge_op(
        conflicted,
        overlay,
        op,
        lambda _op: "state-key",
    )
    assert conflicted == {"state": TOP}

    missing = {"state": BOTTOM}
    ForwardConstantPropagationRule._try_sccp_merge_op(
        missing,
        overlay,
        op,
        lambda _op: "state-key",
    )
    assert missing == {"state": Const(0x13FA9E5, 4)}


def test_auto_demand_is_read_only_and_conservative():
    rule = ForwardConstantPropagationRule()
    unresolved = SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=4,
        next=None,
    )
    mba = SimpleNamespace(
        qty=1,
        get_mblock=lambda _index: SimpleNamespace(
            head=SimpleNamespace(
                opcode=ida_hexrays.m_mov,
                l=unresolved,
                r=None,
                d=None,
                next=None,
            )
        ),
    )

    assert rule._sccp_demand_present(mba) is True

    malformed = SimpleNamespace(qty=1, get_mblock=lambda _index: object())
    assert rule._sccp_demand_present(malformed) is True

    malformed_qty = SimpleNamespace(qty=-1, get_mblock=lambda _index: None)
    assert rule._sccp_demand_present(malformed_qty) is True


@pytest.mark.parametrize(
    ("opcode", "mop_type"),
    (
        (ida_hexrays.m_ldx, ida_hexrays.mop_S),
        (ida_hexrays.m_ldx, ida_hexrays.mop_r),
        (None, ida_hexrays.mop_S),
        (None, ida_hexrays.mop_r),
    ),
)
def test_auto_demand_covers_every_legacy_cython_operand_surface(opcode, mop_type):
    rule = ForwardConstantPropagationRule()
    unresolved = SimpleNamespace(t=mop_type, size=4, next=None)
    instruction = SimpleNamespace(
        opcode=opcode,
        l=unresolved,
        r=None,
        d=None,
        next=None,
    )
    block = SimpleNamespace(head=instruction)
    mba = SimpleNamespace(qty=1, get_mblock=lambda _index: block)

    assert rule._sccp_demand_present(mba) is True


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _compiled_sccp_required() -> bool:
    return os.environ.get("D810_REQUIRE_COMPILED_SCCP") == "1"


def _function_ea(name: str) -> int:
    import idc

    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def _gen_mba(func_ea: int):
    func = idaapi.get_func(func_ea)
    if func is None:
        return None
    mbr = ida_hexrays.mba_ranges_t(func)
    failure = ida_hexrays.hexrays_failure_t()
    return ida_hexrays.gen_microcode(
        mbr,
        failure,
        None,
        ida_hexrays.DECOMP_NO_WAIT,
        ida_hexrays.MMAT_GLBOPT1,
    )


def _mba_hashes(func_ea: int, mba) -> tuple[str, str]:
    """Hash final pseudocode and disposable-MBA topology separately."""
    rendered = dump_mba_json(mba, indent=0)
    payload = json.loads(rendered)
    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    if cfunc is None:
        raise AssertionError(f"could not decompile 0x{func_ea:x} for parity hash")
    pseudocode = "\n".join(
        idaapi.tag_remove(line.line) for line in cfunc.get_pseudocode()
    )
    pseudocode_hash = hashlib.sha256(pseudocode.encode("utf-8")).hexdigest()
    cfg = tuple(
        (
            int(payload["blocks"][index]["serial"]),
            tuple(payload["blocks"][index].get("successors", ())),
        )
        for index in range(len(payload["blocks"]))
    )
    cfg_hash = hashlib.sha256(repr(cfg).encode("utf-8")).hexdigest()
    return pseudocode_hash, cfg_hash


def _run_disposable_mba(func_ea: int, *, cython_enabled: bool, policy: str):
    mode = CythonMode()
    was_enabled = mode.is_enabled()
    if cython_enabled:
        mode.enable()
    else:
        mode.disable()
    try:
        reset_sccp_session()
        mba = _gen_mba(func_ea)
        if mba is None:
            message = "could not generate disposable MBA"
            if _compiled_sccp_required():
                pytest.fail(message)
            pytest.skip(message)

        rule = ForwardConstantPropagationRule()
        rule.configure({"cython_enabled": cython_enabled, "sccp_overlay": policy})
        overlays: list[dict[tuple, int | None]] = []
        solver_results = []
        original_get_overlay = rule._get_sccp_overlay

        def capture_overlay(current_mba):
            result = run_sccp_ex(current_mba)
            if result is None:
                message = "SCCP request fell back to an unavailable backend"
                if _compiled_sccp_required():
                    pytest.fail(message)
                pytest.skip(message)
            if cython_enabled and _compiled_sccp_required():
                assert result.backend == "cython"
            solver_results.append(result)
            overlay = original_get_overlay(current_mba)
            overlays.append(dict(overlay or {}))
            return overlay

        rule._get_sccp_overlay = capture_overlay
        patch_count = rule._run_on_function(mba)
        return (
            tuple(sorted(overlays, key=repr)),
            patch_count,
            *_mba_hashes(func_ea, mba),
            tuple(
                None
                if result is None
                else (result.status.value, result.backend, result.parity_key())
                for result in solver_results
            ),
        )
    finally:
        if was_enabled:
            mode.enable()
        else:
            mode.disable()


class TestSccpOverlayRuntimeParity:
    """Run policy modes on identical source material in disposable MBAs."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_on_and_auto_demand_match_python_and_cython(self, libobfuscated_setup):
        func_ea = _function_ea("test_chained_add")
        if func_ea == idaapi.BADADDR:
            message = "test_chained_add not present in test binary"
            if _compiled_sccp_required():
                pytest.fail(message)
            pytest.skip(message)

        for policy in ("on", "auto"):
            python_run = _run_disposable_mba(
                func_ea,
                cython_enabled=False,
                policy=policy,
            )
            cython_run = _run_disposable_mba(
                func_ea,
                cython_enabled=True,
                policy=policy,
            )

            assert python_run[:4] == cython_run[:4]
            assert python_run[0], f"{policy} must request an SCCP overlay"
            assert python_run[4], f"{policy} must execute an SCCP request"
            assert cython_run[4], f"{policy} must execute an SCCP request"
            if _compiled_sccp_required():
                assert all(result[1] == "cython" for result in cython_run[4])
            assert all(
                result[0] == SccpStatus.CONVERGED.value for result in python_run[4]
            )
            assert all(
                result[0] == SccpStatus.CONVERGED.value for result in cython_run[4]
            )
            assert tuple(result[2] for result in python_run[4]) == tuple(
                result[2] for result in cython_run[4]
            )
