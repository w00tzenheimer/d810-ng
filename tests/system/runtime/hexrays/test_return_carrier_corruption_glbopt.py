from __future__ import annotations

import importlib
import inspect
import sys
import copy
from types import SimpleNamespace

import pytest

from d810.analyses.value_flow.return_carrier_corruption import (
    CarrierCorruptionProof,
    CarrierDefinition,
    ReturnRegDef,
)
from d810.hexrays.ir.native_identity import native_object_identity


class _Operand:
    def __init__(self) -> None:
        self.erased = False
        self.t = 1

    def erase(self) -> None:
        self.erased = True
        self.t = 0


class _Insn:
    def __init__(self, ea: int, opcode: int = 99) -> None:
        self.ea = ea
        self.opcode = opcode
        self.l = _Operand()
        self.r = _Operand()
        self.d = _Operand()
        self.next = None

    def _print(self):
        return f"{self.opcode}:{self.l.t}:{self.r.t}:{self.d.t}"

    def swap(self, other):
        for name in ("opcode", "l", "r", "d"):
            mine = getattr(self, name)
            setattr(self, name, getattr(other, name))
            setattr(other, name, mine)


class _Block:
    def __init__(self, *insns: _Insn) -> None:
        for left, right in zip(insns, insns[1:]):
            left.next = right
        self.head = insns[0] if insns else None
        self.serial = 1
        self.dirty_count = 0

    def mark_lists_dirty(self):
        self.dirty_count += 1


class _Mba:
    def __init__(self, block: _Block, *, maturity: int = 14) -> None:
        self.entry_ea = 0x180014BE0
        self.maturity = maturity
        self._block = block
        block.mba = self
        self.mark_chains_dirty_calls = 0

    def get_mblock(self, serial: int) -> _Block | None:
        if serial == 1:
            return self._block
        return None

    def mark_chains_dirty(self) -> None:
        self.mark_chains_dirty_calls += 1


@pytest.fixture()
def glbopt_module(monkeypatch):
    module_names = (
        "d810.hexrays.hooks.glbopt_diagnostics",
        "d810.hexrays.mutation.instruction_commit",
        "d810.hexrays.mutation.return_carrier_corruption",
    )
    original_modules = {name: sys.modules.get(name) for name in module_names}
    fake_hexrays = SimpleNamespace(
        MMAT_GLBOPT1=14,
        MMAT_GLBOPT2=15,
        m_nop=0,
        mop_z=0,
        minsn_t=copy.deepcopy,
        mbl_array_t=object,
        mblock_t=object,
        mop_a=1,
        mop_d=2,
        mop_n=3,
        mop_r=4,
        mop_S=5,
        m_mov=6,
        m_add=7,
        m_ldx=8,
        reg2mreg=lambda _reg: 0,
    )
    monkeypatch.setitem(sys.modules, "ida_hexrays", fake_hexrays)
    sys.modules.pop("d810.hexrays.mutation.instruction_commit", None)
    sys.modules.pop("d810.hexrays.hooks.glbopt_diagnostics", None)
    sys.modules.pop("d810.hexrays.mutation.return_carrier_corruption", None)
    try:
        module = importlib.import_module("d810.hexrays.hooks.glbopt_diagnostics")
        committer_module = sys.modules["d810.hexrays.mutation.instruction_commit"]
        monkeypatch.setattr(
            committer_module,
            "find_droppable_return_const_corruptions",
            lambda mba, **kw: module.find_droppable_return_const_corruptions(mba, **kw),
        )
        yield module
    finally:
        for name, original in original_modules.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


def _site(module, mba, *, block: int = 1, ea: int = 0x180018F75):
    return module.CandidateSite(
        block_serial=block,
        insn_ea=ea,
        proof=CarrierCorruptionProof(
            ReturnRegDef(block, ea, 151, True, True, 0xB5),
            0,
            (CarrierDefinition(0, 0x180014BE0),),
            True,
        ),
        function_ea=mba.entry_ea,
        mba_identity=native_object_identity(mba),
        maturity=mba.maturity,
    )


def _apply(module, mba):
    snapshot = module.ReturnRegisterConsumptionSnapshot(
        mba.entry_ea,
        native_object_identity(mba),
        module.ida_hexrays.MMAT_GLBOPT1,
        (CarrierDefinition(1, 0x180018F75),),
        "test-session",
        0,
    )
    lifecycle = SimpleNamespace(
        current_session=lambda _ea: SimpleNamespace(identity_key="test-session"),
        current_mba_generation=lambda **_: 0,
        native_mutation_quarantined=False,
        quarantine_native_mutation=lambda **_: None,
    )
    return module.apply_return_const_corruption_cleanup(
        mba,
        prefold_snapshot=snapshot,
        lifecycle_authority=lifecycle,
        return_consumption_reader=lambda _ea: snapshot,
    )


def test_cleanup_rejects_proof_shaped_object(glbopt_module, monkeypatch):
    """A reason string and site coordinates are not semantic permission."""
    insn = _Insn(0x180018F75)
    mba = _Mba(_Block(insn))
    monkeypatch.setattr(
        glbopt_module,
        "find_droppable_return_const_corruptions",
        lambda *_args, **_kwargs: [
            SimpleNamespace(
                block_serial=1, insn_ea=insn.ea, proof=SimpleNamespace(reason="fake")
            )
        ],
    )
    assert _apply(glbopt_module, mba) == 0
    assert insn.opcode == 99
    assert mba.mark_chains_dirty_calls == 0


def test_condition_chain_rebinding_has_no_local_ea_to_serial_authority(
    glbopt_module,
) -> None:
    source = inspect.getsource(glbopt_module.prune_unreachable_condition_chain)

    assert "identity_index.native_key" in source
    assert "MbaBlockIdentityIndex.from_mba" not in source
    assert "ea_to_serial" not in source


def test_return_const_corruption_cleanup_dry_run_does_not_mutate(
    glbopt_module,
    monkeypatch,
) -> None:
    insn = _Insn(0x180018F75, opcode=99)
    mba = _Mba(_Block(insn))
    monkeypatch.setattr(glbopt_module, "_RCCC_APPLY", False)
    monkeypatch.setattr(
        glbopt_module,
        "find_droppable_return_const_corruptions",
        lambda _mba, **_kw: [_site(glbopt_module, mba)],
    )

    assert _apply(glbopt_module, mba) == 0
    assert insn.opcode == 99
    assert not insn.l.erased
    assert not insn.r.erased
    assert not insn.d.erased
    assert mba.mark_chains_dirty_calls == 0


def test_return_const_corruption_cleanup_apply_nops_and_marks_chains_dirty(
    glbopt_module,
    monkeypatch,
) -> None:
    insn = _Insn(0x180018F75, opcode=99)
    mba = _Mba(_Block(insn))
    monkeypatch.setattr(glbopt_module, "_RCCC_APPLY", True)
    monkeypatch.setattr(
        glbopt_module,
        "find_droppable_return_const_corruptions",
        lambda _mba, **_kw: [_site(glbopt_module, mba)],
    )

    assert _apply(glbopt_module, mba) == 1
    assert insn.opcode == glbopt_module.ida_hexrays.m_nop
    assert insn.l.erased
    assert insn.r.erased
    assert insn.d.erased
    assert mba.mark_chains_dirty_calls == 1


def test_return_const_corruption_cleanup_only_runs_at_global_opt_maturities(
    glbopt_module,
    monkeypatch,
) -> None:
    mba = _Mba(_Block(_Insn(0x180018F75)), maturity=13)

    def fail_if_called(_mba):
        raise AssertionError("proof scan should be maturity-gated")

    monkeypatch.setattr(
        glbopt_module,
        "find_droppable_return_const_corruptions",
        fail_if_called,
    )

    assert _apply(glbopt_module, mba) == 0


def test_return_const_corruption_cleanup_runs_at_glbopt2(
    glbopt_module,
    monkeypatch,
) -> None:
    insn = _Insn(0x180018F75, opcode=99)
    mba = _Mba(_Block(insn), maturity=glbopt_module.ida_hexrays.MMAT_GLBOPT2)
    monkeypatch.setattr(glbopt_module, "_RCCC_APPLY", True)
    monkeypatch.setattr(
        glbopt_module,
        "find_droppable_return_const_corruptions",
        lambda _mba, **_kw: [_site(glbopt_module, mba)],
    )

    assert _apply(glbopt_module, mba) == 1
    assert insn.opcode == glbopt_module.ida_hexrays.m_nop


@pytest.mark.parametrize(
    "change", ["native_identity", "maturity", "definition", "duplicate_ea"]
)
def test_cleanup_rejects_stale_or_ambiguous_site(glbopt_module, monkeypatch, change):
    insn = _Insn(0x180018F75)
    mba = _Mba(_Block(insn))
    site = _site(glbopt_module, mba)
    if change == "native_identity":
        mba = _Mba(_Block(insn))
    elif change == "maturity":
        mba.maturity = glbopt_module.ida_hexrays.MMAT_GLBOPT2
    elif change == "duplicate_ea":
        insn.next = _Insn(insn.ea)
    calls = []

    def collect(*_args, **_kwargs):
        calls.append(True)
        return [] if change == "definition" and len(calls) > 1 else [site]

    monkeypatch.setattr(
        glbopt_module, "find_droppable_return_const_corruptions", collect
    )
    assert _apply(glbopt_module, mba) == 0
    assert insn.opcode == 99
    assert mba.mark_chains_dirty_calls == 0


def test_value_use_count_excludes_def_destination_even_with_fresh_swig_proxy(
    glbopt_module,
) -> None:
    mutation = sys.modules["d810.hexrays.mutation.return_carrier_corruption"]

    class _ProxyInsn:
        ea = 0x180018F75
        l = None
        r = None
        next = None

        @property
        def d(self):
            return SimpleNamespace(
                t=glbopt_module.ida_hexrays.mop_r,
                r=8,
                valnum=151,
            )

    class _ProxyBlock:
        head = _ProxyInsn()

    class _ProxyMba:
        qty = 1

        def get_mblock(self, _serial: int) -> _ProxyBlock:
            return _ProxyBlock()

    assert mutation._count_valnum_uses(_ProxyMba(), 8, 151, 0x180018F75) == 0


def test_carrier_source_accepts_add_with_nested_stack_operand(glbopt_module) -> None:
    mutation = sys.modules["d810.hexrays.mutation.return_carrier_corruption"]
    stack = SimpleNamespace(t=glbopt_module.ida_hexrays.mop_S)
    nested = SimpleNamespace(
        t=glbopt_module.ida_hexrays.mop_d,
        d=SimpleNamespace(
            opcode=glbopt_module.ida_hexrays.m_ldx,
            l=stack,
            r=SimpleNamespace(t=glbopt_module.ida_hexrays.mop_n),
        ),
    )
    insn = SimpleNamespace(
        opcode=glbopt_module.ida_hexrays.m_add,
        l=nested,
        r=SimpleNamespace(t=glbopt_module.ida_hexrays.mop_n),
    )

    assert mutation._is_carrier_source(insn)


def test_carrier_source_rejects_complex_arithmetic_stack_operand(
    glbopt_module,
) -> None:
    mutation = sys.modules["d810.hexrays.mutation.return_carrier_corruption"]
    stack = SimpleNamespace(t=glbopt_module.ida_hexrays.mop_S)
    complex_expr = SimpleNamespace(
        t=glbopt_module.ida_hexrays.mop_d,
        d=SimpleNamespace(
            opcode=999,
            l=stack,
            r=SimpleNamespace(t=glbopt_module.ida_hexrays.mop_n),
        ),
    )
    insn = SimpleNamespace(
        opcode=glbopt_module.ida_hexrays.m_add,
        l=complex_expr,
        r=SimpleNamespace(t=glbopt_module.ida_hexrays.mop_n),
    )

    assert not mutation._is_carrier_source(insn)


def test_carrier_source_rejects_unsupported_stack_mention(glbopt_module) -> None:
    mutation = sys.modules["d810.hexrays.mutation.return_carrier_corruption"]
    insn = SimpleNamespace(
        opcode=999,
        l=SimpleNamespace(t=glbopt_module.ida_hexrays.mop_S),
        r=SimpleNamespace(t=glbopt_module.ida_hexrays.mop_n),
    )

    assert not mutation._is_carrier_source(insn)
