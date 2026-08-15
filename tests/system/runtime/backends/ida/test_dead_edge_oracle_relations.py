"""Exact relational-predicate coverage for the native dead-edge oracle."""

from types import SimpleNamespace

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime]

ida_hexrays = pytest.importorskip("ida_hexrays")
idaapi = pytest.importorskip("idaapi")

import d810.backends.ida.native_patch.dead_edge_oracle as oracle  # noqa: E402


_RELATIONS = (
    (ida_hexrays.m_jb, "ult"),
    (ida_hexrays.m_jbe, "ule"),
    (ida_hexrays.m_ja, "ugt"),
    (ida_hexrays.m_jae, "uge"),
    (ida_hexrays.m_jl, "slt"),
    (ida_hexrays.m_jle, "sle"),
    (ida_hexrays.m_jg, "sgt"),
    (ida_hexrays.m_jge, "sge"),
)

_EQUALITY_BRANCHES = (
    (ida_hexrays.m_jz, "eq", True, oracle.DeadEdgeAction.FORCE_TAKEN),
    (ida_hexrays.m_jnz, "ne", False, oracle.DeadEdgeAction.FORCE_FALLTHROUGH),
    (ida_hexrays.m_jz, "eq", False, oracle.DeadEdgeAction.FORCE_FALLTHROUGH),
    (ida_hexrays.m_jnz, "ne", True, oracle.DeadEdgeAction.FORCE_TAKEN),
)


class _FakeMba:
    def __init__(self, tail):
        self.qty = 2
        self._blocks = (
            SimpleNamespace(tail=tail),
            SimpleNamespace(tail=None, start=0x1010),
        )

    def get_mblock(self, serial):
        return self._blocks[serial]


@pytest.mark.parametrize(("opcode", "comparison"), _RELATIONS)
@pytest.mark.parametrize(
    ("verdict", "action", "surviving_ea"),
    (
        (True, oracle.DeadEdgeAction.FORCE_TAKEN, 0x1010),
        (False, oracle.DeadEdgeAction.FORCE_FALLTHROUGH, 0x1002),
    ),
)
def test_every_supported_jump_uses_exact_tri_state_comparison(
    monkeypatch,
    opcode,
    comparison,
    verdict,
    action,
    surviving_ea,
):
    calls = []

    class _Prover:
        def prove_comparison(self, left, right, requested, **context):
            calls.append((left, right, requested, context))
            return verdict

    tail = SimpleNamespace(
        opcode=opcode,
        l=SimpleNamespace(size=4),
        r=SimpleNamespace(size=4),
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=1),
        ea=0x1000,
    )
    mba = _FakeMba(tail)
    insn = SimpleNamespace(Op1=SimpleNamespace(type=idaapi.o_near, addr=0x1010))
    monkeypatch.setattr(oracle, "Z3MopProver", _Prover)
    monkeypatch.setattr(oracle, "_decode_native", lambda _ea: (insn, "jcc", 2))
    monkeypatch.setattr(oracle.ida_bytes, "get_flags", lambda _ea: 0)
    monkeypatch.setattr(oracle.ida_bytes, "is_head", lambda _flags: True)

    candidates, abstentions = oracle._find_opaque_edges(mba, function_ea=0x1000)

    assert abstentions == []
    assert len(candidates) == 1
    assert candidates[0].action is action
    assert candidates[0].proposed_target_ea == surviving_ea
    assert (
        candidates[0].proof_reason == f"z3_proved_{comparison}_{str(verdict).lower()}"
    )
    assert calls == [
        (tail.l, tail.r, comparison, {"blk": mba.get_mblock(0), "ins": tail})
    ]


def test_undecidable_relational_predicate_produces_no_candidate(monkeypatch):
    class _Prover:
        def prove_comparison(self, *_args, **_kwargs):
            return None

    tail = SimpleNamespace(
        opcode=ida_hexrays.m_jl,
        l=SimpleNamespace(size=4),
        r=SimpleNamespace(size=4),
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=1),
        ea=0x1000,
    )
    monkeypatch.setattr(oracle, "Z3MopProver", _Prover)

    candidates, abstentions = oracle._find_opaque_edges(
        _FakeMba(tail), function_ea=0x1000
    )

    assert candidates == []
    assert abstentions == []


@pytest.mark.parametrize(
    ("opcode", "comparison", "verdict", "action"), _EQUALITY_BRANCHES
)
def test_equality_jumps_use_the_width_safe_tri_state_prover(
    monkeypatch, opcode, comparison, verdict, action
):
    calls = []

    class _Prover:
        def prove_comparison(self, left, right, requested, **context):
            calls.append((left, right, requested, context))
            return verdict

    tail = SimpleNamespace(
        opcode=opcode,
        l=SimpleNamespace(size=4),
        r=SimpleNamespace(size=4),
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=1),
        ea=0x1000,
    )
    mba = _FakeMba(tail)
    insn = SimpleNamespace(Op1=SimpleNamespace(type=idaapi.o_near, addr=0x1010))
    monkeypatch.setattr(oracle, "Z3MopProver", _Prover)
    monkeypatch.setattr(oracle, "_decode_native", lambda _ea: (insn, "jcc", 2))
    monkeypatch.setattr(oracle.ida_bytes, "get_flags", lambda _ea: 0)
    monkeypatch.setattr(oracle.ida_bytes, "is_head", lambda _flags: True)

    candidates, abstentions = oracle._find_opaque_edges(mba, function_ea=0x1000)

    assert abstentions == []
    assert len(candidates) == 1
    assert candidates[0].action is action
    assert calls == [
        (tail.l, tail.r, comparison, {"blk": mba.get_mblock(0), "ins": tail})
    ]


@pytest.mark.parametrize("opcode", (ida_hexrays.m_jz, ida_hexrays.m_jnz))
def test_undecidable_equality_predicate_produces_no_candidate(monkeypatch, opcode):
    class _Prover:
        def prove_comparison(self, *_args, **_kwargs):
            return None

    tail = SimpleNamespace(
        opcode=opcode,
        l=SimpleNamespace(size=4),
        r=SimpleNamespace(size=4),
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=1),
        ea=0x1000,
    )
    monkeypatch.setattr(oracle, "Z3MopProver", _Prover)

    candidates, abstentions = oracle._find_opaque_edges(
        _FakeMba(tail), function_ea=0x1000
    )

    assert candidates == []
    assert abstentions == []


def test_unsupported_operand_width_abstains_before_the_prover(monkeypatch):
    class _Prover:
        def prove_comparison(self, *_args, **_kwargs):
            pytest.fail("unsupported-width operands must not reach the prover")

    tail = SimpleNamespace(
        opcode=ida_hexrays.m_jz,
        l=SimpleNamespace(size=8),
        r=SimpleNamespace(size=8),
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=1),
        ea=0x1000,
    )
    monkeypatch.setattr(oracle, "Z3MopProver", _Prover)

    candidates, abstentions = oracle._find_opaque_edges(
        _FakeMba(tail), function_ea=0x1000
    )

    assert candidates == []
    assert [item.reason for item in abstentions] == [
        "UNSUPPORTED_COMPARISON_WIDTH:left=8,right=8"
    ]


@pytest.mark.parametrize(
    ("left_size", "right_size"),
    (
        (object(), 4),
        (4, object()),
    ),
)
def test_malformed_operand_width_abstains_before_the_prover(
    monkeypatch,
    left_size,
    right_size,
):
    class _Prover:
        def prove_comparison(self, *_args, **_kwargs):
            pytest.fail("malformed-width operands must not reach the prover")

    tail = SimpleNamespace(
        opcode=ida_hexrays.m_jz,
        l=SimpleNamespace(size=left_size),
        r=SimpleNamespace(size=right_size),
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=1),
        ea=0x1000,
    )
    monkeypatch.setattr(oracle, "Z3MopProver", _Prover)

    candidates, abstentions = oracle._find_opaque_edges(
        _FakeMba(tail), function_ea=0x1000
    )

    assert candidates == []
    assert [item.reason for item in abstentions] == ["MALFORMED_COMPARISON_WIDTH"]
