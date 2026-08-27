"""Production-shape acceptance regression for assigned call-result predicates."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.analyses.value_flow.model import FactMapping, FactStatus, ValidatedFactView
from d810.analyses.value_flow.observation import FactObservation
from d810.analyses.value_flow import CALL_RETURN_VALUE_FACT_TYPE
from d810.evaluator.hexrays_microcode import def_search
from d810.hexrays.expr.ast import AstConstant, AstLeaf, AstNode
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
from d810.optimizers.microcode.instructions.z3.handler import Z3Optimizer
from d810.optimizers.microcode.instructions.z3.predicates import Z3setnzRuleGeneric

from tests.system.runtime.evaluator.test_def_search_mop_snapshot import (
    _call_result_test_parts,
)


def _observation(fact_id: str, evidence: dict, *, call_ea: int = 0x401000):
    return FactObservation(
        fact_id=fact_id,
        kind=CALL_RETURN_VALUE_FACT_TYPE,
        semantic_key=f"call:{call_ea:x}",
        maturity="MMAT_LOCOPT",
        phase="value-flow",
        confidence=1.0,
        source_ea=call_ea,
        payload={
            "lifecycle_status": "production_proven",
            "source_identity": {"call_ea": call_ea},
            "call_return_value": {
                "schema_version": 1,
                "call_ea": call_ea,
                "callee_ea": 0x402000,
                "result_width_bits": 32,
                "argument_fingerprint": None,
                "evidence": evidence,
            },
        },
    )


def _carrier_only_observation():
    return FactObservation(
        fact_id="legacy-carrier",
        kind=CALL_RETURN_VALUE_FACT_TYPE,
        semantic_key="carrier",
        maturity="MMAT_LOCOPT",
        phase="value-flow",
        confidence=1.0,
        source_ea=0x401000,
        payload={
            "lifecycle_status": "production_proven",
            "source_identity": {"call_ea": 0x401000},
            "details": {"carrier_class": "PASSWORD_COMPARE_RESULT"},
        },
    )


def _view(kind: str) -> ValidatedFactView:
    if kind == "none":
        return ValidatedFactView(maturity="MMAT_LOCOPT")
    if kind == "zero":
        observations = (
            _observation(
                "known-zero", {"kind": "known_bits", "known_zero": 0x40, "known_one": 0}
            ),
        )
    elif kind == "one":
        observations = (
            _observation(
                "known-one", {"kind": "known_bits", "known_zero": 0, "known_one": 0x40}
            ),
        )
    elif kind == "stale":
        observations = (
            _observation(
                "stale", {"kind": "known_bits", "known_zero": 0, "known_one": 0x40}
            ),
        )
        return ValidatedFactView(
            maturity="MMAT_LOCOPT",
            observations=observations,
            mappings=(
                FactMapping(
                    "stale", "MMAT_PREOPTIMIZED", "MMAT_LOCOPT", FactStatus.STALE, 1.0
                ),
            ),
        )
    elif kind == "malformed":
        observations = (
            _observation(
                "malformed",
                {"kind": "known_bits", "known_zero": 0x40, "known_one": 0x40},
            ),
        )
    elif kind == "conflicting":
        observations = (
            _observation("conflict-zero", {"kind": "exact", "value": 0}),
            _observation("conflict-one", {"kind": "exact", "value": 1}),
        )
    elif kind == "carrier":
        observations = (_carrier_only_observation(),)
    else:
        raise AssertionError(kind)
    return ValidatedFactView(maturity="MMAT_LOCOPT", observations=observations)


def _ast_leaf(name: str, mop):
    leaf = AstLeaf(name)
    leaf.mop = mop
    leaf.dest_size = mop.size
    return leaf


def _fixture(monkeypatch):
    """Build a valid m_mov(mop_d(call), mop_r) chain plus a later eax write."""
    assignment, call, destination, block, use = _call_result_test_parts()
    branch = SimpleNamespace(
        opcode=ida_hexrays.m_setnz,
        ea=0x401300,
        _print=lambda: "setnz ((eax >> 6) & 1), 0",
    )
    copy = SimpleNamespace(ea=0x401100, opcode=ida_hexrays.m_mov)
    shift = SimpleNamespace(ea=0x401200, opcode=ida_hexrays.m_shr)
    masked = SimpleNamespace(ea=0x401250, opcode=ida_hexrays.m_and)
    later_write = SimpleNamespace(ea=0x401400, opcode=ida_hexrays.m_mov)
    searched = []

    root_mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=1, valnum=0)
    eax_mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=0, valnum=0)
    count_mop = SimpleNamespace(
        t=ida_hexrays.mop_n, size=1, nnn=SimpleNamespace(value=6)
    )
    mask_mop = SimpleNamespace(
        t=ida_hexrays.mop_n, size=4, nnn=SimpleNamespace(value=1)
    )

    masked_ast = AstNode(
        ida_hexrays.m_and, _ast_leaf("shifted", eax_mop), _ast_leaf("mask", mask_mop)
    )
    masked_ast.dest_size = 4
    shift_ast = AstNode(
        ida_hexrays.m_shr, _ast_leaf("eax", eax_mop), _ast_leaf("count", count_mop)
    )
    shift_ast.dest_size = 4
    copy_ast = _ast_leaf("eax_copy", eax_mop)

    def find_definition(_mop, _block, before):
        searched.append(before)
        if before is branch:
            return masked
        if before is masked:
            return shift
        if before is shift:
            return copy
        if before is copy:
            return assignment
        if before is assignment:
            return later_write
        return None

    def build_ast(instruction, _node_budget=None, **_kwargs):
        if instruction is masked:
            return masked_ast
        if instruction is shift:
            return shift_ast
        if instruction is copy:
            return copy_ast
        return None

    monkeypatch.setattr(def_search, "find_def_in_block", find_definition)
    monkeypatch.setattr(def_search, "_minsn_to_ast_with_budget", build_ast)
    monkeypatch.setattr(
        def_search, "_materialize_mop_for_tracking", lambda mop, *_a, **_k: mop
    )

    from d810.backends.ast import z3 as z3_backend
    from d810.backends.ast.z3_proof_policy import (
        Z3ProofAbstentionReason,
        Z3ProofResult,
        Z3ProofStatus,
    )

    def mop_to_ast(mop, **_kwargs):
        if mop.t == ida_hexrays.mop_n:
            return AstConstant(str(mop.nnn.value), mop.nnn.value, mop.size)
        return _ast_leaf("operand", mop)

    monkeypatch.setattr(z3_backend, "mop_to_ast", mop_to_ast)
    monkeypatch.setattr(def_search, "mop_to_ast", mop_to_ast)
    # The generic setnz rule first probes equality/inequality of its two
    # operands.  Those pair queries are not the call-result acceptance seam;
    # make them explicitly abstain so the production zero/nonzero route below
    # is exercised without asking Z3 to canonicalize synthetic test mops.
    abstained = Z3ProofResult(
        status=Z3ProofStatus.ABSTAINED,
        reason=Z3ProofAbstentionReason.UNSUPPORTED_EXPRESSION,
        observed_expression_nodes=None,
        elapsed_ms=0.0,
    )
    monkeypatch.setattr(
        "d810.backends.ast.z3.Z3MopProver.prove_equal", lambda *_a, **_k: abstained
    )
    monkeypatch.setattr(
        "d810.backends.ast.z3.Z3MopProver.prove_unequal", lambda *_a, **_k: abstained
    )
    return assignment, call, destination, block, branch, later_write, searched, root_mop


def _run(monkeypatch, kind: str):
    assignment, call, destination, block, branch, later_write, searched, root_mop = (
        _fixture(monkeypatch)
    )
    optimizer = Z3Optimizer([ida_hexrays.MMAT_LOCOPT], None)
    rule = Z3setnzRuleGeneric()
    optimizer.add_rule(rule)

    class Candidate:
        dst_mop = SimpleNamespace(size=1)

        def __init__(self):
            self._value = None

        def __getitem__(self, name):
            if name == "x_0":
                return SimpleNamespace(mop=root_mop, size=root_mop.size)
            if name == "x_1":
                return SimpleNamespace(
                    mop=SimpleNamespace(
                        t=ida_hexrays.mop_n,
                        size=4,
                        nnn=SimpleNamespace(value=0),
                    ),
                    size=4,
                )
            if name == "val_res":
                return SimpleNamespace(mop=SimpleNamespace(value=self._value))
            raise KeyError(name)

        def add_constant_leaf(self, _name, value, _size):
            self._value = value

    candidate = Candidate()

    # Keep the production optimizer and production Z3 rule/prover path, while
    # supplying a native-shaped candidate carrier that does not allocate a
    # fresh SWIG mop for the test-only replacement result.
    def valid_candidates(*_args, **_kwargs):
        return [candidate] if rule.check_candidate(candidate) else []

    rule.get_valid_candidates = valid_candidates

    def replacement(candidate):
        value = candidate._value
        return SimpleNamespace(
            opcode=ida_hexrays.m_mov,
            ea=branch.ea,
            d=SimpleNamespace(
                t=ida_hexrays.mop_n, size=1, nnn=SimpleNamespace(value=value)
            ),
            _print=lambda: f"mov predicate, {value}",
        )

    rule.get_replacement = replacement
    manager = object.__new__(InstructionOptimizerManager)
    manager._validated_fact_view_provider = lambda _ea, _maturity: _view(kind)
    manager.instruction_optimizers = [optimizer]
    bound = manager._bind_validated_fact_view_for_callback(block)
    try:
        replacement = optimizer.get_optimized_instruction(block, branch)
    finally:
        for binder, previous in reversed(bound):
            binder(previous)
    return replacement, searched, later_write, candidate._value


@pytest.mark.parametrize(
    "kind", ["none", "stale", "malformed", "conflicting", "carrier"]
)
def test_unknown_or_untrusted_call_result_retains_branch(monkeypatch, kind):
    replacement, searched, later_write, value = _run(monkeypatch, kind)
    assert replacement is None
    assert value is None
    assert later_write not in searched


@pytest.mark.parametrize("kind,expected", [("zero", 0), ("one", 1)])
def test_versioned_call_result_proves_masked_branch_direction(
    monkeypatch, kind, expected
):
    replacement, searched, later_write, value = _run(monkeypatch, kind)
    assert replacement is not None
    assert value == expected
    assert replacement.d.nnn.value == expected
    assert later_write not in searched
