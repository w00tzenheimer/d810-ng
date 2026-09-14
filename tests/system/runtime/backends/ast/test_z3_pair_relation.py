"""Runtime contracts for one-shot complementary Z3 pair proofs."""

from types import SimpleNamespace

import ida_hexrays
import pytest


def _mop(name: str):
    return SimpleNamespace(t=ida_hexrays.mop_r, size=4, name=name)


def test_pair_relation_translates_once_and_preserves_complementary_results(
    monkeypatch,
):
    import d810.backends.ast.z3 as z3mod
    from d810.backends.ast.z3 import Z3MopProver
    from d810.backends.ast.z3_proof_policy import Z3ProofPolicy, Z3ProofStatus

    translations = []

    def _translate(*_args, **_kwargs):
        translations.append(True)
        return z3mod.z3.BitVecVal(7, 32), z3mod.z3.BitVecVal(8, 32)

    monkeypatch.setattr(z3mod, "_translate_mop_pair", _translate)
    prover = Z3MopProver(
        policy=Z3ProofPolicy(max_expression_nodes=8, proof_timeout_ms=100)
    )

    proofs = list(
        prover.prove_equal_then_unequal(_mop("left"), _mop("right"))
    )

    assert translations == [True]
    assert [operation for operation, _result in proofs] == [
        "prove_equal",
        "prove_unequal",
    ]
    equal = proofs[0][1]
    unequal = proofs[1][1]
    assert equal.status is Z3ProofStatus.DISPROVED
    assert unequal.status is Z3ProofStatus.PROVED


def test_pair_relation_short_circuits_after_equal_proof(monkeypatch):
    import d810.backends.ast.z3 as z3mod
    from d810.backends.ast.z3 import Z3MopProver
    from d810.backends.ast.z3_proof_policy import Z3ProofPolicy, Z3ProofStatus

    translations = []

    def _translate(*_args, **_kwargs):
        translations.append(True)
        value = z3mod.z3.BitVecVal(7, 32)
        return value, value

    monkeypatch.setattr(z3mod, "_translate_mop_pair", _translate)
    prover = Z3MopProver(
        policy=Z3ProofPolicy(max_expression_nodes=8, proof_timeout_ms=100)
    )

    proofs = prover.prove_equal_then_unequal(_mop("left"), _mop("right"))
    operation, equal = next(proofs)

    assert translations == [True]
    assert operation == "prove_equal"
    assert equal.status is Z3ProofStatus.PROVED
    proofs.close()


def test_pair_relation_context_mismatch_abstains_for_both_queries(monkeypatch):
    import d810.backends.ast.z3 as z3mod
    from d810.backends.ast.z3 import Z3MopProver
    from d810.backends.ast.z3_proof_policy import (
        Z3ProofAbstentionReason,
        Z3ProofPolicy,
        Z3ProofStatus,
    )

    left_context = z3mod.z3.Context()
    right_context = z3mod.z3.Context()

    def _translate(*_args, **_kwargs):
        return (
            z3mod.z3.BitVecVal(7, 32, ctx=left_context),
            z3mod.z3.BitVecVal(7, 32, ctx=right_context),
        )

    monkeypatch.setattr(z3mod, "_translate_mop_pair", _translate)
    prover = Z3MopProver(
        policy=Z3ProofPolicy(max_expression_nodes=8, proof_timeout_ms=100)
    )

    proofs = list(
        prover.prove_equal_then_unequal(_mop("left"), _mop("right"))
    )

    assert [operation for operation, _result in proofs] == [
        "prove_equal",
        "prove_unequal",
    ]
    assert all(
        result.status is Z3ProofStatus.ABSTAINED
        and result.reason is Z3ProofAbstentionReason.SOLVER_UNKNOWN
        for _operation, result in proofs
    )


def test_pair_relation_requires_z3_before_returning_iterator(monkeypatch):
    import d810.backends.ast.z3 as z3mod
    from d810.backends.ast.z3 import Z3MopProver
    from d810.errors import D810Z3Exception

    monkeypatch.setattr(z3mod, "Z3_INSTALLED", False)

    with pytest.raises(D810Z3Exception, match="Z3 is not installed"):
        Z3MopProver().prove_equal_then_unequal(_mop("left"), _mop("right"))
