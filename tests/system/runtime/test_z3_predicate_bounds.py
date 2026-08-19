"""Runtime contracts for independently bounded generic Z3 predicates."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import logging
from types import SimpleNamespace

import pytest


def _mop(*, mop_type: int, size: int = 4, value: int | None = None):
    payload = SimpleNamespace(t=mop_type, size=size)
    if value is not None:
        payload.nnn = SimpleNamespace(value=value)
    return payload


def _candidate(x0_mop, x1_mop):
    additions: list[tuple[object, int, int]] = []

    class _Candidate:
        dst_mop = SimpleNamespace(size=1)

        def __getitem__(self, name: str):
            if name == "x_0":
                return SimpleNamespace(mop=x0_mop, size=x0_mop.size)
            if name == "x_1":
                return SimpleNamespace(mop=x1_mop, size=x1_mop.size)
            raise KeyError(name)

        def add_constant_leaf(self, name: str, value: int, size: int) -> None:
            additions.append((name, value, size))

    return _Candidate(), additions


@pytest.mark.runtime
def test_three_generic_rules_keep_distinct_immutable_policies() -> None:
    from d810.optimizers.microcode.instructions.z3.predicates import (
        Z3lnotRuleGeneric,
        Z3setnzRuleGeneric,
        Z3setzRuleGeneric,
    )

    rules = (
        Z3setzRuleGeneric(),
        Z3setnzRuleGeneric(),
        Z3lnotRuleGeneric(),
    )
    rules[0].configure({"max_expression_nodes": 1, "proof_timeout_ms": 11})
    rules[1].configure({"max_expression_nodes": 2, "proof_timeout_ms": 22})
    rules[2].configure({"max_expression_nodes": 3, "proof_timeout_ms": 33})

    policies = tuple(rule.z3_proof_policy for rule in rules)
    assert len({id(policy) for policy in policies}) == 3
    assert policies[0].max_expression_nodes == 1
    assert policies[1].max_expression_nodes == 2
    assert policies[2].max_expression_nodes == 3
    assert policies[0].proof_timeout_ms == 11
    assert policies[1].proof_timeout_ms == 22
    assert policies[2].proof_timeout_ms == 33
    assert policies[2].proof_timeout_ms != policies[0].proof_timeout_ms
    with pytest.raises(FrozenInstanceError):
        policies[0].max_expression_nodes = 4096  # type: ignore[misc]


@pytest.mark.runtime
def test_generic_rule_configure_uses_canonical_policy_defaults(monkeypatch) -> None:
    import d810.core.z3_proof as z3_proof
    from d810.backends.ast.z3_proof_policy import Z3ProofPolicy
    from d810.core.z3_proof import Z3ProofFieldAuthority, Z3ProofPolicyAuthority
    from d810.passes.mba_simplify import materialize_mba_transform_options
    from d810.passes.mba_transform_options import MBA_TRANSFORM_OPTION_FIELDS
    from d810.optimizers.microcode.instructions.z3.predicates import (
        Z3lnotRuleGeneric,
        Z3setnzRuleGeneric,
        Z3setzRuleGeneric,
    )

    authority = Z3ProofPolicyAuthority(
        max_expression_nodes=Z3ProofFieldAuthority(
            default=913, minimum=7, maximum=1913
        ),
        proof_timeout_ms=Z3ProofFieldAuthority(
            default=271, minimum=11, maximum=2711
        ),
    )
    monkeypatch.setattr(
        z3_proof,
        "Z3_PROOF_POLICY_AUTHORITY",
        authority,
        raising=False,
    )
    for rule_class in (Z3setzRuleGeneric, Z3setnzRuleGeneric, Z3lnotRuleGeneric):
        rule = rule_class()
        rule.configure({})

        assert rule.z3_proof_policy.max_expression_nodes == 913
        assert rule.z3_proof_policy.proof_timeout_ms == 271

    for transform_id in (
        "z-3-setz-generic",
        "z-3-setnz-generic",
        "z-3-lnot-generic",
    ):
        assert materialize_mba_transform_options(transform_id, {}) == {
            "max_expression_nodes": 913,
            "proof_timeout_ms": 271,
        }
        fields = MBA_TRANSFORM_OPTION_FIELDS[transform_id]
        assert fields[0].default == 913
        assert fields[0].minimum == 7
        assert fields[0].maximum == 1913
        assert fields[1].default == 271
        assert fields[1].minimum == 11
        assert fields[1].maximum == 2711

    with pytest.raises((TypeError, ValueError), match="max_expression_nodes"):
        Z3ProofPolicy(max_expression_nodes=6)
    with pytest.raises((TypeError, ValueError), match="max_expression_nodes"):
        Z3ProofPolicy(max_expression_nodes=1914)
    with pytest.raises((TypeError, ValueError), match="proof_timeout_ms"):
        Z3ProofPolicy(proof_timeout_ms=10)
    with pytest.raises((TypeError, ValueError), match="proof_timeout_ms"):
        Z3ProofPolicy(proof_timeout_ms=2712)


@pytest.mark.runtime
def test_authority_reaches_editor_pass_bridge_and_direct_rule_configuration(
    monkeypatch,
) -> None:
    """One portable authority drives every public/defaulting boundary."""
    from pathlib import Path

    import d810.core.z3_proof as z3_proof
    from d810.backends.ast.z3_proof_policy import Z3ProofPolicy
    from d810.core.config import ProjectConfiguration
    from d810.core.z3_proof import Z3ProofFieldAuthority, Z3ProofPolicyAuthority
    from d810.passes.mba_transform_catalog import mba_transform_editor_spec
    from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation
    from d810.optimizers.microcode.instructions.z3.predicates import (
        Z3lnotRuleGeneric,
        Z3setnzRuleGeneric,
        Z3setzRuleGeneric,
    )

    authority = Z3ProofPolicyAuthority(
        max_expression_nodes=Z3ProofFieldAuthority(
            default=913, minimum=7, maximum=1913
        ),
        proof_timeout_ms=Z3ProofFieldAuthority(
            default=271, minimum=11, maximum=2711
        ),
    )
    monkeypatch.setattr(z3_proof, "Z3_PROOF_POLICY_AUTHORITY", authority)

    for rule_class in (Z3setzRuleGeneric, Z3setnzRuleGeneric, Z3lnotRuleGeneric):
        rule = rule_class()
        rule.configure({})
        assert rule.z3_proof_policy == Z3ProofPolicy(
            max_expression_nodes=913,
            proof_timeout_ms=271,
        )

    editor = mba_transform_editor_spec()
    for transform_id in (
        "z-3-setz-generic",
        "z-3-setnz-generic",
        "z-3-lnot-generic",
    ):
        item = next(
            item for item in editor.transforms if item.transform_id == transform_id
        )
        assert tuple(
            (field.default, field.minimum, field.maximum)
            for field in item.option_fields
        ) == ((913, 7, 1913), (271, 11, 2711))

    project = ProjectConfiguration(
        path=Path("z3-authority.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": "mba-simplify",
                    "options": {
                        "transforms": [
                            "z-3-setz-generic",
                            "z-3-setnz-generic",
                            "z-3-lnot-generic",
                        ]
                    },
                }
            ],
        },
    )
    activation = pipeline_v2_hook_activation(project)
    assert {
        rule.name: (
            rule.config["max_expression_nodes"],
            rule.config["proof_timeout_ms"],
        )
        for rule in activation.instruction_rules
    } == {
        "Z3setzRuleGeneric": (913, 271),
        "Z3setnzRuleGeneric": (913, 271),
        "Z3lnotRuleGeneric": (913, 271),
    }


@pytest.mark.runtime
@pytest.mark.parametrize(
    ("rule_name", "target_operation", "expected_operations"),
    (
        ("setz", "prove_equal", ("prove_equal",)),
        ("setz", "prove_unequal", ("prove_equal", "prove_unequal")),
        (
            "setz",
            "prove_always_zero",
            ("prove_equal", "prove_unequal", "prove_always_zero"),
        ),
        (
            "setz",
            "prove_always_nonzero",
            (
                "prove_equal",
                "prove_unequal",
                "prove_always_zero",
                "prove_always_nonzero",
            ),
        ),
        ("setnz", "prove_equal", ("prove_equal",)),
        ("setnz", "prove_unequal", ("prove_equal", "prove_unequal")),
        (
            "setnz",
            "prove_always_zero",
            ("prove_equal", "prove_unequal", "prove_always_zero"),
        ),
        (
            "setnz",
            "prove_always_nonzero",
            (
                "prove_equal",
                "prove_unequal",
                "prove_always_zero",
                "prove_always_nonzero",
            ),
        ),
        ("lnot", "prove_always_zero", ("prove_always_zero",)),
        (
            "lnot",
            "prove_always_nonzero",
            ("prove_always_zero", "prove_always_nonzero"),
        ),
    ),
)
def test_every_generic_prover_branch_forwards_exact_policy(
    monkeypatch,
    rule_name: str,
    target_operation: str,
    expected_operations: tuple[str, ...],
) -> None:
    import ida_hexrays

    from d810.backends.ast.z3_proof_policy import (
        Z3ProofResult,
        Z3ProofStatus,
    )
    import d810.optimizers.microcode.instructions.z3.predicates as predicates

    class _RecordingProver:
        instances: list["_RecordingProver"] = []

        def __init__(self, *, blk=None, ins=None, policy=None):
            self.blk = blk
            self.ins = ins
            self.policy = policy
            self.operations: list[str] = []
            type(self).instances.append(self)

        def _result(self, operation: str) -> Z3ProofResult:
            self.operations.append(operation)
            return Z3ProofResult(
                status=(
                    Z3ProofStatus.PROVED
                    if operation == target_operation
                    else Z3ProofStatus.DISPROVED
                ),
                reason=None,
                observed_expression_nodes=2,
                elapsed_ms=0.75,
            )

        def prove_equal(self, *_args, **_kwargs):
            return self._result("prove_equal")

        def prove_unequal(self, *_args, **_kwargs):
            return self._result("prove_unequal")

        def prove_always_zero(self, *_args, **_kwargs):
            return self._result("prove_always_zero")

        def prove_always_nonzero(self, *_args, **_kwargs):
            return self._result("prove_always_nonzero")

    monkeypatch.setattr(predicates, "Z3MopProver", _RecordingProver)
    rule_class = {
        "setz": predicates.Z3setzRuleGeneric,
        "setnz": predicates.Z3setnzRuleGeneric,
        "lnot": predicates.Z3lnotRuleGeneric,
    }[rule_name]
    rule = rule_class()
    rule.configure({"max_expression_nodes": 101, "proof_timeout_ms": 1101})
    candidate, additions = _candidate(
        _mop(mop_type=ida_hexrays.mop_r),
        _mop(mop_type=ida_hexrays.mop_n, value=0),
    )

    assert rule.check_candidate(candidate) is True
    assert [
        operation
        for instance in _RecordingProver.instances
        for operation in instance.operations
    ] == list(expected_operations)
    assert all(
        instance.policy is rule.z3_proof_policy
        for instance in _RecordingProver.instances
    )
    for operation in expected_operations:
        matching_instances = [
            instance
            for instance in _RecordingProver.instances
            if operation in instance.operations
        ]
        assert len(matching_instances) == 1
        assert matching_instances[0].policy is rule.z3_proof_policy

    expected_value = {
        "setz": {"prove_equal": 1, "prove_unequal": 0,
                 "prove_always_zero": 1, "prove_always_nonzero": 0},
        "setnz": {"prove_equal": 0, "prove_unequal": 1,
                   "prove_always_zero": 0, "prove_always_nonzero": 1},
        "lnot": {"prove_always_zero": 1, "prove_always_nonzero": 0},
    }[rule_name][target_operation]
    assert additions == [("val_res", expected_value, 1)]


@pytest.mark.runtime
def test_lnot_uses_contextual_zero_then_nonzero_proofs_and_stops(
    monkeypatch,
) -> None:
    """The lnot rule must resolve its operand through the live CFG context."""
    import ida_hexrays

    from d810.backends.ast.z3_proof_policy import (
        Z3ProofResult,
        Z3ProofStatus,
    )
    import d810.optimizers.microcode.instructions.z3.predicates as predicates

    class _ContextualProver:
        instances: list["_ContextualProver"] = []

        def __init__(self, *, blk=None, ins=None, policy=None):
            self.blk = blk
            self.ins = ins
            self.policy = policy
            self.operations: list[str] = []
            type(self).instances.append(self)

        def _result(self, operation: str, status: Z3ProofStatus) -> Z3ProofResult:
            self.operations.append(operation)
            return Z3ProofResult(
                status=status,
                reason=None,
                observed_expression_nodes=7,
                elapsed_ms=0.5,
            )

        def prove_always_zero(self, *_args, **_kwargs):
            return self._result("prove_always_zero", Z3ProofStatus.PROVED)

        def prove_always_nonzero(self, *_args, **_kwargs):
            raise AssertionError("nonzero proof must not run after zero is proved")

        def prove_equal(self, *_args, **_kwargs):
            raise AssertionError("lnot must not use context-free pair proving")

        def prove_unequal(self, *_args, **_kwargs):
            raise AssertionError("lnot must not use context-free pair proving")

    monkeypatch.setattr(predicates, "Z3MopProver", _ContextualProver)
    rule = predicates.Z3lnotRuleGeneric()
    rule.configure({"max_expression_nodes": 41, "proof_timeout_ms": 43})
    block = object()
    instruction = object()
    rule._current_blk = block
    rule._current_ins = instruction
    candidate, additions = _candidate(
        _mop(mop_type=ida_hexrays.mop_r),
        _mop(mop_type=ida_hexrays.mop_n, value=0),
    )

    assert rule.check_candidate(candidate) is True
    assert additions == [("val_res", 1, 1)]
    assert len(_ContextualProver.instances) == 1
    prover = _ContextualProver.instances[0]
    assert prover.blk is block
    assert prover.ins is instruction
    assert prover.policy is rule.z3_proof_policy
    assert prover.policy.max_expression_nodes == 41
    assert prover.policy.proof_timeout_ms == 43
    assert prover.operations == ["prove_always_zero"]


@pytest.mark.runtime
def test_lnot_contextual_proofs_fall_back_to_nonzero_and_fail_closed(
    monkeypatch,
) -> None:
    """A disproved/abstained first query may fall through, never force a result."""
    import ida_hexrays

    from d810.backends.ast.z3_proof_policy import (
        Z3ProofAbstentionReason,
        Z3ProofResult,
        Z3ProofStatus,
    )
    import d810.optimizers.microcode.instructions.z3.predicates as predicates

    class _FallbackProver:
        instances: list["_FallbackProver"] = []
        zero_status = Z3ProofStatus.DISPROVED
        nonzero_status = Z3ProofStatus.PROVED

        def __init__(self, *, blk=None, ins=None, policy=None):
            self.blk = blk
            self.ins = ins
            self.policy = policy
            self.operations: list[str] = []
            type(self).instances.append(self)

        def _result(self, operation: str, status: Z3ProofStatus) -> Z3ProofResult:
            self.operations.append(operation)
            return Z3ProofResult(
                status=status,
                reason=(
                    Z3ProofAbstentionReason.NODE_LIMIT
                    if status is Z3ProofStatus.ABSTAINED
                    else None
                ),
                observed_expression_nodes=9,
                elapsed_ms=0.5,
            )

        def prove_always_zero(self, *_args, **_kwargs):
            return self._result("prove_always_zero", self.zero_status)

        def prove_always_nonzero(self, *_args, **_kwargs):
            return self._result("prove_always_nonzero", self.nonzero_status)

        def prove_equal(self, *_args, **_kwargs):
            raise AssertionError("lnot must not use context-free pair proving")

        def prove_unequal(self, *_args, **_kwargs):
            raise AssertionError("lnot must not use context-free pair proving")

    monkeypatch.setattr(predicates, "Z3MopProver", _FallbackProver)
    rule = predicates.Z3lnotRuleGeneric()
    rule.configure({"max_expression_nodes": 47, "proof_timeout_ms": 53})
    rule._current_blk = object()
    rule._current_ins = object()
    candidate, additions = _candidate(
        _mop(mop_type=ida_hexrays.mop_r),
        _mop(mop_type=ida_hexrays.mop_n, value=0),
    )

    assert rule.check_candidate(candidate) is True
    assert additions == [("val_res", 0, 1)]
    assert _FallbackProver.instances[0].operations == [
        "prove_always_zero",
        "prove_always_nonzero",
    ]

    _FallbackProver.instances.clear()
    _FallbackProver.zero_status = Z3ProofStatus.ABSTAINED
    _FallbackProver.nonzero_status = Z3ProofStatus.DISPROVED
    candidate, additions = _candidate(
        _mop(mop_type=ida_hexrays.mop_r),
        _mop(mop_type=ida_hexrays.mop_n, value=0),
    )

    assert rule.check_candidate(candidate) is False
    assert additions == []
    assert _FallbackProver.instances[0].operations == [
        "prove_always_zero",
        "prove_always_nonzero",
    ]


@pytest.mark.runtime
def test_low_node_setz_abstention_does_not_block_setnz_or_lnot_policy(
    monkeypatch,
) -> None:
    import ida_hexrays

    from d810.backends.ast.z3_proof_policy import (
        Z3ProofAbstentionReason,
        Z3ProofResult,
        Z3ProofStatus,
    )
    import d810.optimizers.microcode.instructions.z3.predicates as predicates

    class _IsolationProver:
        instances: list["_IsolationProver"] = []

        def __init__(self, *, policy, **_kwargs):
            self.policy = policy
            self.operations: list[str] = []
            type(self).instances.append(self)

        def _result(self, operation: str) -> Z3ProofResult:
            self.operations.append(operation)
            if self.policy.max_expression_nodes == 1:
                return Z3ProofResult(
                    status=Z3ProofStatus.ABSTAINED,
                    reason=Z3ProofAbstentionReason.NODE_LIMIT,
                    observed_expression_nodes=1,
                    elapsed_ms=0.5,
                )
            return Z3ProofResult(
                status=Z3ProofStatus.PROVED,
                reason=None,
                observed_expression_nodes=2,
                elapsed_ms=0.75,
            )

        def prove_equal(self, *_args, **_kwargs):
            return self._result("prove_equal")

        def prove_unequal(self, *_args, **_kwargs):
            return self._result("prove_unequal")

        def prove_always_zero(self, *_args, **_kwargs):
            return self._result("prove_always_zero")

        def prove_always_nonzero(self, *_args, **_kwargs):
            return self._result("prove_always_nonzero")

    monkeypatch.setattr(predicates, "Z3MopProver", _IsolationProver)
    setz = predicates.Z3setzRuleGeneric()
    setz.configure({"max_expression_nodes": 1, "proof_timeout_ms": 17})
    setnz = predicates.Z3setnzRuleGeneric()
    setnz.configure({"max_expression_nodes": 2, "proof_timeout_ms": 29})
    lnot = predicates.Z3lnotRuleGeneric()
    lnot.configure({"max_expression_nodes": 3, "proof_timeout_ms": 73})

    setz_candidate, setz_additions = _candidate(
        _mop(mop_type=ida_hexrays.mop_r),
        _mop(mop_type=ida_hexrays.mop_n, value=0),
    )
    setnz_candidate, setnz_additions = _candidate(
        _mop(mop_type=ida_hexrays.mop_r),
        _mop(mop_type=ida_hexrays.mop_n, value=0),
    )

    assert setz.check_candidate(setz_candidate) is False
    assert setz_additions == []
    assert setnz.check_candidate(setnz_candidate) is True
    assert setnz_additions == [("val_res", 0, 1)]

    setz_instances = [
        instance
        for instance in _IsolationProver.instances
        if instance.policy is setz.z3_proof_policy
    ]
    setnz_instances = [
        instance
        for instance in _IsolationProver.instances
        if instance.policy is setnz.z3_proof_policy
    ]
    assert [operation for instance in setz_instances for operation in instance.operations] == [
        "prove_equal",
        "prove_unequal",
        "prove_always_zero",
        "prove_always_nonzero",
    ]
    assert [operation for instance in setnz_instances for operation in instance.operations] == [
        "prove_equal",
    ]
    assert lnot.z3_proof_policy.max_expression_nodes == 3
    assert lnot.z3_proof_policy.proof_timeout_ms == 73
    assert lnot.z3_proof_policy is not setz.z3_proof_policy
    assert lnot.z3_proof_policy is not setnz.z3_proof_policy


@pytest.mark.runtime
@pytest.mark.parametrize(
    "malformed_result",
    (
        SimpleNamespace(
            status="abstained",
            reason="timeout",
            observed_expression_nodes=1,
            elapsed_ms=0.5,
        ),
        SimpleNamespace(
            status="abstained",
            reason="not-a-valid-abstention-reason",
            observed_expression_nodes=1,
            elapsed_ms=0.5,
        ),
    ),
)
def test_malformed_proof_result_is_ignored_without_synthetic_receipt(
    malformed_result,
) -> None:
    from d810.core.observability import reset_diagnostic_bus, subscribe
    from d810.core.observability_events import Z3PredicateProofObserved
    from d810.optimizers.microcode.instructions.z3.predicates import Z3setzRuleGeneric

    events: list[Z3PredicateProofObserved] = []
    reset_diagnostic_bus()
    subscribe(Z3PredicateProofObserved, events.append)
    try:
        rule = Z3setzRuleGeneric()
        rule.configure({})

        assert rule.observe_z3_proof("prove_equal", malformed_result) is False
    finally:
        reset_diagnostic_bus()

    assert events == []


@pytest.mark.runtime
def test_malformed_conclusive_result_cannot_mutate_or_emit_a_receipt(monkeypatch) -> None:
    import ida_hexrays

    import d810.optimizers.microcode.instructions.z3.predicates as predicates
    from d810.backends.ast.z3_proof_policy import Z3ProofStatus
    from d810.core.observability import reset_diagnostic_bus, subscribe
    from d810.core.observability_events import Z3PredicateProofObserved

    class _MalformedProver:
        def __init__(self, **_kwargs):
            pass

        def prove_equal(self, *_args, **_kwargs):
            return SimpleNamespace(
                status=Z3ProofStatus.PROVED,
                reason="not-a-valid-reason",
                observed_expression_nodes=2,
                elapsed_ms=0.5,
            )

        def prove_unequal(self, *_args, **_kwargs):
            return self.prove_equal()

        def prove_always_zero(self, *_args, **_kwargs):
            return self.prove_equal()

        def prove_always_nonzero(self, *_args, **_kwargs):
            return self.prove_equal()

    monkeypatch.setattr(predicates, "Z3MopProver", _MalformedProver)
    events: list[Z3PredicateProofObserved] = []
    reset_diagnostic_bus()
    subscribe(Z3PredicateProofObserved, events.append)
    try:
        rule = predicates.Z3setzRuleGeneric()
        rule.configure({})
        candidate, additions = _candidate(
            _mop(mop_type=ida_hexrays.mop_r),
            _mop(mop_type=ida_hexrays.mop_n, value=0),
        )

        assert rule.check_candidate(candidate) is False
    finally:
        reset_diagnostic_bus()

    assert additions == []
    assert events == []


@pytest.mark.runtime
def test_proof_receipts_preserve_conclusive_and_abstention_reasons_without_errors(
    monkeypatch,
    caplog,
) -> None:
    import ida_hexrays

    from d810.backends.ast.z3_proof_policy import (
        Z3ProofAbstentionReason,
        Z3ProofResult,
        Z3ProofStatus,
    )
    from d810.core.observability import reset_diagnostic_bus, subscribe
    from d810.core.observability_events import Z3PredicateProofObserved
    import d810.optimizers.microcode.instructions.z3.predicates as predicates

    class _FakeProver:
        def __init__(self, *, policy, **_kwargs):
            self.policy = policy

        def prove_equal(self, *_args, **_kwargs):
            return Z3ProofResult(
                status=Z3ProofStatus.ABSTAINED,
                reason=Z3ProofAbstentionReason.TIMEOUT,
                observed_expression_nodes=None,
                elapsed_ms=4.5,
            )

        def prove_unequal(self, *_args, **_kwargs):
            return Z3ProofResult(
                status=Z3ProofStatus.PROVED,
                reason=None,
                observed_expression_nodes=4,
                elapsed_ms=1.5,
            )

    monkeypatch.setattr(predicates, "Z3MopProver", _FakeProver)
    from d810.optimizers.microcode.instructions.z3.predicates import Z3setzRuleGeneric

    events: list[Z3PredicateProofObserved] = []
    reset_diagnostic_bus()
    subscribe(Z3PredicateProofObserved, events.append)
    try:
        rule = Z3setzRuleGeneric()
        rule.configure({"max_expression_nodes": 19, "proof_timeout_ms": 23})
        candidate, additions = _candidate(
            _mop(mop_type=ida_hexrays.mop_r),
            _mop(mop_type=ida_hexrays.mop_n, value=0),
        )
        with caplog.at_level(logging.ERROR):
            assert rule.check_candidate(candidate) is True
    finally:
        reset_diagnostic_bus()

    assert additions == [("val_res", 0, 1)]
    assert [event.status for event in events] == [
        Z3ProofStatus.ABSTAINED,
        Z3ProofStatus.PROVED,
    ]
    assert [event.reason for event in events] == [
        Z3ProofAbstentionReason.TIMEOUT,
        None,
    ]
    assert all(event.transform_id == "z-3-setz-generic" for event in events)
    assert all(event.max_expression_nodes == 19 for event in events)
    assert all(event.proof_timeout_ms == 23 for event in events)
    assert events[0].observed_expression_nodes is None
    assert events[1].observed_expression_nodes == 4
    assert all(event.elapsed_ms >= 0 for event in events)
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR]
