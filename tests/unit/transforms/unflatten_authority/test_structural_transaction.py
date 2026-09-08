"""Attempt-owned partitions live through commit and close as a unit."""

from dataclasses import replace

import pytest

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.structural_identity import StructuralIdentityError, StructuralNodeKind
from d810.transforms.cfg_transaction import TransactionAttemptId
from d810.transforms.unflatten_authority.structural_transaction import (
    StructuralTransactionContext,
    StructuralTransactionCoordinates,
)


def native():
    return NativePreanalysisKey("input", "metapc", 64, 1, "function", "profile", "sdk")


def test_partitions_and_attempt_lifetime_are_distinct():
    attempt = TransactionAttemptId.new("plan", "gateway", 3)
    coordinates = StructuralTransactionCoordinates("snapshot", 4, 3, None, 3)
    context = StructuralTransactionContext(attempt, native(), coordinates)
    a = context.source.intern(StructuralNodeKind.VALUE, None, (1,), ())
    b = context.projected.intern(StructuralNodeKind.VALUE, None, (1,), ())
    assert a != b
    context.source.publish()
    context.projected.publish()
    with pytest.raises(StructuralIdentityError):
        _ = context.observed
    observed = context.begin_observation(attempt, native(), coordinates)
    assert observed.intern(StructuralNodeKind.VALUE, None, (1,), ()) != b
    with pytest.raises(StructuralIdentityError):
        context.begin_observation(attempt, native(), coordinates)
    context.require_scope(attempt, native(), coordinates)
    context.close()
    context.close()
    with pytest.raises(StructuralIdentityError):
        context.require_scope(attempt, native(), coordinates)
    with pytest.raises(StructuralIdentityError):
        observed.resolve(a, StructuralNodeKind.VALUE)


def test_foreign_attempt_restart_epoch_and_native_are_rejected():
    attempt = TransactionAttemptId.new("plan", "gateway", 3)
    coords = StructuralTransactionCoordinates("snapshot", 4, 3, None, 3)
    context = StructuralTransactionContext(attempt, native(), coords)
    with pytest.raises(StructuralIdentityError):
        context.require_scope(replace(attempt), native(), coords)
    with pytest.raises(StructuralIdentityError):
        context.require_scope(attempt, replace(native(), function_rva=2), coords)
    with pytest.raises(StructuralIdentityError):
        context.require_scope(attempt, native(), coords._replace(gateway_generation=4))
    with pytest.raises(StructuralIdentityError):
        context.require_scope(attempt, native(), coords._replace(execution_epoch=1))


def test_scope_does_not_alias_boolean_and_integer_components():
    attempt = TransactionAttemptId.new("plan", "gateway", 3)
    coords = StructuralTransactionCoordinates("snapshot", 1, 3, None, 3)
    context = StructuralTransactionContext(attempt, native(), coords)
    corrupted = native()
    object.__setattr__(corrupted, "function_rva", True)
    with pytest.raises(StructuralIdentityError):
        context.require_scope(attempt, corrupted, coords)
    with pytest.raises(StructuralIdentityError):
        context.require_scope(attempt, native(), coords._replace(maturity=True))


def test_admission_rejects_mutable_attempt_descendant():
    attempt = TransactionAttemptId.new("plan", "gateway", 3)
    object.__setattr__(attempt, "plan_id", ["plan"])
    with pytest.raises((TypeError, ValueError)):
        StructuralTransactionContext(
            attempt,
            native(),
            StructuralTransactionCoordinates("snapshot", 1, 3, None, 3),
        )


def test_admission_rejects_native_scalar_subclasses():
    class MutableInteger(int):
        pass

    value = native()
    object.__setattr__(value, "function_rva", MutableInteger(1))
    attempt = TransactionAttemptId.new("plan", "gateway", 3)
    with pytest.raises(TypeError):
        StructuralTransactionContext(
            attempt, value, StructuralTransactionCoordinates("snapshot", 1, 3, None, 3)
        )


def test_evidence_generation_is_a_separate_scope_coordinate():
    attempt = TransactionAttemptId.new("plan", "gateway", 3)
    coords = StructuralTransactionCoordinates(
        "snapshot",
        1,
        3,
        None,
        evidence_generation=9,
    )
    context = StructuralTransactionContext(attempt, native(), coords)
    with pytest.raises(StructuralIdentityError):
        context.require_scope(
            attempt, native(), coords._replace(evidence_generation=10)
        )
    with pytest.raises(StructuralIdentityError):
        context.begin_observation(
            attempt, native(), coords._replace(evidence_generation=10)
        )
    with pytest.raises(StructuralIdentityError, match="no observation"):
        _ = context.observed
