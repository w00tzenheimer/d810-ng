"""The phase-owned canonical registry-seal memo (task 5b-5, ticket d81-hf7j).

``_canonical_registry_seal`` recomputes a closed record's publication seal by
detaching a canonical copy, re-running its ``__post_init__``, comparing the
candidate against the canonical state and re-deriving the identity.  Every
consumption of an already-published occurrence repeats all of it.

The memo does not change *what* is checked, only *when*: it is guarded by the
exact live occurrence and by the full 32-byte ``OccurrenceDigest`` over that
occurrence's canonical schema, so any ``object.__setattr__`` anywhere in the
reachable graph misses and the untouched computation runs and raises exactly as
before.  These tests are that claim's gate; each one must fail if the guard it
names is removed.
"""

from __future__ import annotations

from dataclasses import fields as dataclass_fields
from unittest.mock import patch

import pytest

from d810.core.typing import get_args, get_type_hints
from d810.transforms.unflatten_authority import bind
from d810.transforms.unflatten_authority import canonical_session
from d810.transforms.unflatten_authority import ids as authority_ids
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.canonical_session import (
    CanonicalSessionPhase,
    _WorkLedger,
    _canonical_validation_session,
)

from . import test_bind


@pytest.fixture(autouse=True)
def _isolated_process_ledger(monkeypatch):
    """Swap in a private ledger so these tests never disturb process totals."""

    monkeypatch.setattr(canonical_session, "_PROCESS_LEDGER", _WorkLedger())
    yield


def _route_registry() -> dict:
    """Return the route publication registry the seal kernel closed over."""

    return bind._canonical_registry_seal.__defaults__[2]


def _published_route_result() -> object:
    """Return one real, published route result and nothing synthetic."""

    accepted = bind.realize_projected_routes(
        **test_bind._task_15_vertical_inputs(
            test_bind._task_15_direct_vertical_case,
        )
    )
    assert type(accepted) is model.ProjectedRouteRealizationAccepted
    return accepted


def _source_authority() -> object:
    """Return one real, published ``SourceBoundRouteAuthority``."""

    authority, *_rest = test_bind._task_15_direct_vertical_case()
    assert type(authority) is model.SourceBoundRouteAuthority
    return authority


# --- R2-F1: byte-identity ------------------------------------------------


@pytest.mark.parametrize(
    "phase",
    (
        CanonicalSessionPhase.PROJECTED_PREPARATION,
        CanonicalSessionPhase.OBSERVED_REVALIDATION,
    ),
)
def test_the_memo_answers_exactly_what_a_strict_recomputation_answers(
    phase,
) -> None:
    """R2-F1: the seal string is identical warm, cleared, and session-free."""

    subject = _published_route_result()
    registry = _route_registry()

    strict = bind._canonical_registry_seal(subject, registry)
    with _canonical_validation_session(phase) as session:
        cold = bind._canonical_registry_seal(subject, registry)
        warm = bind._canonical_registry_seal(subject, registry)
        session._registry_seals.clear()
        recleared = bind._canonical_registry_seal(subject, registry)

    uncached = bind._canonical_registry_seal_uncached(subject, registry)
    assert strict == cold == warm == recleared == uncached
    assert strict.startswith("sha256:") or len(strict) == 64


# --- R2-F6: the fail-closed gate ----------------------------------------


def test_an_unregistered_type_never_memoizes() -> None:
    """R2-F6: ``_feed_occurrence`` stamps unknown types by identity alone.

    Such a digest cannot change under mutation, so the gate must refuse it.
    Falsified by removing the registered-type check in ``_memoizable_digest``.
    """

    class _Unregistered:
        __slots__ = ("value",)

        def __init__(self) -> None:
            self.value = 1

    stranger = _Unregistered()
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        assert bind._memoizable_digest(session, stranger) is None
        # The identity-only stamp really is blind to the mutation, which is
        # exactly why the gate exists.
        before = authority_ids._occurrence_stamp(stranger)
        stranger.value = 2
        assert authority_ids._occurrence_stamp(stranger) == before
        # A registered record type is admitted.
        assert bind._memoizable_digest(session, _published_route_result()) is not None
        metrics = session.metrics

    assert metrics.registry_seal_hits == 0


def test_no_session_never_memoizes() -> None:
    """R2-F6/R2-F8: direct construction outside a phase stays strict."""

    subject = _published_route_result()
    registry = _route_registry()
    assert canonical_session.active_canonical_session() is None
    assert bind._memoizable_digest(None, subject) is None

    snapshot = bind._canonical_record_snapshot
    with patch.object(bind, "_canonical_record_snapshot", wraps=snapshot) as replay:
        first = bind._canonical_registry_seal(subject, registry)
        second = bind._canonical_registry_seal(subject, registry)

    assert first == second
    assert replay.call_count == 2
    metrics = canonical_session.process_work_metrics()
    assert metrics.registry_seal_hits == 0
    assert metrics.registry_seal_misses == 0


# --- R2-F7: no process-global memo --------------------------------------


def test_the_memo_is_owned_by_one_session_and_never_crosses_phases() -> None:
    """R2-F7: a second session starts empty.  Falsified by a module-global."""

    subject = _published_route_result()
    registry = _route_registry()

    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as first:
        bind._canonical_registry_seal(subject, registry)
        assert first.registry_seal_for(id(registry), subject, None) is None
        assert len(first._registry_seals) == 1

    with _canonical_validation_session(
        CanonicalSessionPhase.OBSERVED_REVALIDATION,
    ) as second:
        assert second is not first
        assert second._registry_seals == {}
        digest = bind._memoizable_digest(second, subject)
        assert second.registry_seal_for(id(registry), subject, digest) is None
        bind._canonical_registry_seal(subject, registry)
        assert second.registry_seal_for(id(registry), subject, digest) is not None

    assert first._registry_seals == {}
    assert second._registry_seals == {}


# --- R2-F8: fail closed by fallthrough ----------------------------------


def test_a_closed_session_never_leaks_require_open_out_of_a_seal() -> None:
    """R2-F8: after ``_close`` the seal path takes the full, strict route."""

    subject = _published_route_result()
    registry = _route_registry()
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        expected = bind._canonical_registry_seal(subject, registry)

    assert session.closed is True
    with pytest.raises(RuntimeError):
        session.registry_seal_for(id(registry), subject, b"digest")
    # The production path no longer sees that session at all.
    assert canonical_session.active_canonical_session() is None
    assert bind._canonical_registry_seal(subject, registry) == expected


def test_the_memo_refuses_a_seal_that_is_not_an_exact_string() -> None:
    """The stored answer is the seal itself, so its type is checked at the door."""

    subject = _published_route_result()
    registry = _route_registry()
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        with pytest.raises(TypeError):
            session.store_registry_seal(id(registry), subject, b"digest", b"seal")


def test_the_memo_key_separates_registries_and_occurrences() -> None:
    """Two registries ask two questions; two occurrences are two subjects."""

    subject = _published_route_result()
    other = _source_authority()
    registry = _route_registry()
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        session.store_registry_seal(id(registry), subject, b"d", "sha256:seal")
        assert session.registry_seal_for(id(registry), subject, b"d") == "sha256:seal"
        assert session.registry_seal_for(id(registry) + 1, subject, b"d") is None
        assert session.registry_seal_for(id(registry), other, b"d") is None
        assert session.registry_seal_for(id(registry), subject, b"e") is None


# --- the soundness invariant the memo key depends on --------------------


_SEAL_SUBJECT_TYPE_NAMES = (
    "ClonedSemanticInstructionOrigin", "ClonedSemanticPrefix",
    "DirectRouteRealization", "SharedCarrierSourceBypassRouteRealization",
    "RetainedPrefixRouteRealization", "LoweredConditionalRouteRealization",
    "ClonedConditionalRouteRealization", "FoldedConditionalRouteRealization",
    "TwoArmDirectBranchRouteRealization",
    "BranchFallthroughHelperRouteRealization", "ClonedRouteCorridorRealization",
    "ClonedCarrierRouteCorridorRealization", "SourceBoundRouteAuthority",
    "ProjectedRouteRealizationRow", "ProjectedRouteRealization",
    "SourceBoundRouteAuthorityAccepted", "SourceBoundRouteAuthorityRejected",
    "ProjectedRouteRealizationAccepted", "ProjectedRouteRealizationRejected",
    "RouteRealizationFailure", "RawEffectGatePhaseFact",
    "EffectSiteCoordinate", "TerminalSiteCoordinate",
    "ScalarizedInstructionCoordinate", "ExactEffectBindingResult",
    "LocalAliasScalarizationBindingResult", "ProjectedEffectSiteResult",
    "ProjectedTerminalSiteResult", "ProjectedSemanticSitePhaseResult",
    "ProjectedRouteSitePreservation",
)


def _stamp_incomplete_types() -> set[type]:
    """Types whose structural snapshot reads a field the digest never hashes."""

    authority_ids._ensure_registries()
    incomplete: set[type] = set()
    for record_type in bind._REGISTRY_CANONICAL_RECORD_TYPES:
        snapshot_names = {
            item.name for item in dataclass_fields(record_type)
            if not bind._is_runtime_authority_sidecar(item)
        }
        stamp_names = authority_ids._RECORD_FIELDS.get(
            record_type, authority_ids._EXTERNAL_FIELDS.get(record_type),
        )
        if stamp_names is None or (snapshot_names - set(stamp_names)):
            incomplete.add(record_type)
    return incomplete


def _seal_subject_closure() -> set[type]:
    """Every registered record type reachable from a registry seal subject."""

    by_name = {
        record_type.__qualname__: record_type
        for record_type in bind._REGISTRY_CANONICAL_RECORD_TYPES
    }
    missing = [name for name in _SEAL_SUBJECT_TYPE_NAMES if name not in by_name]
    assert missing == [], missing

    def flatten(annotation):
        yield annotation
        for argument in get_args(annotation):
            yield from flatten(argument)

    seen: set[type] = set()
    stack = [by_name[name] for name in _SEAL_SUBJECT_TYPE_NAMES]
    while stack:
        record_type = stack.pop()
        if record_type in seen:
            continue
        seen.add(record_type)
        for annotation in get_type_hints(record_type).values():
            for member in flatten(annotation):
                if (
                    isinstance(member, type)
                    and member in bind._REGISTRY_CANONICAL_RECORD_TYPES
                ):
                    stack.append(member)
    return seen


def test_the_occurrence_digest_covers_every_field_the_seal_reads() -> None:
    """The memo is only sound while the digest sees everything the seal does.

    ``_registry_structural_snapshot`` enumerates ``dataclasses.fields`` minus
    the runtime authority sidecars; ``_occurrence_stamp`` enumerates the
    canonical schema.  Two records in the model carry a private field the
    schema omits, so a mutation of it would move the seal without moving the
    digest.  Neither is reachable from any seal subject -- and this test is
    what keeps that true when the model grows.
    """

    incomplete = _stamp_incomplete_types()
    # Not vacuous: the discrepancy this guards against exists in the model.
    assert {item.__qualname__ for item in incomplete} == {
        "ObligationEvidenceIndex", "PreparationAuthorityReceipt",
    }
    reachable = _seal_subject_closure()
    assert len(reachable) >= len(_SEAL_SUBJECT_TYPE_NAMES)
    assert sorted(
        item.__qualname__ for item in (reachable & incomplete)
    ) == []
