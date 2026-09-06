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

import ast
import inspect
import textwrap
from dataclasses import fields as dataclass_fields
from unittest.mock import patch

import pytest

from d810.core.typing import get_args, get_type_hints
from d810.transforms.unflatten_authority import bind
from d810.transforms.unflatten_authority import canonical_session
from d810.transforms.unflatten_authority import ids as authority_ids
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority import transaction_api
from d810.transforms.unflatten_authority.canonical_session import (
    CanonicalSessionPhase,
    OccurrenceDigest,
    _WorkLedger,
    _canonical_validation_session,
)

from . import test_bind
from . import test_live_inventory_validation as live


@pytest.fixture(autouse=True)
def _isolated_process_ledger(monkeypatch):
    """Swap in a private ledger so these tests never disturb process totals."""

    monkeypatch.setattr(canonical_session, "_PROCESS_LEDGER", _WorkLedger())
    yield


def _route_registry() -> dict:
    """Return the route publication registry the seal kernel closed over."""

    registry = test_bind._private_route_registry()
    assert registry is bind._canonical_registry_seal.__defaults__[2]
    return registry


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
        stamp = authority_ids._occurrence_stamp(stranger)
        stranger.value = 2
        assert authority_ids._occurrence_stamp(stranger) == stamp
        # A registered record type is admitted, and its guard is a full digest.
        admitted = bind._memoizable_digest(session, _source_authority())
        assert type(admitted) is OccurrenceDigest
        assert len(admitted) == 32
        before = session.metrics
        # The store refuses that identity-only stamp outright: it is a bytes
        # subclass, but it is not the guard this memo is allowed to trust.
        with pytest.raises(TypeError):
            session.store_registry_seal(0, stranger, bytes(stamp), "sha256:never")
        with pytest.raises(TypeError):
            session.store_registry_seal(0, stranger, None, "sha256:never")
        with pytest.raises(TypeError):
            session.store_registry_seal(
                0, stranger, OccurrenceDigest(bytes(stamp)[:16]), "sha256:never",
            )
        assert bind._memoizable_digest(session, stranger) is None
        after = session.metrics

    assert after.registry_seal_hits == before.registry_seal_hits
    assert after.registry_seal_misses == before.registry_seal_misses


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
    """R2-F8: after ``_close`` the seal path takes the full, strict route.

    Scope, stated rather than implied: the production path can never present a
    *closed* session, because ``_canonical_validation_session`` resets the
    ContextVar before it calls ``_close``.  This pins the API contract -- a
    closed session answers nothing -- and then pins that the sessionless path
    still returns the same seal.  The ``RuntimeError`` branch is unreachable
    from production by construction, which is why it is asserted here directly
    instead of being driven through a seal.
    """

    subject = _published_route_result()
    registry = _route_registry()
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        expected = bind._canonical_registry_seal(subject, registry)

    assert session.closed is True
    with pytest.raises(RuntimeError):
        session.registry_seal_for(id(registry), subject, OccurrenceDigest(bytes(32)))
    # The production path no longer sees that session at all.
    assert canonical_session.active_canonical_session() is None
    assert bind._canonical_registry_seal(subject, registry) == expected


def test_the_memo_refuses_a_seal_that_is_not_an_exact_string() -> None:
    """The stored answer is the seal itself, so its type is checked at the door."""

    subject = _published_route_result()
    registry = _route_registry()
    digest = OccurrenceDigest(bytes(32))
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        with pytest.raises(TypeError):
            session.store_registry_seal(id(registry), subject, digest, b"seal")


def test_the_memo_key_separates_registries_and_occurrences() -> None:
    """Two registries ask two questions; two occurrences are two subjects."""

    subject = _published_route_result()
    other = _source_authority()
    registry = _route_registry()
    one = OccurrenceDigest(bytes(31) + b"\x01")
    two = OccurrenceDigest(bytes(31) + b"\x02")
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        session.store_registry_seal(id(registry), subject, one, "sha256:seal")
        assert session.registry_seal_for(id(registry), subject, one) == "sha256:seal"
        assert session.registry_seal_for(id(registry) + 1, subject, one) is None
        assert session.registry_seal_for(id(registry), other, one) is None
        assert session.registry_seal_for(id(registry), subject, two) is None


# --- the soundness invariant the memo key depends on --------------------


def _seal_subject_types() -> frozenset[type]:
    """Every model type ``_canonical_registry_seal_uncached`` dispatches on.

    Read out of the function's own source rather than restated here: a
    hand-written literal is exactly what let three of the thirty-three
    subjects -- the observed logical-endpoint and the two observed topology
    occurrences -- go unchecked in the first version of this test.
    """

    source = textwrap.dedent(inspect.getsource(
        bind._canonical_registry_seal_uncached,
    ))
    tree = ast.parse(source)
    names = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "model"
    }
    types = {
        getattr(model, name) for name in names
        if isinstance(getattr(model, name, None), type)
    }
    return frozenset(
        item for item in types
        if item in bind._REGISTRY_CANONICAL_RECORD_TYPES
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


def _seal_subject_closure(roots: frozenset[type]) -> set[type]:
    """Every registered record type reachable from a registry seal subject."""

    def flatten(annotation):
        yield annotation
        for argument in get_args(annotation):
            yield from flatten(argument)

    seen: set[type] = set()
    stack = list(roots)
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
    roots = _seal_subject_types()
    # The three the hand-written literal missed are in, and the count is the
    # dispatch's own, so a new subject cannot be added without being covered.
    assert {
        "ObservedLogicalEndpointOccurrence", "ObservedRouteTopologyOccurrence",
        "ObservedLoweredConditionalTopologyOccurrence",
    } <= {item.__qualname__ for item in roots}
    assert len(roots) == 33, sorted(item.__qualname__ for item in roots)
    reachable = _seal_subject_closure(roots)
    assert len(reachable) > len(roots)
    assert sorted(
        item.__qualname__ for item in (reachable & incomplete)
    ) == []


def _normalized_route_failure() -> tuple[object, dict]:
    """Mint one published failure whose ``__post_init__`` sorts its anchors."""

    accepted = bind.realize_projected_routes(
        **test_bind._c_complete_kwargs(test_bind._compiler_redirect_goto_case)
    )
    relation = accepted.realization.rows[0].relation
    canonical = tuple(sorted(
        (relation.feeder, relation.old_target), key=authority_ids.canonical_bytes,
    ))
    cells = dict(zip(
        bind._realize_projected_routes_from_claim_inventory.__code__.co_freevars,
        bind._realize_projected_routes_from_claim_inventory.__closure__,
    ))
    failure = cells["failure"].cell_contents(
        claim_id=None, proof_id=None, route_subject_id=None,
        scope=model.RouteRealizationFailureScope.EVIDENCE,
        proposal_id=None, evidence_id=None,
        stage=model.RouteRealizationFailureStage.EFFECT_TERMINAL_PRESERVATION,
        anchored_refs=tuple(reversed(canonical)),
    )
    assert failure.anchored_refs == canonical
    return failure, _route_registry()


# --- R2-F2 / R2-F3: the tamper baseline is unchanged --------------------


def test_a_direct_mutation_is_still_refused_after_a_warm_memo() -> None:
    """R2-F2: forging a direct field moves the digest, so the memo misses.

    This is the slice's most important test.  Falsified by dropping the digest
    from the memo key: the warm entry would then answer for the forged record.
    """

    authority = _source_authority()
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        bind.validate_source_route_authority(authority)
        assert len(session._registry_seals) == 1
        forged = authority_ids.authority_id("forged-source-authority")
        original = authority.source_authority_id
        object.__setattr__(authority, "source_authority_id", forged)
        try:
            with pytest.raises(
                ValueError,
                match="source_authority_id does not match canonical content",
            ):
                bind.validate_source_route_authority(authority)
        finally:
            object.__setattr__(authority, "source_authority_id", original)
        metrics = session.metrics

    # The refusal came from a miss, not from a served answer.
    assert metrics.registry_seal_hits == 0
    assert metrics.registry_seal_misses >= 2


def test_a_deep_mutation_is_still_refused_after_a_warm_memo() -> None:
    """R2-F3: a mutation below the direct children still misses.

    Every direct field of the presented occurrence is the same object, so this
    is exactly the case a shallow or bucketed key would serve wrongly.  It is
    the ``gotcha_mop_equality_memo_on_bucket_hash`` failure mode.
    """

    authority = _source_authority()
    # authority -> bound_evidence -> routes -> route -> evidence -> field:
    # every direct child of the presented occurrence stays the same object.
    deep = authority.bound_evidence.routes[0].evidence
    original = deep.source_anchor_ea
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        warm = bind._canonical_registry_seal(authority, _route_registry())
        object.__setattr__(deep, "source_anchor_ea", original + 1)
        try:
            assert authority.bound_evidence.routes[0].evidence is deep
            with pytest.raises(
                ValueError, match="proposal_id is not content-derived",
            ):
                bind.validate_source_route_authority(authority)
        finally:
            object.__setattr__(deep, "source_anchor_ea", original)
        restored = bind._canonical_registry_seal(authority, _route_registry())
        metrics = session.metrics

    assert restored == warm
    assert metrics.registry_seal_hits == 1


# --- R2-F4: the normalization check candidates A and B would delete -----


def test_the_candidate_versus_canonical_comparison_still_runs() -> None:
    """R2-F4: an unsorted stored tuple is still caught by the clone rebuild.

    ``_canonical_record_snapshot`` compares the presented record against the
    normalized canonical copy.  A memo defers that comparison for a repeat, it
    never removes it: a record the session has not sealed is compared in full.
    """

    failure, registry = _normalized_route_failure()
    canonical = failure.anchored_refs
    assert len(canonical) >= 2
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        object.__setattr__(failure, "anchored_refs", tuple(reversed(canonical)))
        try:
            with pytest.raises(
                ValueError,
                match="registry candidate differs from canonical live state",
            ):
                bind._canonical_registry_seal(failure, registry)
        finally:
            object.__setattr__(failure, "anchored_refs", canonical)
        assert session._registry_seals == {}
        # And the normalized record still seals.
        assert bind._canonical_registry_seal(failure, registry) == registry[
            id(failure)
        ][1]


def test_a_failed_seal_never_populates_a_reusable_entry() -> None:
    """The store happens after success only, so a raise leaves nothing behind."""

    authority = _source_authority()
    original = authority.plan_id
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        object.__setattr__(authority, "plan_id", authority_ids.authority_id("forged"))
        try:
            with pytest.raises(
                ValueError, match="source authority plan differs from proposal",
            ):
                bind._canonical_registry_seal(authority, _route_registry())
            assert session._registry_seals == {}
        finally:
            object.__setattr__(authority, "plan_id", original)


# --- R2-F5: the memo actually fires -------------------------------------


def test_a_memo_hit_performs_no_canonical_record_snapshot() -> None:
    """R2-F5: zero clone rebuilds on a hit, exactly one on a miss."""

    subject = _published_route_result()
    registry = _route_registry()
    snapshot = bind._canonical_record_snapshot
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        with patch.object(bind, "_canonical_record_snapshot", wraps=snapshot) as miss:
            first = bind._canonical_registry_seal(subject, registry)
        with patch.object(bind, "_canonical_record_snapshot", wraps=snapshot) as hit:
            second = bind._canonical_registry_seal(subject, registry)
        metrics = session.metrics

    assert first == second
    assert miss.call_count == 1
    assert hit.call_count == 0
    assert metrics.registry_seal_misses == 1
    assert metrics.registry_seal_hits == 1


def test_the_result_validation_still_calls_the_seal_exactly_once() -> None:
    """R2-F5: the memo changes the work inside a seal, never the call count."""

    accepted = _published_route_result()
    seal = bind._canonical_registry_seal
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ):
        with patch.object(bind, "_canonical_registry_seal", wraps=seal) as replay:
            bind.validate_projected_route_realization_result(accepted)

    assert replay.call_count == 1


# --- R2-F9: the counters ------------------------------------------------


def _prepare_and_measure(*, memo: bool):
    """Run one real preparation and return its own process counter delta."""

    canonical_session.reset_process_work_metrics()
    if memo:
        accepted = transaction_api.prepare_unflatten_authority(
            **live._fixture_arguments()
        )
    else:
        with patch.object(bind, "_registry_seal_memo", lambda value: None):
            accepted = transaction_api.prepare_unflatten_authority(
                **live._fixture_arguments()
            )
    assert type(accepted) is model.UnflattenAuthorityPreparationAccepted
    return canonical_session.process_work_metrics()


def test_the_memo_moves_only_the_counters_it_is_allowed_to_move() -> None:
    """R2-F9: a real before/after over the same real preparation.

    The first leg forces ``_registry_seal_memo`` to refuse every value, which
    is exactly today's pre-memo behaviour, so the two legs differ only by the
    memo.  Stop-rule item 3 bounds the ``occurrence_stamps`` rise **from
    above**; item 2 names the counters that must not move at all.
    """

    before = _prepare_and_measure(memo=False)
    after = _prepare_and_measure(memo=True)

    assert before.registry_seal_hits == 0
    assert before.registry_seal_misses == 0
    assert after.registry_seal_hits > 0
    assert after.registry_seal_misses > 0

    # Stop rule 3: the rise is bounded above by the number of memo lookups.
    bound = after.registry_seal_hits + after.registry_seal_misses
    assert after.occurrence_stamps - before.occurrence_stamps <= bound

    # Stop rule 2: the untouched paths do not move at all.
    for name in (
        "roundtrip_decodes", "inventory_validations", "inventory_seal_checks",
        "inventory_seal_hits", "inventory_seal_mints", "materializations",
        "canonical_bytes_reuses", "bytes_lookup_hits",
    ):
        assert getattr(after, name) == getattr(before, name), name
    assert after.materializations == 0

    # content_id_reuses may move only with the lookups that produce it: both
    # counters are written by the same branch of ids._record_content_id, so a
    # divergence would mean the change escaped the seal.
    assert (
        after.content_id_reuses - before.content_id_reuses
    ) == (after.content_id_lookup_hits - before.content_id_lookup_hits)

    # And the work the memo is meant to remove really fell.
    assert after.wire_encodes < before.wire_encodes
    assert after.content_id_mints < before.content_id_mints
    assert after.deep_validations < before.deep_validations


def test_every_seal_taken_by_a_real_preparation_is_byte_identical() -> None:
    """R2-F1, exhaustively: the memo answers what the strict path answers.

    The fixture mints per-attempt UUIDs, so comparing ID strings across two
    processes is not a valid oracle.  This compares the two paths inside one
    process, on every seal a real preparation actually takes.
    """

    seal = bind._canonical_registry_seal
    uncached = bind._canonical_registry_seal_uncached
    compared: list[tuple[str, str]] = []

    def _oracle(value, registry, *args, _memo=bind._MEMO_TICKET_UNSET, **kwargs):
        answer = seal(value, registry, *args, _memo=_memo, **kwargs)
        compared.append((answer, uncached(value, registry, *args, **kwargs)))
        return answer

    with patch.object(bind, "_canonical_registry_seal", _oracle):
        accepted = transaction_api.prepare_unflatten_authority(
            **live._fixture_arguments()
        )

    assert type(accepted) is model.UnflattenAuthorityPreparationAccepted
    assert len(compared) > 0
    assert [answer for answer, _ in compared] == [
        strict for _, strict in compared
    ]


def test_the_memo_guard_walk_happens_outside_the_publication_lock() -> None:
    """A first registration must not pay the guard walk under the global lock.

    ``_register_registry_occurrence`` holds ``_REGISTRY_PUBLICATION_LOCK`` while
    it seals, and a fresh occurrence can never hit the memo, so taking the
    recursive ``OccurrenceDigest`` walk inside the lock would make the FIRST
    registration leg strictly slower for no gain.  Falsified by moving the
    ``_registry_seal_memo`` call back below the ``with``.
    """

    events: list[str] = []
    real_lock = bind._REGISTRY_PUBLICATION_LOCK
    real_ticket = bind._registry_seal_memo

    class _SpyLock:
        def __enter__(self):
            events.append("lock-acquire")
            return real_lock.__enter__()

        def __exit__(self, *exc):
            events.append("lock-release")
            return real_lock.__exit__(*exc)

    def _ticket(value):
        events.append("guard-walk")
        return real_ticket(value)

    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ):
        with patch.object(bind, "_REGISTRY_PUBLICATION_LOCK", _SpyLock()):
            with patch.object(bind, "_registry_seal_memo", _ticket):
                _published_route_result()

    # Not vacuous: both the guard walks and the lock really happened.
    assert events.count("guard-walk") > 0
    assert events.count("lock-acquire") > 0
    # Every guard walk is outside the lock: no "guard-walk" sits between an
    # acquire and its release.
    depth = 0
    inside = 0
    for event in events:
        if event == "lock-acquire":
            depth += 1
        elif event == "lock-release":
            depth -= 1
        elif depth > 0:
            inside += 1
    assert inside == 0, events
