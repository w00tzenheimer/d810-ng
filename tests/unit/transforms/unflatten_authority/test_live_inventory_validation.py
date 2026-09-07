"""The inventory slice validates live records and canonicalises nothing.

Task 5b-4 converted one measured OLLVM hot-path slice -- the semantic-graph
inventory's CFG refs and the ``SemanticSubjectRef``s bound to them -- from
"canonicalise every live record while validating it" to "validate the semantic
fields; build the canonical representation only at an explicit
``materialize_for_persistence`` boundary".

These tests are the gate for that property.  The central one arms *every*
canonical entry point to raise whenever it is reached from a converted frame
and then drives the real preparation and the real observed revalidation, so it
cannot pass because the converted code was never executed: the tripwire counts
its own arming sites and the test asserts they were reached.
"""

from __future__ import annotations

import ast
import logging
import sys
from dataclasses import fields, replace
from pathlib import Path

import pytest

from d810.analyses.control_flow.graph_checks import (
    check_effectful_reachability_preserved,
    check_entry_reachability_not_collapsed,
    check_terminal_reachability_preserved,
)
from d810.core import logging as d810_logging
from d810.transforms.cfg_transaction import CfgProjection
from d810.transforms.unflatten_authority import bind
from d810.transforms.unflatten_authority import canonical_session
from d810.transforms.unflatten_authority import ids as authority_ids
from d810.transforms.unflatten_authority import model, transaction_api
from d810.transforms.unflatten_authority.canonical_session import (
    _WorkLedger,
    process_work_metrics,
)
from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle

from . import test_bind

#: The frames the slice converted.  ``bind_subjects`` and
#: ``bind_projected_subjects`` keep one coarse per-phase catalog roundtrip that
#: is deliberately outside the slice, so those two are armed only for the
#: record type the slice converted.
_CONVERTED_FRAMES = frozenset({"_validate_inventory_refs"})
_SUBJECT_FRAMES = frozenset({"bind_subjects", "bind_projected_subjects"})

_CANONICAL_ENTRY_POINTS = (
    "canonical_bytes",
    "canonical_decode",
    "validate_canonical_roundtrip",
    "content_id",
    "_record_content_id",
    "_wire",
    "_external_wire",
    "_json_bytes",
)


class _CanonicalReachedFromLiveValidation(AssertionError):
    """Raised when a converted frame reaches a canonical function."""


def _armed_frame(value: object) -> str | None:
    """Return the converted frame this call belongs to, if any.

    A ``__post_init__`` frame *stops* the walk.  ``_validate_inventory_refs``
    re-runs the ``__post_init__`` of every record it descends through, and a
    record's own seal-time content-ID derivation (``SemanticSubjectRef``'s
    ``subject_id``, for one) is its own unconverted site -- explicitly outside
    this slice, see task-5b-4-slice.md.  Attributing it to the caller would
    make this tripwire fire on work the slice never claimed to remove.
    """

    frame = sys._getframe(2)
    while frame is not None:
        name = frame.f_code.co_name
        if name == "__post_init__":
            return None
        if name in _CONVERTED_FRAMES:
            return name
        if name in _SUBJECT_FRAMES and type(value) is model.SemanticSubjectRef:
            return name
        frame = frame.f_back
    return None


def _arm(monkeypatch) -> None:
    """Make every canonical entry point raise inside the converted frames."""

    for name in _CANONICAL_ENTRY_POINTS:
        real = getattr(authority_ids, name)

        def _tripwire(*args, _real=real, _name=name, **kwargs):
            value = args[1] if _name in ("content_id", "_record_content_id") else (
                args[0] if args else None
            )
            frame = _armed_frame(value)
            if frame is not None and not authority_ids.materializing():
                raise _CanonicalReachedFromLiveValidation(
                    f"{_name} reached from {frame}",
                )
            return _real(*args, **kwargs)

        for module in (authority_ids, model, bind, transaction_api):
            if getattr(module, name, None) is real:
                monkeypatch.setattr(module, name, _tripwire)


def _reach_recorder(monkeypatch, reached: list[str]) -> None:
    """Record that the converted frames really ran on this path."""

    for module, name in ((model, "_validate_inventory_refs"),
                         (bind, "bind_subjects"),
                         (bind, "bind_projected_subjects")):
        real = getattr(module, name)

        def _spy(*args, _real=real, _name=name, **kwargs):
            reached.append(_name)
            return _real(*args, **kwargs)

        monkeypatch.setattr(module, name, _spy)


def _fixture_arguments():
    values = test_bind._compiler_guarded_convert_to_goto_case(include_graphs=True)
    plan, attempt, source, projected = values[1], values[5], values[6], values[7]
    raw_effect = check_effectful_reachability_preserved(source, post_cfg=projected)
    gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        raw_effect,
        raw_effect,
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    return {
        "source": source,
        "projection": CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        "plan": plan,
        "attempt_id": attempt,
        "generic_gates": gates,
    }


def test_the_converted_frames_reach_no_canonical_function(monkeypatch) -> None:
    """The proof: run the real preparation with the tripwire armed."""

    reached: list[str] = []
    _reach_recorder(monkeypatch, reached)
    _arm(monkeypatch)

    accepted = transaction_api.prepare_unflatten_authority(**_fixture_arguments())

    assert type(accepted) is model.UnflattenAuthorityPreparationAccepted
    # Not vacuous: the converted frames really ran on this path.
    assert "_validate_inventory_refs" in reached
    assert "bind_subjects" in reached


def test_the_tripwire_would_catch_a_restored_roundtrip(monkeypatch) -> None:
    """The discrimination itself, so the proof above cannot rot into a no-op."""

    _arm(monkeypatch)

    real_live = authority_ids.validate_live_semantic_fields

    def _restored(value, expected_type):
        real_live(value, expected_type)
        authority_ids.canonical_bytes(value)

    monkeypatch.setattr(model, "validate_live_semantic_fields", _restored)

    with pytest.raises(_CanonicalReachedFromLiveValidation):
        transaction_api.prepare_unflatten_authority(**_fixture_arguments())


def test_the_inventory_binding_join_contains_no_canonical_call() -> None:
    """Structural: the binding-vs-subject join is a record comparison now.

    The join used to confirm ``binding.subject == canonical_subject`` with a
    second, redundant ``canonical_bytes`` comparison.  A canonical function
    inside an internal join is exactly what the ruling removes, so this test
    reads the source of ``SemanticGraphInventory.__post_init__`` and requires
    that the statement raising ``binding subject does not match canonical
    subject content`` calls nothing from the canonical family.
    """

    source = Path(model.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    guards = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.If)
        and any(
            isinstance(inner, ast.Constant)
            and inner.value == "binding subject does not match canonical subject content"
            for inner in ast.walk(node)
        )
    ]
    assert len(guards) == 1
    called = {
        inner.func.id
        for inner in ast.walk(guards[0].test)
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
    }
    assert called & set(_CANONICAL_ENTRY_POINTS) == set()


def test_record_equality_and_canonical_bytes_agree_for_subjects() -> None:
    """Why dropping the byte comparison loses nothing, proved structurally.

    ``canonical_bytes`` of a registered record is a function of exactly
    ``ids._RECORD_FIELDS[type]``; dataclass equality is a function of exactly
    the ``compare=True`` fields.  For ``SemanticSubjectRef`` those two sets are
    the same set, so ``a == b`` and ``canonical_bytes(a) == canonical_bytes(b)``
    cannot disagree, and the second comparison was pure duplication.
    """

    authority_ids._ensure_registries()
    schema = authority_ids._RECORD_FIELDS[model.SemanticSubjectRef]
    compared = tuple(
        item.name
        for item in fields(model.SemanticSubjectRef)
        if item.compare and not item.name.startswith("_")
    )
    excluded = tuple(
        item.name
        for item in fields(model.SemanticSubjectRef)
        if not item.compare
    )
    # ``subject_id`` is the one canonical-schema field outside the comparison
    # set, and deliberately so: it is derived from the compared fields, so
    # including it could only ever agree with them -- while comparing it would
    # force every ``==`` to mint a SHA-256 (ticket d81-cxzv).
    assert tuple(name for name in schema if name != "subject_id") == compared
    assert "subject_id" in schema
    assert set(excluded) - {"subject_id"} == {
        name for name in excluded if name.startswith("_")
    }


def _tampered_subject(original, **overrides):
    """Return a subject that never sealed, differing only in ``overrides``.

    Construction cannot produce this record: ``SemanticSubjectRef.__post_init__``
    requires the primary owner to match the locator and the ``subject_id`` to
    match the content.  The join under test exists precisely for a record that
    reached it without sealing, so the test has to build one the same way a
    defect would -- by writing the slots directly.
    """

    tampered = object.__new__(model.SemanticSubjectRef)
    for item in fields(model.SemanticSubjectRef):
        object.__setattr__(
            tampered, item.name, getattr(original, item.name, None),
        )
    for name, value in overrides.items():
        object.__setattr__(tampered, name, value)
    return tampered


def test_the_inventory_still_refuses_a_binding_whose_subject_differs() -> None:
    """Behaviour, not just structure: the join itself still fails closed.

    The two records must share a ``subject_id`` and differ in a compared
    field, or the id-keyed lookup above the join never finds a partner and
    some earlier guard answers instead.  ``match=`` is on the join's own
    message so this cannot pass on a different guard's refusal: with the
    ``if binding.subject != canonical_subject`` line deleted the inventory
    builds and the test fails.
    """

    arguments = _fixture_arguments()
    accepted = transaction_api.prepare_unflatten_authority(**arguments)
    inventory = accepted.prepared.source_inventory
    assert inventory.bindings

    bound_ids = {item.subject.subject_id for item in inventory.bindings}
    target = None
    for candidate in inventory.subjects:
        if candidate.subject_id in bound_ids and candidate.anchor_ea is not None:
            target = candidate
            break
    assert target is not None

    tampered = _tampered_subject(target, anchor_ea=target.anchor_ea + 8)
    assert tampered.subject_id == target.subject_id
    assert tampered != target
    subjects = tuple(
        tampered if item.subject_id == target.subject_id else item
        for item in inventory.subjects
    )

    # Sealed, the record never reaches the join: the inventory re-seals every
    # subject and every binding (model.py, the ``value.__post_init__()`` loop
    # over each nominal tuple) before it joins them, and that seal answers
    # first.  Recorded rather than implied, because it is what makes the join
    # a defence-in-depth guard rather than the only guard.
    with pytest.raises(ValueError, match="^subject primary owner must match locator$"):
        replace(inventory, subjects=subjects)

    # With the seal suppressed the join is the only thing left, and it refuses.
    # Deleting ``if binding.subject != canonical_subject`` makes this fail.
    real_seal = model.SemanticSubjectRef.__post_init__
    try:
        model.SemanticSubjectRef.__post_init__ = lambda self: None
        with pytest.raises(
            ValueError,
            match="^binding subject does not match canonical subject content$",
        ):
            replace(inventory, subjects=subjects)
    finally:
        model.SemanticSubjectRef.__post_init__ = real_seal


def _sealed_subject():
    """Mint one real subject through the producer factory."""

    proposal, catalog = test_bind._fixture()
    handler = proposal.plan_inputs.authoritative_handlers[0]
    locator = model.HandlerSubjectLocator(
        handler.block_ref, handler.anchor_ea, handler.normalized_states,
    )
    subject = authority_ids._subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.HANDLER,
        role=model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        block_ref=handler.block_ref,
        anchor_ea=handler.anchor_ea,
        locator=locator,
    )
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    return subject, {
        "catalog": catalog,
        "phase": model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        "graph_fingerprint": authority_ids.authority_id("source"),
        "generation": catalog.generation,
        "serial_by_ref": serials,
    }


def test_a_corrupted_seal_is_refused_at_the_canonical_boundary() -> None:
    """What replaces the construction-time seal recheck (ticket d81-cxzv).

    ``subject_id`` is no longer supplied and no longer rechecked while the
    record seals: it is derived from ``(kind, role, locator)`` the first time
    anything demands it, so the *only* way to put a wrong value in the slot is
    to write it directly, which no production path does.

    A slot written that way is still refused where it matters -- the canonical
    boundary.  ``validate_canonical_roundtrip`` re-encodes the record, the
    encoder reads the (now poisoned) slot, and the round trip no longer
    reproduces the canonical bytes.  The live validator still accepts it,
    exactly as before, because it deliberately reaches no canonical
    representation at all.
    """

    subject, _kwargs = _sealed_subject()
    authority_ids.validate_canonical_roundtrip(subject, model.SemanticSubjectRef)

    object.__setattr__(subject, "subject_id", "sha256:" + "b" * 64)

    with pytest.raises(ValueError, match="non-canonical wire encoding"):
        authority_ids.validate_canonical_roundtrip(subject, model.SemanticSubjectRef)
    # The live validator accepts it -- this is the gap, stated exactly.
    assert authority_ids.validate_live_semantic_fields(
        subject, model.SemanticSubjectRef,
    ) is None


def test_a_rebuilt_subject_derives_the_same_identity_as_the_eager_algorithm() -> None:
    """The differential replacement for the seal recheck.

    The recheck asserted ``self.subject_id == subject_id(self)``.  With the
    field derived rather than supplied that is true by construction, so the
    thing worth testing is that the derived value is the value the eager code
    produced: ``content_id`` over exactly ``(kind, role, locator)``.
    """

    subject, _kwargs = _sealed_subject()
    assert subject.subject_id == authority_ids.subject_id(
        subject.kind, subject.role, subject.locator,
    )


@pytest.mark.parametrize("binder", ("bind_subjects", "bind_projected_subjects"))
def test_both_binders_accept_a_subject_whose_identity_was_never_demanded(
    binder: str,
) -> None:
    """Binding must not depend on the identity having been minted already."""

    subject, kwargs = _sealed_subject()
    bind_call = getattr(bind, binder)

    bound = bind_call((subject,), **kwargs)
    assert bound[0].subject is subject
    assert bound[0].subject.subject_id == authority_ids.subject_id(
        subject.kind, subject.role, subject.locator,
    )


def test_debug_logging_and_diagnostics_add_no_canonical_work(monkeypatch) -> None:
    """Enabling DEBUG must not make the authority path canonicalise more.

    The ruling requires that logging and diagnostics never trigger
    canonicalisation.  The measurable form of that is an exact one: run the
    real preparation twice, once quiet and once with every authority logger at
    DEBUG, and require identical work counters.
    """

    monkeypatch.setattr(canonical_session, "_PROCESS_LEDGER", _WorkLedger())
    transaction_api.prepare_unflatten_authority(**_fixture_arguments())
    quiet_before = process_work_metrics()
    transaction_api.prepare_unflatten_authority(**_fixture_arguments())
    quiet = process_work_metrics().delta(quiet_before)

    loggers = [
        logging.getLogger(name)
        for name in (
            "d810.transforms.unflatten_authority.transaction_api",
            "d810.transforms.unflatten_authority.bind",
            "d810.transforms.unflatten_authority.evaluate",
            "d810.transforms.unflatten_authority.model",
        )
    ]
    previous = [item.level for item in loggers]
    try:
        for item in loggers:
            item.setLevel(logging.DEBUG)
        d810_logging.LevelFlag.bump_config_version()
        noisy_before = process_work_metrics()
        transaction_api.prepare_unflatten_authority(**_fixture_arguments())
        noisy = process_work_metrics().delta(noisy_before)
    finally:
        for item, level in zip(loggers, previous):
            item.setLevel(level)
        d810_logging.LevelFlag.bump_config_version()

    assert noisy.as_payload() == quiet.as_payload()
    # Not vacuous for the registry-seal memo either: DEBUG must not change how
    # many seals are reused, and the fixture really does reuse some.
    assert quiet.registry_seal_hits > 0
    assert noisy.registry_seal_hits == quiet.registry_seal_hits
    assert noisy.registry_seal_misses == quiet.registry_seal_misses


def _arm_proposal_canonicalisation(monkeypatch, frame_name: str) -> None:
    """Make any canonical encode of a whole proposal raise inside ``frame_name``."""

    for name in ("canonical_bytes", "content_id", "_record_content_id", "_wire"):
        real = getattr(authority_ids, name)

        def _tripwire(*args, _real=real, _name=name, **kwargs):
            value = args[1] if _name in ("content_id", "_record_content_id") else (
                args[0] if args else None
            )
            if (
                type(value) is model.ProposedUnflattenContract
                and not authority_ids.materializing()
            ):
                frame = sys._getframe(1)
                while frame is not None:
                    if frame.f_code.co_name == frame_name:
                        raise _CanonicalReachedFromLiveValidation(
                            f"{_name} reached from {frame_name}",
                        )
                    frame = frame.f_back
            return _real(*args, **kwargs)

        for module in (authority_ids, model, bind, transaction_api):
            if getattr(module, name, None) is real:
                monkeypatch.setattr(module, name, _tripwire)


def test_rejected_route_diagnostics_never_canonicalise_the_proposal(
    monkeypatch, caplog,
) -> None:
    """A rejected route builds its coordinates from the authority's own ID.

    Point 6: no diagnostics argument may reach ``canonical_bytes``.  The
    rejected-binding path holds ``SourceBoundRouteAuthority.proposal_id``,
    which ``__post_init__`` already pins to ``authority_id(self.proposal)``, so
    the coordinate is byte-identical without encoding the proposal again.
    Falsified by restoring ``proposal_id = authority_id(proposal)``.
    """

    values = test_bind._task_15_vertical_inputs(
        test_bind._task_15_direct_vertical_case,
    )
    entered: list[str] = []
    real_coordinates = bind._route_failure_coordinates

    def _spy(*args, **kwargs):
        entered.append("_route_failure_coordinates")
        return real_coordinates(*args, **kwargs)

    monkeypatch.setattr(bind, "_route_failure_coordinates", _spy)
    _arm_proposal_canonicalisation(monkeypatch, "_route_failure_coordinates")

    with caplog.at_level(logging.WARNING):
        rejected = bind.realize_projected_routes(**{**values, "plan": None})

    assert type(rejected) is model.ProjectedRouteRealizationRejected
    # Not vacuous: the diagnostics path really ran and produced a coordinate.
    assert entered == ["_route_failure_coordinates"]
    assert rejected.failures[0].proposal_id == values["source_authority"].proposal_id
    assert authority_ids.materializing() is False


def test_the_proposal_tripwire_would_catch_a_restored_canonicalisation(
    monkeypatch,
) -> None:
    """The discrimination, so the proof above cannot rot into a no-op."""

    values = test_bind._task_15_vertical_inputs(
        test_bind._task_15_direct_vertical_case,
    )
    real_derived = bind._derived_proposal_id

    def _restored(proposal, proof):
        del proof
        return authority_ids.authority_id(proposal)

    monkeypatch.setattr(bind, "_derived_proposal_id", _restored)
    _arm_proposal_canonicalisation(monkeypatch, "_route_failure_coordinates")

    with pytest.raises(_CanonicalReachedFromLiveValidation):
        bind.realize_projected_routes(**{**values, "plan": None})

    assert bind._derived_proposal_id is _restored
    assert real_derived is not _restored
