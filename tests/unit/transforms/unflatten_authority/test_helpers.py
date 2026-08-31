"""Regression contracts for authority test-envelope helpers."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from d810.transforms.unflatten_authority.gates import GenericEffectfulGateFacts
from d810.transforms.unflatten_authority import model

from .helpers import realize_projected_routes_for_test


def test_realize_helper_legacy_effective_facts_stay_in_raw_source_owner_namespace():
    """Renumbering projection must not leak projected serials into the shadow DTO."""
    retained = "retained"
    lost = "lost"
    source_inventory = SimpleNamespace(
        effects=(
            SimpleNamespace(owner_serial=7),
            SimpleNamespace(owner_serial=19),
        ),
        reachable_serials=(7, 19),
        blocks=(
            SimpleNamespace(serial=7, block_ref=retained),
            SimpleNamespace(serial=19, block_ref=lost),
        ),
    )
    projected_inventory = SimpleNamespace(
        effects=(
            SimpleNamespace(owner_serial=101),
            SimpleNamespace(owner_serial=103),
        ),
        reachable_serials=(101,),
        serial_by_ref={retained: 101},
    )
    captured: dict[str, object] = {}

    def capture(**values):
        captured.update(values)
        return "captured"

    with patch(
        "d810.transforms.unflatten_authority.bind.bind_raw_effect_gate_phase_fact",
        side_effect=lambda *, raw_gate_facts, **_ignored: raw_gate_facts,
    ) as bind_raw, patch(
        "d810.transforms.unflatten_authority.bind.realize_projected_routes",
        side_effect=capture,
    ):
        result = realize_projected_routes_for_test(
            source_authority=SimpleNamespace(
                proposal_id="proposal", source_authority_id="source",
            ),
            plan=SimpleNamespace(
                plan_id="plan", unflatten_proposal=SimpleNamespace(claims=()),
            ),
            source_inventory=source_inventory,
            projected_inventory=projected_inventory,
            attempt_id="attempt",
            authority_id="authority",
        )

    assert result == "captured"
    assert bind_raw.call_args.kwargs["raw_gate_facts"] == GenericEffectfulGateFacts(
        False, frozenset({7, 19}), frozenset({7}), frozenset({19}),
        "inherited-helper",
    )
    effective = captured["legacy_effective_gate_facts"]
    assert effective == GenericEffectfulGateFacts(
        True, frozenset({7, 19}), frozenset({7, 19}), frozenset(),
        "inherited-helper",
    )


def test_realize_helper_derives_legacy_shadow_from_bound_raw_fact_with_loss():
    """A bound fact carries stable owners, never the producer DTO fields.

    The corridor fixture deliberately renumbers projected blocks and retires
    one source effect-owner into a validated clone relation.  Supplying its
    already-bound raw fact therefore exercises the compatibility shadow at
    the real public binder boundary.
    """
    from .test_bind import (
        _task_15_corridor_one_block_vertical_case,
        _task_15_corridor_vertical_inputs,
    )

    values = _task_15_corridor_vertical_inputs(
        _task_15_corridor_one_block_vertical_case(),
    )
    raw_fact = values["raw_effect_gate_fact"]
    assert raw_fact.raw_lost_source_owners
    expected_source_serials = frozenset(
        values["source_inventory"].serial_by_ref[owner.ref]
        for owner in raw_fact.pre_effectful_source_owners
    )
    values.pop("legacy_effective_gate_facts")

    accepted = realize_projected_routes_for_test(**values)

    assert type(accepted) is model.ProjectedRouteRealizationAccepted
    phase = accepted.realization.site_phase_result
    assert phase.raw_effect_gate_fact is raw_fact
    assert {
        values["source_inventory"].serial_by_ref[owner.ref]
        for owner in phase.raw_effect_gate_fact.pre_effectful_source_owners
    } == expected_source_serials
