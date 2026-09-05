"""The observed-side seam refusal reports its own stage, not the inventory's.

This is the behavioural half of
``tests/unit/transforms/unflatten_authority/test_transaction_runtime_authority.py::
test_the_observed_seam_refusal_has_its_own_provenance``.  It lives here because
the observed revalidation fixture needs ``d810.hexrays`` (the patch binding and
the MBA identity index), which a unit test may not import.
"""

from __future__ import annotations

import logging

import pytest

from d810.core.runtime_identity import RuntimeJoinRejected
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.patch_binding import bind_patch_plan
from d810.transforms.cfg_transaction import CfgProjection
from d810.transforms.unflatten_authority import transaction_api
from tests.unit.transforms.unflatten_authority.helpers import (
    observed_patch_binding_for_test,
)
from tests.unit.transforms.unflatten_authority.test_transaction_api import (
    _c1_direct_preparation_case,
)


_LIVE_MATURITY = 8  # MMAT_GLBOPT1; the live binder needs a real provider stage


def _bound_authority():
    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    preparation = transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=fixture.attempt_id,
        generic_gates=gates,
    )
    assert preparation.prepared is not None
    refs = tuple(plan.source_coordinates)
    index = MbaBlockIdentityIndex.from_bindings(
        generation=fixture.attempt_id.generation,
        maturity=_LIVE_MATURITY,
        native_key=refs[0][0].identity.native_key,
        snapshot_id=plan.snapshot_id,
        session_id=fixture.attempt_id.session_id,
        bindings=tuple((ref.identity, serial) for ref, serial in refs),
    )
    index.begin_transaction(fixture.attempt_id, quantity=len(source.blocks))
    binding = transaction_api.bind_prepared_unflatten_authority(
        prepared=preparation.prepared,
        patch_binding=bind_patch_plan(plan, index, fixture.attempt_id).bound_plan,
    )
    assert binding.authority is not None
    return {
        "authority": binding.authority,
        "observed": projected,
        "observed_generation": fixture.attempt_id.generation,
        "generic_gates": gates,
        "observed_patch_binding": observed_patch_binding_for_test(binding.authority),
    }


def test_the_observed_seam_is_reached_and_reports_its_own_stage(
    monkeypatch, caplog,
) -> None:
    arguments = _bound_authority()

    reached: list[object] = []
    real = transaction_api._record_route_authority_rebind

    def _observed(evidence, *, phase):
        reached.append(phase)
        return real(evidence, phase=phase)

    monkeypatch.setattr(transaction_api, "_record_route_authority_rebind", _observed)
    accepted = transaction_api.revalidate_observed_unflatten_authority(**arguments)

    assert accepted.accepted
    assert reached  # the seam really is on the observed production path

    def _refused(evidence, *, phase):
        raise RuntimeJoinRejected("the observed seam refuses this bundle")

    monkeypatch.setattr(transaction_api, "_record_route_authority_rebind", _refused)
    with caplog.at_level(logging.WARNING, logger="d810.transforms.unflatten_authority.transaction_api"):
        refused = transaction_api.revalidate_observed_unflatten_authority(**arguments)

    assert not refused.accepted
    messages = [record.getMessage() for record in caplog.records]
    assert any("observed_route_authority_rebind" in message for message in messages)
    assert not any("observed_inventory" in message for message in messages)
