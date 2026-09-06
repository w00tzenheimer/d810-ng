"""The observed half of the live-inventory slice canonicalises nothing either.

This is the runtime twin of
``tests/unit/transforms/unflatten_authority/test_live_inventory_validation.py::
test_the_converted_frames_reach_no_canonical_function``.  It lives here because
the observed revalidation fixture needs ``d810.hexrays`` (the patch binding and
the MBA identity index), which a unit test may not import.
"""

from __future__ import annotations

import sys

import pytest

from d810.transforms.unflatten_authority import bind
from d810.transforms.unflatten_authority import ids as authority_ids
from d810.transforms.unflatten_authority import model, transaction_api
from tests.unit.transforms.unflatten_authority.test_live_inventory_validation import (
    _CANONICAL_ENTRY_POINTS,
    _CONVERTED_FRAMES,
    _SUBJECT_FRAMES,
    _CanonicalReachedFromLiveValidation,
)
from tests.system.runtime.transforms.unflatten_authority.test_observed_seam_provenance import (
    _bound_authority,
)


def _armed_frame(value: object) -> str | None:
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


def test_the_observed_revalidation_reaches_no_canonical_function(
    monkeypatch,
) -> None:
    arguments = _bound_authority()

    reached: list[str] = []
    real = bind.bind_projected_subjects

    def _spy(*args, **kwargs):
        reached.append("bind_projected_subjects")
        return real(*args, **kwargs)

    monkeypatch.setattr(bind, "bind_projected_subjects", _spy)
    _arm(monkeypatch)

    verdict = transaction_api.revalidate_observed_unflatten_authority(**arguments)

    assert verdict.accepted
    # Not vacuous: the converted frame really runs on the observed path.
    assert reached == ["bind_projected_subjects"]


def test_the_observed_tripwire_would_catch_a_restored_roundtrip(
    monkeypatch,
) -> None:
    arguments = _bound_authority()
    _arm(monkeypatch)

    real_live = authority_ids.validate_live_semantic_fields

    def _restored(value, expected_type):
        real_live(value, expected_type)
        authority_ids.canonical_bytes(value)

    monkeypatch.setattr(model, "validate_live_semantic_fields", _restored)

    with pytest.raises(_CanonicalReachedFromLiveValidation):
        transaction_api.revalidate_observed_unflatten_authority(**arguments)
