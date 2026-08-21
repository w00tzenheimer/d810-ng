"""Characterize the closed authority-model package boundary."""

from __future__ import annotations

from .helpers import import_authority_model


def test_authority_model_package_exists_and_is_closed() -> None:
    """The model package is the only import surface for typed authority data."""

    model = import_authority_model()

    assert model.__all__
    assert all(isinstance(name, str) for name in model.__all__)
