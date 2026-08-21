"""Small test-only helpers shared by the authority migration checkpoints."""

from __future__ import annotations

import importlib


def import_authority_model():
    """Import the future model at the package boundary under test."""

    return importlib.import_module("d810.transforms.unflatten_authority.model")
