"""Registry-backed discovery for MBA backends.

This module avoids static imports from ``d810.mba`` to ``d810.backends``.
Pure verification providers are loaded explicitly on demand and resolved
through ``core.registry.Registrant`` classes.
"""

from __future__ import annotations

import importlib

from d810.core.registry import Registrant
from d810.core.typing import Any, ClassVar

_VERIFICATION_BACKEND_MODULES = {
    "z3": "d810.backends.mba.z3",
}


class VerificationEngineProvider(Registrant):
    registrant_name: ClassVar[str]

    @classmethod
    def create_engine(cls) -> Any:
        raise NotImplementedError


def get_verification_engine(name: str = "z3") -> Any:
    """Load only the requested pure verification backend on demand.

    Verification is a portable MBA capability.  It must not discover the
    entire backend tree because that tree also contains optional e-graph and
    live IDA providers.  The explicit module map keeps discovery narrow while
    leaving provider registration in the backend module itself.
    """

    provider = VerificationEngineProvider.find(name)
    if provider is None:
        module_name = _VERIFICATION_BACKEND_MODULES.get(name.lower())
        if module_name is None:
            raise ImportError(f"Verification backend '{name}' is not available")
        importlib.import_module(module_name)
        provider = VerificationEngineProvider.find(name)
    if provider is None:
        raise ImportError(f"Verification backend '{name}' is not available")
    return provider.create_engine()
