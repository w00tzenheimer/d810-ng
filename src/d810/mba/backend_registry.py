"""Registry-backed discovery for MBA backends.

This module avoids static imports from ``d810.mba`` to ``d810.backends``.
The optional Egglog provider uses ``ida_reloader.Scanner``; pure verification
providers are loaded explicitly on demand and resolved through
``core.registry.Registrant`` classes.
"""

from __future__ import annotations

import importlib
from pathlib import Path

from d810._vendor.ida_reloader.ida_reloader import Scanner
from d810.core.registry import Registrant
from d810.core.typing import Any, ClassVar

_SCANNED = False
_VERIFICATION_BACKEND_MODULES = {
    "z3": "d810.backends.mba.z3",
}


def _scan_backends_once() -> None:
    global _SCANNED
    if _SCANNED:
        return
    backends_dir = Path(__file__).resolve().parent.parent / "backends"
    if backends_dir.exists():
        Scanner.scan(
            [str(backends_dir)],
            prefix="d810.backends.",
            skip_packages=True,
        )
    _SCANNED = True


class VerificationEngineProvider(Registrant):
    registrant_name: ClassVar[str]

    @classmethod
    def create_engine(cls) -> Any:
        raise NotImplementedError


class EgglogProvider(Registrant):
    registrant_name: ClassVar[str]

    @classmethod
    def is_available(cls) -> bool:
        raise NotImplementedError

    @classmethod
    def pattern_expr_type(cls) -> Any:
        raise NotImplementedError

    @classmethod
    def verify_pattern_equivalence(cls, left: Any, right: Any) -> bool:
        raise NotImplementedError


def get_verification_engine(name: str = "z3") -> Any:
    """Load only the requested pure verification backend on demand.

    Verification is a portable MBA capability.  It must not discover the
    entire backend tree because that tree also contains optional Egglog and
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


def get_egglog_provider(name: str = "egglog") -> type[EgglogProvider]:
    _scan_backends_once()
    provider = EgglogProvider.find(name)
    if provider is None:
        raise ImportError(f"Egglog backend '{name}' is not available")
    return provider
