"""Registry-backed discovery for MBA backends.

This module avoids static imports from ``d810.mba`` to ``d810.backends``.
Backends are discovered via ``ida_reloader.Scanner`` and resolved through
``core.registry.Registrant`` classes.
"""

from __future__ import annotations

from pathlib import Path

from d810._vendor.ida_reloader.ida_reloader import Scanner
from d810.core.registry import Registrant
from d810.core.typing import Any, ClassVar

_SCANNED = False


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
    _scan_backends_once()
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

