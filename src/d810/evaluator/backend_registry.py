"""Registry-backed discovery for evaluator backends."""

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
    backends_dir = Path(__file__).resolve().parent.parent / "backends" / "evaluator"
    if backends_dir.exists():
        Scanner.scan(
            [str(backends_dir)],
            prefix="d810.backends.evaluator.",
            skip_packages=True,
        )
    _SCANNED = True


class ConcreteEvaluatorProvider(Registrant):
    registrant_name: ClassVar[str]

    @classmethod
    def evaluator_type(cls) -> type[Any]:
        raise NotImplementedError

    @classmethod
    def default_evaluator(cls) -> Any:
        raise NotImplementedError


def get_concrete_provider(name: str = "concrete") -> type[ConcreteEvaluatorProvider]:
    _scan_backends_once()
    provider = ConcreteEvaluatorProvider.find(name)
    if provider is None:
        raise ImportError(f"Concrete evaluator backend '{name}' is not available")
    return provider

