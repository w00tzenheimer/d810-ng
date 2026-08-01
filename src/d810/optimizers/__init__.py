"""D810 optimizer infrastructure and refactored systems.

This module provides the foundational components for the d810 optimization system:
- Declarative DSL for pattern matching
- Core optimization base classes
- Caching for persistent optimization results
- Centralized optimization manager
"""

from d810._vendor.ida_reloader.ida_reloader import Scanner


def load_optimizer_registries(*, scanner=Scanner) -> None:
    """Import every optimizer module so registry-backed hooks are complete."""
    scanner.scan(
        __path__,
        prefix=f"{__name__}.",
        skip_packages=False,
    )


__all__ = ["load_optimizer_registries"]
