"""LS11 C8: DispatcherResolver protocol (ticket d81-mt50).

First ``families -> capabilities`` edge in the tree (DOWN-legal).  Any-typing
precedent: ``families/state_machine_cff/protocols.py``.  ``accepts()`` returns
ranked evidence (``ResolverCandidate``), NEVER ``bool``; ``resolve()`` may fail
after ``accepts()`` succeeds.
"""
from __future__ import annotations

from d810.core.typing import Any, Protocol, runtime_checkable

from d810.capabilities.dispatcher import RouterKind, StateMachineSeed

__all__ = ["DispatcherResolver"]


@runtime_checkable
class DispatcherResolver(Protocol):
    name: str
    router_kind: RouterKind

    def accepts(self, seed: StateMachineSeed, entry: Any) -> Any | None:
        """Return a ResolverCandidate (ranked evidence) or None.  NOT a bool."""
        ...

    def resolve(self, seed: StateMachineSeed, candidate: Any) -> Any | None:
        """Return a DispatcherResolution or None (may fail after accepts())."""
        ...
