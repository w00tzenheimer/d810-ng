"""Composition-root provider registry for backend-supplied analysis seams.

Portable-core (``d810.capabilities`` sits below both ``recon`` and
``backends`` in the layered architecture): portable ``recon`` / ``analyses``
code READS backend implementations from here *without* importing the vendor
backend, while the composition root (``D810State.start_d810`` -- an
optimizer/HIGH-layer module that may legally import backends) REGISTERS them.

This inverts the dependency honestly (backend pushes, portable reads) and is
the mechanism that lets the recon BST-transition analyses drop their direct
``from d810.backends.hexrays.evidence import ...`` edges (Landing Sequence
LS10 -> P1, ticket d81-1w16/llr-pqem).

Convention follows ``d810.core.observability``: a module-global guarded by a
lock with ``register`` / ``get`` / ``reset`` functions.  The composition root
re-registers on every plugin load/reload, so a reload that clears these
module globals is repopulated before any recon analysis runs.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

from d810.core.typing import Any, Callable, Optional


@dataclass(frozen=True)
class BstWalkerProvider:
    """Backend-supplied BST live-mba walkers + constant-folding eval.

    Bundles the Hex-Rays evidence callables the recon BST-transition analyses
    depend on.  The Hex-Rays implementation lives in
    ``d810.backends.hexrays.evidence.bst_analysis``; the composition root
    constructs this bundle from it and registers it via
    :func:`register_bst_walkers`.  Recon consumers read it via
    :func:`get_bst_walkers` and never import the backend.
    """

    detect_state_var_stkoff: Callable[..., Any]
    dump_dispatcher_node: Callable[..., Any]
    find_pre_header_state: Callable[..., Any]
    walk_handler_chain: Callable[..., Any]
    forward_eval_insn: Callable[..., Any]
    resolve_via_bst_walk: Callable[..., Any]


_lock = threading.Lock()
_bst_walkers: Optional[BstWalkerProvider] = None


def register_bst_walkers(provider: BstWalkerProvider) -> None:
    """Register the backend BST-walker provider.

    Called only by the composition root (``D810State.start_d810``), which may
    import ``d810.backends.hexrays.evidence`` to build the bundle.
    """
    global _bst_walkers
    with _lock:
        _bst_walkers = provider


def get_bst_walkers() -> BstWalkerProvider:
    """Return the registered BST-walker provider.

    Raises:
        LookupError: if no provider is registered.  The recon BST-transition
            path REQUIRES this seam, so a missing provider is a
            composition-root wiring bug (fail loud), not an optional miss --
            unlike diagnostic seams that may legitimately be absent.
    """
    with _lock:
        provider = _bst_walkers
    if provider is None:
        raise LookupError(
            "BstWalkerProvider not registered: the composition root "
            "(D810State.start_d810) must call register_bst_walkers() before "
            "recon BST-transition analyses run."
        )
    return provider


def reset_providers_for_tests() -> None:
    """Clear all registered providers (test isolation)."""
    global _bst_walkers
    with _lock:
        _bst_walkers = None
