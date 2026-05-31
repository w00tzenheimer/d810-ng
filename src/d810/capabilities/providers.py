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
    # Block topology accessors.  Portable-core path analyses hold an opaque
    # backend object (a live ``mba_t`` OR a ``_FlowGraphMBAView`` snapshot
    # projection) and must not call its live-MBA method API
    # (``get_mblock``/``nsucc``/``succ``) directly.  They route through these
    # seams; the backend impl makes the identical call on whichever object it
    # is handed, so behaviour is unchanged for both (ticket llr-zeyu).
    #
    # WARNING -- TRANSITIONAL VENDOR BRIDGE, NOT the LLVM/LiSA IR end-state
    # (ticket llr-lxas).  These accessors are phrased in Hex-Rays taxonomy
    # (fetch a block off an opaque live object by serial) and keep a LIVE
    # HANDLE alive in portable code: the analyses re-query the source object
    # mid-analysis instead of consuming a once-lifted ``d810.ir.FlowGraph``.
    # The portable destination is to lift ``mba_t -> FlowGraph`` at the
    # optimizer/hodur call boundary so the path analyses take a ``FlowGraph``
    # and read ``BlockSnapshot.succs`` directly, after which both of these
    # seams (and the ``_FlowGraphMBAView`` mimicry adapter) are DELETED.
    # "gate 0" means the live method-CALLS left portable-core text, NOT that
    # the IR converged.
    get_block: Callable[..., Any]
    block_successors: Callable[..., Any]


@dataclass(frozen=True)
class MicrocodeEvidenceProvider:
    """Backend-supplied LIVE microcode evidence accessors.

    The portable seam for the optimizers-thinning work-backward extractions: portable
    ``analyses`` / ``transforms`` hold an opaque backend object (a live ``mba_t`` OR a
    ``d810.ir.FlowGraph`` projection) and read facts through these callables instead of the
    live-MBA method/attr API. The Hex-Rays impl (``backends/hexrays/evidence``) makes the
    identical call on whichever object it is handed, so behaviour is byte-identical for both
    (the llr-zeyu polymorphism guard). Grows as extractions need methods (YAGNI).
    """

    get_function_entry_ea: Callable[..., Any]
    get_mba_maturity: Callable[..., Any]
    # Block-count + block-adjacency seams keep the reachability BFS in portable
    # code: the backend returns the live ``mba.qty`` block count and a portable
    # ``{serial: (successor_serial, ...)}`` map (omitting serials whose block is
    # ``None``), so the BFS that consumes them never calls the live-MBA method
    # API (``qty``/``get_mblock``/``nsucc``/``succ``) directly.
    get_block_count: Callable[..., Any]
    block_adjacency: Callable[..., Any]
    # GLBOPT1 maturity gate seams.  ``is_glbopt1`` answers the ``mba.maturity ==
    # ida_hexrays.MMAT_GLBOPT1`` predicate; ``glbopt1_maturity`` returns the raw
    # ``MMAT_GLBOPT1`` constant for callers that pass it as an allowed-maturity
    # value rather than testing it.  ``mmat_zero`` returns the raw ``MMAT_ZERO``
    # constant used as the ``getattr(mba, "maturity", <default>)`` fallback when
    # a caller must stay byte-identical for an opaque object missing ``maturity``.
    is_glbopt1: Callable[..., Any]
    glbopt1_maturity: Callable[..., Any]
    mmat_zero: Callable[..., Any]


_lock = threading.Lock()
_bst_walkers: Optional[BstWalkerProvider] = None
_microcode_evidence: Optional[MicrocodeEvidenceProvider] = None


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


def register_microcode_evidence(provider: MicrocodeEvidenceProvider) -> None:
    """Register the backend microcode-evidence provider (composition root only)."""
    global _microcode_evidence
    with _lock:
        _microcode_evidence = provider


def get_microcode_evidence() -> MicrocodeEvidenceProvider:
    """Return the registered microcode-evidence provider.

    Raises:
        LookupError: if no provider is registered -- the portable extraction REQUIRES this
            seam on the live path, so a missing provider is a composition-root wiring bug
            (fail loud), not an optional miss.
    """
    with _lock:
        provider = _microcode_evidence
    if provider is None:
        raise LookupError(
            "MicrocodeEvidenceProvider not registered: the composition root "
            "(D810State.start_d810) must call register_microcode_evidence() before "
            "portable analyses/transforms read live microcode evidence."
        )
    return provider


def reset_providers_for_tests() -> None:
    """Clear all registered providers (test isolation)."""
    global _bst_walkers, _microcode_evidence
    with _lock:
        _bst_walkers = None
        _microcode_evidence = None
