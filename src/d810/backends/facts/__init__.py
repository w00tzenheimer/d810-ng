"""Backend fact-evidence adapters.

Vendor-specific implementations of the portable fact capabilities defined under
``d810.capabilities`` (Landing Sequence LS10).  The Hex-Rays adapter lives in
``d810.backends.facts.ida`` and registers a live :class:`SourceLifter` at import
time.

This package ``__init__`` is intentionally import-light (no ``ida`` submodule
import) so ``import d810.backends.facts`` stays importable without IDA; the
IDA-bound adapter is loaded explicitly via ``import d810.backends.facts.ida``
(done lazily by the composition root in ``D810State.start_d810`` /
``Manager.start``).
"""
