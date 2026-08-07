"""Re-prove starved candidates off the critical path.

The inline budget (``INLINE_TIMEOUT_MS``, 500ms) settles most proofs but not
all: measured on VM_DecryptPacket, 98% of total proof time sat in 4 of 14
proofs, with the worst at 93.6 seconds.  Those four are exactly what this
module absorbs -- they are re-proved at ``DEFAULT_TIMEOUT_MS`` on a worker
thread and written into the table, so the next decompile gets them as a hit.

Why a thread is safe here
-------------------------
IDA's API is not thread-safe, and this worker never touches it.  ``expr``,
``prove`` and ``table`` carry no IDA dependency, and candidate trees are plain
dicts built from ``MopSnapshot`` rather than borrowed ``mop_t``.  The worker
therefore operates entirely on data that has already been copied out of
Hex-Rays.

A thread is used rather than draining at a quiescent point because there is no
reliable quiescent point: the GUI re-decompiles in the background after a
reload, so "nothing in flight" cannot be assumed.

Nothing in here may raise into a decompilation.  A submission before ``start``
is a no-op, and a prover that throws is logged and skipped rather than allowed
to kill the worker and silently end all future escalation.
"""

from __future__ import annotations

import queue
import threading

from d810.backends.cobra.prove import (
    DEFAULT_TIMEOUT_MS,
    ProofResult,
    prove_equivalent,
)
from d810.backends.cobra.table import RewriteTable
from d810.core import getLogger
from d810.core.typing import Any, Callable, Sequence

logger = getLogger(__name__)

#: Bound the backlog. A decompile can enqueue faster than z3 drains, and an
#: unbounded queue would turn that into unbounded memory.
DEFAULT_MAX_QUEUE = 512


class EscalationProver:
    """Worker that re-proves starved candidates and records the verdict."""

    def __init__(
        self,
        table: RewriteTable,
        *,
        prover: Callable[..., ProofResult] = prove_equivalent,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        max_queue: int = DEFAULT_MAX_QUEUE,
    ) -> None:
        self._table = table
        self._prover = prover
        self._timeout_ms = timeout_ms
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._ctx = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stopping.clear()
        self._thread = threading.Thread(
            target=self._run, name="cobra-escalate", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the worker. Safe to call twice, and safe if never started."""
        if self._thread is None:
            return
        self._stopping.set()
        self._queue.put(None)
        self._thread.join(timeout)
        self._thread = None

    def drain(self, timeout: float = 30.0) -> None:
        """Block until the queue is empty. For tests and shutdown only."""
        self._queue.join()

    # -- submission --------------------------------------------------------

    def submit(
        self,
        original: dict,
        bitwidth: int,
        rewrite: dict,
        leaf_names: Sequence[str],
    ) -> None:
        """Queue a candidate for re-proof, marking it PENDING immediately.

        Marking PENDING before enqueueing is what stops the live rule from
        re-submitting the same candidate on every visit; without it the queue
        grows without bound on a hot expression.
        """
        if self._thread is None:
            return
        entry = self._table.lookup(original, bitwidth)
        if entry is not None:
            return
        self._table.record_pending(original, bitwidth)
        try:
            self._queue.put_nowait((original, bitwidth, rewrite, tuple(leaf_names)))
        except queue.Full:
            logger.debug("cobra escalation queue full; dropping %d-leaf candidate",
                         len(leaf_names))

    # -- worker ------------------------------------------------------------

    def _run(self) -> None:
        # Own z3 context, created ON this thread. z3 terms belong to a context
        # and a context is not thread-safe; sharing the default one with the
        # rule's inline proof raises "Z3Exception: context mismatch", which
        # inside IDA escapes into the Hex-Rays C++ callback as SIGSEGV.
        # Measured: EXIT=139 after two applications.
        try:
            import z3

            self._ctx = z3.Context()
        except ImportError:
            self._ctx = None
        while not self._stopping.is_set():
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                break
            try:
                self._prove_one(*item)
            except Exception:  # noqa: BLE001 - one bad candidate must not
                # end escalation for the rest of the session.
                logger.exception("cobra escalation failed for a candidate")
            finally:
                self._queue.task_done()

    def _prove_one(
        self,
        original: dict,
        bitwidth: int,
        rewrite: dict,
        leaf_names: tuple[str, ...],
    ) -> None:
        kwargs = {"timeout_ms": self._timeout_ms}
        ctx = getattr(self, "_ctx", None)
        if ctx is not None:
            kwargs["ctx"] = ctx
        verdict = self._prover(
            original,
            rewrite,
            list(leaf_names),
            bitwidth,
            **kwargs,
        )
        if getattr(verdict, "value", None) == ProofResult.PROVED.value:
            self._table.record_proved(original, bitwidth, rewrite)
            return
        # REFUTED and UNKNOWN both settle to NO_REWRITE. UNKNOWN here means the
        # generous budget also gave up, so re-queueing it every decompile would
        # never converge -- record it and stop asking.
        self._table.record_no_rewrite(original, bitwidth)


__all__ = ["DEFAULT_MAX_QUEUE", "EscalationProver"]
