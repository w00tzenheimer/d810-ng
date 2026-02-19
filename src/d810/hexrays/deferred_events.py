"""
Deferred Graph Modifier Control Plane Events
============================================

Lifecycle events emitted by :class:`DeferredGraphModifier` to enable
safe, observable CFG modification.

Consumers (e.g. :class:`GenericDispatcherUnflatteningRule`) subscribe to
these events to implement safety policies such as verify-failure quarantine
without coupling tightly to the modifier internals.

Design rules
------------
- All payload fields are **primitives** (int, str, None). No live IDA objects.
- Handler exceptions are **logged but never propagated** so a buggy subscriber
  can never crash the optimizer.
- When ``event_emitter is None`` there is **zero overhead**: no payload dict
  is constructed and no emit calls are made.

Usage
-----

Producer (inside DeferredGraphModifier)::

    from d810.hexrays.deferred_events import DeferredEvent, EventEmitter

    emitter = EventEmitter()
    emitter.emit(DeferredEvent.DEFERRED_QUEUE_ADDED, {
        "optimizer_name": "MyRule",
        "function_ea": 0x1000,
        "maturity": 3,
        "pass_id": 0,
        "session_id": "abc123",
        "mod_type": "BLOCK_GOTO_CHANGE",
        "block_serial": 5,
        "new_target": 10,
        "priority": 10,
        "description": "redirect",
    })

Consumer (inside GenericDispatcherUnflatteningRule)::

    from d810.hexrays.deferred_events import DeferredEvent

    def _on_verify_failed(payload: dict) -> None:
        function_ea = payload.get("function_ea")
        self._quarantine_function_ea(function_ea)

    emitter.subscribe(DeferredEvent.DEFERRED_VERIFY_FAILED, _on_verify_failed)
"""
from __future__ import annotations

from d810.core.logging import getLogger
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from d810.core.typing import Callable

_logger = getLogger("D810.deferred_events")


class DeferredEvent(Enum):
    """Lifecycle events emitted by DeferredGraphModifier.

    Queue/coalesce lifecycle
    ------------------------
    DEFERRED_QUEUE_ADDED
        Emitted each time a modification is added to the queue via a
        ``queue_*`` method.

    DEFERRED_COALESCE_STARTED
        Emitted at the start of the coalesce pass (before deduplication).

    DEFERRED_COALESCE_FINISHED
        Emitted after the coalesce pass completes.

    Apply lifecycle
    ---------------
    DEFERRED_APPLY_STARTED
        Emitted when ``apply()`` begins (after coalesce, before iteration).

    DEFERRED_MOD_STARTED
        Emitted immediately before each individual modification is applied.

    DEFERRED_MOD_APPLIED
        Emitted after a modification succeeds (``_apply_single`` returned True).

    DEFERRED_MOD_FAILED
        Emitted after a modification fails (``_apply_single`` returned False or
        raised an exception).

    DEFERRED_VERIFY_FAILED
        Emitted when ``safe_verify`` raises RuntimeError after a modification
        (incremental verify) or after the full batch (post-apply verify).

    DEFERRED_ROLLBACK_STARTED
        Emitted when a rollback closure is about to execute.

    DEFERRED_ROLLBACK_FINISHED
        Emitted after a rollback attempt completes (success or failure).

    DEFERRED_APPLY_FINISHED
        Emitted at the very end of ``apply()``, regardless of outcome.
    """

    # Queue/coalesce lifecycle
    DEFERRED_QUEUE_ADDED = auto()
    DEFERRED_COALESCE_STARTED = auto()
    DEFERRED_COALESCE_FINISHED = auto()

    # Apply lifecycle
    DEFERRED_APPLY_STARTED = auto()
    DEFERRED_MOD_STARTED = auto()
    DEFERRED_MOD_APPLIED = auto()
    DEFERRED_MOD_FAILED = auto()
    DEFERRED_VERIFY_FAILED = auto()
    DEFERRED_ROLLBACK_STARTED = auto()
    DEFERRED_ROLLBACK_FINISHED = auto()
    DEFERRED_APPLY_FINISHED = auto()


@dataclass(frozen=True)
class DeferredEventPayload:
    """Snapshot payload carried by a DeferredEvent.

    All fields are **primitives** - ints, strings, or None. No live IDA
    pointers or objects are ever stored here.

    Required fields (present on all events)
    ----------------------------------------
    optimizer_name : str
        Name of the optimizer/rule that owns the modifier.
    function_ea : int | None
        Entry address of the function being decompiled. None when unknown.
    maturity : int | None
        Current ``mba_t.maturity`` value. None when not yet available.
    pass_id : int
        Maturity-relative pass counter (``cur_maturity_pass``).
    session_id : str
        Opaque identifier for one modifier ``apply()`` cycle (uuid4 hex).

    Modification-specific fields (set on MOD_* events, else None)
    --------------------------------------------------------------
    mod_index : int | None
        Zero-based index of the modification in the sorted apply list.
    mod_type : str | None
        ``ModificationType.name`` string.
    block_serial : int | None
        Serial of the source block being modified.
    new_target : int | None
        New target block serial (nullable for insn-level operations).
    priority : int | None
        Modification sort priority (lower = applied earlier).
    rule_priority : int | None
        Conflict-resolution priority.
    description : str | None
        Human-readable modification description.

    Outcome fields (set on APPLIED/FAILED/VERIFY_FAILED events)
    ------------------------------------------------------------
    result : str | None
        One of: ``"success"``, ``"failed"``, ``"verify_failed"``,
        ``"rolled_back"``, ``"skipped"``.
    error : str | None
        Error or exception message (nullable).
    """

    # Required - all events
    optimizer_name: str = ""
    function_ea: int | None = None
    maturity: int | None = None
    pass_id: int = 0
    session_id: str = ""

    # Modification-specific - MOD_* events
    mod_index: int | None = None
    mod_type: str | None = None
    block_serial: int | None = None
    new_target: int | None = None
    priority: int | None = None
    rule_priority: int | None = None
    description: str | None = None

    # Outcome
    result: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        """Return a plain dict representation (all primitive values)."""
        return {
            "optimizer_name": self.optimizer_name,
            "function_ea": self.function_ea,
            "maturity": self.maturity,
            "pass_id": self.pass_id,
            "session_id": self.session_id,
            "mod_index": self.mod_index,
            "mod_type": self.mod_type,
            "block_serial": self.block_serial,
            "new_target": self.new_target,
            "priority": self.priority,
            "rule_priority": self.rule_priority,
            "description": self.description,
            "result": self.result,
            "error": self.error,
        }


@dataclass
class EventEmitter:
    """Simple observer/pub-sub for :class:`DeferredEvent` notifications.

    Handlers registered via :meth:`subscribe` receive a single positional
    argument: the :class:`DeferredEventPayload` dict.

    Exception safety
    ----------------
    Handler exceptions are **caught, logged, and swallowed**. A buggy
    subscriber can never crash the optimizer or change its behaviour.

    Thread safety
    -------------
    Not thread-safe by design (IDA plugins run single-threaded).

    Example::

        emitter = EventEmitter()

        def on_verify_failed(payload: dict) -> None:
            print("verify failed for", payload.get("function_ea"))

        emitter.subscribe(DeferredEvent.DEFERRED_VERIFY_FAILED, on_verify_failed)
        emitter.emit(DeferredEvent.DEFERRED_VERIFY_FAILED, {"function_ea": 0x1000, ...})
    """

    _handlers: dict[DeferredEvent, list[Callable[[dict], None]]] = field(
        default_factory=lambda: defaultdict(list),
        init=False,
        repr=False,
    )

    def subscribe(
        self,
        event: DeferredEvent,
        callback: Callable[[dict], None],
    ) -> None:
        """Register *callback* to be called when *event* is emitted.

        Args:
            event: The lifecycle event to subscribe to.
            callback: Callable that receives a single payload ``dict``.
        """
        self._handlers[event].append(callback)

    def unsubscribe(
        self,
        event: DeferredEvent,
        callback: Callable[[dict], None],
    ) -> None:
        """Remove a previously registered callback.

        No-op if the callback was never registered.
        """
        handlers = self._handlers.get(event)
        if handlers and callback in handlers:
            handlers.remove(callback)

    def emit(self, event: DeferredEvent, payload: dict) -> None:
        """Dispatch *payload* to all subscribers for *event*.

        Handler exceptions are caught and logged - never propagated.

        Args:
            event: The lifecycle event being fired.
            payload: Plain dict of primitive values (the event data).
        """
        handlers = self._handlers.get(event)
        if not handlers:
            return
        for handler in handlers:
            try:
                handler(payload)
            except Exception as exc:
                _logger.exception(
                    "EventEmitter: handler %r raised for event %s: %s",
                    handler,
                    event.name,
                    exc,
                )
