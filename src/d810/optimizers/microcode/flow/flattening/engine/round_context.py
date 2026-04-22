"""Hierarchical execution-scope stack for the unflattening engine.

``RoundContext`` replaces a flat ``round_number`` counter with a stack of
:class:`RoundFrame` records so pipeline code can both ask "what round am I
in?" and show a human-readable breadcrumb of how we got there — useful for
guardrails, log correlation, and future engine introspection.

A frame describes one scope boundary crossed on the way down the call chain:
the pass that produced this snapshot, the strategy whose ``plan()`` is now
executing, the round that strategy is replanning for, optional sub-scopes
that a strategy wants to publish internally. Each frame carries an ``index``
(0-based within its parent scope) and a ``name`` (human label).

The context is frozen; pushing a frame returns a new ``RoundContext``. No
mutation. Strategies never rewrite the incoming snapshot's context — they
build an updated snapshot via ``dataclasses.replace(snapshot, round_context=
snapshot.round_context.push(frame))`` when they want sub-callbacks to see
the deeper scope.

Layer: ``d810.optimizers.microcode.flow.flattening.engine`` — pure-Python
plumbing, unit-testable without IDA.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from d810.core.typing import Mapping


__all__ = ("RoundFrame", "RoundContext", "EMPTY_METADATA")


# Sentinel for "no metadata" so every frozen frame can share the same
# read-only mapping without allocating a fresh dict per construction.
EMPTY_METADATA: Mapping[str, object] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class RoundFrame:
    """One level of execution scope on the round-context stack.

    ``scope`` is a free-form tag conventionally one of ``"pass"``,
    ``"strategy"``, ``"round"``, ``"sub_round"`` — pipeline code can publish
    custom scopes too. ``index`` is the 0-based position within the parent
    scope (e.g. round 0 is the first projected-replan iteration). ``name``
    is the human label for the scope (``"MMAT_GLBOPT1"``, ``"LFG"``,
    ``"projected_replan"``). ``metadata`` is an optional read-only key/value
    bag for any per-frame diagnostic context.
    """

    scope: str
    index: int
    name: str
    metadata: Mapping[str, object] = field(default_factory=lambda: EMPTY_METADATA)


@dataclass(frozen=True, slots=True)
class RoundContext:
    """Stack of :class:`RoundFrame` records.

    Immutable. Equivalent to a pipeline-aware call stack. The empty stack
    means "pass-entry, pre-strategy" — that's the default on a freshly-built
    :class:`AnalysisSnapshot` before any strategy has been invoked.
    """

    frames: tuple[RoundFrame, ...] = ()

    @property
    def current_scope(self) -> str:
        """Return the leaf frame's scope tag, or ``"pass_entry"`` when empty."""
        return self.frames[-1].scope if self.frames else "pass_entry"

    @property
    def depth(self) -> int:
        return len(self.frames)

    @property
    def in_round(self) -> bool:
        """True iff any frame on the stack is a round / sub_round."""
        return any(f.scope in {"round", "sub_round"} for f in self.frames)

    @property
    def round_index(self) -> int:
        """Return the leaf-most round frame's index, or 0 if no round is active.

        Backward-compatible shim for code that used to inspect a flat
        ``round_number`` counter on the snapshot.
        """
        for frame in reversed(self.frames):
            if frame.scope == "round":
                return frame.index
        return 0

    def push(self, frame: RoundFrame) -> "RoundContext":
        """Return a new context with ``frame`` appended to the stack."""
        return RoundContext(frames=self.frames + (frame,))

    def pop(self) -> "RoundContext":
        """Return a new context with the leaf frame removed.

        Raises :exc:`IndexError` when the stack is empty — callers are
        expected to pair ``push``/``pop`` when they manage their own scope
        lifecycle, though the more common pattern is to use
        ``dataclasses.replace`` to build a parent-scoped snapshot for each
        sub-callback rather than pop explicitly.
        """
        if not self.frames:
            raise IndexError("RoundContext: cannot pop from empty stack")
        return RoundContext(frames=self.frames[:-1])

    def as_trace(self) -> str:
        """Format the stack as ``scope[index]:name`` joined by ``" / "``.

        Returns ``"<pass_entry>"`` for an empty stack. Used by guardrails and
        debug logs to show where in the pipeline a given snapshot originated.
        """
        if not self.frames:
            return "<pass_entry>"
        return " / ".join(
            f"{frame.scope}[{frame.index}]:{frame.name}" for frame in self.frames
        )
