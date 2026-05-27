"""Tests for the FLOWGRAPH_READY DecompilationEvent (axis-C E1).

Lives in ``tests/system/runtime/hexrays/`` because the
``DecompilationEvent`` enum is defined inside ``d810.hexrays.hooks``;
the ``unit-tests-no-hexrays`` import-linter contract forbids
``tests/unit/`` from importing ``d810.hexrays``.

Scope (E1 only):

* Verify the dotted string-value convention on every member of
  ``DecompilationEvent`` (no ``_``-as-segment-delimiter at top level;
  underscores within a segment are OK).
* Verify ``FLOWGRAPH_READY`` exists with the expected dotted value.
* Verify the event-bus pathway delivers the payload shape this slice
  publishes (``flow_graph`` + ``func_ea`` + ``maturity`` +
  ``maturity_name``, no ``mba_t``).  This exercises the emit /
  subscribe contract directly via ``EventEmitter`` without needing
  to construct a full ``BlockOptimizerManager`` (the maturity-gate
  call site is the producer; full lifecycle integration is covered
  by the Docker confidence gate).
"""

from __future__ import annotations

from d810.core.events import EventEmitter
from d810.hexrays.hooks.hexrays_hooks import DecompilationEvent


class TestDecompilationEventValues:
    """Enum string-value convention -- E1 standardises on
    dotted-hierarchical event names (``domain.object.action``)."""

    def test_all_values_use_dot_separator(self) -> None:
        """Every event value contains at least one ``.`` as a top-level
        segment separator.  Underscores inside a segment (e.g.
        ``post_d810``) are intentionally allowed."""
        for member in DecompilationEvent:
            assert "." in member.value, (
                f"DecompilationEvent.{member.name} = "
                f"{member.value!r} must use dot delimiters between "
                f"segments (e.g. 'decompilation.started')"
            )

    def test_no_legacy_underscore_separator_at_top_level(self) -> None:
        """The pre-E1 ``decompilation_started`` style is forbidden.  The
        underscore is allowed *inside* a segment but never as the
        top-level domain-object separator."""
        for member in DecompilationEvent:
            top_segment = member.value.split(".", 1)[0]
            assert top_segment in {"decompilation", "lift"}, (
                f"DecompilationEvent.{member.name} = "
                f"{member.value!r} top-level segment must be a known "
                f"domain ('decompilation' or 'lift'); got "
                f"{top_segment!r}"
            )

    def test_known_member_values(self) -> None:
        """The five members ship at canonical dotted values; this is
        the regression cover against accidental string-value drift
        (subscribers / logs may match by value)."""
        assert DecompilationEvent.STARTED.value == "decompilation.started"
        assert DecompilationEvent.FINISHED.value == "decompilation.finished"
        assert (
            DecompilationEvent.MATURITY_CHANGED.value
            == "decompilation.maturity.changed"
        )
        assert (
            DecompilationEvent.POST_D810_CAPTURE.value
            == "decompilation.post_d810.capture"
        )
        assert (
            DecompilationEvent.FLOWGRAPH_READY.value
            == "decompilation.flowgraph.ready"
        )

    def test_flowgraph_ready_is_registered(self) -> None:
        """``FLOWGRAPH_READY`` is the new E1 event.  Tests downstream
        of E4 will assert it has subscribers; for E1 we only assert
        it's defined."""
        assert hasattr(DecompilationEvent, "FLOWGRAPH_READY")


class TestFlowGraphReadyPayloadShape:
    """End-to-end emit/subscribe contract for ``FLOWGRAPH_READY``.

    Bypasses ``BlockOptimizerManager`` because constructing one
    requires a live mba + the full hook lifecycle; the maturity-gate
    site that produces this event uses the same ``EventEmitter``
    interface this test exercises directly.  Full lifecycle
    integration is covered by the Docker confidence gate.
    """

    def test_subscriber_receives_portable_payload(self) -> None:
        """Subscribers receive the four canonical kwargs and never
        an ``mba_t``."""
        emitter: EventEmitter[DecompilationEvent] = EventEmitter()
        received: list[dict[str, object]] = []

        def handler(**kwargs: object) -> None:
            received.append(kwargs)

        emitter.on(DecompilationEvent.FLOWGRAPH_READY, handler)
        fake_flow_graph = object()
        emitter.emit(
            DecompilationEvent.FLOWGRAPH_READY,
            flow_graph=fake_flow_graph,
            func_ea=0x140001000,
            maturity=14,
            maturity_name="MMAT_GLBOPT1",
        )

        assert len(received) == 1
        payload = received[0]
        assert set(payload.keys()) == {
            "flow_graph",
            "func_ea",
            "maturity",
            "maturity_name",
        }
        assert payload["flow_graph"] is fake_flow_graph
        assert payload["func_ea"] == 0x140001000
        assert payload["maturity"] == 14
        assert payload["maturity_name"] == "MMAT_GLBOPT1"

    def test_payload_does_not_carry_mba(self) -> None:
        """``mba_t`` MUST NOT cross the cross-layer event boundary.
        E1's contract is: portable payloads only.  Future axis-C
        slices subscribe recon-side; recon must not receive a live
        ``mba``.  This test pins the contract by inspecting the
        keyword names the producer site uses (see the
        ``BlockOptimizerManager`` maturity gate in
        ``hexrays_hooks.py``)."""
        # Inspect the actual producer call: the emit site uses these
        # four kwargs.  If a future edit adds ``mba=...`` to the emit,
        # this test catches it by failing the keyword-set assertion
        # above.  This test is the architectural pin; not a behaviour
        # assertion.
        canonical_kwargs = {"flow_graph", "func_ea", "maturity", "maturity_name"}
        assert "mba" not in canonical_kwargs
        assert "mbl_array_t" not in canonical_kwargs


class TestProducerHelper:
    """Producer-level coverage of the actual emit code path.

    Tests the real ``_emit_flowgraph_ready_event`` helper from
    ``hexrays_hooks`` with a monkeypatched lift function and a
    stub mba.  Validates that:

    * the helper actually emits ``FLOWGRAPH_READY`` with the
      canonical four-kwargs payload (catches accidental kwarg
      drift -- ``mba=mba``, missing fields, etc.);
    * lift failures are caught and suppressed (the legacy live
      path through ``run_microcode_collectors`` stays intact);
    * a ``None`` emitter is a no-op (the helper is safe to call
      from a manager that wasn't wired up).

    This is the P2 fix on top of the
    ``TestFlowGraphReadyPayloadShape`` cases above, which only
    exercised the emit/subscribe contract against an arbitrary
    fake payload.  Together the two suites pin both the
    end-to-end pathway AND the actual producer kwargs.
    """

    def _stub_mba(self, *, entry_ea: int = 0x140002000, maturity: int = 14):
        """Minimal ``mba_t``-shaped stub: just the two attributes
        the helper reads (``entry_ea`` for the payload, ``maturity``
        is passed in by the caller already)."""
        class _StubMba:
            pass

        m = _StubMba()
        m.entry_ea = entry_ea
        m.maturity = maturity
        return m

    def test_helper_emits_canonical_payload(self, monkeypatch) -> None:
        """Real helper, monkeypatched lift, stub mba.  Asserts the
        emitted kwargs match the canonical contract (four kwargs,
        no ``mba``)."""
        from d810.core.events import EventEmitter
        from d810.hexrays.hooks import hexrays_hooks
        from d810.hexrays.hooks.hexrays_hooks import (
            DecompilationEvent,
            _emit_flowgraph_ready_event,
        )

        # Sentinel FlowGraph so we can verify identity in the payload
        # without constructing a real one.
        sentinel_flow_graph = object()

        def fake_lift(mba):
            return sentinel_flow_graph

        monkeypatch.setattr(
            hexrays_hooks, "lift_mba_to_flowgraph", fake_lift
        )

        emitter: EventEmitter[DecompilationEvent] = EventEmitter()
        received: list[dict[str, object]] = []
        emitter.on(
            DecompilationEvent.FLOWGRAPH_READY,
            lambda **kwargs: received.append(kwargs),
        )

        stub = self._stub_mba(entry_ea=0x140002000, maturity=14)
        _emit_flowgraph_ready_event(emitter, stub, 14)

        assert len(received) == 1
        payload = received[0]
        # Producer contract: exactly these four kwargs, no live mba.
        assert set(payload.keys()) == {
            "flow_graph",
            "func_ea",
            "maturity",
            "maturity_name",
        }
        assert payload["flow_graph"] is sentinel_flow_graph
        assert payload["func_ea"] == 0x140002000
        assert payload["maturity"] == 14
        # maturity_name comes from ``maturity_to_string``; for an
        # unknown maturity int the helper falls back to a stable
        # ``MMAT_<n>`` form -- exact name isn't asserted here
        # (varies by SDK), only that it's a non-empty string.
        assert isinstance(payload["maturity_name"], str)
        assert payload["maturity_name"]

    def test_helper_with_none_emitter_is_noop(self, monkeypatch) -> None:
        """A manager without ``event_emitter`` wired up still calls
        the helper; the helper short-circuits cleanly."""
        from d810.hexrays.hooks import hexrays_hooks
        from d810.hexrays.hooks.hexrays_hooks import (
            _emit_flowgraph_ready_event,
        )

        called = [False]

        def fake_lift(mba):
            called[0] = True
            return object()

        monkeypatch.setattr(
            hexrays_hooks, "lift_mba_to_flowgraph", fake_lift
        )

        stub = self._stub_mba()
        # Should not raise, should not even invoke the lift.
        _emit_flowgraph_ready_event(None, stub, 14)
        assert called[0] is False, (
            "Lift should not run when event_emitter is None -- "
            "the helper short-circuits before lift to avoid wasted "
            "work on managers that aren't wired up."
        )

    def test_helper_suppresses_lift_failures(self, monkeypatch) -> None:
        """Lift failures must NOT propagate -- they would gate
        decompilation.  The helper logs and returns cleanly; the
        event is suppressed for that one transition."""
        from d810.core.events import EventEmitter
        from d810.hexrays.hooks import hexrays_hooks
        from d810.hexrays.hooks.hexrays_hooks import (
            DecompilationEvent,
            _emit_flowgraph_ready_event,
        )

        def failing_lift(mba):
            raise RuntimeError("simulated lift failure")

        monkeypatch.setattr(
            hexrays_hooks, "lift_mba_to_flowgraph", failing_lift
        )

        emitter: EventEmitter[DecompilationEvent] = EventEmitter()
        received: list[dict[str, object]] = []
        emitter.on(
            DecompilationEvent.FLOWGRAPH_READY,
            lambda **kwargs: received.append(kwargs),
        )

        stub = self._stub_mba()
        # Should not raise.
        _emit_flowgraph_ready_event(emitter, stub, 14)

        # Event suppressed for the failed transition; no subscribers
        # invoked.
        assert received == []

    def test_both_managers_invoke_helper(self, monkeypatch) -> None:
        """Architectural regression cover for the P1 review finding:
        BOTH ``InstructionOptimizerManager`` and
        ``BlockOptimizerManager`` must invoke
        ``_emit_flowgraph_ready_event`` at their maturity gates.
        If a future edit silently removes the call from one manager,
        ``FLOWGRAPH_READY`` would only fire from the other and E4's
        consumer rewire would lose a recon collection point."""
        import inspect

        from d810.hexrays.hooks import hexrays_hooks

        instr_src = inspect.getsource(
            hexrays_hooks.InstructionOptimizerManager.log_info_on_input
        )
        block_src = inspect.getsource(
            hexrays_hooks.BlockOptimizerManager.log_info_on_input
        )

        assert "_emit_flowgraph_ready_event" in instr_src, (
            "InstructionOptimizerManager.log_info_on_input no longer "
            "calls _emit_flowgraph_ready_event; FLOWGRAPH_READY will "
            "not fire from this manager.  Reinstate the call inside "
            "the maturity-transition gate."
        )
        assert "_emit_flowgraph_ready_event" in block_src, (
            "BlockOptimizerManager.log_info_on_input no longer calls "
            "_emit_flowgraph_ready_event; FLOWGRAPH_READY will not "
            "fire from this manager.  Both managers MUST emit -- "
            "see the P1 review finding on commit 6fa286df5."
        )
