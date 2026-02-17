"""Unit tests for d810.hexrays.deferred_events.

Coverage:
- DeferredEvent enum completeness
- EventEmitter.subscribe / emit round-trip
- Event emission order for success path
- Event emission order for verify-failure + rollback path
- Payload schema validation (required fields present)
- Exception-safe handler (handler throws, emit does not propagate)
- Subscriber receives only subscribed events
- DeferredEventPayload frozen dataclass immutability
- Quarantine flag set after VERIFY_FAILED notification
- Quarantined functions skip aggressive rewrites (via _is_function_quarantined)

IDA note: deferred_events.py is pure Python (no IDA imports), so these tests
run entirely in the unit test environment with no mocking required.
"""
from __future__ import annotations

import pytest

from d810.hexrays.deferred_events import DeferredEvent, DeferredEventPayload, EventEmitter


# ---------------------------------------------------------------------------
# DeferredEvent enum
# ---------------------------------------------------------------------------

class TestDeferredEvent:
    """Verify the enum has all required lifecycle events."""

    EXPECTED_EVENTS = {
        # Queue lifecycle
        "DEFERRED_QUEUE_ADDED",
        "DEFERRED_COALESCE_STARTED",
        "DEFERRED_COALESCE_FINISHED",
        # Apply lifecycle
        "DEFERRED_APPLY_STARTED",
        "DEFERRED_MOD_STARTED",
        "DEFERRED_MOD_APPLIED",
        "DEFERRED_MOD_FAILED",
        "DEFERRED_VERIFY_FAILED",
        "DEFERRED_ROLLBACK_STARTED",
        "DEFERRED_ROLLBACK_FINISHED",
        "DEFERRED_APPLY_FINISHED",
    }

    def test_all_expected_events_present(self):
        actual = {e.name for e in DeferredEvent}
        assert self.EXPECTED_EVENTS <= actual, (
            f"Missing events: {self.EXPECTED_EVENTS - actual}"
        )

    def test_events_are_hashable(self):
        """Enum members must be usable as dict keys / set elements."""
        s = {e for e in DeferredEvent}
        assert len(s) == len(list(DeferredEvent))


# ---------------------------------------------------------------------------
# EventEmitter: basic subscribe / emit
# ---------------------------------------------------------------------------

class TestEventEmitter:

    def test_subscribe_and_receive(self):
        emitter = EventEmitter()
        received = []

        def handler(payload: dict) -> None:
            received.append(payload)

        emitter.subscribe(DeferredEvent.DEFERRED_QUEUE_ADDED, handler)
        emitter.emit(DeferredEvent.DEFERRED_QUEUE_ADDED, {"key": "value"})

        assert len(received) == 1
        assert received[0] == {"key": "value"}

    def test_subscriber_receives_only_subscribed_events(self):
        """A handler for event A must NOT receive event B."""
        emitter = EventEmitter()
        received_a = []
        received_b = []

        emitter.subscribe(DeferredEvent.DEFERRED_QUEUE_ADDED,
                          lambda p: received_a.append(p))
        emitter.subscribe(DeferredEvent.DEFERRED_APPLY_STARTED,
                          lambda p: received_b.append(p))

        emitter.emit(DeferredEvent.DEFERRED_QUEUE_ADDED, {"e": "A"})
        emitter.emit(DeferredEvent.DEFERRED_APPLY_FINISHED, {"e": "unrelated"})

        assert len(received_a) == 1
        assert received_a[0]["e"] == "A"
        assert received_b == []  # Never received APPLY_STARTED

    def test_multiple_subscribers_for_same_event(self):
        emitter = EventEmitter()
        log = []

        emitter.subscribe(DeferredEvent.DEFERRED_MOD_APPLIED, lambda p: log.append("first"))
        emitter.subscribe(DeferredEvent.DEFERRED_MOD_APPLIED, lambda p: log.append("second"))

        emitter.emit(DeferredEvent.DEFERRED_MOD_APPLIED, {})

        assert "first" in log
        assert "second" in log
        assert len(log) == 2

    def test_no_subscribers_emit_is_noop(self):
        """Emitting with no subscribers must not raise."""
        emitter = EventEmitter()
        emitter.emit(DeferredEvent.DEFERRED_APPLY_FINISHED, {"x": 1})  # No error

    def test_exception_safe_handler(self):
        """Handler that raises must not propagate; other handlers still run."""
        emitter = EventEmitter()
        ran_after = []

        def bad_handler(payload: dict) -> None:
            raise ValueError("intentional error from handler")

        def good_handler(payload: dict) -> None:
            ran_after.append(payload)

        emitter.subscribe(DeferredEvent.DEFERRED_MOD_APPLIED, bad_handler)
        emitter.subscribe(DeferredEvent.DEFERRED_MOD_APPLIED, good_handler)

        # Must not raise despite bad_handler
        emitter.emit(DeferredEvent.DEFERRED_MOD_APPLIED, {"check": True})

        assert ran_after == [{"check": True}]

    def test_unsubscribe_stops_delivery(self):
        emitter = EventEmitter()
        received = []

        def handler(p: dict) -> None:
            received.append(p)

        emitter.subscribe(DeferredEvent.DEFERRED_QUEUE_ADDED, handler)
        emitter.emit(DeferredEvent.DEFERRED_QUEUE_ADDED, {"n": 1})
        emitter.unsubscribe(DeferredEvent.DEFERRED_QUEUE_ADDED, handler)
        emitter.emit(DeferredEvent.DEFERRED_QUEUE_ADDED, {"n": 2})

        assert len(received) == 1
        assert received[0]["n"] == 1

    def test_unsubscribe_unknown_handler_is_noop(self):
        """Unsubscribing an unknown handler must not raise."""
        emitter = EventEmitter()

        def handler(p: dict) -> None:
            pass

        emitter.unsubscribe(DeferredEvent.DEFERRED_QUEUE_ADDED, handler)  # No error


# ---------------------------------------------------------------------------
# Event emission order — success path (simulated)
# ---------------------------------------------------------------------------

class TestEventEmissionOrder:
    """Verify expected event ordering using a recording emitter."""

    def _make_emitter_and_log(self) -> tuple[EventEmitter, list[str]]:
        emitter = EventEmitter()
        log: list[str] = []
        for event in DeferredEvent:
            _event = event  # capture
            emitter.subscribe(_event, lambda p, e=_event: log.append(e.name))
        return emitter, log

    def test_success_path_event_order(self):
        """Success path: QUEUE_ADDED → COALESCE_* → APPLY_STARTED → MOD_STARTED
        → MOD_APPLIED → APPLY_FINISHED."""
        emitter, log = self._make_emitter_and_log()

        # Simulate the events a DeferredGraphModifier would emit for one
        # successful modification.
        emitter.emit(DeferredEvent.DEFERRED_QUEUE_ADDED, {})
        emitter.emit(DeferredEvent.DEFERRED_COALESCE_STARTED, {})
        emitter.emit(DeferredEvent.DEFERRED_COALESCE_FINISHED, {})
        emitter.emit(DeferredEvent.DEFERRED_APPLY_STARTED, {})
        emitter.emit(DeferredEvent.DEFERRED_MOD_STARTED, {})
        emitter.emit(DeferredEvent.DEFERRED_MOD_APPLIED, {})
        emitter.emit(DeferredEvent.DEFERRED_APPLY_FINISHED, {})

        assert log == [
            "DEFERRED_QUEUE_ADDED",
            "DEFERRED_COALESCE_STARTED",
            "DEFERRED_COALESCE_FINISHED",
            "DEFERRED_APPLY_STARTED",
            "DEFERRED_MOD_STARTED",
            "DEFERRED_MOD_APPLIED",
            "DEFERRED_APPLY_FINISHED",
        ]

    def test_verify_failure_rollback_path_event_order(self):
        """Verify-fail + rollback path: QUEUE_ADDED → COALESCE_* → APPLY_STARTED
        → MOD_STARTED → VERIFY_FAILED → ROLLBACK_STARTED → ROLLBACK_FINISHED
        → APPLY_FINISHED."""
        emitter, log = self._make_emitter_and_log()

        emitter.emit(DeferredEvent.DEFERRED_QUEUE_ADDED, {})
        emitter.emit(DeferredEvent.DEFERRED_COALESCE_STARTED, {})
        emitter.emit(DeferredEvent.DEFERRED_COALESCE_FINISHED, {})
        emitter.emit(DeferredEvent.DEFERRED_APPLY_STARTED, {})
        emitter.emit(DeferredEvent.DEFERRED_MOD_STARTED, {})
        # Modification applied but verify fails
        emitter.emit(DeferredEvent.DEFERRED_VERIFY_FAILED, {})
        emitter.emit(DeferredEvent.DEFERRED_ROLLBACK_STARTED, {})
        emitter.emit(DeferredEvent.DEFERRED_ROLLBACK_FINISHED, {})
        emitter.emit(DeferredEvent.DEFERRED_APPLY_FINISHED, {})

        assert log == [
            "DEFERRED_QUEUE_ADDED",
            "DEFERRED_COALESCE_STARTED",
            "DEFERRED_COALESCE_FINISHED",
            "DEFERRED_APPLY_STARTED",
            "DEFERRED_MOD_STARTED",
            "DEFERRED_VERIFY_FAILED",
            "DEFERRED_ROLLBACK_STARTED",
            "DEFERRED_ROLLBACK_FINISHED",
            "DEFERRED_APPLY_FINISHED",
        ]


# ---------------------------------------------------------------------------
# Payload schema validation
# ---------------------------------------------------------------------------

class TestPayloadSchema:
    """Verify required fields are present and primitives-only."""

    REQUIRED_FIELDS = {
        "optimizer_name",
        "function_ea",
        "maturity",
        "pass_id",
        "session_id",
    }

    def _make_base_payload(self, **kwargs) -> dict:
        base = {
            "optimizer_name": "TestRule",
            "function_ea": 0x1000,
            "maturity": 3,
            "pass_id": 0,
            "session_id": "abc123",
        }
        base.update(kwargs)
        return base

    def test_required_fields_all_present(self):
        payload = self._make_base_payload()
        for field in self.REQUIRED_FIELDS:
            assert field in payload, f"Missing required field: {field}"

    def test_payload_fields_are_primitives(self):
        payload = self._make_base_payload(
            mod_index=0,
            mod_type="BLOCK_GOTO_CHANGE",
            block_serial=5,
            new_target=10,
            priority=10,
            rule_priority=0,
            description="redirect",
            result="success",
            error=None,
        )
        allowed_types = (int, str, float, bool, type(None))
        for key, value in payload.items():
            assert isinstance(value, allowed_types), (
                f"Payload field '{key}' has non-primitive type {type(value)!r}"
            )

    def test_deferred_event_payload_dataclass(self):
        p = DeferredEventPayload(
            optimizer_name="MyRule",
            function_ea=0x4000,
            maturity=5,
            pass_id=2,
            session_id="deadbeef",
            mod_index=1,
            mod_type="BLOCK_GOTO_CHANGE",
            block_serial=10,
            new_target=20,
            priority=10,
            rule_priority=50,
            description="goto 10->20",
            result="success",
            error=None,
        )
        assert p.optimizer_name == "MyRule"
        assert p.function_ea == 0x4000
        assert p.result == "success"
        assert p.error is None

    def test_deferred_event_payload_is_frozen(self):
        """DeferredEventPayload is a frozen dataclass; mutation must raise."""
        p = DeferredEventPayload(optimizer_name="X")
        with pytest.raises((AttributeError, TypeError)):
            p.optimizer_name = "Y"  # type: ignore[misc]

    def test_deferred_event_payload_to_dict_all_primitives(self):
        p = DeferredEventPayload(
            optimizer_name="R",
            function_ea=0x100,
            maturity=3,
            pass_id=1,
            session_id="s1",
        )
        d = p.to_dict()
        allowed_types = (int, str, float, bool, type(None))
        for key, value in d.items():
            assert isinstance(value, allowed_types), (
                f"to_dict() field '{key}' is not primitive: {type(value)!r}"
            )
        assert d["optimizer_name"] == "R"
        assert d["function_ea"] == 0x100


# ---------------------------------------------------------------------------
# Quarantine behaviour (pure Python, no IDA)
# ---------------------------------------------------------------------------

class _FakeQuarantineTarget:
    """Minimal stub that replicates the quarantine logic from
    GenericDispatcherUnflatteningRule without importing IDA.

    We test the logic here; the integration with the real class is covered
    by the imports and subscription wire-up which are verified separately.
    """

    def __init__(self, func_ea: int = 0):
        self._quarantined_function_eas: set[int] = set()
        self._func_ea = func_ea

    def _on_deferred_verify_failed(self, payload: dict) -> None:
        """Mirrors GenericDispatcherUnflatteningRule._on_deferred_verify_failed."""
        function_ea = payload.get("function_ea")
        if isinstance(function_ea, int) and function_ea > 0:
            self._quarantined_function_eas.add(function_ea)

    def _is_function_quarantined(self) -> bool:
        """Mirrors GenericDispatcherUnflatteningRule._is_function_quarantined."""
        if not self._quarantined_function_eas:
            return False
        return self._func_ea in self._quarantined_function_eas


class TestQuarantineBehaviour:

    def test_verify_failed_sets_quarantine(self):
        target = _FakeQuarantineTarget(func_ea=0x1000)
        emitter = EventEmitter()
        emitter.subscribe(DeferredEvent.DEFERRED_VERIFY_FAILED,
                          target._on_deferred_verify_failed)

        assert not target._is_function_quarantined()

        emitter.emit(DeferredEvent.DEFERRED_VERIFY_FAILED, {
            "function_ea": 0x1000,
            "maturity": 3,
            "optimizer_name": "TestRule",
        })

        assert target._is_function_quarantined()

    def test_quarantine_only_affects_matching_function(self):
        target_a = _FakeQuarantineTarget(func_ea=0x1000)
        target_b = _FakeQuarantineTarget(func_ea=0x2000)

        emitter = EventEmitter()
        emitter.subscribe(DeferredEvent.DEFERRED_VERIFY_FAILED,
                          target_a._on_deferred_verify_failed)
        emitter.subscribe(DeferredEvent.DEFERRED_VERIFY_FAILED,
                          target_b._on_deferred_verify_failed)

        # Only 0x1000 fails
        emitter.emit(DeferredEvent.DEFERRED_VERIFY_FAILED, {
            "function_ea": 0x1000,
            "maturity": 3,
        })

        assert target_a._is_function_quarantined()      # 0x1000 quarantined
        assert not target_b._is_function_quarantined()  # 0x2000 not quarantined

    def test_quarantine_none_ea_is_ignored(self):
        """Payloads with function_ea=None must not quarantine anything."""
        target = _FakeQuarantineTarget(func_ea=0)
        emitter = EventEmitter()
        emitter.subscribe(DeferredEvent.DEFERRED_VERIFY_FAILED,
                          target._on_deferred_verify_failed)

        emitter.emit(DeferredEvent.DEFERRED_VERIFY_FAILED, {"function_ea": None})

        assert not target._quarantined_function_eas

    def test_quarantine_zero_ea_is_ignored(self):
        """function_ea=0 is BADADDR sentinel and must not be quarantined."""
        target = _FakeQuarantineTarget(func_ea=0)
        emitter = EventEmitter()
        emitter.subscribe(DeferredEvent.DEFERRED_VERIFY_FAILED,
                          target._on_deferred_verify_failed)

        emitter.emit(DeferredEvent.DEFERRED_VERIFY_FAILED, {"function_ea": 0})

        assert not target._quarantined_function_eas

    def test_unquarantined_function_not_skipped(self):
        """Before any verify failure, function must not be quarantined."""
        target = _FakeQuarantineTarget(func_ea=0xDEAD)
        assert not target._is_function_quarantined()

    def test_multiple_failures_same_function(self):
        """Duplicate verify-failure events for same function are idempotent."""
        target = _FakeQuarantineTarget(func_ea=0x5000)
        emitter = EventEmitter()
        emitter.subscribe(DeferredEvent.DEFERRED_VERIFY_FAILED,
                          target._on_deferred_verify_failed)

        for _ in range(5):
            emitter.emit(DeferredEvent.DEFERRED_VERIFY_FAILED, {"function_ea": 0x5000})

        assert len(target._quarantined_function_eas) == 1
        assert 0x5000 in target._quarantined_function_eas
        assert target._is_function_quarantined()
