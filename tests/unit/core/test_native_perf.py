"""Unit contracts for the opt-in native performance registry."""

from __future__ import annotations

import json

import pytest

from d810.core import native_perf


@pytest.fixture(autouse=True)
def isolated_native_perf_registry():
    """Keep provider registration local to each registry contract test."""
    native_perf.clear_providers_for_tests()
    native_perf.configure(False)
    yield
    native_perf.clear_providers_for_tests()
    native_perf.configure(False)


def test_provider_configuration_reset_and_snapshot_are_explicit():
    events: list[tuple[str, object]] = []
    native_perf.register_provider(
        "zeta",
        snapshot=lambda: {"backend": "test", "counters": {"calls": 3}},
        configure=lambda enabled: events.append(("configure", enabled)),
        reset=lambda: events.append(("reset", None)),
    )

    assert native_perf.configure(True) is True
    native_perf.reset()

    assert events == [("configure", False), ("configure", True), ("reset", None)]
    assert native_perf.snapshot() == {
        "schema_version": 1,
        "enabled": True,
        "backend": "test",
        "provider_names": ["zeta"],
        "provider_identities": {
            "zeta": {
                "backend": "test",
                "counter_domain": "unknown",
                "provider_version": None,
            }
        },
        "session_generation": 1,
        "session": {},
        "lifecycle_depth": 0,
        "lifecycle_errors": [],
        "clock": {
            "native_source": "std::chrono::steady_clock",
            "python_source": "time.perf_counter_ns",
            "unit": "ns",
            "monotonic": True,
            "read_counter": "counters.clock_reads",
        },
        "cython_profile_requested": False,
        "complete": True,
        "provider_errors": {},
        "providers": {
            "zeta": {"backend": "test", "counters": {"calls": 3}},
        },
    }


def test_environment_flag_disables_provider_work_and_receipt():
    events: list[bool] = []
    native_perf.register_provider(
        "alpha",
        snapshot=lambda: {"backend": "test", "counters": {}},
        configure=events.append,
    )

    assert native_perf.configure_from_env({}) is False
    assert events == [False, False]
    assert native_perf.enabled() is False
    assert native_perf.receipt_line() is None


def test_enabled_receipt_has_deterministic_json_schema(monkeypatch):
    monkeypatch.setenv("D810_NATIVE_PERF", "1")
    monkeypatch.delenv("D810_CYTHON_PROFILE", raising=False)
    native_perf.register_provider(
        "beta",
        snapshot=lambda: {"backend": "test", "counters": {"hits": 2}},
    )

    assert native_perf.configure_from_env() is True
    expected = {
        "schema_version": 1,
        "enabled": True,
        "backend": "test",
        "provider_names": ["beta"],
        "provider_identities": {
            "beta": {
                "backend": "test",
                "counter_domain": "unknown",
                "provider_version": None,
            }
        },
        "session_generation": 0,
        "session": {},
        "lifecycle_depth": 0,
        "lifecycle_errors": [],
        "clock": {
            "native_source": "std::chrono::steady_clock",
            "python_source": "time.perf_counter_ns",
            "unit": "ns",
            "monotonic": True,
            "read_counter": "counters.clock_reads",
        },
        "cython_profile_requested": False,
        "complete": True,
        "provider_errors": {},
        "providers": {
            "beta": {"backend": "test", "counters": {"hits": 2}},
        },
    }
    line = native_perf.receipt_line()
    assert line is not None
    prefix, payload = line.split("=", 1)
    assert prefix == "D810_NATIVE_PERF_RECEIPT"
    assert json.loads(payload) == expected
    assert payload == json.dumps(expected, sort_keys=True, separators=(",", ":"))


def test_duplicate_provider_registration_replaces_callbacks_deterministically():
    native_perf.register_provider(
        "same",
        snapshot=lambda: {"backend": "first", "counters": {}},
    )
    native_perf.register_provider(
        "same",
        snapshot=lambda: {"backend": "second", "counters": {}},
    )

    assert native_perf.snapshot()["providers"]["same"]["backend"] == "second"


def test_provider_replacement_retires_previous_hot_path_callback():
    events: list[tuple[str, bool]] = []
    native_perf.register_provider(
        "same",
        snapshot=lambda: {"backend": "first", "counters": {}},
        configure=lambda enabled: events.append(("first", enabled)),
    )
    native_perf.configure(True)
    native_perf.register_provider(
        "same",
        snapshot=lambda: {"backend": "second", "counters": {}},
        configure=lambda enabled: events.append(("second", enabled)),
    )

    assert ("first", False) in events
    assert events[-1] == ("second", True)


def test_failed_provider_retirement_remains_visible_after_successor_installation():
    retired = {"enabled": False}

    def first_configure(enabled: bool) -> None:
        if enabled:
            retired["enabled"] = True
        elif retired["enabled"]:
            raise RuntimeError("retirement boom")

    native_perf.register_provider(
        "same",
        snapshot=lambda: {"backend": "first", "counters": {}},
        configure=first_configure,
    )
    native_perf.configure(True)
    native_perf.register_provider(
        "same",
        snapshot=lambda: {"backend": "second", "counters": {}},
        configure=lambda _enabled: None,
    )

    report = native_perf.snapshot()
    assert report["providers"]["same"]["backend"] == "second"
    assert report["complete"] is False
    assert "retire" in report["provider_errors"]["same"]


def test_provider_callback_failures_are_reported_without_aborting_receipt():
    def fail(_enabled: bool) -> None:
        raise RuntimeError("provider boom")

    native_perf.register_provider(
        "broken",
        snapshot=lambda: {"backend": "test", "counters": {}},
        configure=fail,
    )

    native_perf.configure(True)
    report = native_perf.snapshot()
    assert report["complete"] is False
    assert "broken" in report["provider_errors"]


def test_provider_errors_stay_sticky_until_next_outer_session():
    fail_once = {"enabled": True}

    def configure(enabled: bool) -> None:
        if enabled and fail_once["enabled"]:
            fail_once["enabled"] = False
            raise RuntimeError("configure once")

    native_perf.register_provider(
        "sticky",
        snapshot=lambda: {"backend": "test", "counters": {}},
        configure=configure,
    )
    native_perf.begin_session({"session_id": "current"})
    native_perf.configure(True)
    native_perf.configure(True)
    native_perf.reset()

    current = native_perf.snapshot()
    assert current["complete"] is False
    assert "configure" in current["provider_errors"]["sticky"]
    receipt = native_perf.end_session("current")
    assert receipt is not None
    assert json.loads(receipt.split("=", 1)[1])["complete"] is False

    native_perf.begin_session({"session_id": "next"})
    assert native_perf.snapshot()["complete"] is True
    assert native_perf.snapshot()["provider_errors"] == {}
    native_perf.end_session("next")


def test_reset_errors_stay_sticky_until_next_outer_session():
    fail_once = {"reset": True}

    def reset() -> None:
        if fail_once["reset"]:
            fail_once["reset"] = False
            raise RuntimeError("reset once")

    native_perf.register_provider(
        "reset-sticky",
        snapshot=lambda: {"backend": "test", "counters": {}},
        reset=reset,
    )
    native_perf.configure(True)
    native_perf.begin_session({"session_id": "current"})
    native_perf.reset()
    native_perf.reset()

    assert native_perf.snapshot()["complete"] is False
    assert "reset" in native_perf.snapshot()["provider_errors"]["reset-sticky"]
    native_perf.end_session("current")

    native_perf.begin_session({"session_id": "next"})
    assert native_perf.snapshot()["complete"] is True
    native_perf.end_session("next")


def test_required_provider_validation_reports_missing_provider_explicitly():
    native_perf.configure(True)

    native_perf.require_providers(("ast_types", "pattern_match"))

    report = native_perf.snapshot()
    assert report["complete"] is False
    assert report["provider_errors"]["required"] == (
        "missing required providers: ast_types, pattern_match"
    )


def test_session_metadata_is_safe_and_receipt_generation_is_deterministic():
    class NativeObject:
        pass

    native_perf.register_provider(
        "safe",
        snapshot=lambda: {
            "backend": "test",
            "counter_domain": "native",
            "provider_version": 7,
            "counters": {"clock_reads": 0},
        },
    )
    native_perf.configure(True)
    generation = native_perf.reset(
        {
            "function_ea": 0x401000,
            "session_id": "session-1",
            "native_object": NativeObject(),
        }
    )

    first = native_perf.receipt_json()
    second = native_perf.receipt_json()
    assert generation == 1
    assert first == second
    assert first is not None
    report = json.loads(first)
    assert report["session"] == {
        "function_ea": 0x401000,
        "native_object": "<non-serializable:NativeObject>",
        "session_id": "session-1",
    }
    assert report["provider_identities"]["safe"] == {
        "backend": "test",
        "counter_domain": "native",
        "provider_version": 7,
    }


def test_safe_value_never_stringifies_unknown_mapping_keys():
    class ExplodingKey:
        def __str__(self):
            raise AssertionError("unknown mapping key was stringified")

    native_perf.register_provider(
        "safe-key",
        snapshot=lambda: {"backend": "test", "counters": {}},
    )
    native_perf.configure(True)
    native_perf.reset({"metadata": {ExplodingKey(): "value"}})

    assert native_perf.snapshot()["session"] == {
        "metadata": {"<non-serializable-key:ExplodingKey>": "value"}
    }


def test_nested_sessions_reset_once_and_emit_one_outer_receipt():
    resets: list[str] = []
    native_perf.register_provider(
        "nested",
        snapshot=lambda: {"backend": "test", "counters": {}},
        reset=lambda: resets.append("reset"),
    )
    native_perf.configure(True)

    outer_generation = native_perf.begin_session(
        {"session_id": "outer", "function_ea": 0x401000}
    )
    child_generation = native_perf.begin_session(
        {"session_id": "child", "function_ea": 0x402000}
    )

    assert child_generation == outer_generation
    assert resets == ["reset"]
    assert native_perf.end_session("child") is None
    receipt = native_perf.end_session("outer")
    assert receipt is not None
    assert receipt.startswith(native_perf.RECEIPT_PREFIX)
    report = json.loads(receipt.split("=", 1)[1])
    assert report["session"] == {
        "function_ea": 0x401000,
        "session_id": "outer",
    }
    assert native_perf.end_session("underflow") is None
    assert native_perf.snapshot()["complete"] is False
    native_perf.begin_session({"session_id": "next"})
    assert native_perf.snapshot()["lifecycle_errors"] == []
    assert native_perf.end_session("next") is not None


def test_mismatched_nested_end_preserves_stack_and_marks_outer_receipt_incomplete():
    native_perf.register_provider(
        "nested-mismatch",
        snapshot=lambda: {"backend": "test", "counters": {}},
    )
    native_perf.configure(True)
    native_perf.begin_session({"session_id": "outer"})
    native_perf.begin_session({"session_id": "child"})

    assert native_perf.end_session("outer") is None
    after_mismatch = native_perf.snapshot()
    assert after_mismatch["lifecycle_depth"] == 2
    assert after_mismatch["complete"] is False
    assert after_mismatch["lifecycle_errors"]

    assert native_perf.end_session("child") is None
    receipt = native_perf.end_session("outer")
    assert receipt is not None
    report = json.loads(receipt.split("=", 1)[1])
    assert report["complete"] is False
    assert report["lifecycle_depth"] == 0
