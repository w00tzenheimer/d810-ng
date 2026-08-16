"""Tests for session-only speedup status and Cython policy controls."""

from d810.core.cymode import CythonMode
from d810.core.speedup_session import (
    SpeedupAvailability,
    SpeedupHeadline,
    apply_session_cython_disabled,
    current_speedup_headline,
    probe_speedup_availability,
    speedup_title_suffix,
)


def test_unavailable_headline_wins_over_session_policy():
    availability = SpeedupAvailability(installed=False, detail="missing")

    assert (
        current_speedup_headline(availability, cython_allowed=True)
        is SpeedupHeadline.UNAVAILABLE
    )


def test_installed_speedups_report_enabled_or_disabled_from_session_policy():
    availability = SpeedupAvailability(installed=True, detail="")

    assert (
        current_speedup_headline(availability, cython_allowed=True)
        is SpeedupHeadline.ENABLED
    )
    assert (
        current_speedup_headline(availability, cython_allowed=False)
        is SpeedupHeadline.DISABLED
    )


def test_title_suffix_has_no_partial_or_degraded_state():
    values = {speedup_title_suffix(item) for item in SpeedupHeadline}

    assert values == {
        "SPEEDUPS ENABLED",
        "SPEEDUPS DISABLED",
        "SPEEDUPS UNAVAILABLE",
    }


def test_session_disable_reports_reload_only_when_policy_changes():
    mode = CythonMode()
    original_state = mode.is_enabled()
    try:
        mode.enable()

        assert apply_session_cython_disabled(True) is True
        assert mode.is_enabled() is False
        assert apply_session_cython_disabled(True) is False
    finally:
        mode._enabled = original_state


def test_probe_reports_installed_when_compatible_extension_imports():
    availability = probe_speedup_availability(import_module=lambda name: object())

    assert availability == SpeedupAvailability(installed=True)


def test_probe_retains_import_failure_for_diagnostics():
    def import_module(name):
        raise OSError("wrong architecture")

    availability = probe_speedup_availability(import_module=import_module)

    assert availability.installed is False
    assert availability.detail == "OSError: wrong architecture"
