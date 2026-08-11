"""One tested entry point for "make solver proofs work", used by two callers.

The proof gate in mba-solve needs z3, which d810 deliberately keeps out of
IDA's site-packages: ``install-speedups`` puts it in ``~/.d810-speedups`` and
``ensure_speedups_on_path`` prepends that, pinning the wheel AND the native
libz3 it loads through ``builtins.Z3_LIB_DIRS``. A second copy in
site-packages would leave path order deciding which wrapper pairs with which
native library.

That isolation leaves a reachable state where everything installs cleanly and
no proof can be produced. Rather than duplicate the remedy in the UI and in the
solver backend, both call this.

pip is injected throughout: a unit test must never reach the network.
"""

from __future__ import annotations

import pytest

from d810.speedups.install import (
    SOLVER_SUPPORT_PACKAGES,
    SolverSupportResult,
    install_solver_support,
)


def _probe(present: bool):
    return lambda: present


def test_reports_success_without_installing_when_z3_is_already_there():
    """Re-installing a working solver is wasted network and wasted risk."""
    calls = []
    result = install_solver_support(
        probe=_probe(True), installer=lambda pkgs: calls.append(pkgs)
    )

    assert result.ok is True
    assert result.already_present is True
    assert calls == []


def test_installs_when_z3_is_missing():
    """Absent, then present once pip has run -- the ordinary success path.

    The probe must answer twice: the second call is the post-install check that
    refuses to claim success on pip's exit code alone.
    """
    calls = []
    answers = iter([False, True])
    result = install_solver_support(
        probe=lambda: next(answers), installer=lambda pkgs: calls.append(pkgs)
    )

    assert result.ok is True
    assert result.already_present is False
    assert calls == [SOLVER_SUPPORT_PACKAGES]


def test_pins_the_same_package_set_the_speedups_installer_uses():
    """Two z3 pins that can drift would be two native libraries in one process."""
    from d810.speedups.install import SPEEDUPS_PACKAGES

    assert SOLVER_SUPPORT_PACKAGES == SPEEDUPS_PACKAGES


def test_a_failed_install_reports_rather_than_raises():
    """This is called from a UI action and from a decompiler callback.

    An exception escaping either one is worse than a message: in the callback
    it crosses into Hex-Rays C++ and takes the process down.
    """

    def boom(_pkgs):
        raise RuntimeError("network is down")

    result = install_solver_support(probe=_probe(False), installer=boom)

    assert result.ok is False
    assert "network is down" in result.message


def test_the_failure_message_names_the_manual_fallback():
    def boom(_pkgs):
        raise RuntimeError("nope")

    result = install_solver_support(probe=_probe(False), installer=boom)

    assert "install-speedups" in result.message


def test_verifies_the_install_actually_produced_a_working_solver():
    """pip exiting 0 is not proof that z3 imports.

    A wheel can land for the wrong interpreter, or the native libz3 can fail to
    load. Claiming success on exit code alone would send the user back to a
    pass that still applies nothing.
    """
    answers = iter([False, False])
    result = install_solver_support(
        probe=lambda: next(answers), installer=lambda _pkgs: None
    )

    assert result.ok is False
    assert "still" in result.message.lower()


def test_success_requires_the_post_install_probe_to_pass():
    answers = iter([False, True])
    result = install_solver_support(
        probe=lambda: next(answers), installer=lambda _pkgs: None
    )

    assert result.ok is True


@pytest.mark.parametrize("present", [True, False])
def test_result_is_immutable(present):
    """Callers pass this across a UI boundary; it must not be edited in flight."""
    result = install_solver_support(
        probe=_probe(present), installer=lambda _pkgs: None
    )
    with pytest.raises(Exception):
        result.ok = not result.ok  # type: ignore[misc]


def test_result_carries_a_message_in_every_outcome():
    for probe in (_probe(True), _probe(False)):
        result = install_solver_support(probe=probe, installer=lambda _pkgs: None)
        assert isinstance(result, SolverSupportResult)
        assert result.message
