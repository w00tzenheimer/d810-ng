"""The residual-observation recording kill switch.

``d810-cobra`` declares ``d810.mba.residual-observation.v1`` as a *required*
host capability, so the sink cannot simply be left unregistered: an
unsatisfied requirement fails the whole activation and cobra-solve stops
rewriting.  The switch therefore keeps the capability registered and turns the
recording itself into a no-op.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.settings import D810Settings, get_settings, reset_settings
from d810.mba.residual_observation_sink import SqliteMbaResidualObservationSink


class _RecordingStore:
    def __init__(self) -> None:
        self.calls = 0

    def record_attempt(self, attempt: object) -> object:
        self.calls += 1
        raise AssertionError("recording is disabled")

    def close(self) -> None:
        pass


def test_settings_expose_the_recording_switch_and_default_to_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("D810_MBA_RESIDUAL_RECORDING", raising=False)
    reset_settings()
    try:
        assert get_settings().mba_residual_recording is True
    finally:
        reset_settings()


@pytest.mark.parametrize("value", ["0", "false", "off", "no"])
def test_environment_switches_recording_off(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("D810_MBA_RESIDUAL_RECORDING", value)
    reset_settings()
    try:
        assert get_settings().mba_residual_recording is False
    finally:
        reset_settings()


def test_disabled_sink_records_nothing_and_stays_usable() -> None:
    store = _RecordingStore()
    sink = SqliteMbaResidualObservationSink(store, recording_enabled=False)
    try:
        receipt = sink.record(object())
        assert receipt.status == "rejected"
        assert receipt.reason == "recording_disabled"
        assert store.calls == 0
    finally:
        sink.close()


def _residual_record() -> object:
    """One well-formed residual record for the coefficient solver."""

    from d810.core.function_execution_identity import (
        FunctionExecutionIdentity,
        MbaObservationContext,
    )
    from d810.core.plugins import PluginIdentity
    from d810.mba.extension_api import MbaResidualRecord
    from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
    from d810.mba.provider_routing import MbaProviderKind
    from d810.mba.semantic_canonicalization import canonicalize_mba_term
    from d810.mba.typed_term import TypedBvTerm, term_cost, term_fingerprint

    raw = TypedBvTerm(
        "xor",
        32,
        children=(TypedBvTerm(None, 32, value=1), TypedBvTerm(None, 32, value=2)),
    )
    canonical = canonicalize_mba_term(raw).canonical_term
    identity = FunctionExecutionIdentity(
        input_identity="idb-local:12345678-1234-5678-1234-567812345678",
        input_identity_provenance="current_idb",
        external_evidence_allowed=False,
        database_uuid="12345678-1234-5678-1234-567812345678",
        database_identity="idb-one",
        function_ea=0x401000,
        function_rva=0x1000,
        function_fingerprint="function-fp",
        decompilation_session_id="12345678-1234-5678-1234-567812345679",
        top_level_epoch=1,
        maturity="ir.canonical",
        evidence_generation=2,
    )
    return MbaResidualRecord(
        context=MbaObservationContext(
            function_identity=identity,
            plugin_identity=PluginIdentity("cobra", "d810-cobra", "1.0", "test"),
            instruction_ea=0x401002,
            block_serial=3,
            block_ea=0x401000,
        ),
        attempt_uuid="12345678-1234-5678-1234-56781234567a",
        raw_term=raw,
        canonical_term=canonical,
        outcome=MbaProviderOutcome(
            provider=MbaProviderKind.COEFFICIENT_SOLVER,
            status=ProviderOutcomeStatus.UNCHANGED,
            fingerprint=term_fingerprint(canonical),
            input_cost=term_cost(raw),
            elapsed_ms=1.0,
        ),
        materialized=False,
    )


def test_repeated_observation_canonicalizes_the_raw_term_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The host already canonicalized the term; the sink must not redo it.

    ``d810.backends.mba.extension_host`` canonicalizes on capture and the sink
    canonicalizes again to verify the provider did not tamper with the pair.
    That check stays, but the same raw term must only pay for it once.
    """

    import d810.mba.residual_observation_sink as sink_module
    from d810.mba.discovery_store import MbaDiscoveryStore

    record = _residual_record()

    calls = 0
    original = sink_module.canonicalize_mba_term

    def counting(term):
        nonlocal calls
        calls += 1
        return original(term)

    monkeypatch.setattr(sink_module, "canonicalize_mba_term", counting)

    store = MbaDiscoveryStore(tmp_path / "canonical.sqlite3")
    sink = sink_module.SqliteMbaResidualObservationSink(store)
    try:
        sink.record(record)
        sink.record(record)
        assert calls == 1, f"raw term canonicalized {calls} times"
    finally:
        sink.close()


def test_harness_time_is_logged_at_debug(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    """``elapsed_ms`` only wraps solve/prove; the publish cost needs its own line.

    Without this the whole capture->validate->commit harness is invisible and
    every stored attempt reports ``elapsed_ms`` while taking orders of
    magnitude longer end to end.
    """

    import logging

    import d810.mba.residual_observation_sink as sink_module
    from d810.core.logging import LevelFlag
    from d810.mba.discovery_store import MbaDiscoveryStore

    store = MbaDiscoveryStore(tmp_path / "timing.sqlite3")
    sink = sink_module.SqliteMbaResidualObservationSink(store)
    try:
        with caplog.at_level(
            logging.DEBUG, logger="d810.mba.residual_observation_sink"
        ):
            # ``debug_on`` is a version-cached LevelFlag; ``caplog.at_level``
            # changes the level without telling it.
            LevelFlag.bump_config_version()
            sink.record(_residual_record())
    finally:
        LevelFlag.bump_config_version()
        sink.close()

    assert any(
        "residual observation publish" in message for message in caplog.messages
    ), caplog.messages
