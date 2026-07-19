from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.terminal_byte_evidence import (
    collect_terminal_tail_byte_source_eas,
)


@dataclass(frozen=True)
class _Observation:
    kind: str
    payload: dict[str, object] | None = None
    source_ea: object | None = None
    source_ea_hex: object | None = None
    source_ea_i64: object | None = None


@dataclass(frozen=True)
class _FactView:
    active_observations: tuple[_Observation, ...] = ()


@dataclass(frozen=True)
class _Snapshot:
    diagnostic_fact_view: _FactView | None = None
    validated_fact_view: _FactView | None = None


def test_collects_payload_and_observation_source_eas():
    snapshot = _Snapshot(
        diagnostic_fact_view=_FactView(
            active_observations=(
                _Observation(
                    "TerminalByteEmitterFact",
                    {"corridor_role": "terminal_tail", "source_ea": 0x1000},
                ),
                _Observation(
                    "TerminalByteEmitterFact",
                    {"corridor_role": "terminal_tail", "source_ea_hex": "0x2000"},
                ),
                _Observation(
                    "TerminalByteEmitterFact",
                    {"corridor_role": "terminal_tail"},
                    source_ea=0x3000,
                    source_ea_hex="0x4000",
                    source_ea_i64="20480",
                ),
            ),
        ),
    )

    assert collect_terminal_tail_byte_source_eas(snapshot) == frozenset(
        {0x1000, 0x2000, 0x3000, 0x4000, 20480},
    )


def test_uses_validated_fact_view_when_diagnostic_view_missing():
    snapshot = _Snapshot(
        validated_fact_view=_FactView(
            active_observations=(
                _Observation(
                    "TerminalByteEmitterFact",
                    {"corridor_role": "terminal_tail", "source_ea_hex": "0x1234"},
                ),
            ),
        ),
    )

    assert collect_terminal_tail_byte_source_eas(snapshot) == frozenset({0x1234})


def test_ignores_non_terminal_tail_facts_and_invalid_eas():
    snapshot = _Snapshot(
        diagnostic_fact_view=_FactView(
            active_observations=(
                _Observation(
                    "OtherFact",
                    {"corridor_role": "terminal_tail", "source_ea": 0x1000},
                ),
                _Observation(
                    "TerminalByteEmitterFact",
                    {"corridor_role": "non_terminal_byte_emitter", "source_ea": 0x2000},
                ),
                _Observation(
                    "TerminalByteEmitterFact",
                    {"corridor_role": "terminal_tail", "source_ea_hex": "not-hex"},
                    source_ea=True,
                ),
            ),
        ),
    )

    assert collect_terminal_tail_byte_source_eas(snapshot) == frozenset()


def test_missing_fact_view_returns_empty_set():
    assert collect_terminal_tail_byte_source_eas(object()) == frozenset()
