import pytest

from d810.hexrays.preanalysis import preopt_preanalysis as preopt
from d810.hexrays.preanalysis.flowchart_preanalysis import request_hexrays_redo
from d810.manager import hexrays_frontend_normalization as live_normalization
from d810.transforms.cfg_transaction import (
    CfgGenerationPoisoned,
    CfgTransactionFailure,
    CfgTransactionPhase,
    TransactionAttemptId,
)


def _poison() -> CfgGenerationPoisoned:
    return CfgGenerationPoisoned(
        CfgTransactionFailure(
            attempt_id=TransactionAttemptId(
                plan_id="preopt-poison",
                session_id="preopt-session",
                generation=3,
                attempt_id="preopt-attempt",
            ),
            phase=CfgTransactionPhase.POISONED_RESTART_REQUIRED,
            reason="INTERR: 50856 after PREOPT insertion",
            live_mutation_started=True,
            failure_phase="stage",
            interr_code=50856,
        )
    )


def test_preopt_handler_receives_live_mba_and_can_record_modification(
    monkeypatch,
) -> None:
    monkeypatch.setattr(preopt, "_PREOPT_PREANALYSIS_HANDLERS", {})
    received: list[tuple[int, object]] = []
    mba = object()

    def handler(*, function_ea: int, mba: object, decision: dict) -> None:
        received.append((function_ea, mba))
        decision["microcode_modified"] = True
        decision["details"] = {"terminal_return_carriers": 1}

    preopt.register_preopt_preanalysis_handler("unit", handler)
    decision: dict[str, object] = {"request_redo": False}

    preopt.run_preopt_preanalysis_handlers(
        function_ea=0x40A560,
        mba=mba,
        decision=decision,
    )

    assert received == [(0x40A560, mba)]
    assert decision == {
        "request_redo": False,
        "microcode_modified": True,
        "details": {"terminal_return_carriers": 1},
    }


def test_preopt_handler_failure_does_not_gate_later_handler(monkeypatch) -> None:
    monkeypatch.setattr(preopt, "_PREOPT_PREANALYSIS_HANDLERS", {})

    def failing(*, function_ea: int, mba: object, decision: dict) -> None:
        raise RuntimeError("boom")

    def succeeding(*, function_ea: int, mba: object, decision: dict) -> None:
        request_hexrays_redo(decision, "later_preopt_handler")

    preopt.register_preopt_preanalysis_handler("failing", failing)
    preopt.register_preopt_preanalysis_handler("succeeding", succeeding)
    decision: dict[str, object] = {"request_redo": False}

    preopt.run_preopt_preanalysis_handlers(
        function_ea=0x40A560,
        mba=object(),
        decision=decision,
    )

    assert decision["request_redo"] is True
    assert decision["reason"] == "later_preopt_handler"


def test_preopt_poison_stops_later_handlers_and_propagates(monkeypatch) -> None:
    monkeypatch.setattr(preopt, "_PREOPT_PREANALYSIS_HANDLERS", {})
    later: list[str] = []

    def poison(**_kwargs) -> None:
        raise _poison()

    def must_not_run(**_kwargs) -> None:
        later.append("ran")

    preopt.register_preopt_preanalysis_handler("poison", poison)
    preopt.register_preopt_preanalysis_handler("later", must_not_run)

    with pytest.raises(CfgGenerationPoisoned):
        preopt.run_preopt_preanalysis_handlers(
            function_ea=0x40A560,
            mba=object(),
            decision={"request_redo": False},
        )

    assert later == []


def test_manager_normalization_is_the_named_preopt_publication_authority(
    monkeypatch,
) -> None:
    monkeypatch.setattr(preopt, "_PREOPT_PREANALYSIS_HANDLERS", {})

    live_normalization.install_live_frontend_normalization()

    assert preopt._PREOPT_PREANALYSIS_HANDLERS == {
        "manager.frontend_normalization": (
            live_normalization.run_live_frontend_normalization
        ),
    }

    live_normalization.uninstall_live_frontend_normalization()

    assert preopt._PREOPT_PREANALYSIS_HANDLERS == {}
