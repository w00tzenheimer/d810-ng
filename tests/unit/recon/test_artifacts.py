from __future__ import annotations

from d810.analyses.control_flow.return_frontier import ReturnSite
from d810.passes.artifacts import (
    load_return_sites_from_store,
    load_transition_report_from_store,
    save_transition_report_to_store,
)
from d810.analyses.control_flow.transition_report import (
    DispatcherTransitionReport,
    TransitionKind,
    TransitionPath,
    TransitionRow,
    TransitionSummary,
)


def _report() -> DispatcherTransitionReport:
    path = TransitionPath(
        handler_serial=10,
        chain=(10, 20),
        next_state=None,
        conditional_states=(),
        back_edge=False,
        reaches_exit_block=True,
        classified_exit=True,
        unresolved=False,
    )
    row = TransitionRow(
        state_const=0x1000,
        state_range_lo=None,
        state_range_hi=None,
        handler_serial=10,
        kind=TransitionKind.EXIT,
        next_state=None,
        conditional_states=(),
        state_label="State 0x00001000",
        transition_label="RETURN (exit)",
        chain_preview=(10, 20),
        path=path,
    )
    return DispatcherTransitionReport(
        dispatcher_entry_serial=5,
        state_var_stkoff=0x7BC,
        state_var_lvar_idx=None,
        pre_header_serial=1,
        initial_state=0x1000,
        handler_state_map={10: 0x1000},
        handler_range_map={},
        condition_chain_blocks=(2, 3),
        rows=(row,),
        summary=TransitionSummary(
            handlers_total=1,
            known_count=0,
            conditional_count=0,
            exit_count=1,
            unknown_count=0,
        ),
        diagnostics=(),
    )


class _Provider:
    def collect_return_sites(self, report: DispatcherTransitionReport) -> tuple[ReturnSite, ...]:
        return (
            ReturnSite(
                site_id=f"provider_{report.rows[0].handler_serial}",
                origin_block=report.rows[0].handler_serial,
                expected_terminal_kind="return",
            ),
        )


def test_transition_report_store_round_trip(tmp_path) -> None:
    report = _report()

    save_transition_report_to_store(
        func_ea=0x401000,
        maturity=7,
        report=report,
        log_dir=tmp_path,
    )
    loaded = load_transition_report_from_store(
        func_ea=0x401000,
        maturity=7,
        log_dir=tmp_path,
    )

    assert loaded is not None
    assert loaded.dispatcher_entry_serial == 5
    assert loaded.summary.exit_count == 1


def test_load_return_sites_from_store_uses_caller_provider(tmp_path) -> None:
    save_transition_report_to_store(
        func_ea=0x401000,
        maturity=7,
        report=_report(),
        log_dir=tmp_path,
    )

    sites = load_return_sites_from_store(
        func_ea=0x401000,
        maturity=7,
        log_dir=tmp_path,
        provider=_Provider(),
    )

    assert len(sites) == 1
    assert sites[0].site_id == "provider_10"
