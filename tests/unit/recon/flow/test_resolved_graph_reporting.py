from __future__ import annotations

from types import SimpleNamespace

from d810.recon.flow.resolved_graph_reporting import (
    build_resolved_state_machine_dot_report,
)


class TestBuildResolvedStateMachineDotReport:
    def test_builds_resolved_and_exit_nodes(self):
        sm = SimpleNamespace(
            initial_state=0x1111,
            handlers={
                0x1111: object(),
                0x2222: object(),
            },
            transitions=[
                SimpleNamespace(
                    from_state=0x1111,
                    to_state=0xAAAA,
                    is_conditional=False,
                ),
            ],
        )
        bst_result = SimpleNamespace(
            handler_range_map={
                10: (0xAAAA, 0xAAAA),
            },
            resolve_target=lambda to_state: 10 if to_state == 0xAAAA else None,
        )
        handler_state_map = {10: 0x2222, 20: 0x1111}

        report = build_resolved_state_machine_dot_report(
            sm,
            bst_result,
            handler_state_map,
        )

        assert report.node_count == 2
        assert report.edge_count == 1
        assert report.resolved_count == 1
        assert report.exit_count == 1
        assert '    START -> "0x00001111";' in report.dot_lines
        assert '    "0x00001111" -> "0x00002222";' in report.dot_lines

    def test_marks_unresolved_state_with_self_loop(self):
        sm = SimpleNamespace(
            initial_state=None,
            handlers={0x3333: object()},
            transitions=[
                SimpleNamespace(
                    from_state=0x3333,
                    to_state=0x9999,
                    is_conditional=True,
                ),
            ],
        )
        bst_result = SimpleNamespace(
            handler_range_map={},
            resolve_target=lambda _to_state: None,
        )

        report = build_resolved_state_machine_dot_report(
            sm,
            bst_result,
            {},
        )

        assert report.unresolved_count == 1
        assert report.edge_count == 0
        assert (
            '    "0x00003333" -> "0x00003333" [style=dashed color=red];'
            in report.dot_lines
        )
