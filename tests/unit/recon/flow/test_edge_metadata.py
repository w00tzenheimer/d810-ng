from __future__ import annotations

from d810.analyses.control_flow.edge_metadata import (
    edge_kind_name,
    make_edge_metadata,
    source_kind_name,
)
from d810.analyses.control_flow.linearized_state_dag import (
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNodeKey,
    StateRedirectAnchor,
)
from d810.analyses.control_flow.state_machine_analysis import StateWriteSite


def _edge() -> StateDagEdge:
    return StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=StateDagNodeKey(handler_serial=10, state_const=0x10),
        target_key=StateDagNodeKey(handler_serial=20, state_const=0x20),
        target_state=0x20,
        target_entry_anchor=20,
        target_label="0x20",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=10,
            branch_arm=1,
        ),
        ordered_path=(10, 20),
        last_write_site=None,
    )


class TestEdgeMetadata:
    def test_kind_helpers_return_enum_names(self):
        edge = _edge()
        assert edge_kind_name(edge) == "CONDITIONAL_TRANSITION"
        assert source_kind_name(edge) == "CONDITIONAL_BRANCH"

    def test_make_edge_metadata_formats_optional_fields(self):
        edge = _edge()
        site = StateWriteSite(
            block_serial=14,
            state_value=0x20,
            insn_ea=0x1234,
            insn_index=2,
        )

        metadata = make_edge_metadata(
            edge,
            horizon_block=14,
            site=site,
            target_entry=20,
            first_shared_block=16,
            via_pred=12,
            emission_mode="pred_split",
            rejection_reason=None,
        )

        assert metadata == {
            "edge_kind": "CONDITIONAL_TRANSITION",
            "source_kind": "CONDITIONAL_BRANCH",
            "source_block": 10,
            "branch_arm": 1,
            "target_state": 0x20,
            "target_entry_anchor": 20,
            "horizon_block": 14,
            "state_value": 0x20,
            "state_write_ea": 0x1234,
            "target_entry": 20,
            "first_shared_block": 16,
            "via_pred": 12,
            "emission_mode": "pred_split",
            "rejection_reason": None,
        }
