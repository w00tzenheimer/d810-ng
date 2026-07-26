from __future__ import annotations

import json

from d810.manager.rhad_generated_checksum import (
    BOUNDARY_EXIT_EAS,
    IMPORTED_BLOCK_IDS,
    build_a560_generated_checksum_plan,
)
from d810.ir.semantic_edge import SemanticEdgeRole
from tests.native_preanalysis import make_native_key


def test_checksum_producer_compiles_exact_serial_free_route() -> None:
    plan = build_a560_generated_checksum_plan(
        native_key=make_native_key(
            input_identity=(
                "sha256:2449071691418114b0afbf290b0dae3bf52553c562b2c3a"
                "ebc092a7f18335e4c"
            ),
            function_rva=0x40A560,
        ),
        evidence_generation=7,
    )

    operation = plan.operation("rhad:route@0x40A605")
    assert plan.plan_id.endswith("rhad-generated-reference@0x40A560:g7")
    assert plan.block("native@0x40A5AE").semantic_anchor_ea == 0x40A5AE
    assert operation.predicate_anchor_ea == 0x40A5F6
    assert operation.computed_branch_normalization.condition_producer_ea == 0x40A5F0
    assert operation.computed_branch_normalization.unresolved_transfer_ea == 0x40A605
    assert plan.flag_corridors[0].consumer.instruction_ea == 0x40A5F6
    assert {
        edge.role: edge.target_block_id for edge in operation.edges
    } == {
        SemanticEdgeRole.CONDITIONAL_TAKEN: "native@0x40B6C0",
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH: "native@0x40A607",
    }
    assert plan.native_bodies[0].block_ids == IMPORTED_BLOCK_IDS
    payload = json.loads(
        operation.reference_route_authority.reference_route.reference_ledger_json
    )
    assert tuple(payload["boundary_exit_eas"]) == BOUNDARY_EXIT_EAS
