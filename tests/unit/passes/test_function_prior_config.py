from __future__ import annotations

from d810.passes.function_prior_config import (
    function_prior_keys,
    load_function_analysis_priors_from_config,
    load_return_frontier_edge_proofs,
)


def test_function_prior_keys_normalize_int_hex_and_sub_names():
    assert function_prior_keys(0x180012B60) == (
        "0x180012b60",
        "6442527584",
        "sub_180012b60",
    )
    assert function_prior_keys("sub_180012B60") == (
        "0x180012b60",
        "6442527584",
        "sub_180012b60",
    )
    assert function_prior_keys("  named_function  ") == ("named_function",)


def test_return_frontier_edge_proof_parser_skips_invalid_items():
    proofs = load_return_frontier_edge_proofs(
        [
            {
                "source_block": "10",
                "artifact_block": 11,
                "old_target_block": "12",
                "continuation_block": 13,
                "proof_ids": ("edge-a", 7),
            },
            {"source_block": 1},
            "not-a-proof",
        ]
    )

    assert len(proofs) == 1
    assert proofs[0].source_block == 10
    assert proofs[0].artifact_block == 11
    assert proofs[0].old_target_block == 12
    assert proofs[0].continuation_block == 13
    assert tuple(proofs[0].proof_ids) == ("edge-a", "7")


def test_load_function_analysis_priors_from_config_expands_keys_and_parses_priors():
    priors_by_key = load_function_analysis_priors_from_config(
        {
            "sub_180012B60": {
                "return_frontier_artifacts": {
                    "known_impossible_return_constants": ("0xffffffffffffffff", 5),
                    "impossible_return_artifact_edges": [
                        {
                            "source_block": 80,
                            "artifact_block": 118,
                            "old_target_block": 221,
                            "continuation_block": 223,
                            "proof_ids": ("rf-edge",),
                        }
                    ],
                },
                "terminal_tail_cascade_egress": {
                    "byte_indices": ("1", 2),
                    "split_byte_indices": (3,),
                    "row_target_overrides": [
                        {"byte_index": "4", "target_entry_byte_index": 5},
                        {"byte_index": "bad"},
                    ],
                    "continuation_bridges": [
                        {
                            "continuation_byte_index": 6,
                            "source_byte_index": "7",
                            "target_store_guard_byte_index": 8,
                        }
                    ],
                    "equality_frontier": {
                        "return_frontier_byte_index": 9,
                        "row_byte_indices": (10, "11"),
                        "shared_store_guard_byte_indices": ("12",),
                    },
                    "entry_frontier": {"first_byte_index": "13"},
                },
            },
            "empty": {},
            "invalid": "not-a-dict",
        }
    )

    assert set(priors_by_key) == {
        "0x180012b60",
        "6442527584",
        "sub_180012b60",
    }
    priors = priors_by_key["0x180012b60"]
    assert priors.return_frontier_artifacts.known_impossible_return_constants == (
        frozenset({0xFFFFFFFFFFFFFFFF, 5})
    )
    assert len(priors.return_frontier_artifacts.impossible_return_artifact_edges) == 1

    terminal = priors.terminal_tail_cascade_egress
    assert terminal.byte_indices == (1, 2)
    assert terminal.split_byte_indices == (3,)
    assert len(terminal.row_target_overrides) == 1
    assert terminal.row_target_overrides[0].byte_index == 4
    assert len(terminal.continuation_bridges) == 1
    assert terminal.continuation_bridges[0].max_depth == 8
    assert terminal.equality_frontier is not None
    assert terminal.equality_frontier.row_byte_indices == (10, 11)
    assert terminal.entry_frontier is not None
    assert terminal.entry_frontier.first_byte_index == 13
