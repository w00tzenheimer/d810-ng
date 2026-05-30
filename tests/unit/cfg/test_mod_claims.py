from __future__ import annotations

from types import SimpleNamespace

from d810.transforms.mod_claims import collect_mod_claims


class TestCollectModClaims:
    def test_collects_sources_and_targets_from_mixed_mod_shapes(self):
        modifications = [
            SimpleNamespace(new_target=20, source_serial=10),
            SimpleNamespace(goto_target=30, from_serial=11),
            SimpleNamespace(
                per_pred_targets=((8, 40), (9, 50)),
                source_block=12,
            ),
            SimpleNamespace(conditional_target=60, fallthrough_target=61, src_block=13),
            SimpleNamespace(block_serial=14),
        ]

        claimed_sources, claimed_targets = collect_mod_claims(modifications)

        assert claimed_sources == {8, 9, 10, 11, 12, 13, 14}
        assert claimed_targets == {20, 30, 40, 50, 60, 61}
