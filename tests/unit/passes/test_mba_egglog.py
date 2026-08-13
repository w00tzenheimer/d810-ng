"""Unit tests for the bounded ``mba-egglog`` config-v2 stage (no IDA)."""

from __future__ import annotations

import unittest
from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.core.pass_ids import PassId
from d810.passes.mba_egglog import (
    MBA_EGGLOG_IMPLEMENTATION,
    MBA_EGGLOG_PASS_ID,
    MbaEgglogPass,
    build_mba_egglog_pass,
    parse_mba_egglog_options,
    register_mba_egglog_pass,
)
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation
from d810.passes.registry import PassRegistry


def _config(options: dict | None = None) -> PipelineConfig:
    return PipelineConfig(
        pass_id=MBA_EGGLOG_PASS_ID,
        options=options if options is not None else {},
    )


class TestMbaEgglogOptions(unittest.TestCase):
    def test_defaults_are_bounded_and_proof_gated(self):
        self.assertEqual(
            parse_mba_egglog_options(_config()),
            (2, 3, True, ("GLOBAL_OPTIMIZED",)),
        )

    def test_explicit_options_reach_the_pass(self):
        built = build_mba_egglog_pass(
            _config(
                {
                    "max_leaves": 4,
                    "rounds": 5,
                    "require_proof": False,
                    "maturities": ["GLOBAL_ANALYZED"],
                }
            )
        )
        self.assertIsInstance(built, MbaEgglogPass)
        self.assertEqual(
            (built.max_leaves, built.rounds, built.require_proof, built.maturities),
            (4, 5, False, ("GLOBAL_ANALYZED",)),
        )

    def test_rejects_unsafe_or_unknown_options(self):
        for options in (
            {"max_leaves": 0},
            {"max_leaves": True},
            {"rounds": 7},
            {"require_proof": "yes"},
            {"maturities": []},
            {"maturities": ["NOT_A_MATURITY"]},
            {"surprise": 1},
        ):
            with self.subTest(options=options):
                with self.assertRaises(PipelineConfigError):
                    parse_mba_egglog_options(_config(options))


class TestMbaEgglogRegistration(unittest.TestCase):
    def test_private_instruction_stage_names_the_live_rule(self):
        registry = register_mba_egglog_pass(PassRegistry())
        descriptor = registry.stages_for(MBA_EGGLOG_PASS_ID)[0]

        self.assertEqual(descriptor.implementation_name, MBA_EGGLOG_IMPLEMENTATION)
        self.assertNotIn(MBA_EGGLOG_PASS_ID, registry.public_pass_ids())

    def test_hook_bridge_forwards_all_validated_options(self):
        project = ProjectConfiguration(
            path=Path("mba-egglog.runtime-config-v2.json"),
            additional_configuration={
                "pipeline_v2_mode": "config-v2",
                "pipeline_v2": [
                    {
                        "pass_id": PassId.MBA_EGGLOG,
                        "options": {
                            "max_leaves": 4,
                            "rounds": 5,
                            "require_proof": False,
                            "maturities": ["GLOBAL_ANALYZED"],
                        },
                    }
                ],
            }
        )

        activation = pipeline_v2_hook_activation(project)

        self.assertEqual(
            [rule.name for rule in activation.instruction_rules],
            [MBA_EGGLOG_IMPLEMENTATION],
        )
        rule = activation.instruction_rules[0]
        self.assertEqual(
            rule.config,
            {
                "max_leaves": 4,
                "rounds": 5,
                "require_proof": False,
                "maturities": ["GLOBAL_ANALYZED"],
            },
        )
