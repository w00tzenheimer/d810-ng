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
    MbaEgglogOptions,
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
    def test_defaults_are_degree_one_add_only_and_proof_gated(self):
        options = parse_mba_egglog_options(_config())

        self.assertIsInstance(options, MbaEgglogOptions)
        self.assertEqual(
            (
                options.max_leaves,
                options.max_operator_nodes,
                options.max_degree,
                options.saturation_rounds,
                options.max_eclasses,
                options.max_enodes,
                options.max_rule_firings,
                options.cross_block_constant_preparation,
                options.time_budget_ms,
                options.function_time_budget_ms,
                options.residual_only,
                options.require_proof,
                options.collect_stage_timings,
                options.execution_mode,
                options.families,
                options.maturities,
            ),
            (
                2,
                10,
                1,
                2,
                64,
                128,
                32,
                False,
                3,
                None,
                False,
                True,
                False,
                "interactive",
                ("add",),
                ("GLOBAL_OPTIMIZED",),
            ),
        )

    def test_explicit_options_reach_the_pass(self):
        built = build_mba_egglog_pass(
            _config(
                {
                    "max_leaves": 4,
                    "max_operator_nodes": 12,
                    "max_degree": 2,
                    "saturation_rounds": 5,
                    "max_eclasses": 96,
                    "max_enodes": 192,
                    "max_rule_firings": 48,
                    "cross_block_constant_preparation": True,
                    "time_budget_ms": 9,
                    "function_time_budget_ms": 1000,
                    "residual_only": True,
                    "collect_stage_timings": True,
                    "execution_mode": "noninteractive",
                    "families": ["xor", "add"],
                    "maturities": ["GLOBAL_ANALYZED"],
                }
            )
        )
        self.assertIsInstance(built, MbaEgglogPass)
        self.assertEqual(
            (
                built.max_leaves,
                built.max_operator_nodes,
                built.max_degree,
                built.saturation_rounds,
                built.max_eclasses,
                built.max_enodes,
                built.max_rule_firings,
                built.cross_block_constant_preparation,
                built.time_budget_ms,
                built.function_time_budget_ms,
                built.residual_only,
                built.require_proof,
                built.collect_stage_timings,
                built.execution_mode,
                built.families,
                built.maturities,
            ),
            (
                4,
                12,
                2,
                5,
                96,
                192,
                48,
                True,
                9,
                1000,
                True,
                True,
                True,
                "noninteractive",
                ("xor", "add"),
                ("GLOBAL_ANALYZED",),
            ),
        )

    def test_rejects_invalid_integer_proof_and_unknown_options(self):
        for options in (
            {"max_leaves": 0},
            {"max_leaves": True},
            {"max_operator_nodes": 0},
            {"max_operator_nodes": 1.5},
            {"max_degree": 0},
            {"max_degree": 3},
            {"max_degree": True},
            {"saturation_rounds": 0},
            {"saturation_rounds": 7},
            {"saturation_rounds": "2"},
            {"max_eclasses": 0},
            {"max_eclasses": False},
            {"max_enodes": 0},
            {"max_enodes": 1.5},
            {"max_rule_firings": 0},
            {"max_rule_firings": True},
            {"cross_block_constant_preparation": 1},
            {"time_budget_ms": 0},
            {"time_budget_ms": "3"},
            {"function_time_budget_ms": 0},
            {"function_time_budget_ms": "1000"},
            {"function_time_budget_ms": 5001},
            {"residual_only": 1},
            {"require_proof": False},
            {"require_proof": "yes"},
            {"collect_stage_timings": "yes"},
            {"execution_mode": "batch"},
            {"families": []},
            {"families": ["add", 1]},
            {"maturities": []},
            {"maturities": ["NOT_A_MATURITY"]},
            {"surprise": 1},
        ):
            with self.subTest(options=options):
                with self.assertRaises(PipelineConfigError):
                    parse_mba_egglog_options(_config(options))

    def test_legacy_rounds_alias_is_normalized_and_conflicts_are_rejected(self):
        with self.assertWarns(DeprecationWarning):
            options = parse_mba_egglog_options(_config({"rounds": 4}))

        self.assertEqual(options.saturation_rounds, 4)
        with self.assertRaisesRegex(PipelineConfigError, "cannot both"):
            parse_mba_egglog_options(_config({"rounds": 4, "saturation_rounds": 4}))

    def test_rejects_duplicate_families(self):
        with self.assertRaisesRegex(PipelineConfigError, "unique"):
            parse_mba_egglog_options(_config({"families": ["add", "add"]}))

    def test_rejects_unknown_or_unsupported_families(self):
        for family in ("predicates", "imaginary"):
            with self.subTest(family=family):
                with self.assertRaisesRegex(PipelineConfigError, "supported families"):
                    parse_mba_egglog_options(_config({"families": [family]}))


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
                            "max_operator_nodes": 12,
                            "max_degree": 2,
                            "saturation_rounds": 5,
                            "max_eclasses": 96,
                            "max_enodes": 192,
                            "max_rule_firings": 48,
                            "cross_block_constant_preparation": True,
                            "time_budget_ms": 9,
                            "collect_stage_timings": True,
                            "execution_mode": "noninteractive",
                            "families": ["xor", "add"],
                            "maturities": ["GLOBAL_ANALYZED"],
                        },
                    }
                ],
            },
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
                "max_operator_nodes": 12,
                "max_degree": 2,
                "saturation_rounds": 5,
                "max_eclasses": 96,
                "max_enodes": 192,
                "max_rule_firings": 48,
                "cross_block_constant_preparation": True,
                "cross_block_def_use_preparation": False,
                "time_budget_ms": 9,
                "function_time_budget_ms": None,
                "residual_only": False,
                "require_proof": True,
                "collect_stage_timings": True,
                "execution_mode": "noninteractive",
                "native_proof_mode": "legacy",
                "families": ["xor", "add"],
                "maturities": ["GLOBAL_ANALYZED"],
            },
        )
