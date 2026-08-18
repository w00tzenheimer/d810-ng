"""Unit tests for the bounded ``mba-egraph`` config-v2 stage (no IDA)."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from d810.core.config import ProjectConfiguration
from d810.core.pass_editor_spec import FieldControlKind
from d810.core.pass_ids import PassId
from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendManifest,
    BackendRegistry,
    BackendSpec,
    PassImplementationAmbiguous,
    PassImplementationCandidate,
    PassImplementationMissing,
)
from d810.mba.egraph_contracts import MbaEgraphOptions
from d810.passes.mba_egraph import (
    MBA_EGRAPH_PASS_ID,
    MbaEgraphPass,
    build_mba_egraph_pass,
    mba_egraph_implementation,
    mba_egraph_stages,
    parse_mba_egraph_options,
    register_mba_egraph_pass,
)
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation
from d810.passes.registry import PassRegistry


def _config(options: dict | None = None) -> PipelineConfig:
    return PipelineConfig(
        pass_id=MBA_EGRAPH_PASS_ID,
        options=options if options is not None else {},
    )


def _candidate(rule_name: str = "EgglogOptimizer") -> PassImplementationCandidate:
    return PassImplementationCandidate(
        pass_id=str(MBA_EGRAPH_PASS_ID),
        backend_name="egglog",
        backend_origin="test-extension",
        rule_modules=("test_extension.rule",),
        rule_name=rule_name,
    )


class _FakeImplementationRegistry:
    def __init__(self, candidates: tuple[PassImplementationCandidate, ...] = ()):
        self.candidates = candidates
        self.activated = []

    def implementation_candidates_for(self, pass_id):
        assert str(pass_id) == str(MBA_EGRAPH_PASS_ID)
        return self.candidates

    def require_unique_implementation(self, pass_id, *, install_hint):
        candidates = self.implementation_candidates_for(pass_id)
        if not candidates:
            raise PassImplementationMissing(str(pass_id), install_hint)
        if len(candidates) > 1:
            raise PassImplementationAmbiguous(str(pass_id), candidates)
        return candidates[0]

    def activate_implementation(self, candidate):
        self.activated.append(candidate)


class TestMbaEgraphOptions(unittest.TestCase):
    def test_parser_returns_the_portable_options_type(self):
        options = parse_mba_egraph_options(_config())

        self.assertIs(type(options), MbaEgraphOptions)

    def test_defaults_are_degree_one_add_only_and_proof_gated(self):
        options = parse_mba_egraph_options(_config())

        self.assertIsInstance(options, MbaEgraphOptions)
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
                options.cross_block_def_use_preparation,
                options.learned_replay_enabled,
                options.learned_replay_max_entries,
                options.learned_replay_max_bytes,
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
                False,
                False,
                256,
                2_097_152,
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
        built = build_mba_egraph_pass(
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
                    "cross_block_def_use_preparation": True,
                    "learned_replay_enabled": True,
                    "learned_replay_max_entries": 64,
                    "learned_replay_max_bytes": 1_048_576,
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
        self.assertIsInstance(built, MbaEgraphPass)
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
                built.cross_block_def_use_preparation,
                built.learned_replay_enabled,
                built.learned_replay_max_entries,
                built.learned_replay_max_bytes,
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
                True,
                True,
                64,
                1_048_576,
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
            {"learned_replay_enabled": 1},
            {"learned_replay_max_entries": 0},
            {"learned_replay_max_entries": True},
            {"learned_replay_max_bytes": 0},
            {"learned_replay_max_bytes": True},
            {"time_budget_ms": 0},
            {"time_budget_ms": "3"},
            {"function_time_budget_ms": "1000"},
            {"function_time_budget_ms": 5001},
            {"residual_only": 1},
            {"require_proof": False},
            {"require_proof": "yes"},
            {"collect_stage_timings": "yes"},
            {"execution_mode": "batch"},
            {"execution_mode": []},
            {"execution_mode": {}},
            {"families": []},
            {"families": ["add", 1]},
            {"maturities": []},
            {"maturities": ["NOT_A_MATURITY"]},
            {"surprise": 1},
        ):
            with self.subTest(options=options):
                with self.assertRaises(PipelineConfigError):
                    parse_mba_egraph_options(_config(options))

    def test_zero_function_budget_means_no_function_cap(self):
        options = parse_mba_egraph_options(_config({"function_time_budget_ms": 0}))

        self.assertIsNone(options.function_time_budget_ms)

    def test_rounds_option_is_rejected(self):
        with self.assertRaisesRegex(PipelineConfigError, "unknown options"):
            parse_mba_egraph_options(_config({"rounds": 4}))

        with self.assertRaisesRegex(PipelineConfigError, "unknown options"):
            parse_mba_egraph_options(_config({"rounds": 4, "saturation_rounds": 4}))

    def test_rejects_duplicate_families(self):
        with self.assertRaisesRegex(PipelineConfigError, "unique"):
            parse_mba_egraph_options(_config({"families": ["add", "add"]}))

    def test_fixed_rotate_family_is_explicitly_supported(self):
        options = parse_mba_egraph_options(_config({"families": ["fixed_rotate"]}))

        self.assertEqual(options.families, ("fixed_rotate",))
        self.assertFalse(options.cross_block_constant_preparation)
        self.assertFalse(options.cross_block_def_use_preparation)

    def test_fixed_rotate_family_rejects_cross_block_preparation(self):
        for preparation in (
            {"cross_block_constant_preparation": True},
            {"cross_block_def_use_preparation": True},
            {
                "cross_block_constant_preparation": True,
                "cross_block_def_use_preparation": True,
            },
        ):
            with self.subTest(preparation=preparation):
                with self.assertRaisesRegex(
                    PipelineConfigError,
                    "fixed_rotate.*cross-block preparation",
                ):
                    parse_mba_egraph_options(
                        _config({"families": ["fixed_rotate"], **preparation})
                    )

    def test_rejects_mixed_fixed_rotate_family(self):
        with self.assertRaisesRegex(PipelineConfigError, "fixed_rotate.*alone"):
            parse_mba_egraph_options(_config({"families": ["add", "fixed_rotate"]}))

    def test_rejects_unknown_or_unsupported_families(self):
        for family in ("predicates", "imaginary"):
            with self.subTest(family=family):
                with self.assertRaisesRegex(PipelineConfigError, "supported families"):
                    parse_mba_egraph_options(_config({"families": [family]}))


class TestMbaEgraphRegistration(unittest.TestCase):
    def test_public_instruction_stage_names_the_declared_rule_and_exposes_all_options(
        self,
    ):
        candidate = _candidate("DeclaredEgglogOptimizer")
        backend_registry = _FakeImplementationRegistry((candidate,))
        with patch("d810.backends.registry", return_value=backend_registry):
            registry = register_mba_egraph_pass(PassRegistry())
        descriptor = registry.stages_for(MBA_EGRAPH_PASS_ID)[0]

        self.assertEqual(descriptor.implementation_name, candidate.rule_name)
        self.assertIn(MBA_EGRAPH_PASS_ID, registry.public_pass_ids())
        editor = registry.editor_spec_for(MBA_EGRAPH_PASS_ID)
        self.assertIsNotNone(editor)
        assert editor is not None
        self.assertEqual(
            {field.path for field in editor.fields},
            {
                ("max_leaves",),
                ("max_operator_nodes",),
                ("max_degree",),
                ("saturation_rounds",),
                ("max_eclasses",),
                ("max_enodes",),
                ("max_rule_firings",),
                ("cross_block_constant_preparation",),
                ("cross_block_def_use_preparation",),
                ("learned_replay_enabled",),
                ("learned_replay_max_entries",),
                ("learned_replay_max_bytes",),
                ("time_budget_ms",),
                ("function_time_budget_ms",),
                ("residual_only",),
                ("require_proof",),
                ("collect_stage_timings",),
                ("execution_mode",),
                ("native_proof_mode",),
                ("families",),
                ("maturities",),
            },
        )
        function_budget = next(
            field
            for field in editor.fields
            if field.path == ("function_time_budget_ms",)
        )
        self.assertEqual(function_budget.control, FieldControlKind.INTEGER)
        self.assertEqual(function_budget.default, 0)
        proof = next(
            field for field in editor.fields if field.path == ("require_proof",)
        )
        self.assertTrue(proof.read_only)

    def test_absent_extension_keeps_public_pass_and_editor_visible(self):
        backend_registry = _FakeImplementationRegistry()
        with patch("d810.backends.registry", return_value=backend_registry):
            registry = register_mba_egraph_pass(PassRegistry())

        self.assertEqual(registry.stages_for(MBA_EGRAPH_PASS_ID), ())
        self.assertIn(MBA_EGRAPH_PASS_ID, registry.public_pass_ids())
        self.assertIsNotNone(registry.editor_spec_for(MBA_EGRAPH_PASS_ID))

    def test_declaration_helper_returns_only_a_unique_candidate(self):
        candidate = _candidate("DeclaredEgglogOptimizer")
        with patch(
            "d810.backends.registry",
            return_value=_FakeImplementationRegistry((candidate,)),
        ):
            self.assertEqual(mba_egraph_implementation(), candidate)

        for candidates in ((), (candidate, _candidate("OtherOptimizer"))):
            with self.subTest(candidates=candidates):
                with patch(
                    "d810.backends.registry",
                    return_value=_FakeImplementationRegistry(candidates),
                ):
                    self.assertIsNone(mba_egraph_implementation())

    def test_declaration_only_stage_helper_is_empty_for_zero_or_multiple(self):
        candidate = _candidate("DeclaredEgglogOptimizer")
        for candidates in ((), (candidate, _candidate("OtherOptimizer"))):
            with self.subTest(candidates=candidates):
                with patch(
                    "d810.backends.registry",
                    return_value=_FakeImplementationRegistry(candidates),
                ):
                    self.assertEqual(mba_egraph_stages(), ())

    def test_hook_bridge_forwards_all_validated_options(self):
        project = ProjectConfiguration(
            path=Path("mba-egraph.runtime-config-v2.json"),
            additional_configuration={
                "pipeline_v2": [
                    {
                        "pass_id": PassId.MBA_EGRAPH,
                        "options": {
                            "max_leaves": 4,
                            "max_operator_nodes": 12,
                            "max_degree": 2,
                            "saturation_rounds": 5,
                            "max_eclasses": 96,
                            "max_enodes": 192,
                            "max_rule_firings": 48,
                            "cross_block_constant_preparation": True,
                            "learned_replay_enabled": True,
                            "learned_replay_max_entries": 64,
                            "learned_replay_max_bytes": 1_048_576,
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

        candidate = _candidate("DeclaredEgglogOptimizer")
        backend_registry = _FakeImplementationRegistry((candidate,))
        with patch("d810.backends.registry", return_value=backend_registry):
            activation = pipeline_v2_hook_activation(project)

        self.assertEqual(
            [rule.name for rule in activation.instruction_rules],
            [candidate.rule_name],
        )
        self.assertEqual(backend_registry.activated, [candidate])
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
                "learned_replay_enabled": True,
                "learned_replay_max_entries": 64,
                "learned_replay_max_bytes": 1_048_576,
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

    def test_selected_absent_extension_is_an_install_error(self):
        project = ProjectConfiguration(
            path=Path("mba-egraph.missing.runtime-config-v2.json"),
            additional_configuration={
                "pipeline_v2_mode": "config-v2",
                "pipeline_v2": [{"pass_id": PassId.MBA_EGRAPH, "options": {}}],
            },
        )

        with patch(
            "d810.backends.registry",
            return_value=_FakeImplementationRegistry(),
        ):
            with self.assertRaises(PassImplementationMissing) as ctx:
                pipeline_v2_hook_activation(project)

        self.assertEqual(
            str(ctx.exception),
            "pass 'mba-egraph' has no implementation; install d810-egglog",
        )

    def test_ambiguous_selected_extensions_fail_before_rule_config(self):
        project = ProjectConfiguration(
            path=Path("mba-egraph.ambiguous.runtime-config-v2.json"),
            additional_configuration={
                "pipeline_v2_mode": "config-v2",
                "pipeline_v2": [{"pass_id": PassId.MBA_EGRAPH, "options": {}}],
            },
        )
        candidates = (_candidate("FirstOptimizer"), _candidate("SecondOptimizer"))
        with patch(
            "d810.backends.registry",
            return_value=_FakeImplementationRegistry(candidates),
        ):
            with patch(
                "d810.passes.pipeline_v2_hook_bridge._rule_config",
                side_effect=AssertionError("rule config emitted before resolution"),
            ):
                with self.assertRaises(PassImplementationAmbiguous):
                    pipeline_v2_hook_activation(project)

    def test_selected_extension_uses_strict_registry_activation(self):
        project = ProjectConfiguration(
            path=Path("mba-egraph.strict-activation.runtime-config-v2.json"),
            additional_configuration={
                "pipeline_v2_mode": "config-v2",
                "pipeline_v2": [{"pass_id": PassId.MBA_EGRAPH, "options": {}}],
            },
        )
        candidate = _candidate("DeclaredEgglogOptimizer")
        activation_calls = []

        class _StrictRegistry(_FakeImplementationRegistry):
            def __init__(self):
                super().__init__((candidate,))

            def activate_implementation(self, selected):
                activation_calls.append(selected)

        with patch("d810.backends.registry", return_value=_StrictRegistry()):
            with patch(
                "d810.backends.load_extension_rule_for_candidate",
                side_effect=AssertionError("raw lookup bypassed strict activation"),
            ):
                pipeline_v2_hook_activation(project)

        self.assertEqual(activation_calls, [candidate])

    def test_malformed_unselected_extension_keeps_public_registry_startable(self):
        manifest = BackendManifest(
            name="egglog",
            api_version=PLUGIN_API_VERSION,
            provides=object(),
            implements={"mba-egraph": "EgglogOptimizer"},
        )
        backend_registry = BackendRegistry(
            source=lambda: (
                BackendSpec(
                    name="egglog",
                    origin="malformed-test-extension",
                    load_manifest=lambda: manifest,
                ),
            )
        )

        with patch("d810.backends.registry", return_value=backend_registry):
            registry = operational_config_v2_pass_registry()

        self.assertIn(MBA_EGRAPH_PASS_ID, registry.public_pass_ids())
        self.assertIsNotNone(registry.editor_spec_for(MBA_EGRAPH_PASS_ID))
        self.assertEqual(registry.stages_for(MBA_EGRAPH_PASS_ID), ())
