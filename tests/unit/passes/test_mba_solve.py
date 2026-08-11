"""Unit tests for the ``mba-solve`` config-v2 pass (no IDA)."""

from __future__ import annotations

import unittest

from d810.core.deobfuscation_case import StrategyWorkflowStage
from d810.passes.mba_solve import (
    DEFAULT_MAX_LEAVES,
    MBA_SOLVE_PASS_ID,
    MbaSolvePass,
    build_mba_solve_pass,
    mba_solve_pass_registry,
    parse_mba_solve_options,
)
from d810.passes.pass_pipeline import PipelineConfig


def _config(options: dict | None = None) -> PipelineConfig:
    return PipelineConfig(
        pass_id=MBA_SOLVE_PASS_ID,
        workflow_stage=StrategyWorkflowStage.FRONTEND_NORMALIZATION,
        options=options if options is not None else {},
    )


class TestAutoInstallSolver(unittest.TestCase):
    """Opt-in installation of the solver the proof gate needs.

    z3 is not a dependency: d810 keeps it in ~/.d810-speedups so the wheel and
    the native libz3 stay pinned together. That leaves a state where everything
    installs cleanly and no proof can be produced, so mba-solve applies nothing.
    This option lets a project close that gap by itself.
    """

    def test_defaults_to_off(self):
        """Installing runs pip: network, and tens of seconds of frozen UI.

        Doing that unprompted while a project loads would be a surprise with no
        way to decline, so it is opt-in and the workbench action is the
        discoverable path.
        """
        _, _, _, auto_install = parse_mba_solve_options(_config())
        self.assertFalse(auto_install)

    def test_can_be_enabled(self):
        _, _, _, auto_install = parse_mba_solve_options(
            _config({"auto_install_solver": True})
        )
        self.assertTrue(auto_install)

    def test_rejects_a_non_boolean(self):
        with self.assertRaises(ValueError):
            parse_mba_solve_options(_config({"auto_install_solver": "yes"}))

    def test_reaches_the_built_pass(self):
        built = build_mba_solve_pass(_config({"auto_install_solver": True}))
        self.assertTrue(built.auto_install_solver)

    def test_reaches_the_rule_through_the_hook_bridge(self):
        """An option the bridge drops is an option that silently does nothing.

        The pass validates it and the editor offers it, but the rule only ever
        sees what the bridge forwards -- so a missing key here produces a
        setting that looks configurable and has no effect.
        """
        from d810.passes.pipeline_v2_hook_bridge import _mba_solve_options

        forwarded = _mba_solve_options(_config({"auto_install_solver": True}))
        self.assertIs(forwarded["auto_install_solver"], True)

    def test_every_validated_option_is_forwarded_to_the_rule(self):
        """Guards the next option too, not just this one."""
        from d810.passes.pipeline_v2_hook_bridge import _mba_solve_options

        forwarded = set(_mba_solve_options(_config()))
        registry = mba_solve_pass_registry()
        template = registry.config_template_for(MBA_SOLVE_PASS_ID)
        self.assertEqual(forwarded, set(template.options))

    def test_is_offered_in_the_editor_and_seeded_in_the_template(self):
        """A JSON-only option is one nobody discovers."""
        registry = mba_solve_pass_registry()
        editor = registry.editor_spec_for(MBA_SOLVE_PASS_ID)
        template = registry.config_template_for(MBA_SOLVE_PASS_ID)

        field_ids = {field.field_id for field in editor.fields}
        self.assertIn("auto_install_solver", field_ids)
        self.assertIn("auto_install_solver", template.options)
        self.assertIs(template.options["auto_install_solver"], False)


class TestOptions(unittest.TestCase):
    def test_defaults(self):
        max_leaves, require_proof, maturities, _ = parse_mba_solve_options(_config())
        self.assertEqual(max_leaves, DEFAULT_MAX_LEAVES)
        self.assertTrue(require_proof)
        self.assertEqual(maturities, ("GLOBAL_OPTIMIZED",))

    def test_default_leaf_cap_is_8_not_16(self):
        # Signature cost is 2**n: 256 evaluations at 8, 65,536 at 16.
        self.assertEqual(DEFAULT_MAX_LEAVES, 8)

    def test_explicit_values(self):
        max_leaves, require_proof, maturities, _ = parse_mba_solve_options(
            _config({
                "max_leaves": 4,
                "require_proof": False,
                "maturities": ["GLOBAL_ANALYZED"],
            })
        )
        self.assertEqual(max_leaves, 4)
        self.assertFalse(require_proof)
        self.assertEqual(maturities, ("GLOBAL_ANALYZED",))

    def test_unknown_option_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            parse_mba_solve_options(_config({"nope": 1}))
        self.assertIn("nope", str(ctx.exception))

    def test_non_integer_leaf_cap_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_mba_solve_options(_config({"max_leaves": "8"}))

    def test_bool_is_not_an_integer_leaf_cap(self):
        with self.assertRaises(ValueError):
            parse_mba_solve_options(_config({"max_leaves": True}))

    def test_non_bool_require_proof_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_mba_solve_options(_config({"require_proof": "yes"}))


class TestPassConstruction(unittest.TestCase):
    def test_build_from_config(self):
        built = build_mba_solve_pass(_config({"max_leaves": 6}))
        self.assertIsInstance(built, MbaSolvePass)
        self.assertEqual(built.max_leaves, 6)
        self.assertEqual(built.name, MBA_SOLVE_PASS_ID)

    def test_rejects_nonsense_leaf_cap(self):
        with self.assertRaises(ValueError):
            MbaSolvePass(max_leaves=0)

    def test_refuses_an_explosive_leaf_cap(self):
        # 2**17 evaluations per candidate; refuse rather than crawl.
        with self.assertRaises(ValueError):
            MbaSolvePass(max_leaves=17)


class TestRegistry(unittest.TestCase):
    def test_pass_registers_under_its_id(self):
        registry = mba_solve_pass_registry()
        self.assertIn(MBA_SOLVE_PASS_ID, registry.registered_pass_ids())

    def test_registry_reports_it_as_configured(self):
        self.assertTrue(mba_solve_pass_registry().is_configured(MBA_SOLVE_PASS_ID))

    def test_template_runs_at_frontend_normalization(self):
        template = mba_solve_pass_registry().config_template_for(MBA_SOLVE_PASS_ID)
        self.assertEqual(
            template.workflow_stage, StrategyWorkflowStage.FRONTEND_NORMALIZATION
        )

    def test_template_defaults_are_conservative(self):
        template = mba_solve_pass_registry().config_template_for(MBA_SOLVE_PASS_ID)
        self.assertEqual(template.options["max_leaves"], DEFAULT_MAX_LEAVES)
        self.assertTrue(template.options["require_proof"])


if __name__ == "__main__":
    unittest.main()


class TestMaturitiesOption(unittest.TestCase):
    """Maturity must be config-driven, not hardcoded.

    Config speaks the portable IRMaturity vocabulary (CALL_MODELED,
    GLOBAL_ANALYZED), not IDA's MMAT_* -- the passes layer must stay
    hexrays-agnostic, and the rule does the mapping.

    Measured on VM_DecryptPacket: with CALL_MODELED (MMAT_CALLS) in the list
    the rule applied 61 rewrites over 87.6 minutes without finishing a
    decompile, so GLOBAL_ANALYZED (MMAT_GLBOPT1) -- the maturity the design was
    actually justified on -- was never reached. Comparing the two lists needs them selectable from config;
    monkeypatching the rule is unreliable because d810's reload machinery
    leaves several class copies in one process and a patch can miss the
    instance the manager built.
    """

    def test_defaults_to_glbopt2_only(self):
        pass_ = build_mba_solve_pass(
            PipelineConfig(
                pass_id=MBA_SOLVE_PASS_ID,
                workflow_stage=StrategyWorkflowStage.FRONTEND_NORMALIZATION,
                options={},
            )
        )
        self.assertEqual(pass_.maturities, ("GLOBAL_OPTIMIZED",))

    def test_accepts_an_explicit_single_maturity(self):
        pass_ = build_mba_solve_pass(
            PipelineConfig(
                pass_id=MBA_SOLVE_PASS_ID,
                workflow_stage=StrategyWorkflowStage.FRONTEND_NORMALIZATION,
                options={"maturities": ["GLOBAL_ANALYZED"]},
            )
        )
        self.assertEqual(pass_.maturities, ("GLOBAL_ANALYZED",))

    def test_rejects_an_unknown_maturity_name(self):
        with self.assertRaises(ValueError):
            build_mba_solve_pass(
                PipelineConfig(
                    pass_id=MBA_SOLVE_PASS_ID,
                    workflow_stage=StrategyWorkflowStage.FRONTEND_NORMALIZATION,
                    options={"maturities": ["NOT_A_MATURITY"]},
                )
            )

    def test_rejects_an_empty_maturity_list(self):
        """An empty list would silently disable the rule everywhere."""
        with self.assertRaises(ValueError):
            build_mba_solve_pass(
                PipelineConfig(
                    pass_id=MBA_SOLVE_PASS_ID,
                    workflow_stage=StrategyWorkflowStage.FRONTEND_NORMALIZATION,
                    options={"maturities": []},
                )
            )
