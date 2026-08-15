"""Real-IDB structural matcher corpus for the paired native POD benchmark."""

from __future__ import annotations

import json

import pytest

from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test
from d810.optimizers.microcode.instructions.egraph.egglog_handler import (
    EgglogOptimizer,
)
from tests.system.e2e.egglog_native_corpus import (
    NativeEgglogCorpusEntry,
    build_native_egglog_attempt_receipt,
)
from tests.system.e2e.test_mba_compiler_shape_corpus import (
    _CATALOGUE_CASES,
    _build_native_corpus_binary,
    _catalogue_reaches_provider,
)


_PROFILE_PROJECT = "mba_compiler_shape_egglog_profile.json"
_DIRECT_RULES = {function: rule for function, rule in _CATALOGUE_CASES}
_SOURCE_NAMES_BY_RULE = {
    "Add_HackersDelightRule_2": (
        "Add_HackersDelightRule_2",
        "Add_OllvmRule_3",
    ),
}
_NONMATCH_FUNCTIONS = (
    tuple(f"mba_shape_coefficient_{index:02d}" for index in range(1, 11))
    + tuple(f"mba_shape_nonlinear_{index:02d}" for index in range(1, 9))
    + (
        "mba_shape_matcher_refusal_01",
        "mba_shape_matcher_refusal_02",
        "mba_shape_matcher_refusal_03",
    )
)
_PROFILE_FUNCTIONS = tuple(_DIRECT_RULES) + _NONMATCH_FUNCTIONS


def _native_ast_leaf_assignments(node):
    """Expose proof-side leaf identity for the one live parity boundary."""

    if node.is_leaf():
        mop = node.mop
        if hasattr(mop, "to_cache_key"):
            key = tuple(mop.to_cache_key())
        else:
            from d810.hexrays.expr.ast import get_mop_key

            key = tuple(get_mop_key(mop))
        return ("leaf", key, id(mop), repr(mop))
    return (
        "node",
        int(node.opcode),
        _native_ast_leaf_assignments(node.left),
        None if node.right is None else _native_ast_leaf_assignments(node.right),
    )


@pytest.mark.usefixtures("configure_hexrays")
class TestEgglogCompilerShapeProfile:
    """Thirty distinct real-IDB roots: direct matches and structural misses."""

    binary_name = "mba_compiler_shapes.dylib"

    @classmethod
    def setup_class(cls) -> None:
        _build_native_corpus_binary()

    @pytest.mark.parametrize("function", _PROFILE_FUNCTIONS)
    def test_records_one_real_matcher_attempt_per_compiler_shape(
        self,
        function: str,
        ida_database,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        expected_rule = _DIRECT_RULES.get(function)
        expect_provider_outcome = (
            expected_rule is not None and _catalogue_reaches_provider(function)
        )
        expect_mutation = expect_provider_outcome
        proof_boundaries = []
        if function == "mba_shape_catalogue_04":
            original_prove = EgglogOptimizer._prove_ast_equivalence

            def capture_proof(original, replacement, *, width, timeout_ms=50):
                verdict = original_prove(
                    original,
                    replacement,
                    width=width,
                    timeout_ms=timeout_ms,
                )
                proof_boundaries.append(
                    (
                        _native_ast_leaf_assignments(original),
                        _native_ast_leaf_assignments(replacement),
                        verdict,
                    )
                )
                return verdict

            monkeypatch.setattr(
                EgglogOptimizer,
                "_prove_ast_equivalence",
                staticmethod(capture_proof),
            )
        entry = NativeEgglogCorpusEntry(
            corpus="egglog-compiler-shapes",
            function=function,
            project=_PROFILE_PROJECT,
            expected_sources=(
                (_SOURCE_NAMES_BY_RULE.get(expected_rule, (expected_rule,)),)
                if expect_provider_outcome
                else ()
            ),
            expected_outcomes=("applied",) if expect_provider_outcome else (),
        )
        captured_attempts = ()

        def capture_runtime_state(state) -> None:
            nonlocal captured_attempts
            optimizer = next(
                rule
                for rule in state.current_ins_rules
                if rule.name == "EgglogOptimizer"
            )
            captured_attempts = optimizer.provider_outcomes()

        run_deobfuscation_test(
            DeobfuscationCase(
                function=function,
                description="real-IDB native POD matcher performance sample",
                project=_PROFILE_PROJECT,
                must_change=expect_mutation,
                required_rules=["EgglogOptimizer"] if expect_mutation else [],
                check_stats=True,
            ),
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            capture_runtime_state=capture_runtime_state,
        )

        if function == "mba_shape_catalogue_04":
            assert proof_boundaries
            assert all(boundary[-1] for boundary in proof_boundaries), proof_boundaries

        print(
            "\nEGGLOG_MBA_REAL_CORPUS_RECEIPT="
            + json.dumps(
                build_native_egglog_attempt_receipt(
                    captured_attempts,
                    entry=entry,
                ),
                sort_keys=True,
            )
        )
