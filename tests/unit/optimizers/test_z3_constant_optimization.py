"""Source-level policy guard for the IDA-backed constant optimizer."""

from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest

from d810.backends.ast.z3_proof_policy import Z3ProofPolicy, Z3ProofResult
from d810.core.z3_proof import Z3ProofAbstentionReason, Z3ProofStatus


SOURCE = Path(
    "src/d810/optimizers/microcode/instructions/z3/cst.py"
).read_text(encoding="utf-8")
MODULE = ast.parse(SOURCE)


def _class() -> ast.ClassDef:
    return next(
        node
        for node in MODULE.body
        if isinstance(node, ast.ClassDef) and node.name == "Z3ConstantOptimization"
    )


def _method(name: str) -> ast.FunctionDef:
    return next(
        node
        for node in _class().body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


def test_z3_constant_optimizer_declares_policy_owned_transform_id() -> None:
    assignment = next(
        node
        for node in _class().body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "PROOF_TRANSFORM_ID"
            for target in node.targets
        )
    )

    assert ast.literal_eval(assignment.value) == "z-3-constant-optimization"


def test_z3_constant_optimizer_has_no_direct_unbounded_prover_construction() -> None:
    method = _method("_check_constant_candidate")
    direct_constructions = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Z3MopProver"
    ]
    owned_prover_calls = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "make_z3_mop_prover"
    ]
    proof_calls = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "prove_equal"
    ]

    assert direct_constructions == []
    assert len(owned_prover_calls) == 1
    assert len(proof_calls) == 1
    source = ast.unparse(method)
    assert "observe_z3_proof" in source
    assert "Z3ProofStatus.PROVED" in source


class _Candidate:
    def __init__(self) -> None:
        self.mop = SimpleNamespace(size=4)
        self.added_constants: list[tuple[str, int, int]] = []

    def get_information(self):
        return ([object()], [1, 2, 3], [10, 11, 12])

    def add_constant_leaf(self, name: str, value: int, size: int) -> None:
        self.added_constants.append((name, value, size))


class _ForbiddenDirectProver:
    def __init__(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("constant optimizer constructed an unbounded prover directly")


def _compiled_candidate_method(namespace: dict[str, object]):
    method = copy.deepcopy(_method("_check_constant_candidate"))
    method.decorator_list = []
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    exec(compile(module, "cst.py", "exec"), namespace)
    return namespace["_check_constant_candidate"]


@pytest.mark.parametrize(
    ("result", "expect_replacement"),
    (
        (Z3ProofResult(Z3ProofStatus.PROVED, None, 9, 1.5), True),
        (Z3ProofResult(Z3ProofStatus.DISPROVED, None, 9, 1.5), False),
        (
            Z3ProofResult(
                Z3ProofStatus.ABSTAINED,
                Z3ProofAbstentionReason.TIMEOUT,
                9,
                7.0,
            ),
            False,
        ),
        (
            Z3ProofResult(
                Z3ProofStatus.ABSTAINED,
                Z3ProofAbstentionReason.SOLVER_UNKNOWN,
                9,
                1.5,
            ),
            False,
        ),
    ),
)
def test_z3_constant_candidate_uses_contextual_bounded_policy_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    result: Z3ProofResult,
    expect_replacement: bool,
) -> None:
    candidate = _Candidate()
    replacement = object()
    observations: list[tuple[str, Z3ProofResult]] = []
    prover_contexts: list[tuple[object, object, Z3ProofPolicy]] = []
    evaluator_module = ModuleType("d810.evaluator.evaluators")
    evaluator_module.probe_is_constant = lambda ast, leaves: (True, 0x41)
    monkeypatch.setitem(sys.modules, evaluator_module.__name__, evaluator_module)

    namespace: dict[str, object] = {
        "ida_hexrays": SimpleNamespace(
            minsn_t=object,
            mop_t=lambda: SimpleNamespace(size=4),
        ),
        "minsn_to_ast": lambda instruction: candidate,
        "logger": SimpleNamespace(
            debug_on=False,
            debug=lambda *args, **kwargs: None,
            error=lambda *args, **kwargs: None,
        ),
        "format_minsn_t": lambda instruction: "candidate",
        "safe_make_number": lambda mop, value, size: None,
        "Z3MopProver": _ForbiddenDirectProver,
        "Z3ProofStatus": Z3ProofStatus,
        "AstProxy": type("AstProxy", (), {}),
        "AstNode": object,
        "typing": SimpleNamespace(cast=lambda typ, value: value),
        "AstEvaluationException": RuntimeError,
    }
    method = _compiled_candidate_method(namespace)

    class _Prover:
        def prove_equal(self, left: object, right: object) -> Z3ProofResult:
            return result

    class _Rule:
        min_nb_opcode = 3
        min_nb_constant = 3
        _current_blk = object()
        definition_search_ins = object()
        z3_proof_policy = Z3ProofPolicy(
            max_expression_nodes=31,
            proof_timeout_ms=7,
        )

        def make_z3_mop_prover(self, *, prover_cls=None):
            assert prover_cls is _ForbiddenDirectProver
            prover_contexts.append(
                (self._current_blk, self.definition_search_ins, self.z3_proof_policy)
            )
            return _Prover()

        def observe_z3_proof(self, operation: str, proof: Z3ProofResult) -> bool:
            observations.append((operation, proof))
            return True

        def get_replacement(self, candidate_ast: object) -> object:
            return replacement

    rule = _Rule()

    optimized = method(rule, object())

    assert optimized is (replacement if expect_replacement else None)
    assert prover_contexts == [
        (rule._current_blk, rule.definition_search_ins, rule.z3_proof_policy)
    ]
    assert observations == [("prove_equal", result)]
    assert candidate.added_constants == (
        [("c_res", 0x41, candidate.mop.size)] if expect_replacement else []
    )
