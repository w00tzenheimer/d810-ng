"""``TransitionProof.trusted`` must be a real boolean decision (d81-9q6e).

Round-2 ruling: a missing or non-boolean trust value fails closed *everywhere*
on the trust path, not only in the two duck-typed adapters.  ``TransitionProof``
is the recovery layer's own proof constructor and its ``trusted`` flag is read
back with ``bool(...)`` coercions by route-authority predicates
(``minimal_state_recovery.py:2709``, ``:6139``), so a non-boolean value stored
here would be laundered into a trusted row exactly as ``"false"`` was in
``branch_ownership``.

There is no untyped adapter for this type -- every producer is in-tree -- so
the gate belongs at construction, where it can raise instead of abstaining.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from d810.analyses.control_flow.minimal_state_recovery import TransitionProof


class TestTrustMustBeABoolean:
    @pytest.mark.parametrize("trusted", [True, False])
    def test_a_boolean_is_accepted(self, trusted: bool) -> None:
        proof = TransitionProof("fixpoint", "global_fold", trusted)
        assert proof.trusted is trusted

    @pytest.mark.parametrize(
        "trusted",
        ["true", "false", "", 1, 0, 1.0, None, [], {}],
    )
    def test_a_non_boolean_is_refused(self, trusted: object) -> None:
        with pytest.raises(TypeError):
            TransitionProof("fixpoint", "global_fold", trusted)  # type: ignore[arg-type]

    def test_the_refusal_names_the_field(self) -> None:
        with pytest.raises(TypeError, match="TransitionProof.trusted"):
            TransitionProof("fixpoint", "global_fold", "false")  # type: ignore[arg-type]


class TestEveryProducerPassesABoolean:
    """Static sweep, so a new producer cannot introduce a coercion."""

    @staticmethod
    def _trusted_arguments(path: pathlib.Path) -> list[tuple[int, str]]:
        tree = ast.parse(path.read_text())
        found: list[tuple[int, str]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "id", None) != "TransitionProof":
                continue
            keywords = {kw.arg: kw.value for kw in node.keywords}
            value = node.args[2] if len(node.args) > 2 else keywords.get("trusted")
            found.append(
                (node.lineno, "MISSING" if value is None else ast.unparse(value))
            )
        return found

    def test_no_producer_passes_a_non_boolean_expression(self) -> None:
        src_root = pathlib.Path(__file__).resolve().parents[4] / "src" / "d810"
        offenders: list[str] = []
        sites = 0
        for path in sorted(src_root.rglob("*.py")):
            for lineno, expression in self._trusted_arguments(path):
                sites += 1
                if expression == "MISSING":
                    offenders.append(f"{path}:{lineno}: no trusted argument")
                    continue
                if expression in {"True", "False"}:
                    continue
                if expression.startswith("not "):
                    continue
                offenders.append(f"{path}:{lineno}: {expression}")
        assert sites > 0, "found no TransitionProof construction sites at all"
        assert offenders == [], (
            "these TransitionProof producers pass a value that is not provably "
            f"a bool: {offenders}"
        )
