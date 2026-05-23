from __future__ import annotations

from unittest.mock import patch

import pytest

z3 = pytest.importorskip("z3")

from d810.backends.mba.z3 import Z3VerificationEngine
from d810.mba.dsl import Var
from d810.mba.verifier import VerificationOptions


def test_prove_equivalence_timeout_does_not_mutate_z3_global_state():
    engine = Z3VerificationEngine()
    x, y = Var("x"), Var("y")

    with patch.object(z3, "set_option", wraps=z3.set_option) as set_option:
        is_equivalent, counterexample = engine.prove_equivalence(
            (x | y) - (x & y),
            x ^ y,
            options=VerificationOptions(timeout_ms=500),
        )

    assert is_equivalent is True
    assert counterexample is None
    set_option.assert_not_called()
