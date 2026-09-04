"""Unit tests: ``_try_emulator_eval_address`` must use the exact-result API.

Regression for ticket ``d81-3xer`` (P1 review blocker): the emulator-based
address-resolution fallback called raw ``MicroCodeInterpreter.eval()`` and
accepted ANY integer ``> 0x10000`` as a plausible pointer.  That path bypasses
the exactness tracking added for ticket ``d81-1t9x`` (``EvalResult`` /
``Exactness`` / ``eval_mop`` / ``_require_exact``): a value derived from a
tainted synthetic call result could still be folded from as if it were a
proven address.

Rationale for source-level checks (same approach as
``test_fold_readonlydata_mop_v.py``): ``fold_readonlydata.py`` transitively
imports ``d810.hexrays.utils.hexrays_helpers``, which builds ``OPCODES_INFO``
at import time using every ``ida_hexrays.m_*`` opcode constant. Importing the
module in a shared pytest process depends on IDA stub state populated by
earlier test files, so behavioral coverage of the actual fold decision lives
in ``tests/system/runtime/``. The source-level checks below are the correct
unit-test layer for the wiring itself: they run with zero IDA dependency and
fail loudly if the raw, non-exact ``interpreter.eval(`` call ever comes back.
"""

from __future__ import annotations

import pathlib

_SRC = pathlib.Path(
    "src/d810/optimizers/microcode/instructions/peephole/fold_readonlydata.py"
)


def _read_src() -> str:
    return _SRC.read_text()


class TestEmulatorEvalAddressUsesExactResultApi:
    """``_try_emulator_eval_address`` must not call the raw, non-exact eval."""

    def test_raw_eval_call_is_absent(self) -> None:
        """The tainted-value-bypassing ``interpreter.eval(`` call is gone."""
        src = _read_src()
        assert "interpreter.eval(" not in src, (
            "_try_emulator_eval_address must not call the raw "
            "MicroCodeInterpreter.eval() -- it carries no exactness "
            "information, so a tainted (synthetic-call-derived) value can be "
            "mistaken for a proven address. Use eval_mop_result()/exact_value "
            "(or eval_mop()) instead."
        )

    def test_exact_result_api_is_used(self) -> None:
        """The exact-or-None evaluator API is used to resolve the address."""
        src = _read_src()
        assert "eval_mop_result(" in src or ".eval_mop(" in src, (
            "_try_emulator_eval_address must resolve the address through "
            "eval_mop_result()/eval_mop() so a tainted evaluation cannot "
            "become a fold address"
        )

    def test_address_from_eval_result_helper_is_used(self) -> None:
        """The pure exactness-checking helper decides what counts as an address."""
        src = _read_src()
        assert "address_from_eval_result" in src, (
            "_try_emulator_eval_address must route its result through "
            "address_from_eval_result() (d810.evaluator.hexrays_microcode."
            "p_taint) so only an EXACT evaluation can become a fold address"
        )
