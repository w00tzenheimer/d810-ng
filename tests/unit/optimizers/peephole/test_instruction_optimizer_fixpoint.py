"""Structural test: InstructionOptimizer must have a fixpoint loop."""
import pathlib

SRC = pathlib.Path(
    "src/d810/optimizers/microcode/instructions/handler.py"
).read_text()


def test_fixpoint_constant_exists():
    """A MAX_FIXPOINT_PASSES or equivalent ceiling must be present."""
    assert (
        "MAX_FIXPOINT" in SRC or "max_fixpoint" in SRC or "MAX_PASSES" in SRC
    ), "Missing fixpoint iteration ceiling constant"


def test_fixpoint_loop_present():
    """The block-processing method must loop until no rules fire."""
    assert (
        "while" in SRC and (
            "changed" in SRC or "any_change" in SRC or "num_change" in SRC
            or "total_change" in SRC
        )
    ), "Missing fixpoint while-loop driven by a change flag"
