"""Z3-based single-iteration loop prover (diagnostic tool).

This module provides formal verification that a loop executes exactly once.
It serves as a **diagnostic tool** to detect residual single-iteration loops
after unflattening.

**Note**: The recommended fix for detected loops is to run the appropriate
unflattener with `min_comparison_value >= 2` (e.g., BadWhileLoop) rather
than implementing custom loop unrolling.

Pattern detected::

    for (state = INIT; state == CHECK; state = UPDATE) {
        body;
    }

A loop is single-iteration if:
1. INIT == CHECK (first iteration enters the loop)
2. UPDATE != CHECK (second iteration exits)

Example::

    for (state = 0xF6A1F; state == 0xF6A1F; state = 0xF6A20) {
        // body
    }

    prove_single_iteration(init=0xF6A1F, check=0xF6A1F, update=0xF6A20)
    # Returns True: enters once (0xF6A1F == 0xF6A1F), exits (0xF6A20 != 0xF6A1F)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from d810.core import getLogger

if TYPE_CHECKING:
    pass

logger = getLogger("D810.loop_prover")

# Try to import Z3, fall back to simple comparison if unavailable
try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    logger.warning("Z3 not available, using simple comparison for loop proving")


@dataclass
class SingleIterationLoop:
    """Represents a detected single-iteration loop.

    Attributes:
        block_serial: The block containing the loop check
        init_value: Value the loop variable is initialized to
        check_value: Value compared against in the loop condition
        update_value: Value assigned at end of loop body
        bit_width: Bit width of the loop variable (default 64)
        proven: Whether Z3 has proven this is single-iteration
    """
    block_serial: int
    init_value: int
    check_value: int
    update_value: int
    bit_width: int = 64
    proven: bool = False
    description: str = ""

    def __post_init__(self):
        if not self.description:
            self.description = (
                f"loop at block {self.block_serial}: "
                f"init={hex(self.init_value)}, check={hex(self.check_value)}, "
                f"update={hex(self.update_value)}"
            )


def prove_single_iteration_simple(
    init_value: int,
    check_value: int,
    update_value: int,
) -> bool:
    """Prove single-iteration using simple comparison (no Z3).

    For pattern: for (i = init; i == check; i = update)

    Single-iteration if:
    - init == check (enters loop)
    - update != check (exits after one iteration)

    Args:
        init_value: Initial value of loop variable
        check_value: Value compared in loop condition
        update_value: Value after loop body

    Returns:
        True if provably single-iteration
    """
    enters = (init_value == check_value)
    exits_after_one = (update_value != check_value)
    return enters and exits_after_one


def prove_single_iteration_z3(
    init_value: int,
    check_value: int,
    update_value: int,
    bit_width: int = 64,
) -> bool:
    """Prove single-iteration using Z3 SMT solver.

    For pattern: for (i = init; i == check; i = update)

    Uses Z3 to formally prove:
    - First iteration: init == check (must be SAT to enter)
    - Second iteration: update == check (must be UNSAT to exit)

    This handles edge cases like overflow that simple comparison might miss.

    Args:
        init_value: Initial value of loop variable
        check_value: Value compared in loop condition
        update_value: Value after loop body
        bit_width: Bit width for bitvector operations

    Returns:
        True if Z3 proves single-iteration
    """
    if not Z3_AVAILABLE:
        return prove_single_iteration_simple(init_value, check_value, update_value)

    # Create bitvector constants
    init_bv = z3.BitVecVal(init_value, bit_width)
    check_bv = z3.BitVecVal(check_value, bit_width)
    update_bv = z3.BitVecVal(update_value, bit_width)

    # Check 1: First iteration enters (init == check must be true)
    s1 = z3.Solver()
    s1.add(init_bv != check_bv)
    first_enters = (s1.check() == z3.unsat)  # UNSAT means init == check

    if not first_enters:
        logger.debug(
            "Loop does not enter: init=%s != check=%s",
            hex(init_value), hex(check_value)
        )
        return False

    # Check 2: Second iteration exits (update == check must be false)
    s2 = z3.Solver()
    s2.add(update_bv == check_bv)
    second_exits = (s2.check() == z3.unsat)  # UNSAT means update != check

    if not second_exits:
        logger.debug(
            "Loop does not exit after one iteration: update=%s == check=%s",
            hex(update_value), hex(check_value)
        )
        return False

    logger.debug(
        "Z3 proved single-iteration: init=%s, check=%s, update=%s",
        hex(init_value), hex(check_value), hex(update_value)
    )
    return True


def prove_single_iteration(
    init_value: int,
    check_value: int,
    update_value: int,
    bit_width: int = 64,
    use_z3: bool = True,
) -> bool:
    """Prove a loop executes exactly once.

    For pattern: for (i = init; i == check; i = update)

    Args:
        init_value: Initial value of loop variable
        check_value: Value compared in loop condition
        update_value: Value after loop body
        bit_width: Bit width for bitvector operations (Z3 only)
        use_z3: Use Z3 for formal verification (falls back to simple if unavailable)

    Returns:
        True if the loop provably executes exactly once

    Example::

        # Typical post-unflattening residual loop
        prove_single_iteration(
            init_value=0xF6A1F,    # state = 0xF6A1F
            check_value=0xF6A1F,   # state == 0xF6A1F
            update_value=0xF6A20,  # state = 0xF6A20
        )
        # Returns True
    """
    if use_z3 and Z3_AVAILABLE:
        return prove_single_iteration_z3(init_value, check_value, update_value, bit_width)
    return prove_single_iteration_simple(init_value, check_value, update_value)


@dataclass
class SingleIterationLoopTracker:
    """Tracks single-iteration loops detected during unflattening.

    Usage::

        tracker = SingleIterationLoopTracker()

        # During unflattening
        tracker.record_loop(
            block_serial=42,
            init_value=0xF6A1F,
            check_value=0xF6A1F,
            update_value=0xF6A20,
        )

        # Get proven loops for cleanup
        for loop in tracker.get_proven_loops():
            schedule_cleanup(loop)
    """
    loops: list[SingleIterationLoop] = field(default_factory=list)

    def record_loop(
        self,
        block_serial: int,
        init_value: int,
        check_value: int,
        update_value: int,
        bit_width: int = 64,
    ) -> SingleIterationLoop | None:
        """Record a potential single-iteration loop and verify it.

        Args:
            block_serial: Block containing the loop
            init_value: Initial value
            check_value: Check value
            update_value: Update value
            bit_width: Bit width of loop variable

        Returns:
            The loop if proven single-iteration, None otherwise
        """
        loop = SingleIterationLoop(
            block_serial=block_serial,
            init_value=init_value,
            check_value=check_value,
            update_value=update_value,
            bit_width=bit_width,
        )

        if prove_single_iteration(init_value, check_value, update_value, bit_width):
            loop.proven = True
            self.loops.append(loop)
            logger.info("Recorded proven single-iteration loop: %s", loop.description)
            return loop

        logger.debug("Loop not proven single-iteration: %s", loop.description)
        return None

    def get_proven_loops(self) -> list[SingleIterationLoop]:
        """Get all loops proven to be single-iteration."""
        return [loop for loop in self.loops if loop.proven]

    def clear(self) -> None:
        """Clear all tracked loops."""
        self.loops.clear()
