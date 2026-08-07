"""Prove two expression trees equivalent with Z3.  No IDA dependency.

The obligation is **tree vs tree over free leaf variables**, not
``minsn`` vs ``minsn``.  A candidate's original instruction is only a fragment
(``and eax, ecx, ecx``); the expression under test is the def-use-inlined tree
spanning several instructions, so there is no single instruction to compare
against.

``z3`` is optional -- it is not a declared d810 dependency -- so its absence is
reported as ``UNAVAILABLE`` rather than raised.
"""

from __future__ import annotations

import enum

try:  # z3-solver is optional
    import z3

    _Z3_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on environment
    z3 = None  # type: ignore[assignment]
    _Z3_AVAILABLE = False


class ProofResult(enum.Enum):
    PROVED = "proved"
    REFUTED = "refuted"
    #: Solver gave up. Must be treated as failure: the timeout is a yield
    #: control, and at 20s three of sixty candidates timed out that were all
    #: provable at 300s. Log it distinctly from REFUTED -- they mean very
    #: different things.
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


#: Multiplication is where bitvector reasoning gets hard; be generous.  This
#: is the budget for the OFF-critical-path prover, which nobody is waiting on.
DEFAULT_TIMEOUT_MS = 120_000

#: Budget for a proof that a live decompilation is blocked on.
#:
#: Set from measurement, not taste.  Sorted proof times (ms) over the 14
#: accepted candidates on VM_DecryptPacket:
#:
#:     0  1  3  8  115  197  284  440  701  1611  6213  18554  68113  93610
#:
#: 98% of total proof time sits in 4 of those 14, so a tight budget sheds
#: almost all the cost and little of the value: 500ms keeps 8/14 for 4.05s of
#: inline time, while 1000ms buys exactly one more proof for +2.7s and 2000ms
#: buys two more for +7.3s.  500ms is the knee.
#:
#: Shortening this is SAFE but not free: a starved proof yields UNKNOWN, which
#: the caller must treat as "skip", so the cost is coverage.  Anything that
#: still needs proving escalates to DEFAULT_TIMEOUT_MS off the critical path.
INLINE_TIMEOUT_MS = 500


def z3_available() -> bool:
    return _Z3_AVAILABLE


def _to_z3(tree: dict, env: dict, bits: int, ctx=None):
    kind = tree["kind"]
    if kind == "const":
        # The context must be threaded all the way down: a term built in the
        # default context and combined with one built elsewhere raises
        # "Z3Exception: context mismatch".
        return z3.BitVecVal(tree["value"] & ((1 << bits) - 1), bits, ctx=ctx)
    if kind == "var":
        return env[tree["name"]]
    if kind == "un":
        operand = _to_z3(tree["a"], env, bits, ctx)
        return (-operand) if tree["op"] == "-" else (~operand)

    left = _to_z3(tree["a"], env, bits, ctx)
    right = _to_z3(tree["b"], env, bits, ctx)
    op = tree["op"]
    if op == "+":
        return left + right
    if op == "-":
        return left - right
    if op == "*":
        return left * right
    if op == "&":
        return left & right
    if op == "|":
        return left | right
    if op == "^":
        return left ^ right
    raise ValueError(f"unknown operator {op!r}")


def prove_equivalent(
    original: dict,
    rewrite: dict,
    leaf_names: list[str] | tuple[str, ...],
    bitwidth: int,
    *,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ctx=None,
) -> ProofResult:
    """Return whether *rewrite* is equivalent to *original* for all inputs.

    ``ctx`` is a ``z3.Context``.  **Every thread must supply its own.**  z3
    terms belong to a context and a context is not thread-safe: sharing the
    default one between the inline proof on the main thread and the escalation
    worker raises "Z3Exception: context mismatch", and inside IDA that
    exception escapes the rule into the Hex-Rays C++ callback and takes the
    process down with SIGSEGV.  Measured: EXIT=139 after two applications.
    """
    if not _Z3_AVAILABLE:
        return ProofResult.UNAVAILABLE

    env = {
        name: z3.BitVec(f"v{i}", bitwidth, ctx=ctx)
        for i, name in enumerate(leaf_names)
    }
    solver = z3.Solver(ctx=ctx)
    solver.set("timeout", timeout_ms)
    solver.add(
        _to_z3(original, env, bitwidth, ctx) != _to_z3(rewrite, env, bitwidth, ctx)
    )

    verdict = solver.check()
    if verdict == z3.unsat:
        return ProofResult.PROVED
    if verdict == z3.sat:
        return ProofResult.REFUTED
    return ProofResult.UNKNOWN
