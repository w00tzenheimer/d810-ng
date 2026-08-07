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


#: Multiplication is where bitvector reasoning gets hard; be generous.
DEFAULT_TIMEOUT_MS = 120_000


def z3_available() -> bool:
    return _Z3_AVAILABLE


def _to_z3(tree: dict, env: dict, bits: int):
    kind = tree["kind"]
    if kind == "const":
        return z3.BitVecVal(tree["value"] & ((1 << bits) - 1), bits)
    if kind == "var":
        return env[tree["name"]]
    if kind == "un":
        operand = _to_z3(tree["a"], env, bits)
        return (-operand) if tree["op"] == "-" else (~operand)

    left = _to_z3(tree["a"], env, bits)
    right = _to_z3(tree["b"], env, bits)
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
) -> ProofResult:
    """Return whether *rewrite* is equivalent to *original* for all inputs."""
    if not _Z3_AVAILABLE:
        return ProofResult.UNAVAILABLE

    env = {name: z3.BitVec(f"v{i}", bitwidth) for i, name in enumerate(leaf_names)}
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    solver.add(_to_z3(original, env, bitwidth) != _to_z3(rewrite, env, bitwidth))

    verdict = solver.check()
    if verdict == z3.unsat:
        return ProofResult.PROVED
    if verdict == z3.sat:
        return ProofResult.REFUTED
    return ProofResult.UNKNOWN
