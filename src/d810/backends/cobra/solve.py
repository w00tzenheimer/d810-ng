"""Drive cobra-cli and turn its answer back into a tree.

Kept separate from ``detect``/``convert`` so it carries no IDA dependency: the
solver only ever sees an expression string and a bit width.
"""

from __future__ import annotations

import dataclasses
import enum
import subprocess

from d810.backends.cobra.expr import (
    ExprParseError,
    parse_cobra_output,
    signature_of,
)
from d810.backends.cobra.probe import CobraProbe
from d810.core import getLogger

logger = getLogger(__name__)

#: cobra-cli is a solver, not a formatter; large inputs can take a while.
DEFAULT_TIMEOUT_SECONDS = 180

try:  # the in-process binding is built only when D810_BUILD_COBRA=1
    from d810.backends.cobra import _cobra

    _BINDING_AVAILABLE = True
    _BINDING_ERROR = ""
except ImportError as exc:  # pragma: no cover - depends on build configuration
    _cobra = None  # type: ignore[assignment]
    _BINDING_AVAILABLE = False
    # Keep the message. A wheel built with D810_BUILD_COBRA=0 and a wheel whose
    # extension failed to link are indistinguishable without it, and both
    # present as "mba-solve quietly does nothing".
    _BINDING_ERROR = str(exc)


class SolveStatus(enum.Enum):
    SOLVED = "solved"
    UNCHANGED = "unchanged"
    FAILED = "failed"


@dataclasses.dataclass(frozen=True)
class SolveResult:
    status: SolveStatus
    tree: dict | None = None
    raw_output: str = ""
    reason: str = ""

    @property
    def solved(self) -> bool:
        return self.status is SolveStatus.SOLVED


def binding_available() -> bool:
    """Whether the in-process solver binding was built."""
    return _BINDING_AVAILABLE


def d810_backend_probe() -> str | None:
    """Backend plugin protocol hook: ``None`` if usable, else why not.

    This module imports fine with or without the compiled extension, so import
    success is not evidence the backend works -- see
    :mod:`d810.core.plugins`.
    """
    if _BINDING_AVAILABLE:
        return None
    detail = f": {_BINDING_ERROR}" if _BINDING_ERROR else ""
    return (
        "native _cobra extension not built "
        "(rebuild with D810_BUILD_COBRA=1, or install a wheel that ships it)"
        f"{detail}"
    )


def solve_signature(
    tree: dict,
    leaf_names: list[str] | tuple[str, ...],
    bitwidth: int,
    *,
    max_vars: int = 16,
) -> SolveResult:
    """Solve *tree* in-process via the Cython binding.

    Preferred over :func:`solve_expression`: no subprocess, no text round-trip
    in either direction, and shifts are reachable (cobra-cli's tokenizer has no
    shift operator, so ``Expr::Kind::kShr`` can never come back through it).

    The solver sees only a signature, so it cannot report "unchanged" -- it has
    no input expression to compare against. A result identical to *tree* is
    therefore normal and is reported as UNCHANGED here by comparing directly.
    """
    if not _BINDING_AVAILABLE:
        return SolveResult(
            SolveStatus.FAILED,
            reason="CoBRA binding not built; rebuild with D810_BUILD_COBRA=1",
        )

    try:
        signature = signature_of(tree, leaf_names, bitwidth)
    except Exception as exc:  # noqa: BLE001 - a bad tree is a skip, not a crash
        return SolveResult(SolveStatus.FAILED, reason=f"could not evaluate: {exc}")

    try:
        solved = _cobra.simplify(
            signature, list(leaf_names), bitwidth, tree, max_vars
        )
    except ValueError as exc:
        return SolveResult(SolveStatus.FAILED, reason=str(exc))
    except Exception as exc:  # noqa: BLE001 - solver errors must not escape
        logger.debug("cobra binding raised: %s", exc)
        return SolveResult(SolveStatus.FAILED, reason=str(exc))

    if solved is None:
        return SolveResult(SolveStatus.UNCHANGED)
    if solved == tree:
        return SolveResult(SolveStatus.UNCHANGED)
    return SolveResult(SolveStatus.SOLVED, tree=solved)


def solve_expression(
    probe: CobraProbe,
    expression: str,
    bitwidth: int,
    leaf_names: list[str] | tuple[str, ...],
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> SolveResult:
    """Run cobra-cli on *expression* and parse the result.

    Never raises for an unavailable or misbehaving solver: a failure is a
    result, so a missing binary is indistinguishable from the feature being
    off.
    """
    if not probe.available or probe.path is None:
        return SolveResult(SolveStatus.FAILED, reason=probe.reason)

    try:
        completed = subprocess.run(
            [str(probe.path), "--mba", expression, "--bitwidth", str(bitwidth)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return SolveResult(SolveStatus.FAILED, reason=f"timeout after {timeout}s")
    except OSError as exc:
        return SolveResult(SolveStatus.FAILED, reason=f"could not run cobra-cli: {exc}")

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[:200]
        return SolveResult(
            SolveStatus.FAILED, reason=f"exit {completed.returncode}: {detail}"
        )

    output = completed.stdout.strip()
    if not output:
        return SolveResult(SolveStatus.FAILED, reason="empty output")

    if output.replace(" ", "") == expression.replace(" ", ""):
        return SolveResult(SolveStatus.UNCHANGED, raw_output=output)

    try:
        tree = parse_cobra_output(output, list(leaf_names))
    except ExprParseError as exc:
        return SolveResult(
            SolveStatus.FAILED, raw_output=output, reason=f"unparsable: {exc}"
        )

    return SolveResult(SolveStatus.SOLVED, tree=tree, raw_output=output)
