"""CoBRA backend: solve linear MBA that d810's pattern catalogue cannot match.

d810's 203 ``mba-simplify`` transforms are pattern-matched identities.  On
coefficient-based linear MBA they fire zero times -- measured, not assumed.
CoBRA (github.com/trailofbits/CoBRA) is a signature-driven solver that closes
exactly that gap.

Layout mirrors what each piece needs:

* ``expr``   -- parse/evaluate/accept.  Pure data, no IDA, unit-testable.
* ``probe``  -- locate the cobra-cli binary, or report a structured skip.

Everything that touches ``ida_hexrays`` (candidate detection, microcode
reconstruction) lives outside this pure core so that unit tests can exercise
the logic without IDA, per the import-linter contract.

Design and measurements:
``docs/plans/2026-08-06-cobra-mba-solve-integration.md``
"""

from __future__ import annotations

from d810.backends.cobra.expr import (
    ExprParseError,
    accept_rewrite,
    evaluate,
    node_count,
    parse_cobra_output,
)
from d810.backends.cobra.probe import CobraProbe, CobraStatus, find_cobra_cli

__all__ = [
    "CobraProbe",
    "CobraStatus",
    "ExprParseError",
    "accept_rewrite",
    "evaluate",
    "find_cobra_cli",
    "node_count",
    "parse_cobra_output",
]
