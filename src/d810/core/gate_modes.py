"""Shared gate operation mode contract for flow unflattening rules.

Defines a three-mode enum that standardises how each unflattening entry
point interacts with dispatcher-recon gates.  The contract is
**descriptive first** (documenting what each rule already does) and
**prescriptive second** (future enforcement can switch modes at runtime).

Current mapping of existing entry points
-----------------------------------------

+-------------------------------+-----------------+-----------------------------------+
| Entry point                   | Effective mode  | Notes                             |
+-------------------------------+-----------------+-----------------------------------+
| GenericUnflatteningRule       | GATE_ONLY       | evaluate_unflattening_gate()      |
|                               |                 | enforced; no planner influence    |
+-------------------------------+-----------------+-----------------------------------+
| FixPredecessor                | GATE_ONLY       | evaluate_fix_predecessor_gate()   |
|                               |                 | always enforced                   |
+-------------------------------+-----------------+-----------------------------------+
| MbaStatePreconditioner        | GATE_ONLY or    | require_unflattening_gate=True    |
|                               | COLLECT_ONLY    | maps to GATE_ONLY; False maps to  |
|                               |                 | COLLECT_ONLY                      |
+-------------------------------+-----------------+-----------------------------------+
| HodurUnflattener              | GATE_SELECT     | Full gate accounting + strategy   |
|                               |                 | selection (when executor exists)   |
+-------------------------------+-----------------+-----------------------------------+
| CF Unflattener                | COLLECT_ONLY    | No flow-context gate; only bulk   |
|                               |                 | safeguard (edge-count check)      |
+-------------------------------+-----------------+-----------------------------------+
"""
from __future__ import annotations

import enum


class GateOperationMode(str, enum.Enum):
    """Shared gate operation mode for flow unflattening rules.

    Three modes govern how a rule interacts with the dispatcher-recon
    gate infrastructure provided by :class:`FlowMaturityContext`:

    ``COLLECT_ONLY``
        Run recon/analysis and record results, but **skip gate
        enforcement**.  The rule always proceeds regardless of what the
        gate would have decided.  Useful for early rollout or rules
        that have their own independent safeguards (e.g. edge-count
        checks).

    ``GATE_ONLY``
        Run recon **and** enforce gates.  If the gate returns
        ``allowed=False`` the rule is skipped.  The gate result does
        **not** feed into strategy/planner selection.

    ``GATE_SELECT``
        Full mode: recon + gate enforcement + planner-hint influence.
        Gate results are recorded in gate accounting and may influence
        downstream strategy selection (K6 hint scoring).

    The default mode is ``GATE_SELECT`` so that new rules get the
    strictest behaviour unless explicitly opted out.
    """

    COLLECT_ONLY = "collect_only"
    GATE_ONLY = "gate_only"
    GATE_SELECT = "gate_select"

    @property
    def enforces_gate(self) -> bool:
        """Return True if this mode enforces gate decisions."""
        return self is not GateOperationMode.COLLECT_ONLY

    @property
    def influences_planner(self) -> bool:
        """Return True if gate results feed into planner/strategy selection."""
        return self is GateOperationMode.GATE_SELECT
