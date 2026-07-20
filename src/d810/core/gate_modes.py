"Shared gate operation mode contract for flow unflattening rules.\n\nDefines a three-mode enum that standardises how each unflattening entry\npoint interacts with dispatcher-preanalysis gates.  The contract is\n**descriptive first** (documenting what each rule already does) and\n**prescriptive second** (future enforcement can switch modes at runtime).\n\nCurrent mapping of existing entry points\n-----------------------------------------\n\n+-------------------------------+-----------------+-----------------------------------+\n| Entry point                   | Effective mode  | Notes                             |\n+-------------------------------+-----------------+-----------------------------------+\n| OLLVM father-history backend  | GATE_ONLY       | evaluate_unflattening_gate()      |\n|                               |                 | enforced; no planner influence    |\n+-------------------------------+-----------------+-----------------------------------+\n| FixPredecessor                | GATE_ONLY       | evaluate_fix_predecessor_gate()   |\n|                               |                 | always enforced                   |\n+-------------------------------+-----------------+-----------------------------------+\n| MbaStatePreconditioner        | GATE_ONLY or    | require_unflattening_gate=True    |\n|                               | COLLECT_ONLY    | maps to GATE_ONLY; False maps to  |\n|                               |                 | COLLECT_ONLY                      |\n+-------------------------------+-----------------+-----------------------------------+\n| StateMachineCffUnflattener    | GATE_SELECT     | Full gate accounting + strategy   |\n|                               |                 | selection (when executor exists)   |\n+-------------------------------+-----------------+-----------------------------------+\n| CF Unflattener                | COLLECT_ONLY    | No flow-context gate; only bulk   |\n|                               |                 | safeguard (edge-count check)      |\n+-------------------------------+-----------------+-----------------------------------+\n"
from __future__ import annotations

import enum


class GateOperationMode(str, enum.Enum):
    "Shared gate operation mode for flow unflattening rules.\n\n    Three modes govern how a rule interacts with the dispatcher-preanalysis\n    gate infrastructure provided by :class:`FlowMaturityContext`:\n\n    ``COLLECT_ONLY``\n        Run preanalysis/analysis and record results, but **skip gate\n        enforcement**.  The rule always proceeds regardless of what the\n        gate would have decided.  Useful for early rollout or rules\n        that have their own independent safeguards (e.g. edge-count\n        checks).\n\n    ``GATE_ONLY``\n        Run preanalysis **and** enforce gates.  If the gate returns\n        ``allowed=False`` the rule is skipped.  The gate result does\n        **not** feed into strategy/planner selection.\n\n    ``GATE_SELECT``\n        Full mode: preanalysis + gate enforcement + planner-hint influence.\n        Gate results are recorded in gate accounting and may influence\n        downstream strategy selection (K6 hint scoring).\n\n    The default mode is ``GATE_SELECT`` so that new rules get the\n    strictest behaviour unless explicitly opted out.\n    "

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
