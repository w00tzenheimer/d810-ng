"""Reduced-product machine recovery orchestration (P4, epic llr-ogr2, ticket llr-1d8u).

Composes the three CFF recovery engines (StaticShape pattern, AbstractInterp set-domain
spine, Concolic emulation) into ONE sound :class:`RecoveredMachine` via the textbook
reduced product: a sound abstract-interpretation spine refined by concolic execution of
its ⊤ cells, with EVERY refinement gated through the §7 completeness
:class:`~d810.analyses.machine.refinement_gate.CompletenessGate` so it can only narrow
soundly (the Z3-proven soundness obligation, truth
``reduced_product_cff_refinement/is_sound_iff``).

The orchestrator (:func:`recover_machine`) is opt-in only -- the ``RecoverDispatcher``
pass selects it when ``project_config["recovery_engine"] == "reduced_product"``; absent
that key the legacy single-engine path is byte-identical.

Re-exports the P1 contract (:class:`RecoveredMachine`) for convenience.

Portable: no IDA imports.
"""
from __future__ import annotations

from d810.analyses.control_flow.recovered_machine import (
    MachineRow,
    MachineTransition,
    RecoveredMachine,
    Soundness,
)
from d810.analyses.control_flow.machine_recovery_engine import (
    DispatcherAnchors,
    MachineRecoveryEngine,
)
from d810.analyses.machine.orchestrator import (
    compose_reduced_product,
    recover_machine,
)
from d810.analyses.machine.refinement_gate import (
    CompletenessGate,
    ConcolicCellValue,
    GateMode,
    TopCell,
    gamma_members,
)
from d810.analyses.machine.cross_validate import CrossValidation, cross_validate
from d810.analyses.machine.engine_rank import rank_machines, specificity
from d810.analyses.machine.k_escalation import (
    KBudget,
    should_escalate,
    should_escalate_density,
)

__all__ = [
    # P1 contract re-exports
    "RecoveredMachine",
    "MachineRow",
    "MachineTransition",
    "Soundness",
    "DispatcherAnchors",
    "MachineRecoveryEngine",
    # P4 orchestrator
    "recover_machine",
    "compose_reduced_product",
    # gate
    "CompletenessGate",
    "ConcolicCellValue",
    "GateMode",
    "TopCell",
    "gamma_members",
    # policy
    "cross_validate",
    "CrossValidation",
    "rank_machines",
    "specificity",
    "KBudget",
    "should_escalate",
    "should_escalate_density",
]
