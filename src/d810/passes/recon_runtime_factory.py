"""Factory for the default portable recon/fact runtime bundle.

The manager decides when the recon pipeline is enabled and when project
profiles may extend it. This module owns the portable default collector
inventory and the ``ReconPhase`` / ``ReconAnalysisRuntime`` construction.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from d810.analyses.control_flow.cfg_shape import CFGShapeCollector
from d810.analyses.control_flow.compare_chain_collector import CompareChainCollector
from d810.analyses.control_flow.ctree_structure import CtreeStructureCollector
from d810.analyses.control_flow.dispatch_pattern import DispatchPatternCollector
from d810.analyses.control_flow.fixpred_signals import FixPredSignalsCollector
from d810.analyses.control_flow.handler_transitions import HandlerTransitionsCollector
from d810.analyses.control_flow.opcode_distribution import OpcodeDistributionCollector
from d810.analyses.control_flow.profile_classifier_collector import (
    FlowProfileClassifierCollector,
)
from d810.analyses.control_flow.return_frontier_collector import ReturnFrontierCollector
from d810.analyses.control_flow.state_transition_anchor import (
    StateTransitionAnchorFactCollector,
)
from d810.analyses.value_flow.byte_emit_corridor import ByteEmitCorridorFactCollector
from d810.analyses.value_flow.call_anchor import CallAnchorFactCollector
from d810.analyses.value_flow.folded_loop_guard import FoldedLoopGuardFactCollector
from d810.analyses.value_flow.induction_carrier import InductionVariableFactCollector
from d810.analyses.value_flow.loop_carrier import LoopPredicateValueFactCollector
from d810.analyses.value_flow.return_carrier import ReturnSlotFactCollector
from d810.analyses.value_flow.return_frontier import ReturnFrontierFactCollector
from d810.analyses.value_flow.state_write_anchor import StateWriteAnchorFactCollector
from d810.analyses.value_flow.terminal_byte_emitter import (
    TerminalByteEmitterFactCollector,
)
from d810.analyses.value_flow.zero_blob import ZeroBlobFactCollector
from d810.core.logging import getLogger
from d810.passes.analysis import AnalysisPhase
from d810.passes.artifacts import recon_db_path
from d810.passes.phase import ReconPhase
from d810.passes.runtime import ReconAnalysisRuntime
from d810.passes.store import ReconStore

logger = getLogger("D810.recon.factory")

DEFAULT_RECON_COLLECTOR_FACTORIES = (
    CFGShapeCollector,
    OpcodeDistributionCollector,
    DispatchPatternCollector,
    HandlerTransitionsCollector,
    ReturnFrontierCollector,
    CtreeStructureCollector,
    CompareChainCollector,
    FlowProfileClassifierCollector,
    FixPredSignalsCollector,
)
DEFAULT_RECON_COLLECTOR_NAMES = tuple(
    factory.name for factory in DEFAULT_RECON_COLLECTOR_FACTORIES
)

DEFAULT_FACT_COLLECTOR_FACTORIES = (
    InductionVariableFactCollector,
    LoopPredicateValueFactCollector,
    ReturnSlotFactCollector,
    TerminalByteEmitterFactCollector,
    ByteEmitCorridorFactCollector,
    CallAnchorFactCollector,
    ZeroBlobFactCollector,
    ReturnFrontierFactCollector,
    StateWriteAnchorFactCollector,
    StateTransitionAnchorFactCollector,
    FoldedLoopGuardFactCollector,
)
DEFAULT_FACT_COLLECTOR_NAMES = tuple(
    factory.name for factory in DEFAULT_FACT_COLLECTOR_FACTORIES
)


@dataclass(slots=True)
class ReconRuntimeBundle:
    """Default recon runtime objects and their owned store lifetime."""

    recon_phase: ReconPhase
    recon_runtime: ReconAnalysisRuntime
    db_path: Path
    default_fact_collector_count: int
    _store: ReconStore

    def close(self) -> None:
        try:
            self._store.close()
        except Exception:
            logger.exception("Failed to close recon store")


def register_default_recon_collectors(phase: ReconPhase) -> int:
    """Register the default portable recon collector inventory."""
    for factory in DEFAULT_RECON_COLLECTOR_FACTORIES:
        phase.register(factory())
    return len(DEFAULT_RECON_COLLECTOR_FACTORIES)


def register_default_fact_collectors(runtime: ReconAnalysisRuntime) -> int:
    """Register the default portable maturity fact collector inventory."""
    for factory in DEFAULT_FACT_COLLECTOR_FACTORIES:
        runtime.register_fact_collector(factory())
    return len(DEFAULT_FACT_COLLECTOR_FACTORIES)


def _create_default_recon_phase(
    log_dir: Path | str | None,
) -> tuple[ReconPhase, ReconStore, Path]:
    db_path = recon_db_path(log_dir)
    store = ReconStore(db_path)
    phase = ReconPhase(store=store)
    register_default_recon_collectors(phase)
    return phase, store, db_path


def build_recon_phase(log_dir: Path | str | None) -> ReconPhase | None:
    """Construct a ``ReconPhase`` with the default collector inventory."""
    try:
        phase, _store, db_path = _create_default_recon_phase(log_dir)
        logger.info(
            "ReconPhase enabled: %d collectors, db=%s",
            phase.collector_count,
            db_path,
        )
        return phase
    except Exception as exc:
        logger.warning("Failed to build recon pipeline: %s", exc)
        return None


def build_recon_runtime_bundle(
    *,
    log_dir: Path | str | None,
    config: dict | None = None,
    analysis_phase: AnalysisPhase | None = None,
) -> ReconRuntimeBundle | None:
    """Build the default recon phase and fact runtime bundle.

    ``config`` is accepted for the manager-facing API shape; project-specific
    profile registration remains in the manager so profiles can extend the
    runtime through the existing callback seam.
    """
    del config
    try:
        phase, store, db_path = _create_default_recon_phase(log_dir)
        runtime = ReconAnalysisRuntime(
            phase,
            analysis_phase or AnalysisPhase(),
            store,
        )
        fact_count = register_default_fact_collectors(runtime)
        logger.info(
            "ReconPhase enabled: %d collectors, db=%s",
            phase.collector_count,
            db_path,
        )
        logger.info(
            "ReconAnalysisRuntime enabled: %d fact collectors",
            fact_count,
        )
        return ReconRuntimeBundle(
            recon_phase=phase,
            recon_runtime=runtime,
            db_path=db_path,
            default_fact_collector_count=fact_count,
            _store=store,
        )
    except Exception as exc:
        logger.warning("Failed to build recon runtime bundle: %s", exc)
        return None
