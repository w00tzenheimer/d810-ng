from __future__ import annotations

import contextlib
import dataclasses
import inspect
import json
import os
import pathlib
import pstats
import sqlite3
import tempfile
import time

try:
    import cProfile
except ImportError:
    cProfile = None  # type: ignore[assignment]

from d810.backends.mba.ida import adapt_rules
from d810.core import (
    MOP_CONSTANT_CACHE,
    MOP_TO_AST_CACHE,
    typing,
)
from d810.core.config import D810Configuration, ProjectConfiguration
from d810.core.logging import clear_logs, configure_loggers, getLogger
from d810.core.persistence import ActiveRuleInferenceConfig, create_optimization_storage
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.core.platform import resolve_arch_config
from d810.core.project import ProjectContext, ProjectManager
from d810.core.registry import EventEmitter, SingletonMeta
from d810.core.rule_scope import (
    FunctionRuleOverlay,
    RuleInferenceOverlay,
    RuleScopeEvent,
    RuleScopeInvalidation,
    RuleScopeService,
)
from d810.core.stats import OptimizationStatistics
from d810.core.typing import TYPE_CHECKING
from d810.backends.ast.z3 import Z3MopProver
from d810.backends.hexrays.evidence import bst_analysis as _bst_evidence
from d810.capabilities.providers import BstWalkerProvider, register_bst_walkers
from d810.hexrays.hooks.ctree_hooks import CtreeOptimizationRule, CtreeOptimizerManager
from d810.hexrays.hooks.hexrays_hooks import (
    HEXRAYS_MICROCODE_PROVIDER,
    BlockOptimizerManager,
    DecompilationEvent,
    HexraysDecompilationHook,
    InstructionOptimizerManager,
)
from d810.mba.rules import VerifiableRule
from d810.optimizers.microcode.flow.context import FlowMaturityContext
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule
from d810.optimizers.microcode.instructions.handler import (
    InstructionOptimizationRule,
    InstructionOptimizer,
)
from d810.recon.collectors.cfg_shape import CFGShapeCollector
from d810.recon.collectors.compare_chain import CompareChainCollector
from d810.recon.collectors.ctree_structure import CtreeStructureCollector
from d810.recon.collectors.dispatch_pattern import DispatchPatternCollector
from d810.recon.collectors.fixpred_signals import FixPredSignalsCollector
from d810.recon.collectors.handler_transitions import HandlerTransitionsCollector
from d810.recon.collectors.opcode_distribution import OpcodeDistributionCollector
from d810.recon.collectors.profile_classifier import FlowProfileClassifierCollector
from d810.recon.collectors.return_frontier import ReturnFrontierCollector
from d810.recon.function_priors import FunctionAnalysisPriors
from d810.recon.flow.return_frontier_artifacts import (
    ReturnFrontierArtifactEdgeProof,
    ReturnFrontierArtifactPriors,
)
from d810.recon.flow.terminal_tail_priors import (
    TerminalTailCascadeEgressPriors,
    TerminalTailContinuationBridgePrior,
    TerminalTailEntryFrontierPriors,
    TerminalTailEqualityFrontierPriors,
    TerminalTailRowTargetOverride,
)
from d810.recon.facts.collectors import (
    ByteEmitCorridorFactCollector,
    CallAnchorFactCollector,
    InductionVariableFactCollector,
    LoopPredicateValueFactCollector,
    OllvmValueFlowEvidenceCollector,
    ReturnSlotFactCollector,
    ReturnFrontierFactCollector,
    StateTransitionAnchorFactCollector,
    StateWriteAnchorFactCollector,
    TerminalByteEmitterFactCollector,
    ZeroBlobFactCollector,
)
from d810.optimizers.microcode.microcode_dump import mba_to_dict
from d810.recon.analysis import AnalysisPhase
from d810.recon.inferences import unflattening_inference
from d810.recon.phase import ReconPhase
from d810.recon.runtime import ReconAnalysisRuntime
from d810.recon.store import ReconStore, shutdown_all_writers

try:
    import pyinstrument  # type: ignore
except ImportError:
    pyinstrument = None

if TYPE_CHECKING:
    from d810.ui.ida_ui import D810GUI


D810_LOG_DIR_NAME = "d810_logs"

logger = getLogger("D810")


def maybe_run_tail_distinct(mba: typing.Any) -> None:
    """Env-gated hook: ``D810_TAIL_DISTINCT_BYTE`` topology-only experiment.

    Thin manager-level re-export of the implementation in
    :mod:`d810.hexrays.mutation.byte_emit_tail_isolation_runtime`.  The real
    helper lives outside ``d810.manager`` so optimizer call sites can
    import it without crossing the layered-architecture import contract
    (optimizers must not depend on ``d810.ui``, and manager transitively
    imports UI).
    """
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        maybe_run_tail_distinct as _impl,
    )
    _impl(mba)


@dataclasses.dataclass(frozen=True, slots=True)
class PostD810ProtectedBundleSpec:
    """Diagnostic bundle that must remain sound across post-D810 compaction."""

    func_ea_i64: int
    maturity_name: str
    name: str
    pre_blocks: tuple[int, ...]
    pre_markers: tuple[str, ...]
    protected_offsets: tuple[int, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class PostD810HandoffViolation:
    """Diagnostic-only post-D810 invariant failure."""

    bundle_name: str
    pre_snapshot_id: int
    post_snapshot_id: int
    missing_def_offsets: tuple[int, ...]
    use_sites: tuple[str, ...]
    def_sites: tuple[str, ...]


_POST_D810_PROTECTED_BUNDLES: tuple[PostD810ProtectedBundleSpec, ...] = (
    PostD810ProtectedBundleSpec(
        func_ea_i64=0x180012B60,
        maturity_name="MMAT_GLBOPT1",
        name="sub7ffd_80_118_setup_bundle",
        pre_blocks=(80, 118),
        pre_markers=(
            "ldx    ds.2, %var_178.8, %var_230.8",
            "#-0x4B6C02C3E6626146.8",
            "#-0x4B6C02C3E6626145.8",
            "#0xE6334342.4",
            "#0x1C6BAB0E.4",
            "%var_230.8",
            "%var_678.8",
            "%var_680.8",
        ),
        protected_offsets=(0x4D8, 0x4E8),
    ),
    PostD810ProtectedBundleSpec(
        func_ea_i64=0x180012B60,
        maturity_name="MMAT_GLBOPT1",
        name="sub7ffd_223_221_private_setup_bundle",
        pre_blocks=(223, 221),
        pre_markers=(
            "ldx    ds.2, %var_178.8, %var_230.8",
            "#-0x4B6C02C3E6626146.8",
            "#-0x4B6C02C3E6626145.8",
            "%var_230.8",
            "%var_678.8",
            "%var_680.8",
        ),
        protected_offsets=(0x4D8, 0x4E8),
    ),
)


def _find_previous_snapshot_id(
    conn: sqlite3.Connection,
    *,
    func_ea_i64: int,
    maturity_name: str,
    phase: str,
    before_snapshot_id: int,
) -> int | None:
    row = conn.execute(
        """
        SELECT id
        FROM snapshots
        WHERE func_ea_i64 = ? AND maturity = ? AND phase = ? AND id < ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (int(func_ea_i64), str(maturity_name), str(phase), int(before_snapshot_id)),
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return int(row[0])


def _snapshot_contains_bundle_markers(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int,
    blocks: tuple[int, ...],
    markers: tuple[str, ...],
) -> bool:
    placeholders = ",".join("?" for _ in blocks)
    rows = conn.execute(
        f"""
        SELECT dstr
        FROM instructions
        WHERE snapshot_id = ? AND block_serial IN ({placeholders})
        ORDER BY block_serial, insn_index
        """,
        (int(snapshot_id), *[int(block) for block in blocks]),
    ).fetchall()
    if not rows:
        return False
    texts = tuple(str(row[0] or "") for row in rows)
    return all(any(marker in text for text in texts) for marker in markers)


def _collect_offset_sites(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int,
    offsets: tuple[int, ...],
) -> tuple[set[int], tuple[str, ...], set[int], tuple[str, ...]]:
    placeholders = ",".join("?" for _ in offsets)
    use_rows = conn.execute(
        f"""
        SELECT block_serial, insn_index, src_l_stkoff, src_r_stkoff, dstr
        FROM instructions
        WHERE snapshot_id = ?
          AND (src_l_stkoff IN ({placeholders}) OR src_r_stkoff IN ({placeholders}))
        ORDER BY block_serial, insn_index
        """,
        (
            int(snapshot_id),
            *[int(offset) for offset in offsets],
            *[int(offset) for offset in offsets],
        ),
    ).fetchall()
    def_rows = conn.execute(
        f"""
        SELECT block_serial, insn_index, dest_stkoff, dstr
        FROM instructions
        WHERE snapshot_id = ? AND dest_stkoff IN ({placeholders})
        ORDER BY block_serial, insn_index
        """,
        (int(snapshot_id), *[int(offset) for offset in offsets]),
    ).fetchall()

    used_offsets: set[int] = set()
    use_sites: list[str] = []
    for block_serial, insn_index, src_l_stkoff, src_r_stkoff, dstr in use_rows:
        if src_l_stkoff in offsets:
            used_offsets.add(int(src_l_stkoff))
        if src_r_stkoff in offsets:
            used_offsets.add(int(src_r_stkoff))
        use_sites.append(f"blk[{int(block_serial)}]:{int(insn_index)} {str(dstr or '')}")

    defined_offsets: set[int] = {int(row[2]) for row in def_rows if row[2] is not None}
    def_sites = tuple(
        f"blk[{int(block_serial)}]:{int(insn_index)} {str(dstr or '')}"
        for block_serial, insn_index, _, dstr in def_rows
    )
    return used_offsets, tuple(use_sites), defined_offsets, def_sites


def detect_post_d810_handoff_violations(
    conn: sqlite3.Connection,
    *,
    func_ea_i64: int,
    maturity_name: str,
    post_snapshot_id: int,
) -> tuple[PostD810HandoffViolation, ...]:
    """Detect protected-bundle def/use violations introduced at post-D810."""

    pre_snapshot_id = _find_previous_snapshot_id(
        conn,
        func_ea_i64=int(func_ea_i64),
        maturity_name=str(maturity_name),
        phase="post_pipeline",
        before_snapshot_id=int(post_snapshot_id),
    )
    if pre_snapshot_id is None:
        return ()

    violations: list[PostD810HandoffViolation] = []
    for bundle in _POST_D810_PROTECTED_BUNDLES:
        if int(bundle.func_ea_i64) != int(func_ea_i64):
            continue
        if bundle.maturity_name != str(maturity_name):
            continue
        if not _snapshot_contains_bundle_markers(
            conn,
            snapshot_id=pre_snapshot_id,
            blocks=bundle.pre_blocks,
            markers=bundle.pre_markers,
        ):
            continue
        used_offsets, use_sites, defined_offsets, def_sites = _collect_offset_sites(
            conn,
            snapshot_id=int(post_snapshot_id),
            offsets=bundle.protected_offsets,
        )
        if not used_offsets:
            continue
        missing_offsets = tuple(sorted(used_offsets - defined_offsets))
        if not missing_offsets:
            continue
        violations.append(
            PostD810HandoffViolation(
                bundle_name=bundle.name,
                pre_snapshot_id=int(pre_snapshot_id),
                post_snapshot_id=int(post_snapshot_id),
                missing_def_offsets=missing_offsets,
                use_sites=use_sites,
                def_sites=def_sites,
            )
        )
    return tuple(violations)


class CProfileWrapper:
    """
    A simple wrapper around cProfile.Profile that exposes an `.is_running` property.
    """

    def __init__(self):
        self._profiler = cProfile.Profile()
        self._is_running = False

    @property
    def is_running(self):
        return self._is_running

    def enable(self, *args, **kwargs):
        self._profiler.enable(*args, **kwargs)
        self._is_running = True

    def disable(self):
        self._profiler.disable()
        self._is_running = False

    @property
    def profiler(self):
        return self._profiler

    def snapshot(self, output_path: str) -> None:
        """Dump current stats to file and start a fresh profiler for the next segment."""
        if self._is_running:
            self._profiler.disable()
        self._profiler.dump_stats(output_path)
        self._profiler = cProfile.Profile()
        if self._is_running:
            self._profiler.enable()


def _maturity_name(maturity: int) -> str:
    """Map IDA maturity integer to a human-readable name for file labels."""
    try:
        import ida_hexrays

        _names = {
            ida_hexrays.MMAT_ZERO: "MMAT_ZERO",
            ida_hexrays.MMAT_GENERATED: "MMAT_GENERATED",
            ida_hexrays.MMAT_PREOPTIMIZED: "MMAT_PREOPTIMIZED",
            ida_hexrays.MMAT_LOCOPT: "MMAT_LOCOPT",
            ida_hexrays.MMAT_CALLS: "MMAT_CALLS",
            ida_hexrays.MMAT_GLBOPT1: "MMAT_GLBOPT1",
            ida_hexrays.MMAT_GLBOPT2: "MMAT_GLBOPT2",
            ida_hexrays.MMAT_GLBOPT3: "MMAT_GLBOPT3",
            ida_hexrays.MMAT_LVARS: "MMAT_LVARS",
        }
        return _names.get(maturity, f"MMAT_{maturity}")
    except ImportError:
        return f"MMAT_{maturity}"


@dataclasses.dataclass
class D810Manager:
    log_dir: pathlib.Path
    stats: OptimizationStatistics = dataclasses.field(
        default_factory=OptimizationStatistics
    )
    instruction_optimizer_rules: list = dataclasses.field(default_factory=list)
    instruction_optimizer_config: dict = dataclasses.field(default_factory=dict)
    block_optimizer_rules: list = dataclasses.field(default_factory=list)
    block_optimizer_config: dict = dataclasses.field(default_factory=dict)
    ctree_optimizer_rules: list = dataclasses.field(default_factory=list)
    ctree_optimizer_config: dict = dataclasses.field(default_factory=dict)
    config: dict = dataclasses.field(default_factory=dict)
    event_emitter: EventEmitter = dataclasses.field(default_factory=EventEmitter)
    rule_scope_service: RuleScopeService = dataclasses.field(
        default_factory=RuleScopeService
    )
    storage: typing.Any = None
    _active_rule_inference: RuleInferenceOverlay | None = dataclasses.field(
        default=None, init=False
    )
    profiler: typing.Any = dataclasses.field(
        default_factory=lambda: pyinstrument.Profiler() if pyinstrument else None
    )
    cprofiler: CProfileWrapper | None = dataclasses.field(
        default_factory=lambda: CProfileWrapper() if cProfile else None
    )
    instruction_optimizer: InstructionOptimizerManager = dataclasses.field(init=False)
    block_optimizer: BlockOptimizerManager = dataclasses.field(init=False)
    ctree_optimizer: CtreeOptimizerManager = dataclasses.field(init=False)
    hx_decompiler_hook: HexraysDecompilationHook = dataclasses.field(init=False)
    _started: bool = dataclasses.field(default=False, init=False)
    _profiling_enabled: bool = dataclasses.field(default=False, init=False)
    _start_ts: float = dataclasses.field(default=0.0, init=False)
    _recon_phase: typing.Any = dataclasses.field(default=None, init=False)
    _function_analysis_priors: dict[str, FunctionAnalysisPriors] = (
        dataclasses.field(default_factory=dict, init=False)
    )

    @property
    def started(self):
        return self._started

    @property
    def recon_db(self) -> pathlib.Path | None:
        """Path to the recon SQLite database, or None if recon is disabled."""
        rt = getattr(self, "_recon_runtime", None)
        if rt is None:
            return None
        return rt._store.db_path

    def configure(self, **kwargs):
        self.config = kwargs
        self._load_function_analysis_priors_from_config(
            kwargs.get("function_analysis_priors", {})
        )

    @staticmethod
    def _coerce_prior_constants(value: typing.Any) -> tuple[object, ...]:
        if value is None:
            return ()
        if isinstance(value, (str, int)):
            return (value,)
        try:
            return tuple(value)
        except TypeError:
            return (value,)

    @staticmethod
    def _coerce_prior_int_tuple(value: typing.Any) -> tuple[int, ...]:
        return tuple(
            int(item)
            for item in D810Manager._coerce_prior_constants(value)
        )

    @staticmethod
    def _load_return_frontier_edge_proofs(
        raw: typing.Any,
    ) -> tuple[ReturnFrontierArtifactEdgeProof, ...]:
        if not isinstance(raw, (list, tuple)):
            return ()
        proofs: list[ReturnFrontierArtifactEdgeProof] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                proofs.append(
                    ReturnFrontierArtifactEdgeProof(
                        source_block=int(item["source_block"]),
                        artifact_block=int(item["artifact_block"]),
                        old_target_block=int(item["old_target_block"]),
                        continuation_block=int(item["continuation_block"]),
                        proof_ids=tuple(
                            str(proof_id)
                            for proof_id in item.get("proof_ids", ())
                        ),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        return tuple(proofs)

    @staticmethod
    def _load_terminal_tail_cascade_priors(
        raw: typing.Any,
    ) -> TerminalTailCascadeEgressPriors:
        if not isinstance(raw, dict):
            return TerminalTailCascadeEgressPriors()

        row_target_overrides = []
        for item in raw.get("row_target_overrides", ()) or ():
            if not isinstance(item, dict):
                continue
            try:
                row_target_overrides.append(
                    TerminalTailRowTargetOverride(
                        byte_index=int(item["byte_index"]),
                        target_entry_byte_index=int(
                            item["target_entry_byte_index"]
                        ),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue

        continuation_bridges = []
        for item in raw.get("continuation_bridges", ()) or ():
            if not isinstance(item, dict):
                continue
            try:
                continuation_bridges.append(
                    TerminalTailContinuationBridgePrior(
                        continuation_byte_index=int(
                            item["continuation_byte_index"]
                        ),
                        source_byte_index=int(item["source_byte_index"]),
                        target_store_guard_byte_index=int(
                            item["target_store_guard_byte_index"]
                        ),
                        max_depth=int(item.get("max_depth", 8)),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue

        equality_raw = raw.get("equality_frontier")
        equality = None
        if isinstance(equality_raw, dict):
            try:
                equality = TerminalTailEqualityFrontierPriors(
                    return_frontier_byte_index=int(
                        equality_raw["return_frontier_byte_index"]
                    ),
                    row_byte_indices=D810Manager._coerce_prior_int_tuple(
                        equality_raw.get("row_byte_indices", ())
                    ),
                    shared_store_guard_byte_indices=(
                        D810Manager._coerce_prior_int_tuple(
                            equality_raw.get(
                                "shared_store_guard_byte_indices",
                                (),
                            )
                        )
                    ),
                )
            except (KeyError, TypeError, ValueError):
                equality = None

        entry_raw = raw.get("entry_frontier")
        entry = None
        if isinstance(entry_raw, dict):
            try:
                entry = TerminalTailEntryFrontierPriors(
                    first_byte_index=int(entry_raw["first_byte_index"])
                )
            except (KeyError, TypeError, ValueError):
                entry = None

        return TerminalTailCascadeEgressPriors(
            byte_indices=D810Manager._coerce_prior_int_tuple(
                raw.get("byte_indices", ())
            ),
            split_byte_indices=D810Manager._coerce_prior_int_tuple(
                raw.get("split_byte_indices", ())
            ),
            row_target_overrides=tuple(row_target_overrides),
            continuation_bridges=tuple(continuation_bridges),
            equality_frontier=equality,
            entry_frontier=entry,
        )

    def _load_function_analysis_priors_from_config(self, raw: typing.Any) -> None:
        self._function_analysis_priors = {}
        if not isinstance(raw, dict):
            return
        for function, raw_priors in raw.items():
            if not isinstance(raw_priors, dict):
                continue
            return_frontier = raw_priors.get("return_frontier_artifacts", {})
            if not isinstance(return_frontier, dict):
                return_frontier = {}
            constants = return_frontier.get(
                "known_impossible_return_constants",
                raw_priors.get("known_impossible_return_constants", ()),
            )
            artifact_priors = (
                ReturnFrontierArtifactPriors
                .from_known_impossible_return_constants(
                    self._coerce_prior_constants(constants)
                )
            )
            artifact_priors = artifact_priors.with_impossible_return_artifact_edges(
                self._load_return_frontier_edge_proofs(
                    return_frontier.get("impossible_return_artifact_edges", ())
                )
            )
            priors = FunctionAnalysisPriors(
                return_frontier_artifacts=artifact_priors,
                terminal_tail_cascade_egress=(
                    self._load_terminal_tail_cascade_priors(
                        raw_priors.get("terminal_tail_cascade_egress", {})
                    )
                ),
            )
            if not priors.is_empty:
                self.add_function_analysis_priors(function, priors)

    @staticmethod
    def _function_prior_keys(identifier: str | int) -> tuple[str, ...]:
        keys: set[str] = set()
        if isinstance(identifier, int):
            value = int(identifier)
            keys.add(str(value).lower())
            keys.add(f"0x{value:x}".lower())
            keys.add(f"sub_{value:x}".lower())
            return tuple(sorted(keys))

        raw = str(identifier).strip()
        if not raw:
            return tuple()
        keys.add(raw.lower())
        normalized = raw.lower()
        parse_target = normalized
        parse_base = 0
        if normalized.startswith("sub_"):
            parse_target = normalized[4:]
            parse_base = 16
        try:
            value = int(parse_target, parse_base)
        except ValueError:
            value = None
        if value is not None:
            keys.add(str(value).lower())
            keys.add(f"0x{value:x}".lower())
            keys.add(f"sub_{value:x}".lower())
        return tuple(sorted(keys))

    def snapshot_function_analysis_priors(self) -> dict[str, FunctionAnalysisPriors]:
        return dict(self._function_analysis_priors)

    def restore_function_analysis_priors(
        self,
        snapshot: dict[str, FunctionAnalysisPriors] | None,
    ) -> None:
        self._function_analysis_priors = dict(snapshot or {})

    def add_function_analysis_priors(
        self,
        function: str | int,
        priors: FunctionAnalysisPriors,
    ) -> None:
        existing = self.function_analysis_priors(function)
        merged = existing.merge(priors)
        for key in self._function_prior_keys(function):
            self._function_analysis_priors[key] = merged

    def function_analysis_priors(self, function: str | int) -> FunctionAnalysisPriors:
        for key in self._function_prior_keys(function):
            priors = self._function_analysis_priors.get(key)
            if priors is not None:
                return priors
        return FunctionAnalysisPriors()

    def function_analysis_priors_for_ea(self, func_ea: int) -> FunctionAnalysisPriors:
        identifiers: list[str | int] = [int(func_ea)]
        try:
            import ida_name

            name = ida_name.get_name(int(func_ea))
        except Exception:
            name = ""
        if name:
            identifiers.append(str(name))

        priors = FunctionAnalysisPriors()
        for identifier in identifiers:
            priors = priors.merge(self.function_analysis_priors(identifier))
        return priors

    def emit_rule_scope_invalidation(
        self,
        reason: RuleScopeEvent,
        *,
        project_name: str | None = None,
        func_eas: frozenset[int] | None = None,
        changed_rules: frozenset[str] | None = None,
    ) -> None:
        self.event_emitter.emit(
            reason,
            RuleScopeInvalidation(
                reason=reason,
                project_name=project_name,
                func_eas=func_eas,
                changed_rules=changed_rules,
            ),
        )

    @property
    def is_profiling(self) -> bool:
        """Return True if either cProfile or pyinstrument profiler is currently running."""
        if self.cprofiler and self.cprofiler.is_running:
            return True
        if self.profiler and getattr(self.profiler, "is_running", False):
            return True
        return False

    def start_profiling(self):
        if not self._profiling_enabled:
            return

        if self.cprofiler and not self.cprofiler.is_running:
            self.cprofiler.enable()
        if self.profiler and not self.profiler.is_running:
            self.profiler.start()

    def stop_profiling(self) -> pathlib.Path | None:
        if self.cprofiler and self.cprofiler.is_running:
            self.cprofiler.disable()
            output_path = self.log_dir / "d810_cprofile.prof"
            self.cprofiler.profiler.dump_stats(str(output_path))
            pstats.Stats(str(output_path)).strip_dirs().sort_stats("time").print_stats()
            return output_path
        if self.profiler and self.profiler.is_running:
            self.profiler.stop()
            self.profiler.print()
            # save the report as an HTML file in the log directory for easy access.
            output_path = self.log_dir / "d810_profile.html"
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(self.profiler.output_html())
            return output_path

    def enable_profiling(self):
        self._profiling_enabled = True
        self.start_profiling()

    def disable_profiling(self):
        self._profiling_enabled = False
        self.stop_profiling()

    def dump_profiling_segment(self, new_maturity: int) -> None:
        """Dump cProfile snapshot when maturity changes, then re-enable for next phase."""
        if not self._profiling_enabled:
            return
        if not self.cprofiler or not self.cprofiler.is_running:
            return
        label = _maturity_name(new_maturity)
        output_path = self.log_dir / f"d810_cprofile_{label}.prof"
        self.cprofiler.snapshot(str(output_path))
        logger.info("Profiling segment dumped for %s: %s", label, output_path)

    def capture_post_d810_mba(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        """Write post-maturity MBA snapshot when configured via environment."""
        from d810.core.settings import get_settings
        _s = get_settings()
        if _s.capture_post_maturity is None:
            return
        if int(maturity) != _s.capture_post_maturity:
            return
        capture_file = _s.capture_post_file
        try:
            data = mba_to_dict(mba)
            with open(capture_file, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            logger.info(
                "Post-D810 MBA captured at maturity %s -> %s (%d blocks)",
                _maturity_name(maturity),
                capture_file,
                data.get("num_blocks", -1),
            )
        except Exception:
            logger.exception("Post-D810 capture failed")

    def capture_post_d810_facts(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        """Capture maturity facts on the post-D810 snapshot.

        Pre-D810 fact capture happens in the Hex-Rays block hook before D810
        runs at a maturity.  Some fact classes are specifically about what D810
        leaves behind after reconstruction, so they need the matching
        post-D810 view as well.  The lifecycle runtime deduplicates by
        ``(func_ea, maturity, phase)``, making this a no-op on repeated events.

        ``snapshot`` is the SnapshotRef emitted by the hexrays hook's
        post-D810 capture; the persistence callback emits
        ``observe_fact_*`` events against it.
        """
        if self._recon_runtime is None:
            return
        try:
            func_ea = int(getattr(mba, "entry_ea", 0) or 0)
            provider_phase = ProviderPhaseSnapshot(
                provider_name="hexrays_microcode",
                provider_level=int(maturity),
                friendly_provider_level=_maturity_name(int(maturity)),
            )
            try:
                from d810.hexrays.fact_target import mba_to_fact_target

                target = mba_to_fact_target(mba)
            except Exception:
                logger.exception(
                    "Post-D810 fact target adaptation failed for func=0x%x; "
                    "skipping fact capture",
                    func_ea,
                )
                return
            self._recon_runtime.capture_maturity_facts(
                target,
                func_ea=func_ea,
                provider_phase=provider_phase,
                phase="post_d810",
                snapshot=snapshot,
            )
        except Exception:
            logger.exception("FactLifecycleRuntime post-D810 capture failed")

    def _collect_recon_on_flowgraph_ready(
        self,
        *,
        flow_graph,
        func_ea: int,
        maturity: int,
        maturity_name: str,
        producer: str | None = None,
        producer_stage_id: int | None = None,
        producer_stage_name: str | None = None,
        snapshot_stage: typing.Any = None,
        snapshot: typing.Any = None,
    ) -> None:
        """``FLOWGRAPH_READY`` handler for portable microcode analysis.

        E4a: replaces the two legacy ``run_microcode_collectors(mba, ...)``
        calls that used to live inline at the
        ``InstructionOptimizerManager`` / ``BlockOptimizerManager``
        maturity gates.  Both gates emit ``FLOWGRAPH_READY`` for the
        same ``(func_ea, maturity)`` -- the per-``(func_ea, maturity)``
        guard inside ``ReconPhase.run_microcode_collectors`` already
        dedupes collector saves, so two events fire but only one
        collection pass executes.

        Collectors that need a live ``mba_t`` are gone -- 7 of 8
        microcode collectors already had dual-path support
        (``FlowGraph`` duck-typed branch); ``handler_transitions``'s
        graph path activates when its metadata blob carries
        ``transition_result`` + ``dispatcher_entry_serial``, which
        is identical to the prior live-mba behavior (live path also
        required that metadata).  Producing real handler-transition
        metadata is a separate slice.

        E4b: this same subscriber also captures pre-D810 maturity
        facts from the portable ``FlowGraph``.  Capture runs on every
        event whether or not it carries the diagnostic ``snapshot`` --
        it is a production path (the captured ReturnCarrierFacts feed
        return-leak suppression).  The block-manager producer adds the
        ``snapshot`` for diagnostic DB attachment; the instruction
        manager carries none.  ``capture_maturity_facts`` decouples the
        two dedup keys ("fact capture fired" vs "diag attachment
        fired"), so the no-snapshot event capturing first does NOT
        prevent the snapshot-bearing event from later attaching
        observations to the diagnostic snapshot.

        (Regression note: gating capture on ``snapshot is not None``
        -- 217716af2 -- silently disabled fact capture in every
        non-diagnostic run, un-suppressing leaked terminal state
        constants.  Full diagnostics masked it because the snapshot
        was only ever present under ``--full-diagnostics``.)
        """
        if self._recon_phase is None and self._recon_runtime is None:
            return
        provider_phase = ProviderPhaseSnapshot(
            provider_name=HEXRAYS_MICROCODE_PROVIDER,
            provider_level=int(maturity),
            friendly_provider_level=str(maturity_name),
        )
        if self._recon_phase is not None:
            try:
                self._recon_phase.run_microcode_collectors(
                    flow_graph,
                    func_ea=int(func_ea),
                    provider_phase=provider_phase,
                )
            except Exception:
                logger.exception(
                    "ReconPhase FLOWGRAPH_READY collection failed at "
                    "func=0x%x maturity=%s",
                    int(func_ea),
                    maturity_name,
                )
        if self._recon_runtime is not None:
            # Pre-D810 fact capture is a PRODUCTION path: the captured
            # ReturnCarrierFacts feed return-leak suppression via
            # ``analyze_and_persist``.  It must run on every event regardless
            # of whether a diagnostic ``snapshot`` is present -- gating it on
            # ``snapshot is not None`` (217716af2) silently disabled capture in
            # non-diagnostic runs, which un-suppressed leaked terminal state
            # constants (e.g. sub_7FFD ``return 0xC5FB34A1D9A6E315``).  The
            # snapshot is forwarded only for diagnostic DB attachment, which
            # ``capture_maturity_facts`` decouples from capture itself.
            try:
                self._recon_runtime.capture_maturity_facts(
                    flow_graph,
                    func_ea=int(func_ea),
                    provider_phase=provider_phase,
                    phase="pre_d810",
                    snapshot=snapshot,
                )
            except Exception:
                logger.exception(
                    "FactLifecycleRuntime FLOWGRAPH_READY capture failed at "
                    "func=0x%x maturity=%s",
                    int(func_ea),
                    maturity_name,
                )

    def _resolve_post_d810_linearization_context(
        self,
        mba: typing.Any,
        target_maturity: int,
    ) -> tuple[int | None, int | None]:
        """Resolve dispatcher/state-var context for post-D810 rendering."""
        entry_ea = int(getattr(mba, "entry_ea", 0) or 0)
        candidates = [
            rule
            for rule in getattr(self.block_optimizer, "cfg_rules", ())
            if type(rule).__name__ == "HodurUnflattener"
            and int(getattr(rule, "_last_func_ea", 0) or 0) == entry_ea
        ]

        def _try_rules(rules: list[typing.Any]) -> tuple[int | None, int | None]:
            for rule in rules:
                dispatcher_serial: int | None = None
                dispatcher_ea = int(getattr(rule, "_last_dispatcher_ea", 0) or 0)
                if dispatcher_ea:
                    for i in range(int(getattr(mba, "qty", 0) or 0)):
                        blk = mba.get_mblock(i)
                        if blk is not None and int(getattr(blk, "start", 0) or 0) == dispatcher_ea:
                            dispatcher_serial = int(getattr(blk, "serial", i))
                            break
                if dispatcher_serial is None:
                    raw_serial = int(getattr(rule, "_last_dispatcher_serial", -1) or -1)
                    if 0 <= raw_serial < int(getattr(mba, "qty", 0) or 0):
                        dispatcher_serial = raw_serial

                if dispatcher_serial is None:
                    continue

                state_var_stkoff: int | None = None
                try:
                    state_machine = getattr(rule, "state_machine", None)
                    state_var_stkoff = rule._get_effective_state_var_stkoff(state_machine)
                except Exception:
                    state_var_stkoff = None
                return dispatcher_serial, state_var_stkoff
            return None, None

        exact_maturity = [
            rule
            for rule in candidates
            if getattr(rule, "_current_tracked_maturity", None) is None
            or int(getattr(rule, "_current_tracked_maturity", 0)) == int(target_maturity)
        ]
        dispatcher_serial, state_var_stkoff = _try_rules(exact_maturity)
        if dispatcher_serial is not None:
            return dispatcher_serial, state_var_stkoff
        dispatcher_serial, state_var_stkoff = _try_rules(candidates)
        if dispatcher_serial is not None:
            return dispatcher_serial, state_var_stkoff
        return None, None

    def attach_post_d810_rendered_program(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        """Attach a rendered linearized program to a post-D810 snapshot.

        ``snapshot`` is the SnapshotRef emitted by the hexrays hook's
        post-D810 capture. When ``None``, the diag pipeline is
        disabled / no capture happened, and there is nothing to attach.
        """
        from d810.core.settings import get_settings

        _s = get_settings()
        if _s.capture_post_maturity is None:
            return
        target_mat = _s.capture_post_maturity
        if int(maturity) != target_mat:
            return
        if int(getattr(mba, "qty", 0) or 0) <= 0:
            return
        if snapshot is None:
            return

        try:
            from d810.recon.flow.linearized_state_dag import (
                BoundaryInlineMode,
                ProgramCommentMode,
                ProgramRenderStrategy,
                RenderOrderStrategy,
            )
            from d810.optimizers.microcode.microcode_dump import (
                build_live_linearized_program,
                resolve_dispatcher_context_for_linearized_program,
            )
            from d810.recon.observability import observe_rendered_program

            dispatcher_serial, state_var_stkoff = self._resolve_post_d810_linearization_context(
                mba,
                int(maturity),
            )
            if dispatcher_serial is None:
                dispatcher_serial, state_var_stkoff = (
                    resolve_dispatcher_context_for_linearized_program(mba)
                )

            if dispatcher_serial is None or dispatcher_serial < 0:
                logger.debug(
                    "post_d810 linearized program skipped: no trusted dispatcher context "
                    "for func=0x%x maturity=%s",
                    int(getattr(mba, "entry_ea", 0) or 0),
                    _maturity_name(int(maturity)),
                )
                return

            program = build_live_linearized_program(
                mba,
                dispatcher_serial,
                state_var_stkoff=state_var_stkoff,
                order_strategy=RenderOrderStrategy.SEMANTIC,
                program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
                boundary_inline_mode=BoundaryInlineMode.INLINE_SINGLE_LEVEL,
                comment_mode=ProgramCommentMode.MINIMAL,
            )
            observe_rendered_program(snapshot, program)
        except Exception:
            logger.warning(
                "post_d810 rendered program attach failed for func=0x%x maturity=%s",
                int(getattr(mba, "entry_ea", 0) or 0),
                _maturity_name(int(maturity)),
                exc_info=True,
            )

    def probe_post_d810_glbopt_dce(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        """Run the GLBOPT DCE probe against byte-emit EAs from the environment.

        Triggered by ``D810_GLBOPT_DCE_EAS=0xAAA,0xBBB`` (comma-separated
        hex EAs).  The probe is non-destructive: it forces def/use lists
        ready via ``make_lists_ready()`` and logs IDA's classification of
        each byte-emit instruction so we can see *why* ``optimize_global``
        will DCE it between snap17 and snap18.
        """
        import os

        raw = os.environ.get("D810_GLBOPT_DCE_EAS", "")
        if not raw:
            return
        # Only probe at the first POST_D810_CAPTURE for the function (LOCOPT
        # event arrives with the mba already advanced to MMAT_GLBOPT1 -- the
        # state we actually want to inspect, prior to optimize_global running
        # its full kill pass).
        try:
            import ida_hexrays as _hx
            if int(maturity) != int(_hx.MMAT_LOCOPT):
                return
        except Exception:
            pass
        try:
            byte_emit_eas = [int(s.strip(), 0) for s in raw.split(",") if s.strip()]
        except ValueError:
            logger.warning(
                "D810_GLBOPT_DCE_EAS=%r is not parseable as comma-separated hex EAs",
                raw,
            )
            return
        if int(getattr(mba, "qty", 0) or 0) <= 0:
            return
        try:
            from d810.hexrays.diagnostics.glbopt_dce_probe import probe_byte_emit_dce

            lines = probe_byte_emit_dce(mba, byte_emit_eas)
        except Exception:
            logger.warning(
                "glbopt DCE probe failed for func=0x%x maturity=%s",
                int(getattr(mba, "entry_ea", 0) or 0),
                _maturity_name(int(maturity)),
                exc_info=True,
            )
            return
        report = "\n".join(lines)
        logger.warning(
            "\n[GLBOPT_DCE_PROBE func=0x%x maturity=%s]\n%s",
            int(getattr(mba, "entry_ea", 0) or 0),
            _maturity_name(int(maturity)),
            report,
        )

    def validate_post_d810_handoff(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        """Log diagnostic violations when post-D810 compaction orphans live uses."""
        if snapshot is None:
            return
        try:
            from d810.core.observability import (
                get_active_diag_conn,
                resolve_snapshot_id_for,
            )

            diag_db = get_active_diag_conn(int(getattr(mba, "entry_ea", 0) or 0))
            snapshot_id = resolve_snapshot_id_for(snapshot)
            if diag_db is None or snapshot_id is None:
                return
            violations = detect_post_d810_handoff_violations(
                diag_db,
                func_ea_i64=int(getattr(mba, "entry_ea", 0) or 0),
                maturity_name=_maturity_name(int(maturity)),
                post_snapshot_id=int(snapshot_id),
            )
            for violation in violations:
                missing_offsets = ", ".join(
                    f"0x{offset:X}" for offset in violation.missing_def_offsets
                )
                logger.warning(
                    "post_d810 handoff invalid for %s: snapshot %d -> %d left live uses "
                    "without defs for offsets [%s]; uses=%s defs=%s",
                    violation.bundle_name,
                    violation.pre_snapshot_id,
                    violation.post_snapshot_id,
                    missing_offsets,
                    list(violation.use_sites),
                    list(violation.def_sites),
                )
        except Exception:
            logger.debug("post_d810 handoff validation failed", exc_info=True)

    def start(self):
        if self._started:
            self.stop()
        logger.debug("Starting manager...")
        # Ensure side-effect registrants are loaded before manager construction.
        from d810.optimizers.microcode.instructions.pattern_matching import (  # noqa: F401
            experimental,
        )

        try:
            from d810.mba.backend_registry import get_egglog_provider

            if bool(get_egglog_provider("egglog").is_available()):
                from d810.optimizers.microcode.flow.egraph import (  # noqa: F401
                    block_optimizer,
                )
                from d810.optimizers.microcode.instructions.egraph import (  # noqa: F401
                    egglog_handler,
                )
        except ImportError:
            pass

        self.rule_scope_service.attach(self.event_emitter)
        self._init_storage()
        self.rule_scope_service.set_overlay_provider(self._get_rule_overlay)
        self.rule_scope_service.set_active_inference(self._active_rule_inference)
        self.rule_scope_service.register_inference("unflattening", unflattening_inference)

        # Instantiate core manager classes from registry
        self.instruction_optimizer = InstructionOptimizerManager(
            self.stats, self.log_dir, optimizer_cls=InstructionOptimizer
        )
        project_name = str(self.config.get("project_name", ""))
        idb_key = str(self.config.get("idb_key", project_name))
        self.instruction_optimizer.configure(
            **self.instruction_optimizer_config,
            rule_scope_service=self.rule_scope_service,
            rule_scope_project_name=project_name,
            rule_scope_idb_key=idb_key,
        )
        self.block_optimizer = BlockOptimizerManager(
            self.stats, self.log_dir, ctx_cls=FlowMaturityContext
        )
        self.block_optimizer.configure(
            **self.block_optimizer_config,
            rule_scope_service=self.rule_scope_service,
            rule_scope_project_name=project_name,
            rule_scope_idb_key=idb_key,
            function_priors_provider=self.function_analysis_priors_for_ea,
        )
        for rule in self.instruction_optimizer_rules:
            rule.log_dir = self.log_dir
            self.instruction_optimizer.add_rule(rule)

        for cfg_rule in self.block_optimizer_rules:
            cfg_rule.log_dir = self.log_dir
            self.block_optimizer.add_rule(cfg_rule)

        # Build PassPipeline when feature flag is enabled (default OFF), or when
        # the explicit loop-carrier experiment is requested. Zero overhead when
        # both are disabled - no imports of pass modules occur.
        _pass_pipeline = None
        _enable_pass_pipeline = bool(self.config.get("enable_pass_pipeline", False))
        _enable_loop_carrier_refresh = (
            os.environ.get("D810_LOOP_CARRIER_BACKEDGE_REFRESH", "").strip() == "1"
        )
        if _enable_pass_pipeline or _enable_loop_carrier_refresh:
            _pass_pipeline = self._build_pass_pipeline(
                include_default_cleanup=_enable_pass_pipeline,
                enable_loop_carrier_backedge_refresh=_enable_loop_carrier_refresh,
            )

        # Build ReconPhase when feature flag is enabled (default ON).
        # Passive collection with minimal overhead; disable with
        # "enable_recon_pipeline": false in project config.
        self._recon_phase = None
        if self.config.get("enable_recon_pipeline", True):
            self._recon_phase = self._build_recon_phase()

        # Wire recon phase + runtime into microcode optimizers.
        # The runtime provides reset_for_func() at decompilation start;
        # the phase dispatches collectors at each maturity.
        self._recon_runtime = None
        if self._recon_phase is not None:
            self._recon_runtime = ReconAnalysisRuntime(
                self._recon_phase,
                AnalysisPhase(),
                self._recon_phase._store,
            )
            self._recon_runtime.register_fact_collector(InductionVariableFactCollector())
            self._recon_runtime.register_fact_collector(LoopPredicateValueFactCollector())
            self._recon_runtime.register_fact_collector(OllvmValueFlowEvidenceCollector())
            self._recon_runtime.register_fact_collector(ReturnSlotFactCollector())
            self._recon_runtime.register_fact_collector(TerminalByteEmitterFactCollector())
            self._recon_runtime.register_fact_collector(ByteEmitCorridorFactCollector())
            self._recon_runtime.register_fact_collector(CallAnchorFactCollector())
            self._recon_runtime.register_fact_collector(ZeroBlobFactCollector())
            self._recon_runtime.register_fact_collector(ReturnFrontierFactCollector())
            self._recon_runtime.register_fact_collector(StateWriteAnchorFactCollector())
            self._recon_runtime.register_fact_collector(StateTransitionAnchorFactCollector())
            self.instruction_optimizer.configure(
                recon_phase=self._recon_phase,
                recon_runtime=self._recon_runtime,
            )
            self.block_optimizer.configure(
                recon_phase=self._recon_phase,
                recon_runtime=self._recon_runtime,
            )

        # Wire PassPipeline into BlockOptimizerManager so it fires at
        # MMAT_GLBOPT2, after the unflattener has run at MMAT_GLBOPT1.
        if _pass_pipeline is not None:
            self.block_optimizer.configure(pass_pipeline=_pass_pipeline)

        # Build ctree optimizer with recon phase and runtime from the start.
        self.ctree_optimizer = CtreeOptimizerManager(
            self.stats,
            recon_phase=self._recon_phase,
            recon_runtime=self._recon_runtime,
        )

        for ctree_rule in self.ctree_optimizer_rules:
            ctree_rule.log_dir = self.log_dir
            self.ctree_optimizer.add_rule(ctree_rule)

        self.hx_decompiler_hook = HexraysDecompilationHook(
            self.event_emitter.emit,
            ctree_optimizer_manager=self.ctree_optimizer,
            block_optimizer=self.block_optimizer,
        )
        self._compile_rule_scope()
        self._install_hooks()
        self._started = True

    def _init_storage(self) -> None:
        old_storage = self.storage
        backend = (
            str(self.config.get("function_rules_backend", "sqlite")).strip().lower()
        )
        target = self.config.get("function_rules_storage")
        if target is None:
            if backend == "sqlite":
                target = self.log_dir / "d810_function_rules.db"
            else:
                target = "$ d810.optimization_storage"
        try:
            if old_storage is not None:
                try:
                    old_storage.close()
                except Exception:
                    pass
            self.storage = create_optimization_storage(target, backend=backend)
            logger.info(
                "Function-rules storage configured: backend=%s target=%s",
                backend,
                target,
            )
            self._load_active_inference_from_storage()
            self.emit_rule_scope_invalidation(
                RuleScopeEvent.IDB_OVERLAY_RELOADED,
                project_name=str(self.config.get("project_name", "")),
            )
        except Exception as exc:
            self.storage = None
            logger.warning("Failed to initialize function-rules storage: %s", exc)
            self.emit_rule_scope_invalidation(
                RuleScopeEvent.IDB_OVERLAY_RELOADED,
                project_name=str(self.config.get("project_name", "")),
            )

    def _load_active_inference_from_storage(self) -> None:
        storage = self.storage
        if storage is None or not hasattr(storage, "get_active_rule_inference"):
            self._active_rule_inference = None
            self.rule_scope_service.set_active_inference(None)
            return
        persisted = storage.get_active_rule_inference()
        if persisted is None:
            self._active_rule_inference = None
            self.rule_scope_service.set_active_inference(None)
            return
        inference = RuleInferenceOverlay(
            name=str(persisted.name).strip() or "unnamed_inference",
            enabled_rules=frozenset(str(rule) for rule in persisted.enabled_rules),
            disabled_rules=frozenset(str(rule) for rule in persisted.disabled_rules),
            target_func_eas=frozenset(int(ea) for ea in persisted.target_func_eas),
            target_tags_any=frozenset(
                str(tag).strip()
                for tag in persisted.target_tags_any
                if str(tag).strip()
            ),
            target_tags_all=frozenset(
                str(tag).strip()
                for tag in persisted.target_tags_all
                if str(tag).strip()
            ),
            notes=str(persisted.notes),
        )
        self._active_rule_inference = inference
        self.rule_scope_service.set_active_inference(inference)
        self.emit_rule_scope_invalidation(
            RuleScopeEvent.INFERENCE_APPLIED,
            project_name=str(self.config.get("project_name", "")),
            changed_rules=frozenset(inference.enabled_rules | inference.disabled_rules),
        )

    def _get_rule_overlay(self, function_ea: int) -> FunctionRuleOverlay | None:
        storage = self.storage
        if storage is None:
            return None
        config = storage.get_function_rules(function_ea)
        if config is None:
            return None
        return FunctionRuleOverlay(
            enabled_rules=frozenset(config.enabled_rules),
            disabled_rules=frozenset(config.disabled_rules),
            function_tags=frozenset(config.tags),
        )

    def get_function_rule_override(self, function_addr: int):
        if self.storage is None:
            self._init_storage()
        if self.storage is None:
            return None
        return self.storage.get_function_rules(function_addr)

    def set_function_rule_override(
        self,
        *,
        function_addr: int,
        enabled_rules: typing.Optional[typing.Set[str]] = None,
        disabled_rules: typing.Optional[typing.Set[str]] = None,
        notes: str = "",
    ) -> None:
        if self.storage is None:
            self._init_storage()
        if self.storage is None:
            logger.warning("Function-rules storage unavailable; override not persisted")
            return
        self.storage.set_function_rules(
            function_addr=function_addr,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            notes=notes,
        )
        self.emit_rule_scope_invalidation(
            RuleScopeEvent.FUNCTION_OVERRIDE_UPDATED,
            project_name=str(self.config.get("project_name", "")),
            func_eas=frozenset({int(function_addr)}),
            changed_rules=frozenset(
                (enabled_rules or set()) | (disabled_rules or set())
            ),
        )

    def clear_function_rule_override(self, function_addr: int) -> None:
        if self.storage is None:
            self._init_storage()
        if self.storage is None:
            logger.warning("Function-rules storage unavailable; override not cleared")
            return

        existing = self.storage.get_function_rules(function_addr)
        if existing is None:
            return

        if existing.tags:
            self.storage.set_function_rules(
                function_addr=function_addr,
                enabled_rules=set(),
                disabled_rules=set(),
                notes="",
            )
        else:
            self.storage.clear_function_rules(function_addr)

        self.emit_rule_scope_invalidation(
            RuleScopeEvent.FUNCTION_OVERRIDE_UPDATED,
            project_name=str(self.config.get("project_name", "")),
            func_eas=frozenset({int(function_addr)}),
            changed_rules=frozenset(
                set(existing.enabled_rules) | set(existing.disabled_rules)
            ),
        )

    def get_function_tags(self, function_addr: int) -> set[str]:
        if self.storage is None:
            self._init_storage()
        if self.storage is None:
            return set()
        if not hasattr(self.storage, "get_function_tags"):
            return set()
        return set(self.storage.get_function_tags(function_addr))

    def set_function_tags(
        self,
        *,
        function_addr: int,
        tags: typing.Optional[typing.Set[str]] = None,
    ) -> None:
        if self.storage is None:
            self._init_storage()
        if self.storage is None:
            logger.warning("Function-rules storage unavailable; tags not persisted")
            return
        if not hasattr(self.storage, "set_function_tags"):
            logger.warning("Function-rules storage does not support function tags")
            return
        normalized_tags = {
            str(tag).strip() for tag in (tags or set()) if str(tag).strip()
        }
        self.storage.set_function_tags(function_addr, normalized_tags)
        self.emit_rule_scope_invalidation(
            RuleScopeEvent.FUNCTION_TAGS_UPDATED,
            project_name=str(self.config.get("project_name", "")),
            func_eas=frozenset({int(function_addr)}),
        )

    def set_active_rule_inference(
        self,
        *,
        inference_name: str,
        enabled_rules: typing.Optional[typing.Set[str]] = None,
        disabled_rules: typing.Optional[typing.Set[str]] = None,
        target_func_eas: typing.Optional[typing.Set[int]] = None,
        target_tags_any: typing.Optional[typing.Set[str]] = None,
        target_tags_all: typing.Optional[typing.Set[str]] = None,
        notes: str = "",
    ) -> None:
        if self.storage is None:
            self._init_storage()
        inference = RuleInferenceOverlay(
            name=str(inference_name).strip() or "unnamed_inference",
            enabled_rules=frozenset(enabled_rules or set()),
            disabled_rules=frozenset(disabled_rules or set()),
            target_func_eas=frozenset(int(ea) for ea in (target_func_eas or set())),
            target_tags_any=frozenset(
                str(tag).strip()
                for tag in (target_tags_any or set())
                if str(tag).strip()
            ),
            target_tags_all=frozenset(
                str(tag).strip()
                for tag in (target_tags_all or set())
                if str(tag).strip()
            ),
            notes=notes,
        )
        self._active_rule_inference = inference
        self.rule_scope_service.set_active_inference(inference)
        if self.storage is not None and hasattr(self.storage, "set_active_rule_inference"):
            self.storage.set_active_rule_inference(
                ActiveRuleInferenceConfig(
                    name=inference.name,
                    enabled_rules=set(inference.enabled_rules),
                    disabled_rules=set(inference.disabled_rules),
                    target_func_eas=set(inference.target_func_eas),
                    target_tags_any=set(inference.target_tags_any),
                    target_tags_all=set(inference.target_tags_all),
                    notes=inference.notes,
                )
            )
        self.emit_rule_scope_invalidation(
            RuleScopeEvent.INFERENCE_APPLIED,
            project_name=str(self.config.get("project_name", "")),
            changed_rules=frozenset(
                (enabled_rules or set()) | (disabled_rules or set())
            ),
        )

    def clear_active_rule_inference(self) -> None:
        if self.storage is None:
            self._init_storage()
        self._active_rule_inference = None
        self.rule_scope_service.set_active_inference(None)
        if self.storage is not None and hasattr(
            self.storage, "clear_active_rule_inference"
        ):
            self.storage.clear_active_rule_inference()
        self.emit_rule_scope_invalidation(
            RuleScopeEvent.INFERENCE_CLEARED,
            project_name=str(self.config.get("project_name", "")),
        )

    def get_active_rule_inference(self) -> RuleInferenceOverlay | None:
        return self._active_rule_inference

    def _compile_rule_scope(self) -> None:
        self.rule_scope_service.compile_base_rules(
            project_name=str(self.config.get("project_name", "")),
            instruction_rules=self.instruction_optimizer_rules,
            flow_rules=self.block_optimizer_rules,
            ctree_rules=self.ctree_optimizer_rules,
        )

    def _start_timer(self):
        self._start_ts = time.perf_counter()

    def _stop_timer(self, report: bool = True):
        if report:
            m, s = divmod(time.perf_counter() - self._start_ts, 60)
            logger.info(
                "Decompilation finished in %dm %ds",
                int(m),
                int(s),
            )
        self._start_ts = 0.0

    def _install_hooks(self):
        # must become before listeners are installed
        for _subscriber in (
            self.start_profiling,
            self.stats.reset,
            MOP_CONSTANT_CACHE.clear,
            MOP_TO_AST_CACHE.clear,
            Z3MopProver().clear_caches,
            self.instruction_optimizer.reset_cycle_detection,
            self.block_optimizer.reset_pass_counter,
            self.block_optimizer.reset_pipeline_tracker,
            self.block_optimizer.reset_perf_counters,
            self._start_timer,
        ):
            self.event_emitter.on(DecompilationEvent.STARTED, _subscriber)

        for _subscriber in (
            self.stop_profiling,
            self.stats.report,
            lambda: logger.info(
                "MOP_CONSTANT_CACHE stats: %s", MOP_CONSTANT_CACHE.stats
            ),
            lambda: logger.info("MOP_TO_AST_CACHE stats: %s", MOP_TO_AST_CACHE.stats),
            self.block_optimizer.report_perf_counters,
            self._stop_timer,
        ):
            self.event_emitter.on(DecompilationEvent.FINISHED, _subscriber)

        if self._recon_runtime is not None:
            self.event_emitter.on(
                DecompilationEvent.FINISHED,
                self._recon_runtime.mark_decompilation_finished,
            )

        # E4a/E4b: single shared FLOWGRAPH_READY subscriber for the
        # portable microcode analysis path.  Both manager maturity
        # gates emit this event for the same ``(func_ea, maturity)``;
        # ``ReconPhase.run_microcode_collectors`` dedupes by
        # ``(func_ea, maturity)`` internally, while pre-D810 fact
        # capture only runs on the block-manager event carrying a
        # diagnostic snapshot.
        if self._recon_phase is not None or self._recon_runtime is not None:
            self.event_emitter.on(
                DecompilationEvent.FLOWGRAPH_READY,
                self._collect_recon_on_flowgraph_ready,
            )

        self.event_emitter.on(
            DecompilationEvent.MATURITY_CHANGED, self.dump_profiling_segment
        )
        self.event_emitter.on(
            DecompilationEvent.POST_D810_CAPTURE, self.capture_post_d810_mba
        )
        self.event_emitter.on(
            DecompilationEvent.POST_D810_CAPTURE, self.attach_post_d810_rendered_program
        )
        self.event_emitter.on(
            DecompilationEvent.POST_D810_CAPTURE, self.validate_post_d810_handoff
        )
        self.event_emitter.on(
            DecompilationEvent.POST_D810_CAPTURE, self.probe_post_d810_glbopt_dce
        )

        self.instruction_optimizer.event_emitter = self.event_emitter
        self.block_optimizer.event_emitter = self.event_emitter
        self.instruction_optimizer.install()
        self.block_optimizer.install()
        self.hx_decompiler_hook.hook()

    def _build_pass_pipeline(
        self,
        *,
        include_default_cleanup: bool = True,
        enable_loop_carrier_backedge_refresh: bool = False,
    ):
        """Construct a PassPipeline with the 2 safe cleanup FlowGraphTransformes for MMAT_GLBOPT2.

        Only called when config["enable_pass_pipeline"] is True. Imports are
        deferred here so that pass modules are never loaded when the flag is
        disabled (zero overhead guarantee).

        The following transform are included:
        - SimplifyIdenticalBranchPass: 2-way blocks with identical targets -> goto
          (emits ConvertToGoto / RedirectBranch, handled correctly by deferred modifier)
        - GotoChainRemovalPass: consecutive goto chains -> direct target
          (emits RedirectGoto / RedirectBranch, handled correctly by deferred modifier)

        The following transform are intentionally excluded at MMAT_GLBOPT2:
        - DeadBlockEliminationPass: emits NopInstructions which calls blk.make_nop().
          make_nop() removes the goto but does not update block type or edges, so
          mba.verify(True) rejects the inconsistent state at MMAT_GLBOPT2.
        - BlockMergeTransform: same reason - emits NopInstructions on trailing
          gotos, which leaves dangling edges that fail verification at
          MMAT_GLBOPT2. The cleanup-family tail-goto merge strategy owns this
          NOP cleanup in project flow-rule configuration instead.

        OpaqueJumpFixerPass and FakeJumpFixerPass are also excluded -
        they require pre-computed fix dicts from the legacy analysis side.

        Returns:
            PassPipeline instance with IDAIRTranslator and the 2 safe cleanup transform.
        """
        from d810.cfg.pipeline import FlowGraphTransformPipeline
        from d810.cfg.transform.simplify_identical_branch import (
            SimplifyIdenticalBranchPass,
        )
        from d810.hexrays.mutation.ir_translator import IDAIRTranslator
        from d810.hexrays.mutation.transform.goto_chain_removal import (
            GotoChainRemovalPass,
        )

        backend = IDAIRTranslator()
        passes = []
        if include_default_cleanup:
            passes.extend(
                [
                    SimplifyIdenticalBranchPass(),
                    GotoChainRemovalPass(),
                ]
            )
        if enable_loop_carrier_backedge_refresh:
            from d810.cfg.transform.loop_carrier_backedge_refresh import (
                LoopCarrierBackedgeRefreshPass,
            )

            def _fact_view_provider(func_ea: int, maturity: int | str):
                if self._recon_runtime is None:
                    return None
                if isinstance(maturity, int):
                    maturity = _maturity_name(maturity)
                return self._recon_runtime.validated_fact_view(func_ea, maturity)

            passes.append(
                LoopCarrierBackedgeRefreshPass(
                    fact_view_provider=_fact_view_provider,
                )
            )
        pipeline = FlowGraphTransformPipeline(backend, passes)
        logger.info(
            "PassPipeline enabled: %s",
            repr(pipeline),
        )
        return pipeline

    def _build_recon_phase(self) -> "ReconPhase | None":
        """Construct a ReconPhase with all flow-recovery collectors.

        Only called when config["enable_recon_pipeline"] is True (the default).
        Imports are guarded at module level - if the recon package is unavailable
        this returns None and the plugin loads normally.

        Returns:
            ReconPhase instance with all collectors registered, or None on failure.
        """
        try:
            db_path = (self.log_dir / "d810_recon.db") if self.log_dir else None
            if db_path is None:
                db_path = pathlib.Path(tempfile.gettempdir()) / "d810_recon.db"
            store = ReconStore(db_path)
            phase = ReconPhase(store=store)
            phase.register(CFGShapeCollector())
            phase.register(OpcodeDistributionCollector())
            phase.register(DispatchPatternCollector())
            phase.register(HandlerTransitionsCollector())
            phase.register(ReturnFrontierCollector())
            phase.register(CtreeStructureCollector())
            phase.register(CompareChainCollector())
            phase.register(FlowProfileClassifierCollector())
            phase.register(FixPredSignalsCollector())
            logger.info(
                "ReconPhase enabled: %d collectors, db=%s",
                phase.collector_count,
                db_path,
            )
            return phase
        except Exception as exc:
            logger.warning("Failed to build recon pipeline: %s", exc)
            return None

    def configure_instruction_optimizer(self, rules, **kwargs):
        self.instruction_optimizer_rules = list(rules)
        self.instruction_optimizer_config = kwargs

    def configure_block_optimizer(self, rules, **kwargs):
        self.block_optimizer_rules = list(rules)
        self.block_optimizer_config = kwargs

    def configure_ctree_optimizer(self, rules, **kwargs):
        self.ctree_optimizer_rules = list(rules)
        self.ctree_optimizer_config = kwargs

    def stop(self):
        if not self._started:
            return
        self._started = False

        self.instruction_optimizer.remove()
        self.block_optimizer.remove()
        self.hx_decompiler_hook.unhook()
        shutdown_all_writers()
        self.event_emitter.clear()
        if self.profiler or self.cprofiler:
            self.stop_profiling()
        if self.storage is not None:
            try:
                self.storage.close()
            except Exception:
                pass
            self.storage = None
        if self._recon_phase is not None:
            try:
                self._recon_phase._store.close()
            except Exception:
                pass
            self._recon_phase = None


@contextlib.contextmanager
def d810_hooks_suppressed(manager: D810Manager):
    """Temporarily suppress d810ng optimization hooks for clean decompilation.

    Used to get pre-deobfuscation microcode snapshots by decompiling
    with d810ng hooks temporarily removed.

    Args:
        manager: The D810Manager instance whose hooks should be temporarily removed.

    Yields:
        None

    Example:
        >>> with d810_hooks_suppressed(state.manager):
        ...     # Decompile with hooks disabled to get pre-deobfuscation state
        ...     mba = gen_microcode(func_ea, maturity)
    """
    if not manager.started:
        # If manager not started, hooks aren't installed anyway
        yield
        return

    # Remove optimizer hooks
    manager.instruction_optimizer.remove()
    manager.block_optimizer.remove()
    try:
        yield
    finally:
        # Restore optimizer hooks
        manager.instruction_optimizer.install()
        manager.block_optimizer.install()


class D810State(metaclass=SingletonMeta):
    """
    State class representing the runtime state of the D810 plugin.

    This class is responsible for managing the configuration, the project
    manager, the current project, the current instruction and block rules,
    the known instruction and block rules, and the D810 manager.

    It also provides a GUI for the plugin.
    """

    # placeholders for runtime state
    log_dir: pathlib.Path
    manager: D810Manager
    gui: D810GUI
    current_project: ProjectConfiguration

    def __init__(self):
        self.gui = None  # Set by load(gui=True)
        self.reset()

    def is_loaded(self):
        return self._is_loaded

    @property
    def stats(self) -> OptimizationStatistics:
        """Forward stats access to the manager."""
        if hasattr(self, "manager") and self.manager is not None:
            return self.manager.stats
        # Return a fresh stats object if manager not yet initialized
        return OptimizationStatistics()

    def reset(self, d810_config: D810Configuration | None = None) -> None:
        self._initialized: bool = False
        self.d810_config: D810Configuration = d810_config or D810Configuration()
        # manage projects via ProjectManager
        self.project_manager = ProjectManager(self.d810_config)
        self.current_project_index: int = 0
        self.current_ins_rules: typing.List = []
        self.current_blk_rules: typing.List = []
        self.known_ins_rules: typing.List = []
        self.known_blk_rules: typing.List = []
        self._is_loaded: bool = False
        self.gui = None  # Reset gui reference
        # Perform logger setup based on current config
        self.log_dir = self.d810_config.log_dir / D810_LOG_DIR_NAME
        if self.d810_config.get("erase_logs_on_reload"):
            clear_logs(self.log_dir)
        configure_loggers(self.log_dir)
        # Always rely on the D810Configuration.log_dir property which falls back
        # to a sensible default when the option is missing, instead of reading
        # the raw option that may be None and break pathlib.Path construction.
        self.manager = D810Manager(self.log_dir)
        self._initialized = True

    def add_project(self, config: ProjectConfiguration):
        self.project_manager.add(config)

    def update_project(
        self, old_config: ProjectConfiguration, new_config: ProjectConfiguration
    ):
        self.project_manager.update(old_config.path.name, new_config)

    def del_project(self, config: ProjectConfiguration):
        self.project_manager.delete(config)

    def load_project(self, project_index: int) -> ProjectConfiguration:
        self.current_project_index = project_index
        self.current_project = self.project_manager.get(project_index)
        self.current_ins_rules = []
        self.current_blk_rules = []

        for rule in self.known_ins_rules:
            for rule_conf in self.current_project.ins_rules:
                if not rule_conf.is_activated:
                    continue
                if rule.name == rule_conf.name:
                    effective_config = resolve_arch_config(rule_conf.config)
                    effective_config["dump_intermediate_microcode"] = (
                        self.d810_config.get("dump_intermediate_microcode")
                    )
                    rule.configure(effective_config)
                    rule.set_log_dir(self.log_dir)
                    self.current_ins_rules.append(rule)
        logger.debug("Instruction rules configured")
        for blk_rule in self.known_blk_rules:
            for rule_conf in self.current_project.blk_rules:
                if not rule_conf.is_activated:
                    continue
                if blk_rule.name == rule_conf.name:
                    effective_config = resolve_arch_config(rule_conf.config)
                    effective_config["dump_intermediate_microcode"] = (
                        self.d810_config.get("dump_intermediate_microcode")
                    )
                    blk_rule.configure(effective_config)
                    blk_rule.set_log_dir(self.log_dir)
                    self.current_blk_rules.append(blk_rule)
        logger.debug("Block rules configured")
        cfg = dict(self.current_project.additional_configuration)
        cfg.setdefault("project_name", self.current_project.path.name)
        self.manager.configure(**cfg)
        self.manager.emit_rule_scope_invalidation(
            RuleScopeEvent.PROJECT_RULES_RELOADED,
            project_name=self.current_project.path.name,
        )
        if self.manager.started:
            self.manager.instruction_optimizer.configure(
                **self.manager.instruction_optimizer_config,
                rule_scope_service=self.manager.rule_scope_service,
                rule_scope_project_name=self.current_project.path.name,
                rule_scope_idb_key=str(
                    cfg.get("idb_key", self.current_project.path.name)
                ),
            )
            self.manager.block_optimizer.configure(
                rule_scope_service=self.manager.rule_scope_service,
                rule_scope_project_name=self.current_project.path.name,
                rule_scope_idb_key=str(
                    cfg.get("idb_key", self.current_project.path.name)
                ),
                function_priors_provider=(
                    self.manager.function_analysis_priors_for_ea
                ),
            )
            self.manager._compile_rule_scope()
        if getattr(self, "gui", None) is not None:
            logger.info(
                "d810-ng: Rules reconfigured for project %s",
                self.current_project.path.name,
            )
        logger.debug(
            "Loaded project %s (%s) from %s",
            self.current_project.path.name,
            self.current_project.description,
            self.current_project.path,
        )
        return self.current_project

    def _register_backend_analysis_providers(self) -> None:
        """Push backend-supplied analysis seams into the portable provider registry.

        Composition-root injection (Landing Sequence LS10): the Hex-Rays evidence
        walkers live in ``d810.backends.hexrays.evidence.bst_analysis``, but the
        portable recon BST-transition analyses must not import the vendor backend.
        Here -- a HIGH-layer module that may legally import backends -- we push the
        callables into ``d810.capabilities.providers`` so recon reads them via
        ``get_bst_walkers()`` without a backend import (see ticket d81-1w16).

        Re-registered on every start so a plugin reload that clears the registry
        module globals is repopulated before any recon analysis runs.
        """
        register_bst_walkers(
            BstWalkerProvider(
                detect_state_var_stkoff=_bst_evidence._detect_state_var_stkoff,
                dump_dispatcher_node=_bst_evidence._dump_dispatcher_node,
                find_pre_header_state=_bst_evidence._find_pre_header_state,
                walk_handler_chain=_bst_evidence._walk_handler_chain,
                forward_eval_insn=_bst_evidence._forward_eval_insn,
                resolve_via_bst_walk=_bst_evidence.resolve_via_bst_walk,
            )
        )

    def start_d810(self):
        self._register_backend_analysis_providers()
        self.manager.configure_instruction_optimizer(
            [rule for rule in self.current_ins_rules],
            generate_z3_code=self.d810_config.get("generate_z3_code"),
            dump_intermediate_microcode=self.d810_config.get(
                "dump_intermediate_microcode"
            ),
            **self.current_project.additional_configuration,
        )
        self.manager.configure_block_optimizer(
            [rule for rule in self.current_blk_rules],
            **self.current_project.additional_configuration,
        )
        self.manager.start()
        logger.info("D-810 ready to deobfuscate...")
        self.d810_config.set("last_project_index", self.current_project_index)
        self.d810_config.save()

    def stop_d810(self):
        logger.info("Stopping D-810...")
        self.manager.stop()

    def load(
        self,
        gui: bool = True,
        d810_config: D810Configuration | None = None,
    ):
        self.reset(d810_config=d810_config)
        # Determine which project to auto-load. Fall back to first entry (0)
        # when the configuration value is missing or invalid, and clamp the
        # index to the available range to avoid IndexError when projects were
        # renamed or removed.
        raw_index = self.d810_config.get("last_project_index", 0)
        try:
            self.current_project_index = int(raw_index)
        except (TypeError, ValueError):
            logger.warning(
                "Invalid last_project_index %r in configuration; defaulting to 0",
                raw_index,
            )
            self.current_project_index = 0

        self.current_ins_rules = []
        self.current_blk_rules = []

        # Build lists of available rules, skipping abstract / hidden ones
        self.known_ins_rules = [
            rule_cls()
            for rule_cls in InstructionOptimizationRule.registry.values()
            if not inspect.isabstract(rule_cls)
        ]

        # Add VerifiableRules (DSL-based MBA rules) wrapped with IDA adapter
        # These rules use the new DSL system for pattern matching and verification
        verifiable_instances = VerifiableRule.instantiate_all()
        self.known_ins_rules.extend(adapt_rules(verifiable_instances))

        self.known_blk_rules = [
            rule_cls()
            for rule_cls in FlowOptimizationRule.registry.values()
            if not inspect.isabstract(rule_cls)
        ]

        # Clamp to available projects, if any
        if projects := len(self.project_manager):
            self.current_project_index = max(
                0, min(self.current_project_index, projects - 1)
            )
            self._is_loaded = self.load_project(self.current_project_index) is not None
        else:
            logger.warning("No project configurations available; plugin is idle.")
            self.current_project = None  # type: ignore[assignment]
            self._is_loaded = False

        if gui and self._is_loaded:
            # Lazy import to avoid Qt dependency in headless mode
            from d810.ui.ida_ui import D810GUI

            self.gui = D810GUI(self)
            self.gui.show_windows()

    def unload(self, gui: bool = True):
        self.manager.stop()
        if gui and self._is_loaded:
            self.gui.term()
            del self.gui
        self._is_loaded = False

    @contextlib.contextmanager
    def for_project(self, name: str) -> typing.Generator[ProjectContext, None, None]:
        _old_project_index = self.current_project_index
        project_index = self.project_manager.index(name)
        if project_index != _old_project_index:
            logger.info("switching to project %s", name)
        self.load_project(project_index)

        ctx = ProjectContext(state=self, project_index=project_index)
        try:
            yield ctx
        finally:
            ctx.restore()
            if project_index != _old_project_index:
                logger.info("switching back to project %s", _old_project_index)
                self.load_project(_old_project_index)
