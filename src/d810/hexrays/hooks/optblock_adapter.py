from __future__ import annotations

import math
import pathlib
import sqlite3
import time
import traceback
from collections import defaultdict

import ida_hexrays

from d810.hexrays.hooks.optimization_suppression import (
    d810_optimization_is_suppressed,
)

from d810.core import getLogger, typing
from d810.core.decompilation_session import DecompilationEvent
from d810.core.execution_scope import ExecutionPipeline, ExecutionStageIdentity
from d810.errors import D810Exception
from d810.hexrays.hooks.callback_mutation_diagnostics import (
    LiveNopSite,
    build_callback_nop_delta_records,
    build_callback_nop_inventory_records,
    capture_block_nop_sites,
    capture_live_nop_sites,
)
from d810.hexrays.lifecycle import _emit_flowgraph_ready_event
from d810.hexrays.observability import observe_optblock_callback_exception
from d810.hexrays.ir_maturity import ida_maturity_to_ir
from d810.hexrays.mutation.return_carrier_corruption import (
    snapshot_return_reg_consumer_def_eas,
)
from d810.hexrays.mutation.block_retention import synchronize_explicit_goto_flag
from d810.hexrays.utils.hexrays_formatters import maturity_to_string

main_logger = getLogger("d810")
optimizer_logger = getLogger("d810.optimizer")
_RUN_LATER_DOMAIN_OPTIMIZER_RULE = "optimizer_rule"
_PROJECT_CONFIG_KEYS = frozenset(
    {
        "pipeline_v2",
        "pipeline_v2_mode",
        "router_resolution",
    }
)


def _current_mba_runtime_identity(mba: object) -> int:
    """Name one live ``mba_t`` for adapter-local cache invalidation only."""
    try:
        return int(mba.this)
    except (AttributeError, TypeError, ValueError):
        return id(mba)


def _safe_callback_int(value: object) -> int | None:
    """Best-effort numeric context for an exception-path diagnostic."""
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _safe_callback_attr(value: object, name: str) -> object | None:
    try:
        return getattr(value, name, None)
    except Exception:
        return None


def _optblock_callback_exception_context(
    blk: object,
) -> tuple[int, str, int | None, int | None, str]:
    """Build context without allowing a damaged SWIG object to mask failure."""
    mba = _safe_callback_attr(blk, "mba")
    func_ea = _safe_callback_int(_safe_callback_attr(mba, "entry_ea")) or 0
    maturity_value = _safe_callback_int(_safe_callback_attr(mba, "maturity"))
    try:
        maturity = (
            str(maturity_to_string(maturity_value))
            if maturity_value is not None
            else "UNKNOWN"
        )
    except Exception:
        maturity = "UNKNOWN"
    block_serial = _safe_callback_int(_safe_callback_attr(blk, "serial"))
    block_ea = _safe_callback_int(_safe_callback_attr(blk, "start"))
    if block_serial is None or block_ea is None:
        # A serial is snapshot-local.  It is only a usable diagnostic identity
        # when the same damaged callback object also supplies its EA anchor.
        block_serial = None
        block_ea = None
    block_anchor = (
        f"blk{block_serial}@0x{block_ea:x}"
        if block_serial is not None and block_ea is not None
        else "unknown"
    )
    return func_ea, maturity, block_serial, block_ea, block_anchor


def _report_optblock_callback_exception(blk: object, error: Exception) -> None:
    """Log and publish one callback exception before the SWIG bridge rethrows."""
    try:
        func_ea, maturity, block_serial, block_ea, block_anchor = (
            _optblock_callback_exception_context(blk)
        )
        optimizer_logger.exception(
            "Unhandled optblock callback exception func=0x%x maturity=%s %s %s: %s",
            func_ea,
            maturity,
            block_anchor,
            type(error).__name__,
            error,
        )
        traceback_text = traceback.format_exc()
        try:
            observe_optblock_callback_exception(
                func_ea=func_ea,
                maturity=maturity,
                block_serial=block_serial,
                block_ea=block_ea,
                error_type=type(error).__name__,
                error_message=str(error) or type(error).__name__,
                traceback_text=traceback_text,
            )
        except Exception:
            optimizer_logger.exception(
                "Failed to publish optblock callback exception func=0x%x %s",
                func_ea,
                block_anchor,
            )
    except BaseException:
        # This reporter runs on a SWIG callback exception path.  Diagnostics
        # are strictly best-effort: even a damaged logger or publisher must
        # never replace the exact optimizer exception that ``func`` rethrows.
        return


if typing.TYPE_CHECKING:
    from d810.core import OptimizationStatistics

FlowMaturityContext: typing.TypeAlias = typing.Any
FlowOptimizationRule: typing.TypeAlias = typing.Any


class BlockOptimizerManager(ida_hexrays.optblock_t):
    # Base pass limit for a small function (<=32 blocks). For larger functions
    # the limit scales as: base * (1 + log2(block_count / 32)).
    # This is a safety net against infinite loops where the optimizer keeps
    # matching but never converges.
    _BASE_PASSES_PER_MATURITY = 2000

    def __init__(
        self,
        stats: OptimizationStatistics,
        log_dir: pathlib.Path,
        *,
        ctx_cls: type,
    ):
        optimizer_logger.debug("Initializing {0}...".format(self.__class__.__name__))
        super().__init__()
        self.log_dir = log_dir
        self.stats = stats
        self._flow_context_type = ctx_cls
        self.cfg_rules: list[FlowOptimizationRule] = []
        self._execution_scope_service = None
        self._execution_scope_project_name = ""
        self._execution_scope_idb_key = ""
        self._perf_compare_execution_scope = False
        self._perf_counters = {
            "scoped_calls": 0,
            "legacy_calls": 0,
            "scoped_candidates_total": 0,
            "legacy_candidates_total": 0,
            "scoped_lookup_ns": 0,
        }

        self.current_maturity = None
        self._pass_count = 0
        self._max_passes_current = self._BASE_PASSES_PER_MATURITY
        self._generation: int = 0
        self._flow_context: FlowMaturityContext | None = None
        self._flow_context_key: tuple[int, int, int, int, int] | None = None
        # Narrow manager-owned evidence and outcome ports.
        self._validated_fact_view_provider = None
        self._fact_consumer_callback = None
        self._flow_context_summary_provider = None
        self._planner_outcome_callback = None
        self._flow_gate_outcome_callback = None
        # Manager-owned lifecycle port for session reset, capture, analysis,
        # and rule-scope hint delivery.
        self._decompilation_lifecycle = None
        # v2 (d81-fzlo): pre-fold rax-family consumer DEF EAs, keyed by func_ea so
        # the capture (GLBOPT1 optblock) survives the GLBOPT1->GLBOPT2 maturity
        # boundary to the glbopt() consume (which fires at GLBOPT2). The per-maturity
        # flow_context is invalidated across that boundary and cannot carry it.
        self._prefold_rccc_by_func: dict[int, frozenset[int]] = {}
        self._function_priors_provider = None
        self._dispatcher_artifact_planner = None
        # Optional PassPipeline - set via configure(pass_pipeline=...). None
        # means the pipeline is disabled (zero overhead). When set, fires once
        # at MMAT_GLBOPT2 (after the unflattener has finished at MMAT_GLBOPT1).
        self._pass_pipeline = None  # PassPipeline | None
        self._pipeline_last_maturity: int = -1
        self._post_d810_pipeline_last_maturity: int = -1
        self._impossible_return_artifact_rewrite_applied: set[tuple[int, int]] = set()
        self._terminal_zero_literal_rewrite_applied: set[tuple[int, int]] = set()
        self._terminal_tail_cascade_egress_applied: set[tuple[int, int]] = set()
        self._project_config: dict[str, typing.Any] = {}
        # When the PassPipeline fires and applies changes, we must skip all
        # remaining block optimizer rule calls for the rest of this maturity.
        # IDA will re-enter at the next maturity with fresh block pointers.
        # Accessing stale mop_t pointers after pipeline mutations causes segfaults.
        self._pipeline_just_fired: bool = False
        self._run_later_scheduler = None
        self._scheduled_stage_identities: frozenset[ExecutionStageIdentity] = frozenset()
        self._scheduled_flow_implementations: tuple[FlowOptimizationRule, ...] = ()
        # usage tracking moved to centralized statistics object
        # Optional event emitter - set by D810Manager after construction.
        self.event_emitter = None

    def reset_pass_counter(self) -> None:
        """Reset the per-maturity pass counter and generation counter.

        Called when maturity changes so the guard does not carry over.
        """
        self._pass_count = 0
        self._max_passes_current = self._BASE_PASSES_PER_MATURITY
        self._generation = 0

    @property
    def generation(self) -> int:
        """Monotonically increasing counter incremented whenever any rule applies patches.

        Rules can use this (via ``self.current_generation``) to detect that the CFG
        has changed since they last ran, allowing them to re-run within the same maturity.
        """
        return self._generation

    def reset_pipeline_tracker(self) -> None:
        """Reset the pipeline-last-maturity tracker.

        Called at decompilation start so the PassPipeline fires fresh for
        each new function decompilation.
        """
        self._pipeline_last_maturity = -1
        self._post_d810_pipeline_last_maturity = -1
        self._pipeline_just_fired = False
        self._impossible_return_artifact_rewrite_applied.clear()
        self._terminal_zero_literal_rewrite_applied.clear()
        self._terminal_tail_cascade_egress_applied.clear()
        self._reset_run_later_state()
        for cfg_rule in self.cfg_rules:
            reset_pass_manager = getattr(cfg_rule, "reset_pass_manager_state", None)
            if callable(reset_pass_manager):
                reset_pass_manager()

    def _reset_run_later_state(self) -> None:
        self._scheduled_stage_identities = frozenset()
        self._scheduled_flow_implementations = ()
        scheduler = self._run_later_scheduler
        if scheduler is not None:
            reset_all = getattr(scheduler, "reset_all", None)
            if callable(reset_all):
                reset_all()

    def _current_ir_maturity(self):
        if self.current_maturity is None:
            return None
        try:
            return ida_maturity_to_ir(int(self.current_maturity))
        except ValueError:
            optimizer_logger.debug(
                "run_later scheduler skipped unsupported maturity %s",
                maturity_to_string(int(self.current_maturity)),
            )
            return None

    def _drain_run_later_for_maturity(
        self,
        mba: ida_hexrays.mbl_array_t,
    ) -> None:
        self._scheduled_stage_identities = frozenset()
        self._scheduled_flow_implementations = ()
        scheduler = self._run_later_scheduler
        if scheduler is None or self.current_maturity is None:
            return
        current_ir_maturity = self._current_ir_maturity()
        if current_ir_maturity is None:
            return
        drain = getattr(scheduler, "drain", None)
        if not callable(drain):
            return
        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        if func_ea == 0:
            return
        pending = drain(
            func_ea=func_ea,
            current_maturity=current_ir_maturity,
            domain=_RUN_LATER_DOMAIN_OPTIMIZER_RULE,
        )
        if not pending:
            return
        identities = frozenset(
            ExecutionStageIdentity(
                pass_id=str(item.pass_id),
                stage_id=str(item.stage_id),
            )
            for item in pending
            if getattr(item, "stage_id", None)
        )
        service = self._execution_scope_service
        if service is None:
            return
        stages = service.scheduled_stages(
            identities=identities,
            func_ea=func_ea,
            pipeline=ExecutionPipeline.FLOW,
        )
        self._scheduled_stage_identities = identities
        self._scheduled_flow_implementations = tuple(
            stage.implementation for stage in stages
        )
        if self._scheduled_stage_identities:
            optimizer_logger.info(
                "run_later scheduler activated flow stages at %s for function %#x: %s",
                maturity_to_string(int(self.current_maturity)),
                func_ea,
                sorted(
                    f"{identity.pass_id}/{identity.stage_id}"
                    for identity in self._scheduled_stage_identities
                ),
            )

    def _is_loop_carrier_only_pipeline(self) -> bool:
        pipeline = self._pass_pipeline
        if pipeline is None:
            return False
        passes = tuple(getattr(pipeline, "passes", ()) or ())
        if not passes:
            return False
        return all(
            getattr(pass_, "name", None) == "loop_carrier_backedge_refresh"
            for pass_ in passes
        )

    def _run_pass_pipeline_once(
        self,
        mba: ida_hexrays.mbl_array_t,
        *,
        phase_label: str,
    ) -> None:
        if self._pass_pipeline is None:
            return
        try:
            func_ea_hex = hex(int(getattr(mba, "entry_ea", 0) or 0))
            optimizer_logger.info(
                "PassPipeline: running %d pass(es) on function %s at %s",
                len(self._pass_pipeline.passes),
                func_ea_hex,
                phase_label,
            )
            mutation_gateway = self._flow_context.new_mba_mutation_gateway()
            if mutation_gateway is None:
                optimizer_logger.warning(
                    "PassPipeline: skipped function %s at %s without a "
                    "coordinator-owned mutation gateway",
                    func_ea_hex,
                    phase_label,
                )
                return
            total = self._pass_pipeline.run(
                mba,
                mutation_gateway=mutation_gateway,
            )
            if total > 0:
                optimizer_logger.info(
                    "PassPipeline: applied %d total modification(s) on function %s at %s",
                    total,
                    func_ea_hex,
                    phase_label,
                )
                self._pipeline_just_fired = True
            else:
                optimizer_logger.debug(
                    "PassPipeline: no modifications applied on function %s at %s",
                    func_ea_hex,
                    phase_label,
                )
        except Exception:
            optimizer_logger.exception(
                "PassPipeline: error during %s processing",
                phase_label,
            )

    def _invalidate_flow_context(self, reason: str = "") -> None:
        if self._flow_context is not None and reason:
            optimizer_logger.debug("Invalidating flow context: %s", reason)
        self._flow_context = None
        self._flow_context_key = None

    def prefold_return_reg_consumer_def_eas_for(self, func_ea: int) -> frozenset[int]:
        """GLBOPT1 pre-fold rax-family consumer DEF EAs captured for *func_ea*
        (empty if none); function-keyed so it survives to the GLBOPT2 glbopt()
        consume (ticket d81-fzlo)."""
        return self._prefold_rccc_by_func.get(int(func_ea), frozenset())

    def reset_perf_counters(self) -> None:
        for key in self._perf_counters:
            self._perf_counters[key] = 0

    def report_perf_counters(self) -> None:
        scoped_calls = int(self._perf_counters["scoped_calls"])
        legacy_calls = int(self._perf_counters["legacy_calls"])
        scoped_candidates = int(self._perf_counters["scoped_candidates_total"])
        legacy_candidates = int(self._perf_counters["legacy_candidates_total"])
        scoped_lookup_ns = int(self._perf_counters["scoped_lookup_ns"])

        if scoped_calls == 0 and legacy_calls == 0:
            return
        scoped_avg = (scoped_candidates / scoped_calls) if scoped_calls else 0.0
        legacy_avg = (legacy_candidates / legacy_calls) if legacy_calls else 0.0
        lookup_us = (scoped_lookup_ns / scoped_calls / 1000.0) if scoped_calls else 0.0
        optimizer_logger.info(
            "Rule iteration perf: scoped_calls=%d legacy_calls=%d "
            "scoped_avg_candidates=%.2f legacy_avg_candidates=%.2f "
            "scoped_lookup_avg_us=%.2f compare=%s",
            scoped_calls,
            legacy_calls,
            scoped_avg,
            legacy_avg,
            lookup_us,
            self._perf_compare_execution_scope,
        )

    def func(self, blk: ida_hexrays.mblock_t):
        try:
            result = self._func(blk)
            if (
                int(result) == 0
                and not self._pipeline_just_fired
                and synchronize_explicit_goto_flag(blk)
            ):
                result = 1
            return result
        except Exception as error:
            _report_optblock_callback_exception(blk, error)
            raise

    def _func(self, blk: ida_hexrays.mblock_t):
        if self.log_info_on_input(blk):
            # PREOPT structural import invalidated the callback-local block.
            # Report one change so Hex-Rays revisits the updated MBA before
            # this adapter touches the stale pointer again.
            return 1

        # Pipeline guard: after the PassPipeline fires and mutates the MBA,
        # all mop_t pointers held by block optimizer rules are stale. Running
        # them would cause a segfault. Skip rule execution for all remaining
        # blocks in this maturity. The flag is cleared when maturity changes
        # (in log_info_on_input) or at decompilation start (reset_pipeline_tracker).
        if self._pipeline_just_fired:
            return 0

        # Bug 3 fix: pass guard -- if the block optimizer has been called too
        # many times at the same maturity without a maturity change, bail out
        # to prevent infinite-loop hangs.
        #
        # The limit scales with function size so that large functions (e.g.
        # AntiDebug_ExceptionFilter, ~370 blocks) get enough budget for both
        # instruction rules and flow rules (e.g. ForwardConstPropRule) to fire.
        # Formula: base * (1 + log2(block_count / 32)) for block_count > 32.
        mba = blk.mba
        if self._pass_count == 0 and mba is not None:
            mba_qty = int(mba.qty) if mba.qty else 32
            if mba_qty > 32:
                scaled = int(
                    self._BASE_PASSES_PER_MATURITY * (1 + math.log2(mba_qty / 32))
                )
                if scaled != self._max_passes_current:
                    self._max_passes_current = scaled
                    optimizer_logger.debug(
                        "BlockOptimizer pass limit scaled to %d "
                        "(block_count=%d, maturity=%s)",
                        self._max_passes_current,
                        mba_qty,
                        maturity_to_string(self.current_maturity),
                    )
            else:
                self._max_passes_current = self._BASE_PASSES_PER_MATURITY

        self._pass_count += 1
        if self._pass_count > self._max_passes_current:
            if self._pass_count == self._max_passes_current + 1:
                optimizer_logger.warning(
                    "BlockOptimizer exceeded %d passes at maturity %s; "
                    "suppressing further optimizations until maturity changes",
                    self._max_passes_current,
                    maturity_to_string(self.current_maturity),
                )
            return 0

        # Bug 2 fix: catch exceptions so they don't escape to IDA's callback
        # handler, which would continue with a corrupted MBA and hang at the
        # next maturity level.  Mirrors InstructionOptimizerManager.func().
        try:
            nb_patch = self.optimize(blk)
            return nb_patch
        except RuntimeError as e:
            optimizer_logger.warning(
                "RuntimeError in block optimizer on blk %d: %s", blk.serial, e
            )
            # Disable remaining passes for this maturity after a runtime failure.
            # Continuing to call block rules in the same maturity after an
            # unknown IDA exception often re-enters with stale state.
            self._pass_count = self._max_passes_current + 1
        except D810Exception as e:
            optimizer_logger.warning(
                "D810Exception in block optimizer on blk %d: %s", blk.serial, e
            )
            self._pass_count = self._max_passes_current + 1
        except sqlite3.DatabaseError as e:
            optimizer_logger.warning(
                "DatabaseError in block optimizer on blk %d: %s", blk.serial, e
            )
            self._pass_count = self._max_passes_current + 1
        return 0

    def log_info_on_input(self, blk: ida_hexrays.mblock_t):
        mba: ida_hexrays.mbl_array_t = blk.mba

        if (mba is not None) and (mba.maturity != self.current_maturity):
            callback_input_snapshot = None
            try:
                from d810.hexrays.mba_serializer import mba_to_block_snapshots

                callback_input_snapshot = tuple(mba_to_block_snapshots(mba))
            except Exception:
                # Snapshot comparison is a conservative notification aid, not
                # an execution prerequisite. Minimal SDK test doubles and an
                # unavailable diagnostic serializer must not suppress maturity
                # transitions or queued run-later work.
                pass
            if main_logger.debug_on:
                main_logger.debug(
                    "BlockOptimizer called at maturity: %s",
                    maturity_to_string(mba.maturity),
                )

            # --- Diagnostic: post_d810 snapshot for the PREVIOUS maturity ---
            _post_snap_ref = None
            if self.current_maturity is not None:
                try:
                    from d810.hexrays.mba_serializer import mba_to_block_snapshots
                    from d810.hexrays.observability import (
                        request_capture_mba_snapshot,
                    )

                    _prev_mat_name = maturity_to_string(self.current_maturity)
                    _post_snap_ref = request_capture_mba_snapshot(
                        blocks=mba_to_block_snapshots(mba),
                        label=f"maturity_{_prev_mat_name}_post_d810",
                        func_ea=int(getattr(mba, "entry_ea", 0) or 0),
                        maturity=_prev_mat_name,
                        phase="post_d810",
                    )
                except Exception:
                    pass  # diagnostic, never gates decompilation

            if self.current_maturity is not None and self.event_emitter is not None:
                self.event_emitter.emit(
                    DecompilationEvent.POST_D810_CAPTURE,
                    mba,
                    int(self.current_maturity),
                    _post_snap_ref,
                )

            if (
                self._pass_pipeline is not None
                and self.current_maturity is not None
                and int(self.current_maturity) == int(ida_hexrays.MMAT_GLBOPT1)
                and self._post_d810_pipeline_last_maturity != int(self.current_maturity)
                and self._is_loop_carrier_only_pipeline()
            ):
                self._post_d810_pipeline_last_maturity = int(self.current_maturity)
                self._run_pass_pipeline_once(
                    mba,
                    phase_label="MMAT_GLBOPT1_post_d810",
                )

            self.current_maturity = mba.maturity
            self._pipeline_just_fired = False
            self.reset_pass_counter()
            self._invalidate_flow_context("maturity changed")
            self._drain_run_later_for_maturity(mba)

            # Axis-C end-state event (E1): mirror the
            # ``InstructionOptimizerManager`` site -- emit
            # ``FLOWGRAPH_READY`` so the cross-layer event lands at
            # every existing preanalysis-collection lifecycle point. When
            # E4 swaps the live-mba ``run_microcode_collectors(...)``
            # path for ``FLOWGRAPH_READY`` subscribers, neither
            # manager silently drops out of the chain.
            #
            # NOTE (E4a): the emit moved AFTER ``reset_for_func``
            # below.  See the comment block at the emit site for
            # the ordering rationale.

            # --- Diagnostic: pre_d810 snapshot for the NEW maturity ---
            _pre_snap_ref = None
            try:
                from d810.hexrays.mba_serializer import mba_to_block_snapshots
                from d810.hexrays.observability import (
                    request_capture_mba_snapshot,
                )

                _new_mat_name = maturity_to_string(self.current_maturity)
                _pre_snap_ref = request_capture_mba_snapshot(
                    blocks=mba_to_block_snapshots(mba),
                    label=f"maturity_{_new_mat_name}_pre_d810",
                    func_ea=int(getattr(mba, "entry_ea", 0) or 0),
                    maturity=_new_mat_name,
                    phase="pre_d810",
                )
            except Exception:
                pass  # diagnostic, never gates decompilation

            mba_ea = int(getattr(mba, "entry_ea", 0) or 0)
            _emit_flowgraph_ready_event(
                self.event_emitter,
                mba,
                snapshot=_pre_snap_ref,
            )
            if self._decompilation_lifecycle is not None:
                self._decompilation_lifecycle.analyze_current_function(
                    function_ea=mba_ea,
                    source="analyzed",
                )

            self._run_glbopt1_preanalysis_backed_extensions(mba)

            # PassPipeline: fire once at MMAT_GLBOPT2, after the unflattener
            # has already run at MMAT_GLBOPT1.  Runs at most once per maturity
            # level per decompilation.  No-op when _pass_pipeline is None.
            if (
                self._pass_pipeline is not None
                and int(self.current_maturity) == int(ida_hexrays.MMAT_GLBOPT2)
                and self._pipeline_last_maturity != int(self.current_maturity)
            ):
                self._pipeline_last_maturity = int(self.current_maturity)
                # Marking _pipeline_just_fired when this applies remains
                # important: block optimizer rules must not touch stale mop_t
                # pointers after the pipeline mutates CFG.
                self._run_pass_pipeline_once(mba, phase_label="MMAT_GLBOPT2")

            callback_changed = False
            if callback_input_snapshot is not None:
                try:
                    callback_changed = callback_input_snapshot != tuple(
                        mba_to_block_snapshots(mba)
                    )
                except Exception:
                    # The input was observable but the post-state was not.
                    # Conservatively ask Hex-Rays to revisit the MBA.
                    callback_changed = True
            if callback_changed:
                optimizer_logger.info(
                    "maturity-boundary callback modified MBA: maturity=%s",
                    maturity_to_string(int(mba.maturity)),
                )
            return callback_changed

        return False

    # statistics are managed centrally via the stats object

    def _resolve_active_rules(
        self, blk: ida_hexrays.mblock_t
    ) -> tuple[FlowOptimizationRule, ...] | None:
        if self._execution_scope_service is None:
            # FAIL CLOSED: If execution scope service not initialized, run NO rules
            # instead of ALL rules. This prevents hangs when optimizer callbacks
            # fire before configure() is called.
            optimizer_logger.warning(
                "Execution scope service not initialized at block optimize time - no rules will run. "
                "This may indicate a race condition during initialization."
            )
            return ()
        if blk.mba is None or blk.mba.entry_ea is None:
            return ()
        if self.current_maturity is None:
            return ()
        t0_ns = time.perf_counter_ns()
        stages = self._execution_scope_service.active_stages(
            project_name=self._execution_scope_project_name,
            idb_key=self._execution_scope_idb_key,
            func_ea=int(blk.mba.entry_ea),
            pipeline=ExecutionPipeline.FLOW,
            maturity=int(self.current_maturity),
        )
        self._perf_counters["scoped_lookup_ns"] += time.perf_counter_ns() - t0_ns
        return self._include_run_later_rules(
            tuple(stage.implementation for stage in stages),
            func_entry_ea=int(blk.mba.entry_ea),
        )

    def _include_run_later_rules(
        self,
        active_rules: tuple[FlowOptimizationRule, ...],
        *,
        func_entry_ea: int,
    ) -> tuple[FlowOptimizationRule, ...]:
        if not self._scheduled_flow_implementations:
            return active_rules
        del func_entry_ea
        ordered = list(active_rules)
        for implementation in self._scheduled_flow_implementations:
            if all(existing is not implementation for existing in ordered):
                ordered.append(implementation)
        return tuple(ordered)

    def _legacy_candidate_count(self, func_entry_ea: int) -> int:
        count = 0
        for cfg_rule in self.cfg_rules:
            if self.check_if_rule_is_activated_for_address(cfg_rule, func_entry_ea):
                count += 1
        return count

    @staticmethod
    def _rule_priority(cfg_rule: FlowOptimizationRule) -> int:
        raw_priority = getattr(cfg_rule, "priority", getattr(cfg_rule, "PRIORITY", 100))
        try:
            return int(raw_priority)
        except (TypeError, ValueError):
            return 100

    def _order_rules_for_execution(
        self, rules: tuple[FlowOptimizationRule, ...]
    ) -> tuple[FlowOptimizationRule, ...]:
        # Higher safety priorities run first. Python's stable sort preserves the
        # config-v2 public pipeline order for rules in the same priority phase.
        return tuple(
            sorted(
                rules,
                key=lambda rule: -self._rule_priority(rule),
            )
        )

    def _group_rules_by_priority(
        self, rules: tuple[FlowOptimizationRule, ...]
    ) -> tuple[tuple[int, tuple[FlowOptimizationRule, ...]], ...]:
        grouped: dict[int, list[FlowOptimizationRule]] = defaultdict(list)
        for rule in rules:
            grouped[self._rule_priority(rule)].append(rule)
        return tuple(
            (priority, tuple(grouped[priority]))
            for priority in sorted(grouped.keys(), reverse=True)
        )

    @staticmethod
    def _frontend_generation_is_stale(
        flow_context: FlowMaturityContext | None,
    ) -> bool:
        """Return whether manager-owned evidence requires a fresh PREOPT MBA."""
        if flow_context is None:
            return False
        state_provider = getattr(flow_context, "resolver_session_state", None)
        state = state_provider() if callable(state_provider) else None
        if state is None or not bool(getattr(state, "is_materialized", False)):
            return False
        native_preanalysis = getattr(state, "native_preanalysis", None)
        normalized_generation = getattr(
            native_preanalysis,
            "normalization_published_postvalidated_generation",
            None,
        )
        evidence_generation = getattr(state, "evidence_generation", None)
        return bool(
            getattr(state, "pending_preopt_reimport", False)
            or evidence_generation is None
            or normalized_generation is None
            or int(normalized_generation) != int(evidence_generation)
        )

    def _get_or_create_flow_context(
        self,
        blk: ida_hexrays.mblock_t,
        *,
        phase_priority: int,
        phase_index: int,
        phase_rules: tuple[FlowOptimizationRule, ...],
    ) -> FlowMaturityContext | None:
        mba = blk.mba
        if mba is None or mba.entry_ea is None or self.current_maturity is None:
            return None
        lifecycle = self._decompilation_lifecycle
        generation_getter = getattr(lifecycle, "current_mba_generation", None)
        current_mba_generation = (
            int(generation_getter(function_ea=int(mba.entry_ea)))
            if callable(generation_getter)
            else 0
        )
        evidence_generation_getter = getattr(
            lifecycle,
            "current_evidence_generation",
            None,
        )
        current_evidence_generation = (
            int(evidence_generation_getter(function_ea=int(mba.entry_ea)))
            if callable(evidence_generation_getter)
            else 0
        )
        key = (
            int(mba.entry_ea),
            int(self.current_maturity),
            current_mba_generation,
            current_evidence_generation,
            _current_mba_runtime_identity(mba),
        )
        if self._flow_context is None or self._flow_context_key != key:
            self._flow_context = self._flow_context_type(
                mba=mba,
                func_ea=int(mba.entry_ea),
                maturity=int(self.current_maturity),
            )
            self._flow_context_key = key
            self._attach_hint_summary(self._flow_context)
            if (
                self._planner_outcome_callback is not None
                or self._flow_gate_outcome_callback is not None
            ):
                self._flow_context.set_outcome_callback(self._record_flow_outcome)
            if (
                self._validated_fact_view_provider is not None
                or self._fact_consumer_callback is not None
            ):
                self._flow_context.set_fact_lifecycle_callbacks(
                    view_provider=self._validated_fact_view_provider,
                    consumer_callback=self._fact_consumer_callback,
                )
            # v2 (d81-fzlo): capture the pre-fold rax-family consumer DEF EAs ONCE
            # per (func, GLBOPT1), here in the create-branch where the mba is still
            # in tree form (pre optimize_global fold). Stored FUNCTION-keyed (not on
            # the per-maturity flow_context, which is invalidated before the GLBOPT2
            # glbopt() consume).
            if int(self.current_maturity) == ida_hexrays.MMAT_GLBOPT1:
                # Best-effort: a non-standard / partial mba (e.g. a unit-test mock
                # without get_mblock) must not break the optblock pass. On failure
                # the cleanup simply fails closed (no severance evidence captured ->
                # nothing dropped).
                try:
                    self._prefold_rccc_by_func[int(mba.entry_ea)] = frozenset(
                        snapshot_return_reg_consumer_def_eas(mba)
                    )
                except Exception:  # noqa: BLE001 -- capture is best-effort
                    optimizer_logger.debug(
                        "RCCC pre-fold capture skipped", exc_info=True
                    )
            # A live MBA identity index is expensive to lift and valid for
            # this flow context's current MBA generation.  Bind it when the
            # context is born, never once per optimized block.
            self._bind_resolver_session_state(self._flow_context, mba)
            self._bind_mutation_gateway_port(self._flow_context, mba)
            self._bind_semantic_native_body_materializer_port(
                self._flow_context,
                mba,
            )
        else:
            self._flow_context.refresh_mba(mba)
        self._flow_context.set_function_priors_provider(self._function_priors_provider)
        self._flow_context.set_phase(
            priority=phase_priority,
            phase_index=phase_index,
            active_rule_names=tuple(str(rule.name) for rule in phase_rules),
        )
        self._flow_context.prime_for_rules(phase_rules)
        return self._flow_context

    def _bind_mutation_gateway_port(
        self,
        flow_context: FlowMaturityContext,
        mba: ida_hexrays.mbl_array_t,
    ) -> None:
        """Inject session-owned structural-mutation routing into flow rules."""
        lifecycle = self._decompilation_lifecycle
        set_factory = getattr(flow_context, "set_mutation_gateway_factory", None)
        if lifecycle is None or not callable(set_factory):
            return
        function_ea = int(getattr(mba, "entry_ea", 0) or 0)
        maturity = int(getattr(mba, "maturity", self.current_maturity) or 0)
        build_index = getattr(lifecycle, "build_current_mba_identity_index", None)
        if callable(build_index):
            try:
                if build_index(function_ea=function_ea, mba=mba) is None:
                    return
            except Exception:
                optimizer_logger.debug(
                    "current-MBA identity index unavailable for func=0x%x",
                    function_ea,
                    exc_info=True,
                )
                return
        new_gateway = getattr(lifecycle, "new_current_mba_mutation_gateway", None)
        if not callable(new_gateway):
            return

        def fresh_gateway() -> object | None:
            current_mba = flow_context.mba
            current_function_ea = int(
                getattr(current_mba, "entry_ea", function_ea) or function_ea
            )
            current_maturity = int(
                getattr(current_mba, "maturity", maturity) or maturity
            )
            if (
                build_index(
                    function_ea=current_function_ea,
                    mba=current_mba,
                )
                is None
            ):
                return None
            return new_gateway(
                function_ea=current_function_ea,
                maturity=current_maturity,
            )

        set_factory(fresh_gateway)

    def _new_coordinator_mutation_gateway(
        self,
        mba: ida_hexrays.mbl_array_t,
    ) -> object | None:
        """Build a gateway without depending on a maturity flow context.

        Whole-MBA GLBOPT1 extensions run before the per-maturity context is
        created.  Their mutation authority therefore comes directly from the
        lifecycle coordinator, which owns both the live identity index and the
        gateway factory.
        """
        lifecycle = self._decompilation_lifecycle
        if lifecycle is None:
            return None
        function_ea = int(getattr(mba, "entry_ea", 0) or 0)
        maturity = int(getattr(mba, "maturity", self.current_maturity) or 0)
        build_index = getattr(lifecycle, "build_current_mba_identity_index", None)
        if not callable(build_index):
            return None
        if build_index(function_ea=function_ea, mba=mba) is None:
            return None
        new_gateway = getattr(lifecycle, "new_current_mba_mutation_gateway", None)
        if not callable(new_gateway):
            return None
        return new_gateway(function_ea=function_ea, maturity=maturity)

    def _bind_semantic_native_body_materializer_port(
        self,
        flow_context: FlowMaturityContext,
        mba: ida_hexrays.mbl_array_t,
    ) -> None:
        """Inject manager-owned unpublished-body realization into flow rules."""
        set_factory = getattr(
            flow_context,
            "set_semantic_native_body_materializer_factory",
            None,
        )
        if not callable(set_factory):
            return
        lifecycle = self._decompilation_lifecycle
        if lifecycle is None:
            set_factory(None)
            return
        new_materializer = getattr(
            lifecycle,
            "new_semantic_native_body_materializer",
            None,
        )
        if not callable(new_materializer):
            set_factory(None)
            return
        function_ea = int(getattr(mba, "entry_ea", 0) or 0)
        set_factory(
            lambda: new_materializer(
                function_ea=function_ea,
                mba=flow_context.mba,
            )
        )

    def _bind_resolver_session_state(
        self,
        flow_context: FlowMaturityContext,
        mba: ida_hexrays.mbl_array_t,
    ) -> None:
        """Inject the active lifecycle resolver attachment into flow rules."""
        set_state = getattr(flow_context, "set_resolver_session_state", None)
        if not callable(set_state):
            return
        lifecycle = self._decompilation_lifecycle
        if lifecycle is None:
            set_state(None)
            return
        function_ea = int(getattr(mba, "entry_ea", 0) or 0)
        try:
            session = lifecycle.current_session(function_ea)
            if session is None:
                set_state(None)
                return
            from d810.analyses.control_flow.native_preanalysis_session import (
                attached_resolver_session_state,
            )

            set_state(attached_resolver_session_state(session))
        except Exception:
            optimizer_logger.debug(
                "resolver session state unavailable for func=0x%x",
                function_ea,
                exc_info=True,
            )
            set_state(None)

    def _attach_hint_summary(self, flow_context: FlowMaturityContext) -> None:
        """Derive and attach a persisted hint summary when available."""
        provider = self._flow_context_summary_provider
        if not callable(provider):
            return
        summary = provider(flow_context.func_ea)
        if summary is None:
            return
        flow_context.set_hint_summary(summary)
        optimizer_logger.debug(
            "Attached hint summary to flow context: func=0x%x type=%s conf=%.2f",
            flow_context.func_ea,
            summary.obfuscation_type,
            summary.confidence,
        )

    _KNOWN_GATE_TYPES: typing.ClassVar[frozenset[str]] = frozenset(
        {
            "unflattening_gate",
            "fixpred_gate",
            "preconditioner_gate",
        }
    )

    def _record_flow_outcome(
        self,
        func_ea: int,
        outcome_object: object,
        consumer_type: str,
    ) -> None:
        """Callback for flow-context rules to record outcomes."""
        if consumer_type == "planner":
            callback = self._planner_outcome_callback
            if callable(callback):
                callback(func_ea, outcome_object)
        else:
            if consumer_type not in self._KNOWN_GATE_TYPES:
                optimizer_logger.warning(
                    "_record_flow_outcome: unknown consumer_type=%r for func=0x%x",
                    consumer_type,
                    func_ea,
                )
            callback = self._flow_gate_outcome_callback
            if callable(callback):
                callback(func_ea, outcome_object, gate_name=consumer_type)

    def _record_run_later_requests(
        self,
        flow_context: FlowMaturityContext | None,
        *,
        rule: FlowOptimizationRule,
        func_ea: int,
    ) -> None:
        if flow_context is None:
            return
        drain_requests = getattr(flow_context, "drain_run_later_requests", None)
        if not callable(drain_requests):
            return
        requests = drain_requests()
        if not requests:
            return

        scheduler = self._run_later_scheduler
        current_ir_maturity = self._current_ir_maturity()
        if scheduler is None or current_ir_maturity is None:
            optimizer_logger.debug(
                "discarding %d run_later request(s) for %s: scheduler unavailable",
                len(requests),
                str(rule.name),
            )
            return
        request_method = getattr(scheduler, "request", None)
        if not callable(request_method):
            return
        service = self._execution_scope_service
        if service is None:
            return
        for requested_target_id, request in requests:
            identity = (
                service.identity_for_implementation(
                    rule,
                    pipeline=ExecutionPipeline.FLOW,
                )
                if requested_target_id == str(rule.name)
                else service.identity_for_target(
                    requested_target_id,
                    pipeline=ExecutionPipeline.FLOW,
                )
            )
            if identity is None:
                optimizer_logger.warning(
                    "discarding flow run_later for unknown execution target %s",
                    requested_target_id,
                )
                continue
            accepted = request_method(
                func_ea=func_ea,
                pass_id=identity.pass_id,
                stage_id=identity.stage_id,
                current_maturity=current_ir_maturity,
                run_later=request,
                domain=_RUN_LATER_DOMAIN_OPTIMIZER_RULE,
            )
            if accepted:
                optimizer_logger.debug(
                    "scheduled run_later for %s/%s at %s (func=%#x)",
                    identity.pass_id,
                    identity.stage_id,
                    getattr(request, "at", "?"),
                    func_ea,
                )

    def _configure_rule_scheduler(self, cfg_rule: FlowOptimizationRule) -> None:
        set_pass_scheduler = getattr(cfg_rule, "set_pass_scheduler", None)
        if callable(set_pass_scheduler):
            set_pass_scheduler(self._run_later_scheduler)

    def _configure_rule_project_config(self, cfg_rule: FlowOptimizationRule) -> None:
        set_project_config = getattr(cfg_rule, "set_project_config", None)
        if callable(set_project_config):
            set_project_config(self._project_config)

    def _capture_callback_nop_sites(
        self,
        mba: object,
    ) -> tuple[LiveNopSite, ...] | None:
        """Capture NOP sites only when the diagnostic consumer is installed."""
        if self._fact_consumer_callback is None:
            return None
        try:
            return capture_live_nop_sites(mba)
        except Exception:
            optimizer_logger.debug(
                "failed to capture pre-callback NOP sites",
                exc_info=True,
            )
            return None

    def _capture_callback_block_nop_sites(
        self,
        block: object,
    ) -> tuple[LiveNopSite, ...] | None:
        """Capture only the block owned by one optblock callback."""
        if self._fact_consumer_callback is None:
            return None
        try:
            return capture_block_nop_sites(block)
        except Exception:
            optimizer_logger.debug(
                "failed to capture pre-optblock-callback NOP sites",
                exc_info=True,
            )
            return None

    def _report_callback_nop_delta(
        self,
        mba: object,
        *,
        before: tuple[LiveNopSite, ...] | None,
        callback_kind: str,
        callback_name: str,
        callback_result: int | None,
        exception_name: str | None = None,
    ) -> None:
        """Persist newly created NOPs without affecting callback behavior."""
        if before is None or self._fact_consumer_callback is None:
            return
        try:
            maturity_value = getattr(mba, "maturity", self.current_maturity)
            records = build_callback_nop_delta_records(
                before=before,
                after=capture_live_nop_sites(mba),
                callback_kind=callback_kind,
                callback_name=callback_name,
                callback_result=(
                    None if callback_result is None else int(callback_result)
                ),
                maturity=maturity_to_string(maturity_value),
                exception_name=exception_name,
            )
            if records:
                self._fact_consumer_callback(
                    int(getattr(mba, "entry_ea", 0) or 0),
                    records,
                )
        except Exception:
            optimizer_logger.debug(
                "failed to persist callback NOP delta",
                exc_info=True,
            )

    def _report_callback_block_nop_delta(
        self,
        block: object,
        *,
        before: tuple[LiveNopSite, ...] | None,
        callback_kind: str,
        callback_name: str,
        callback_result: int | None,
        exception_name: str | None = None,
    ) -> None:
        """Persist one optblock callback's block-local NOP delta."""
        if before is None or self._fact_consumer_callback is None:
            return
        try:
            mba = getattr(block, "mba", None)
            maturity_value = getattr(mba, "maturity", self.current_maturity)
            records = build_callback_nop_delta_records(
                before=before,
                after=capture_block_nop_sites(block),
                callback_kind=callback_kind,
                callback_name=callback_name,
                callback_result=(
                    None if callback_result is None else int(callback_result)
                ),
                maturity=maturity_to_string(maturity_value),
                exception_name=exception_name,
            )
            if records:
                self._fact_consumer_callback(
                    int(getattr(mba, "entry_ea", 0) or 0),
                    records,
                )
        except Exception:
            optimizer_logger.debug(
                "failed to persist optblock callback NOP delta",
                exc_info=True,
            )

    def _report_callback_nop_inventory(
        self,
        mba: object,
        *,
        sites: tuple[LiveNopSite, ...] | None,
        callback_kind: str,
        callback_name: str,
        stage: str,
    ) -> None:
        """Persist boundary presence or absence without changing behavior."""
        if sites is None or self._fact_consumer_callback is None:
            return
        try:
            maturity_value = getattr(mba, "maturity", self.current_maturity)
            records = build_callback_nop_inventory_records(
                sites=sites,
                callback_kind=callback_kind,
                callback_name=callback_name,
                stage=stage,
                maturity=maturity_to_string(maturity_value),
            )
            self._fact_consumer_callback(
                int(getattr(mba, "entry_ea", 0) or 0),
                records,
            )
        except Exception:
            optimizer_logger.debug(
                "failed to persist callback NOP inventory",
                exc_info=True,
            )

    @staticmethod
    def _extract_project_config(kwargs: dict[str, typing.Any]) -> dict[str, typing.Any]:
        return {
            key: value for key, value in kwargs.items() if key in _PROJECT_CONFIG_KEYS
        }

    def optimize(self, blk: ida_hexrays.mblock_t):
        if d810_optimization_is_suppressed():
            return 0
        active_rules = self._resolve_active_rules(blk)
        rules = active_rules if active_rules is not None else tuple(self.cfg_rules)
        rules = self._order_rules_for_execution(rules)
        phases = self._group_rules_by_priority(rules)
        func_ea = (
            int(blk.mba.entry_ea)
            if (blk.mba is not None and blk.mba.entry_ea is not None)
            else 0
        )

        if active_rules is not None:
            self._perf_counters["scoped_calls"] += 1
            self._perf_counters["scoped_candidates_total"] += len(rules)
            if self._perf_compare_execution_scope and func_ea != 0:
                self._perf_counters["legacy_candidates_total"] += (
                    self._legacy_candidate_count(func_ea)
                )
        else:
            self._perf_counters["legacy_calls"] += 1
            if func_ea != 0:
                self._perf_counters["legacy_candidates_total"] += (
                    self._legacy_candidate_count(func_ea)
                )
            else:
                self._perf_counters["legacy_candidates_total"] += len(rules)

        for phase_index, (phase_priority, phase_rules) in enumerate(phases, start=1):
            flow_context = self._get_or_create_flow_context(
                blk,
                phase_priority=phase_priority,
                phase_index=phase_index,
                phase_rules=phase_rules,
            )
            if self._frontend_generation_is_stale(flow_context):
                optimizer_logger.info(
                    "flow pipeline deferred for function %#x: "
                    "receipt-backed PREOPT reimport pending",
                    func_ea,
                )
                return 0
            for cfg_rule in phase_rules:
                cfg_rule.current_maturity = self.current_maturity
                cfg_rule.current_generation = self._generation
                cfg_rule.set_flow_context(flow_context)
                guard = blk.mba is not None and blk.mba.entry_ea is not None
                if active_rules is None:
                    guard &= self.check_if_rule_is_activated_for_address(
                        cfg_rule, blk.mba.entry_ea
                    )
                if guard:
                    # uee-b7ze causality fence: when
                    # ``D810_FENCE_INSN_OPT_AT_GLBOPT1`` is set, also
                    # gate FlowOptimizationRule.optimize at GLBOPT1
                    # (covers JumpFixer / IndirectBranchResolver /
                    # IdentityCallResolver / etc.).  HCC's hodur
                    # unflattener fires through a SEPARATE
                    # orchestration path (not cfg_rule.optimize), so
                    # this fence does NOT block HCC.
                    try:
                        import os as _os

                        if _os.environ.get(
                            "D810_FENCE_INSN_OPT_AT_GLBOPT1",
                            "",
                        ) and int(self.current_maturity) == int(
                            ida_hexrays.MMAT_GLBOPT1
                        ):
                            if not getattr(
                                cfg_rule,
                                "_fence_logged_glbopt1",
                                False,
                            ):
                                optimizer_logger.info(
                                    "FENCE_INSN_OPT_AT_GLBOPT1 active for"
                                    " FlowOptimizationRule %s",
                                    type(cfg_rule).__name__,
                                )
                                cfg_rule._fence_logged_glbopt1 = True
                            continue
                    except Exception:
                        pass
                    rule_name = str(cfg_rule.name)
                    if flow_context is not None:
                        set_current_rule_name = getattr(
                            flow_context,
                            "set_current_rule_name",
                            None,
                        )
                        if callable(set_current_rule_name):
                            set_current_rule_name(rule_name)
                    callback_nop_sites = self._capture_callback_block_nop_sites(blk)
                    callback_result: int | None = None
                    callback_exception_name: str | None = None
                    try:
                        callback_result = cfg_rule.optimize(blk)
                        nb_patch = callback_result
                    except Exception as error:
                        callback_exception_name = type(error).__name__
                        raise
                    finally:
                        self._report_callback_block_nop_delta(
                            blk,
                            before=callback_nop_sites,
                            callback_kind="optblock_rule",
                            callback_name=rule_name,
                            callback_result=callback_result,
                            exception_name=callback_exception_name,
                        )
                        self._record_run_later_requests(
                            flow_context,
                            rule=cfg_rule,
                            func_ea=func_ea,
                        )
                        if flow_context is not None:
                            set_current_rule_name = getattr(
                                flow_context,
                                "set_current_rule_name",
                                None,
                            )
                            if callable(set_current_rule_name):
                                set_current_rule_name(None)
                    if nb_patch > 0:
                        optimizer_logger.info(
                            "Rule {0} matched: {1} patches".format(
                                cfg_rule.name, nb_patch
                            )
                        )
                        if self.stats is not None:
                            self.stats.record_cfg_rule_patches(
                                cfg_rule.name,
                                nb_patch,
                                maturity=self.current_maturity,
                            )
                        self._generation += 1
                        # Rebuild analysis context after any CFG write so lower
                        # priorities see fresh facts on the next callback pass.
                        self._invalidate_flow_context(
                            f"{cfg_rule.name} applied {nb_patch} patch(es)"
                        )
                        return nb_patch

        impossible_artifact_patch_count = (
            self._maybe_rewrite_impossible_return_artifact_edges(blk)
        )
        literal_return_patch_count = (
            self._maybe_rewrite_terminal_zero_guard_literal_edges(blk)
        )
        late_patch_count = impossible_artifact_patch_count + literal_return_patch_count
        if late_patch_count > 0:
            self._generation += 1
            self._invalidate_flow_context(
                f"late terminal return cleanup applied {late_patch_count} patch(es)"
            )
            return late_patch_count
        return 0

    def _maybe_rewrite_impossible_return_artifact_edges(
        self,
        blk: ida_hexrays.mblock_t,
    ) -> int:
        mba = getattr(blk, "mba", None)
        if mba is None or self.current_maturity is None:
            return 0
        if int(self.current_maturity) != int(ida_hexrays.MMAT_GLBOPT2):
            return 0
        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        key = (func_ea, int(self.current_maturity))
        if key in self._impossible_return_artifact_rewrite_applied:
            return 0
        try:
            from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
                impossible_return_artifact_rewrite_enabled,
                maybe_rewrite_impossible_return_artifact_edges,
            )

            if not impossible_return_artifact_rewrite_enabled():
                return 0
            applied = maybe_rewrite_impossible_return_artifact_edges(
                mba,
                mutation_gateway=self._flow_context.new_mba_mutation_gateway(),
            )
        except Exception:
            optimizer_logger.exception(
                "impossible return artifact return-edge cleanup failed"
            )
            return 0
        if not applied:
            return 0
        self._impossible_return_artifact_rewrite_applied.add(key)
        if self.stats is not None:
            self.stats.record_cfg_rule_patches(
                "impossible_return_artifact_edges",
                len(applied),
                maturity=self.current_maturity,
            )
        return len(applied)

    def _run_glbopt1_preanalysis_backed_extensions(
        self,
        mba: ida_hexrays.mba_t,
    ) -> None:
        """Run whole-function GLBOPT1 rewrites consuming preanalysis evidence.

        This is intentionally not a normal ``FlowOptimizationRule`` callback:
        terminal-tail egress consumes whole-function facts emitted by
        ``FLOWGRAPH_READY`` / ``analyze_and_persist`` above and then mutates
        multiple blocks. Running it at the next maturity is too late because
        IDA may already have collapsed the CFG shape that those facts describe.
        """
        terminal_tail_patch_count = (
            self._maybe_run_terminal_tail_cascade_egress_lowering(mba)
        )
        if terminal_tail_patch_count <= 0:
            return
        self._generation += 1
        self._invalidate_flow_context(
            "terminal tail cascade egress applied "
            f"{terminal_tail_patch_count} patch(es)"
        )

    def _maybe_run_terminal_tail_cascade_egress_lowering(
        self,
        mba: ida_hexrays.mba_t,
    ) -> int:
        if mba is None or self.current_maturity is None:
            return 0
        current_maturity_name = maturity_to_string(self.current_maturity)
        if current_maturity_name != "MMAT_GLBOPT1":
            return 0
        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        key = (func_ea, int(self.current_maturity))
        if key in self._terminal_tail_cascade_egress_applied:
            return 0

        priors = None
        if self._function_priors_provider is not None:
            try:
                priors = self._function_priors_provider(func_ea)
            except Exception:
                optimizer_logger.exception(
                    "terminal tail cascade egress prior lookup failed for func=0x%x",
                    func_ea,
                )
                priors = None
        else:
            optimizer_logger.debug(
                "terminal tail cascade egress has no function priors provider "
                "for func=0x%x; using discovered facts",
                func_ea,
            )
        cascade_priors = getattr(priors, "terminal_tail_cascade_egress", None)
        configured_byte_indices = tuple(
            getattr(cascade_priors, "byte_indices", ()) or ()
        )
        optimizer_logger.debug(
            "terminal tail cascade egress candidate for func=0x%x: "
            "configured_byte_indices=%s split_byte_indices=%s",
            func_ea,
            configured_byte_indices,
            tuple(getattr(cascade_priors, "split_byte_indices", ()) or ()),
        )

        fact_view = None
        if callable(self._validated_fact_view_provider):
            try:
                fact_view = self._validated_fact_view_provider(
                    func_ea,
                    current_maturity_name,
                )
            except Exception:
                optimizer_logger.exception(
                    "terminal tail cascade egress fact lookup failed for func=0x%x",
                    func_ea,
                )
                fact_view = None

        try:
            from d810.analyses.control_flow.runtime_evidence import (
                ensure_terminal_byte_fact_view,
                get_latest_reconstruction_dag,
            )
            from d810.analyses.control_flow.persisted_preanalysis_dag import (
                get_persisted_preanalysis_dag,
            )
            from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
                maybe_run_terminal_tail_cascade_egress_lowering,
            )

            fact_view = ensure_terminal_byte_fact_view(
                mba,
                func_ea=func_ea,
                maturity=int(self.current_maturity),
                fact_view=fact_view,
                phase="post_d810",
            )
            dag = get_latest_reconstruction_dag(func_ea)
            if dag is None:
                dag = get_persisted_preanalysis_dag(func_ea)
            mutation_gateway = self._new_coordinator_mutation_gateway(mba)
            if mutation_gateway is None:
                optimizer_logger.warning(
                    "terminal tail cascade egress skipped without a "
                    "coordinator-owned mutation gateway for func=0x%x",
                    func_ea,
                )
                return 0
            applied = maybe_run_terminal_tail_cascade_egress_lowering(
                mba,
                mutation_gateway=mutation_gateway,
                fact_view=fact_view,
                dag=dag,
                cascade_priors=cascade_priors,
                dispatcher_artifact_planner=self._dispatcher_artifact_planner,
            )
        except Exception:
            optimizer_logger.exception(
                "terminal tail cascade egress lowering failed for func=0x%x",
                func_ea,
            )
            return 0

        self._terminal_tail_cascade_egress_applied.add(key)
        if not applied:
            return 0
        if self.stats is not None:
            self.stats.record_cfg_rule_patches(
                "terminal_tail_cascade_egress",
                1,
                maturity=self.current_maturity,
            )
        return 1

    def _maybe_rewrite_terminal_zero_guard_literal_edges(
        self,
        blk: ida_hexrays.mblock_t,
    ) -> int:
        mba = getattr(blk, "mba", None)
        if mba is None or self.current_maturity is None:
            return 0
        if int(self.current_maturity) != int(ida_hexrays.MMAT_GLBOPT2):
            return 0
        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        key = (func_ea, int(self.current_maturity))
        if key in self._terminal_zero_literal_rewrite_applied:
            return 0
        try:
            from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
                maybe_rewrite_terminal_zero_guard_literal_return_edges,
                terminal_zero_guard_literal_return_rewrite_enabled,
                terminal_zero_guard_literal_return_values,
            )

            if not terminal_zero_guard_literal_return_rewrite_enabled():
                return 0
            if not terminal_zero_guard_literal_return_values(mba):
                return 0
            applied = maybe_rewrite_terminal_zero_guard_literal_return_edges(
                mba,
                mutation_gateway=self._flow_context.new_mba_mutation_gateway(),
            )
        except Exception:
            optimizer_logger.exception(
                "terminal zero-guard literal return cleanup failed"
            )
            return 0
        if not applied:
            return 0
        self._terminal_zero_literal_rewrite_applied.add(key)
        if self.stats is not None:
            self.stats.record_cfg_rule_patches(
                "terminal_zero_guard_literal_return_edges",
                len(applied),
                maturity=self.current_maturity,
            )
        return len(applied)

    def add_rule(self, cfg_rule: FlowOptimizationRule):
        optimizer_logger.info("Adding cfg rule {0}".format(cfg_rule))
        if cfg_rule not in self.cfg_rules:
            self.cfg_rules.append(cfg_rule)
        self._configure_rule_scheduler(cfg_rule)
        self._configure_rule_project_config(cfg_rule)

    def configure(self, **kwargs):
        if "project_name" in kwargs or any(
            key in kwargs for key in _PROJECT_CONFIG_KEYS
        ):
            self._project_config = self._extract_project_config(kwargs)
        self._validated_fact_view_provider = kwargs.get(
            "validated_fact_view_provider",
            self._validated_fact_view_provider,
        )
        self._fact_consumer_callback = kwargs.get(
            "fact_consumer_callback",
            self._fact_consumer_callback,
        )
        self._flow_context_summary_provider = kwargs.get(
            "flow_context_summary_provider",
            self._flow_context_summary_provider,
        )
        self._planner_outcome_callback = kwargs.get(
            "planner_outcome_callback",
            self._planner_outcome_callback,
        )
        self._flow_gate_outcome_callback = kwargs.get(
            "flow_gate_outcome_callback",
            self._flow_gate_outcome_callback,
        )
        self._decompilation_lifecycle = kwargs.get(
            "decompilation_lifecycle",
            self._decompilation_lifecycle,
        )
        self._function_priors_provider = kwargs.get(
            "function_priors_provider",
            self._function_priors_provider,
        )
        self._dispatcher_artifact_planner = kwargs.get(
            "dispatcher_artifact_planner",
            self._dispatcher_artifact_planner,
        )
        self._pass_pipeline = kwargs.get("pass_pipeline", self._pass_pipeline)
        self._run_later_scheduler = kwargs.get(
            "pass_scheduler",
            self._run_later_scheduler,
        )
        for cfg_rule in self.cfg_rules:
            self._configure_rule_scheduler(cfg_rule)
            self._configure_rule_project_config(cfg_rule)
        self._execution_scope_service = kwargs.get(
            "execution_scope_service", self._execution_scope_service
        )
        self._execution_scope_project_name = str(
            kwargs.get(
                "execution_scope_project_name", self._execution_scope_project_name
            )
        )
        self._execution_scope_idb_key = str(
            kwargs.get("execution_scope_idb_key", self._execution_scope_idb_key)
        )
        self._perf_compare_execution_scope = bool(
            kwargs.get(
                "execution_scope_perf_compare", self._perf_compare_execution_scope
            )
        )

    def check_if_rule_is_activated_for_address(
        self, cfg_rule: FlowOptimizationRule, func_entry_ea: int
    ):
        if cfg_rule.use_whitelist and (
            func_entry_ea not in cfg_rule.whitelisted_function_ea_list
        ):
            return False
        if cfg_rule.use_blacklist and (
            func_entry_ea in cfg_rule.blacklisted_function_ea_list
        ):
            return False
        return True
