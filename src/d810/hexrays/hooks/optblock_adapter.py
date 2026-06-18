from __future__ import annotations

import math
import pathlib
import sqlite3
import time
from collections import defaultdict

import ida_hexrays

from d810.core import getLogger, typing
from d810.core.rule_scope import PIPELINE_FLOW
from d810.errors import D810Exception
from d810.hexrays.lifecycle import (
    DecompilationEvent,
    _emit_flowgraph_ready_event,
)
from d810.hexrays.ir_maturity import ida_maturity_to_ir
from d810.hexrays.utils.hexrays_formatters import maturity_to_string

main_logger = getLogger("D810")
optimizer_logger = getLogger("D810.optimizer")
_RUN_LATER_DOMAIN_OPTIMIZER_RULE = "optimizer_rule"

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
        self._rule_scope_service = None
        self._rule_scope_project_name = ""
        self._rule_scope_idb_key = ""
        self._perf_compare_rule_scope = False
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
        self._flow_context_key: tuple[int, int] | None = None
        # Optional ReconPhase - set via configure(recon_phase=...). None means
        # recon is disabled (zero overhead when not enabled).
        self._recon_phase = None  # ReconPhase | None
        # Optional ReconAnalysisRuntime - set via configure(recon_runtime=...).
        # Used to reset recon state when a new function is decompiled.
        self._recon_runtime = None  # ReconAnalysisRuntime | None
        self._function_priors_provider = None
        # Optional PassPipeline - set via configure(pass_pipeline=...). None
        # means the pipeline is disabled (zero overhead). When set, fires once
        # at MMAT_GLBOPT2 (after the unflattener has finished at MMAT_GLBOPT1).
        self._pass_pipeline = None  # PassPipeline | None
        self._pipeline_last_maturity: int = -1
        self._post_d810_pipeline_last_maturity: int = -1
        self._impossible_return_artifact_rewrite_applied: set[tuple[int, int]] = set()
        self._terminal_zero_literal_rewrite_applied: set[tuple[int, int]] = set()
        # When the PassPipeline fires and applies changes, we must skip all
        # remaining block optimizer rule calls for the rest of this maturity.
        # IDA will re-enter at the next maturity with fresh block pointers.
        # Accessing stale mop_t pointers after pipeline mutations causes segfaults.
        self._pipeline_just_fired: bool = False
        self._run_later_scheduler = None
        self._run_later_rule_names: frozenset[str] = frozenset()
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
        self._reset_run_later_state()
        for cfg_rule in self.cfg_rules:
            reset_pass_manager = getattr(cfg_rule, "reset_pass_manager_state", None)
            if callable(reset_pass_manager):
                reset_pass_manager()

    def _reset_run_later_state(self) -> None:
        self._run_later_rule_names = frozenset()
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
        self._run_later_rule_names = frozenset()
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
        self._run_later_rule_names = frozenset(
            str(getattr(item, "pass_id", ""))
            for item in pending
            if str(getattr(item, "pass_id", ""))
        )
        if self._run_later_rule_names:
            optimizer_logger.info(
                "run_later scheduler activated flow rules at %s for function %#x: %s",
                maturity_to_string(int(self.current_maturity)),
                func_ea,
                sorted(self._run_later_rule_names),
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
            total = self._pass_pipeline.run(mba)
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
            self._perf_compare_rule_scope,
        )

    def func(self, blk: ida_hexrays.mblock_t):
        self.log_info_on_input(blk)

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
            if main_logger.debug_on:
                main_logger.debug(
                    "BlockOptimizer called at maturity: %s",
                    maturity_to_string(mba.maturity),
                )

            # Notify listeners that D810 just finished running for the previous
            # maturity level. Policy decisions (capture/logging/etc.) are handled
            # by subscribers in the manager layer.
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
            # every existing recon-collection lifecycle point.  When
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

            # uee-b7ze renderer-boundary isolation: when
            # ``D810_FORCE_BLK129_TO_BLK130`` is set AND we're entering
            # MMAT_LVARS for the sub_7FFD3338C040 entry_ea, force
            # blk[129]'s 2-way conditional to unconditionally route to
            # blk[130].  Diagnostic-only knob: tests whether IDA's
            # pseudocode renderer drops the call because the renderer
            # proves blk[130]'s arm of blk[129] unreachable, vs. some
            # other renderer-side DCE.  Acceptance: final --- AFTER ---
            # contains "0x11, 0x4A".
            try:
                import os as _os_force
                _force_env = _os_force.environ.get(
                    "D810_FORCE_BLK129_TO_BLK130", "",
                )
                # Fire on entering MMAT_GLBOPT3 (the last maturity
                # d810 observes before MMAT_LVARS).  d810 doesn't get
                # a per-block callback at MMAT_LVARS itself, so this
                # is the latest moment we can mutate the live mba
                # before IDA's variable analysis + ctree generation.
                _is_late_pre_lvars = int(self.current_maturity) in (
                    int(ida_hexrays.MMAT_GLBOPT3),
                    int(ida_hexrays.MMAT_LVARS),
                )
                if _force_env and _is_late_pre_lvars:
                    from d810.hexrays.mutation.deferred_modifier import (
                        DeferredGraphModifier,
                    )
                    _qty = int(getattr(mba, "qty", 0) or 0)
                    if _qty > 130:
                        _b129 = mba.get_mblock(129)
                        _b130 = mba.get_mblock(130)
                        if _b129 is not None and _b130 is not None:
                            try:
                                _b129_type = int(_b129.type)
                                _b129_nsucc = int(_b129.nsucc())
                                _b129_succs = tuple(
                                    int(_b129.succ(i))
                                    for i in range(_b129_nsucc)
                                )
                                _b129_tail_op = (
                                    int(_b129.tail.opcode)
                                    if _b129.tail is not None else -1
                                )
                                # Dump blk[129] condition + raw context
                                # so we can correlate with renderer
                                # behavior even if the patch fails.
                                main_logger.warning(
                                    "FORCE_BLK129 LVARS pre-patch:"
                                    " type=%d nsucc=%d succs=%s"
                                    " tail_opcode=%d (env=%r)",
                                    _b129_type, _b129_nsucc,
                                    list(_b129_succs), _b129_tail_op,
                                    _force_env,
                                )
                                # Try to coerce to a clean 1-way goto
                                # to blk[130].  If blk[129] is already
                                # 1-way, just retarget; else convert.
                                _modifier = DeferredGraphModifier(mba)
                                if _b129_nsucc == 1:
                                    _modifier.queue_goto_change(
                                        129,
                                        130,
                                        description="FORCE_BLK129 LVARS retarget",
                                    )
                                    _ok = _modifier.apply(
                                        defer_post_apply_maintenance=True,
                                    ) > 0
                                    main_logger.warning(
                                        "FORCE_BLK129 retarget 1-way -> 130: %s",
                                        _ok,
                                    )
                                else:
                                    _modifier.queue_convert_to_goto(
                                        129,
                                        130,
                                        description="FORCE_BLK129 LVARS convert to goto",
                                    )
                                    _modifier.apply(
                                        defer_post_apply_maintenance=True,
                                    )
                                    main_logger.warning(
                                        "FORCE_BLK129 rewrite 2-way -> 1-way goto blk[130] applied"
                                    )
                            except Exception as _e_force:
                                main_logger.warning(
                                    "FORCE_BLK129 patch raised: %s",
                                    _e_force,
                                )
            except Exception:
                pass  # diagnostic, never gates decompilation

            # Recon: reset state when a new function is decompiled, then
            # fire microcode collectors at this maturity. No-op when recon is
            # disabled (_recon_phase / _recon_runtime is None).
            # The runtime deduplicates reset_for_func across managers.
            mba_ea = int(getattr(mba, "entry_ea", 0) or 0)
            if self._recon_runtime is not None:
                try:
                    did_reset = self._recon_runtime.reset_for_func(mba_ea)
                except Exception:
                    optimizer_logger.exception(
                        "ReconRuntime reset failed for func=0x%x", mba_ea
                    )
                    did_reset = False
                if did_reset and self._rule_scope_service is not None:
                    try:
                        self._rule_scope_service.clear_hint_state(mba_ea)
                    except Exception:
                        optimizer_logger.exception(
                            "RuleScopeService clear_hint_state failed for func=0x%x",
                            mba_ea,
                        )
            # E4a: emit ``FLOWGRAPH_READY`` AFTER ``reset_for_func``.
            # Critical ordering: ``reset_for_func`` clears the
            # ``ReconPhase`` maturity guard and calls ``store.clear_func``;
            # if we emitted BEFORE the reset, the subscriber would
            # collect into a store that the reset immediately wipes,
            # AND a stale ``_fired`` guard from a prior decompilation
            # could even suppress the collection entirely.  The old
            # direct ``run_microcode_collectors(mba, ...)`` call was
            # placed AFTER the reset for the same reason; the
            # subscriber must inherit that placement.
            _emit_flowgraph_ready_event(
                self.event_emitter,
                mba,
                snapshot=_pre_snap_ref,
            )
            # ``run_microcode_collectors(mba, ...)`` is now invoked by
            # the ``FLOWGRAPH_READY`` subscriber on ``D810`` (see
            # ``manager.flowgraph_ready.FlowGraphReadySubscriber``).  The
            # event fires immediately above and ``ReconPhase`` dedupes
            # by ``(func_ea, maturity)``, so a direct call here would
            # double-collect.
            #
            # ``capture_maturity_facts`` is also routed through the
            # ``FLOWGRAPH_READY`` subscriber when this block-manager
            # event carries ``_pre_snap_ref``.  Keep it there so
            # pre-D810 facts observe the portable ``FlowGraph`` and
            # stay in lockstep with the recon collection event.
            if self._recon_phase is not None:
                if self._recon_runtime is not None:
                    try:
                        hints = self._recon_runtime.analyze_and_persist(mba_ea)
                        if hints is not None and self._rule_scope_service is not None:
                            result = self._rule_scope_service.apply_hints(hints)
                            optimizer_logger.info(
                                "Applied recon hints to rule scope (block) for func=0x%x",
                                mba_ea,
                            )
                            self._recon_runtime.record_rule_scope_outcome(
                                func_ea=mba_ea,
                                hints=hints,
                                apply_result=result,
                                source="analyzed",
                            )
                    except Exception:
                        optimizer_logger.exception(
                            "ReconRuntime analyze_and_persist (block) failed for func=0x%x",
                            mba_ea,
                        )

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

    # statistics are managed centrally via the stats object

    def _resolve_active_rules(
        self, blk: ida_hexrays.mblock_t
    ) -> tuple[FlowOptimizationRule, ...] | None:
        if self._rule_scope_service is None:
            # FAIL CLOSED: If rule scope service not initialized, run NO rules
            # instead of ALL rules. This prevents hangs when optimizer callbacks
            # fire before configure() is called.
            optimizer_logger.warning(
                "Rule scope service not initialized at block optimize time - no rules will run. "
                "This may indicate a race condition during initialization."
            )
            return ()
        if blk.mba is None or blk.mba.entry_ea is None:
            return ()
        if self.current_maturity is None:
            return ()
        t0_ns = time.perf_counter_ns()
        rules = self._rule_scope_service.get_active_rules(
            project_name=self._rule_scope_project_name,
            idb_key=self._rule_scope_idb_key,
            func_ea=int(blk.mba.entry_ea),
            pipeline=PIPELINE_FLOW,
            maturity=int(self.current_maturity),
        )
        self._perf_counters["scoped_lookup_ns"] += time.perf_counter_ns() - t0_ns
        return self._include_run_later_rules(
            rules,
            func_entry_ea=int(blk.mba.entry_ea),
        )

    def _include_run_later_rules(
        self,
        active_rules: tuple[FlowOptimizationRule, ...],
        *,
        func_entry_ea: int,
    ) -> tuple[FlowOptimizationRule, ...]:
        if not self._run_later_rule_names:
            return active_rules

        by_name = {str(rule.name): rule for rule in active_rules}
        missing = set(self._run_later_rule_names)
        for cfg_rule in self.cfg_rules:
            rule_name = str(cfg_rule.name)
            if rule_name not in self._run_later_rule_names:
                continue
            missing.discard(rule_name)
            if rule_name in by_name:
                continue
            if not self.check_if_rule_is_activated_for_address(
                cfg_rule,
                func_entry_ea,
            ):
                continue
            by_name[rule_name] = cfg_rule

        if missing:
            optimizer_logger.warning(
                "run_later scheduler could not find configured flow rule(s): %s",
                sorted(missing),
            )
        return tuple(by_name.values())

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
        # Higher priority values run first. Name is a deterministic tiebreaker.
        return tuple(
            sorted(
                rules,
                key=lambda rule: (-self._rule_priority(rule), str(rule.name)),
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
        key = (int(mba.entry_ea), int(self.current_maturity))
        if self._flow_context is None or self._flow_context_key != key:
            self._flow_context = self._flow_context_type(
                mba=mba,
                func_ea=int(mba.entry_ea),
                maturity=int(self.current_maturity),
            )
            self._flow_context_key = key
            self._attach_hint_summary(self._flow_context)
            if self._recon_runtime is not None:
                self._flow_context.set_outcome_callback(self._record_flow_outcome)
                self._flow_context.set_fact_lifecycle_callbacks(
                    view_provider=self._recon_runtime.validated_fact_view,
                    consumer_callback=self._recon_runtime.record_fact_consumers,
                )
        else:
            self._flow_context.refresh_mba(mba)
        self._flow_context.set_function_priors_provider(
            self._function_priors_provider
        )
        self._flow_context.set_phase(
            priority=phase_priority,
            phase_index=phase_index,
            active_rule_names=tuple(str(rule.name) for rule in phase_rules),
        )
        self._flow_context.prime_for_rules(phase_rules)
        return self._flow_context

    def _attach_hint_summary(self, flow_context: FlowMaturityContext) -> None:
        """Derive and attach a hint summary from the recon store if available."""
        if self._recon_runtime is None:
            return
        summary = self._recon_runtime.load_flow_context_summary(flow_context.func_ea)
        if summary is None:
            return
        flow_context.set_hint_summary(summary)
        optimizer_logger.debug(
            "Attached hint summary to flow context: func=0x%x type=%s conf=%.2f",
            flow_context.func_ea,
            summary.obfuscation_type,
            summary.confidence,
        )

    _KNOWN_GATE_TYPES: typing.ClassVar[frozenset[str]] = frozenset({
        "unflattening_gate", "fixpred_gate", "preconditioner_gate",
    })

    def _record_flow_outcome(
        self, func_ea: int, outcome_object: object, consumer_type: str,
    ) -> None:
        """Callback for flow-context rules to record outcomes."""
        if self._recon_runtime is None:
            return
        if consumer_type == "planner":
            self._recon_runtime.record_planner_outcome(func_ea, outcome_object)
        else:
            if consumer_type not in self._KNOWN_GATE_TYPES:
                optimizer_logger.warning(
                    "_record_flow_outcome: unknown consumer_type=%r for func=0x%x",
                    consumer_type, func_ea,
                )
            self._recon_runtime.record_flow_gate_outcome(func_ea, outcome_object, gate_name=consumer_type)

    def _record_run_later_requests(
        self,
        flow_context: FlowMaturityContext | None,
        *,
        rule_name: str,
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
                rule_name,
            )
            return
        request_method = getattr(scheduler, "request", None)
        if not callable(request_method):
            return
        for requested_pass_id, request in requests:
            accepted = request_method(
                func_ea=func_ea,
                pass_id=requested_pass_id,
                current_maturity=current_ir_maturity,
                run_later=request,
                domain=_RUN_LATER_DOMAIN_OPTIMIZER_RULE,
            )
            if accepted:
                optimizer_logger.debug(
                    "scheduled run_later for %s at %s (func=%#x)",
                    requested_pass_id,
                    getattr(request, "at", "?"),
                    func_ea,
                )

    def _configure_rule_scheduler(self, cfg_rule: FlowOptimizationRule) -> None:
        set_pass_scheduler = getattr(cfg_rule, "set_pass_scheduler", None)
        if callable(set_pass_scheduler):
            set_pass_scheduler(self._run_later_scheduler)

    def optimize(self, blk: ida_hexrays.mblock_t):
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
            if self._perf_compare_rule_scope and func_ea != 0:
                self._perf_counters[
                    "legacy_candidates_total"
                ] += self._legacy_candidate_count(func_ea)
        else:
            self._perf_counters["legacy_calls"] += 1
            if func_ea != 0:
                self._perf_counters[
                    "legacy_candidates_total"
                ] += self._legacy_candidate_count(func_ea)
            else:
                self._perf_counters["legacy_candidates_total"] += len(rules)

        for phase_index, (phase_priority, phase_rules) in enumerate(phases, start=1):
            flow_context = self._get_or_create_flow_context(
                blk,
                phase_priority=phase_priority,
                phase_index=phase_index,
                phase_rules=phase_rules,
            )
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
                        if (
                            _os.environ.get(
                                "D810_FENCE_INSN_OPT_AT_GLBOPT1", "",
                            )
                            and int(self.current_maturity)
                            == int(ida_hexrays.MMAT_GLBOPT1)
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
                    try:
                        nb_patch = cfg_rule.optimize(blk)
                    finally:
                        self._record_run_later_requests(
                            flow_context,
                            rule_name=rule_name,
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
                "late terminal return cleanup applied "
                f"{late_patch_count} patch(es)"
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
                maybe_rewrite_impossible_return_artifact_edges,
            )

            applied = maybe_rewrite_impossible_return_artifact_edges(mba)
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
            )

            applied = maybe_rewrite_terminal_zero_guard_literal_return_edges(mba)
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

    def configure(self, **kwargs):
        self._recon_phase = kwargs.get("recon_phase", self._recon_phase)
        self._recon_runtime = kwargs.get("recon_runtime", self._recon_runtime)
        self._function_priors_provider = kwargs.get(
            "function_priors_provider",
            self._function_priors_provider,
        )
        self._pass_pipeline = kwargs.get("pass_pipeline", self._pass_pipeline)
        self._run_later_scheduler = kwargs.get(
            "pass_scheduler",
            self._run_later_scheduler,
        )
        for cfg_rule in self.cfg_rules:
            self._configure_rule_scheduler(cfg_rule)
        self._rule_scope_service = kwargs.get(
            "rule_scope_service", self._rule_scope_service
        )
        self._rule_scope_project_name = str(
            kwargs.get("rule_scope_project_name", self._rule_scope_project_name)
        )
        self._rule_scope_idb_key = str(
            kwargs.get("rule_scope_idb_key", self._rule_scope_idb_key)
        )
        self._perf_compare_rule_scope = bool(
            kwargs.get("rule_scope_perf_compare", self._perf_compare_rule_scope)
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
