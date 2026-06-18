from __future__ import annotations

import pathlib
from collections import defaultdict

import ida_hexrays

from d810.core import getLogger, typing
from d810.core.cymode import CythonMode
from d810.core.rule_scope import PIPELINE_INSTRUCTION
from d810.errors import D810Exception
from d810.hexrays.ir.minsn_utils import build_z3_equivalence_proof
from d810.hexrays.lifecycle import (
    DecompilationEvent,
    _emit_flowgraph_ready_event,
)
from d810.hexrays.ir_maturity import ida_maturity_to_ir
from d810.hexrays.mutation.cfg_verify import safe_verify
from d810.hexrays.utils.hexrays_formatters import (
    count_minsn_nodes,
    dump_microcode_for_debug,
    format_minsn_t,
    maturity_to_string,
)
from d810.hexrays.utils.hexrays_helpers import check_ins_mop_size_are_ok
from d810.mba.backend_registry import get_egglog_provider

main_logger = getLogger("D810")
optimizer_logger = getLogger("D810.optimizer")
z3_file_logger = getLogger("D810.z3_test")
_RUN_LATER_DOMAIN_OPTIMIZER_RULE = "optimizer_rule"

# ---------------------------------------------------------------------------
# hash_minsn: Cython fast path with pure-Python fallback
# ---------------------------------------------------------------------------
# The Cython version (in speedups/cythxr/_chexrays_api.pyx) hashes the opcode
# and all three operands (l, r, d) at the C level for speed.  When Cython is
# unavailable we fall back to hashing the printed representation of the
# instruction, which is slower but always available.
#
# The OptimizationCache class (in d810.backends.hexrays.evidence.caching) was considered for
# seen-hash storage but rejected: it is SQLite-backed, function-level, and
# designed for cross-session persistence -- far too heavy for per-instruction,
# per-decompilation cycle detection.  A lightweight
# ``dict[int, set[int]]`` (instruction EA -> set of post-rewrite hashes) is
# used instead.
# ---------------------------------------------------------------------------
_cy_hash_minsn = None
if CythonMode().is_enabled():
    try:
        from d810.speedups.cythxr._chexrays_api import hash_minsn as _cy_hash_minsn
    except ImportError:
        pass


def _hash_minsn_fallback(ins: ida_hexrays.minsn_t, func_entry_ea: int = 0) -> int:
    """Pure-Python fallback for hashing an minsn_t.

    Uses the printed representation of the instruction as a proxy for its
    structural content.  Slower than Cython but always available.
    """
    return hash((ins.opcode, ins._print(), func_entry_ea))


def hash_minsn(ins: ida_hexrays.minsn_t, func_entry_ea: int = 0) -> int:
    """Return a structural hash for an minsn_t, using Cython when available."""
    if _cy_hash_minsn is not None:
        try:
            return int(_cy_hash_minsn(ins, func_entry_ea))
        except Exception:
            pass
    return _hash_minsn_fallback(ins, func_entry_ea)


# Note: VerifiableRule and adapt_rules are loaded/filtered in manager.py
# Rules are added to PatternOptimizer via add_rule() based on project config

# Try to import egglog-based optimizer (optional dependency)
try:
    EGGLOG_AVAILABLE = bool(get_egglog_provider("egglog").is_available())
except ImportError:
    EGGLOG_AVAILABLE = False

DEFAULT_OPTIMIZATION_PATTERN_MATURITIES = [
    ida_hexrays.MMAT_PREOPTIMIZED,
    ida_hexrays.MMAT_LOCOPT,
    ida_hexrays.MMAT_CALLS,
    ida_hexrays.MMAT_GLBOPT1,
]
DEFAULT_OPTIMIZATION_CHAIN_MATURITIES = [
    ida_hexrays.MMAT_PREOPTIMIZED,
    ida_hexrays.MMAT_LOCOPT,
    ida_hexrays.MMAT_CALLS,
    ida_hexrays.MMAT_GLBOPT1,
]
DEFAULT_OPTIMIZATION_Z3_MATURITIES = [
    ida_hexrays.MMAT_PREOPTIMIZED,
    ida_hexrays.MMAT_LOCOPT,
    ida_hexrays.MMAT_CALLS,
    ida_hexrays.MMAT_GLBOPT1,
]
DEFAULT_OPTIMIZATION_EARLY_MATURITIES = [
    ida_hexrays.MMAT_GENERATED,
    ida_hexrays.MMAT_PREOPTIMIZED,
]
DEFAULT_OPTIMIZATION_PEEPHOLE_MATURITIES = [
    ida_hexrays.MMAT_PREOPTIMIZED,
    ida_hexrays.MMAT_LOCOPT,
    ida_hexrays.MMAT_CALLS,
    ida_hexrays.MMAT_GLBOPT1,
    ida_hexrays.MMAT_GLBOPT2,
]
DEFAULT_ANALYZER_MATURITIES = [
    ida_hexrays.MMAT_PREOPTIMIZED,
    ida_hexrays.MMAT_LOCOPT,
    ida_hexrays.MMAT_CALLS,
    ida_hexrays.MMAT_GLBOPT1,
]


if typing.TYPE_CHECKING:
    from d810.core import OptimizationStatistics

ChainOptimizer: typing.TypeAlias = typing.Any
EarlyOptimizer: typing.TypeAlias = typing.Any
EgglogOptimizer: typing.TypeAlias = typing.Any
InstructionAnalyzer: typing.TypeAlias = typing.Any
InstructionOptimizationRule: typing.TypeAlias = typing.Any
InstructionOptimizer: typing.TypeAlias = typing.Any
PatternOptimizer: typing.TypeAlias = typing.Any
PeepholeOptimizer: typing.TypeAlias = typing.Any
Z3Optimizer: typing.TypeAlias = typing.Any


class InstructionOptimizerManager(ida_hexrays.optinsn_t):
    def __init__(
        self,
        stats: OptimizationStatistics,
        log_dir: pathlib.Path,
        *,
        optimizer_cls: type,
    ):
        optimizer_logger.debug("Initializing {0}...".format(self.__class__.__name__))
        super().__init__()
        self.log_dir = log_dir
        self.stats = stats
        self._instruction_optimizer_type = optimizer_cls
        self.instruction_visitor = InstructionVisitorManager(self)
        self._last_optimizer_tried = None
        self.current_maturity = None
        self.current_blk_serial = None
        self.generate_z3_code = False
        self.dump_intermediate_microcode = False
        self._rule_scope_service = None
        self._rule_scope_project_name = ""
        self._rule_scope_idb_key = ""
        self._rule_scope_func_ea = -1
        self._active_instruction_rule_names_by_maturity: dict[int, frozenset[str]] = {}
        self._run_later_scheduler = None
        self._run_later_rule_names: frozenset[str] = frozenset()

        # Cycle detection: maps instruction EA -> set of post-rewrite hashes.
        # If a rewrite produces an instruction whose hash was already seen for
        # that EA, we have a cycle (Rule A: X->Y, Rule B: Y->X) and break it.
        self._rewrite_seen: dict[int, set[int]] = defaultdict(set)

        # Optional event emitter - set by D810Manager after construction to
        # allow emitting DecompilationEvent.MATURITY_CHANGED events.
        self.event_emitter = None

        # Optional ReconPhase - set via configure(recon_phase=...) when recon
        # is enabled in the project config. None means recon is disabled (zero
        # overhead: the guard below short-circuits immediately).
        self._recon_phase = None  # ReconPhase | None
        # Optional ReconAnalysisRuntime - set via configure(recon_runtime=...).
        # Used to reset recon state when a new function is decompiled.
        self._recon_runtime = None  # ReconAnalysisRuntime | None

        self.instruction_optimizers = []
        self._active_optimizers: list = []
        # usage tracking moved to centralized statistics object
        ChainOptimizer: type[ChainOptimizer] = self._instruction_optimizer_type.get(
            "ChainOptimizer"
        )
        EarlyOptimizer: type[EarlyOptimizer] = self._instruction_optimizer_type.get(
            "EarlyOptimizer"
        )
        InstructionAnalyzer: type[InstructionAnalyzer] = (
            self._instruction_optimizer_type.get("InstructionAnalyzer")
        )
        PatternOptimizer: type[PatternOptimizer] = self._instruction_optimizer_type.get(
            "PatternOptimizer"
        )
        PeepholeOptimizer: type[PeepholeOptimizer] = (
            self._instruction_optimizer_type.get("PeepholeOptimizer")
        )
        Z3Optimizer: type[Z3Optimizer] = self._instruction_optimizer_type.get(
            "Z3Optimizer"
        )

        # PatternOptimizer: Rules are added via add_rule() from D810Manager based on
        # project configuration. This ensures only rules enabled in the project's
        # ins_rules (with is_activated: true) are loaded.
        # Previously this loaded ALL VerifiableRules, bypassing project config.
        self.add_optimizer(
            PatternOptimizer(
                DEFAULT_OPTIMIZATION_PATTERN_MATURITIES,
                stats=self.stats,
                log_dir=self.log_dir,
            )
        )

        # EXPERIMENTAL: Egglog-based optimizer using equality saturation
        # Currently DISABLED by default because egglog's saturation() is too slow
        # for real-time IDA decompilation. The overhead of running equality saturation
        # on every instruction makes decompilation impractically slow (>100x slower).
        #
        # The egglog backend still works correctly for batch/offline analysis.
        # To enable for testing, set ENABLE_EGGLOG_OPTIMIZER = True below:
        ENABLE_EGGLOG_OPTIMIZER = False  # Set to True to enable (SLOW!)

        if ENABLE_EGGLOG_OPTIMIZER and EGGLOG_AVAILABLE:
            EgglogOptimizer: type[EgglogOptimizer] = (
                self._instruction_optimizer_type.get("EgglogOptimizer")
            )
            if EgglogOptimizer is not None:
                self.add_optimizer(
                    EgglogOptimizer(
                        DEFAULT_OPTIMIZATION_PATTERN_MATURITIES,
                        stats=self.stats,
                        log_dir=self.log_dir,
                    )
                )
                optimizer_logger.warning(
                    "[EgglogOptimizer] ENABLED (experimental) - using equality saturation. "
                    "Expect SLOW decompilation!"
                )
            else:
                optimizer_logger.debug("[EgglogOptimizer] Not registered - skipping")
        elif EGGLOG_AVAILABLE:
            optimizer_logger.debug(
                "[EgglogOptimizer] Disabled (set ENABLE_EGGLOG_OPTIMIZER=True to enable)"
            )
        else:
            optimizer_logger.debug("[EgglogOptimizer] egglog not installed - skipping")

        self.add_optimizer(
            ChainOptimizer(
                DEFAULT_OPTIMIZATION_CHAIN_MATURITIES,
                stats=self.stats,
                log_dir=self.log_dir,
            )
        )
        self.add_optimizer(
            Z3Optimizer(
                DEFAULT_OPTIMIZATION_Z3_MATURITIES,
                stats=self.stats,
                log_dir=self.log_dir,
            )
        )
        self.add_optimizer(
            EarlyOptimizer(
                DEFAULT_OPTIMIZATION_EARLY_MATURITIES,
                stats=self.stats,
                log_dir=self.log_dir,
            )
        )
        self.add_optimizer(
            PeepholeOptimizer(
                DEFAULT_OPTIMIZATION_PEEPHOLE_MATURITIES,
                stats=self.stats,
                log_dir=self.log_dir,
            )
        )
        self.analyzer = InstructionAnalyzer(
            DEFAULT_ANALYZER_MATURITIES,
            stats=self.stats,
            log_dir=self.log_dir,
        )

    def add_optimizer(self, optimizer: InstructionOptimizer):
        set_run_later_callback = getattr(optimizer, "set_run_later_callback", None)
        if callable(set_run_later_callback):
            set_run_later_callback(self._record_run_later_requests)
        self.instruction_optimizers.append(optimizer)

    def add_rule(self, rule: InstructionOptimizationRule):
        # optimizer_log.info("Trying to add rule {0}".format(rule))
        for ins_optimizer in self.instruction_optimizers:
            ins_optimizer.add_rule(rule)
        self.analyzer.add_rule(rule)

    def reset_cycle_detection(self) -> None:
        """Clear the rewrite-cycle seen set.

        Called on decompilation start (via DecompilationEvent.STARTED in the
        manager) and on maturity change (in log_info_on_input).
        """
        self._rewrite_seen.clear()

    def reset_run_later_state(self) -> None:
        self._run_later_rule_names = frozenset()
        scheduler = self._run_later_scheduler
        if scheduler is not None:
            reset_all = getattr(scheduler, "reset_all", None)
            if callable(reset_all):
                reset_all()

    def _ir_maturity_for(self, maturity: int):
        try:
            return ida_maturity_to_ir(int(maturity))
        except ValueError:
            optimizer_logger.debug(
                "run_later scheduler skipped unsupported instruction maturity %s",
                maturity_to_string(int(maturity)),
            )
            return None

    def _current_ir_maturity(self):
        if self.current_maturity is None:
            return None
        return self._ir_maturity_for(int(self.current_maturity))

    def _drain_run_later_for_maturity(self, mba: ida_hexrays.mbl_array_t) -> None:
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
                "run_later scheduler activated instruction rules at %s for "
                "function %#x: %s",
                maturity_to_string(int(self.current_maturity)),
                func_ea,
                sorted(self._run_later_rule_names),
            )

    def _record_run_later_requests(self, rule, maturity: int) -> None:
        drain_requests = getattr(rule, "drain_run_later_requests", None)
        if not callable(drain_requests):
            return
        requests = drain_requests()
        if not requests:
            return
        scheduler = self._run_later_scheduler
        current_ir_maturity = self._ir_maturity_for(int(maturity))
        if scheduler is None or current_ir_maturity is None:
            optimizer_logger.debug(
                "discarding %d instruction run_later request(s) for %s: "
                "scheduler unavailable",
                len(requests),
                self._rule_name(rule),
            )
            return
        request_method = getattr(scheduler, "request", None)
        if not callable(request_method):
            return
        func_ea = int(self._rule_scope_func_ea)
        if func_ea <= 0:
            return
        for request in requests:
            accepted = request_method(
                func_ea=func_ea,
                pass_id=self._rule_name(rule),
                current_maturity=current_ir_maturity,
                run_later=request,
                domain=_RUN_LATER_DOMAIN_OPTIMIZER_RULE,
            )
            if accepted:
                optimizer_logger.debug(
                    "scheduled instruction run_later for %s at %s (func=%#x)",
                    self._rule_name(rule),
                    getattr(request, "at", "?"),
                    func_ea,
                )

    def func(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t) -> bool:
        self.log_info_on_input(blk, ins)
        try:
            optimization_performed = self.optimize(blk, ins)

            if not optimization_performed:
                # ``minsn_t.for_all_insns`` does not populate the visitor's
                # ``blk`` member (only the ``mba``/``mblock_t`` overloads do), so
                # nested sub-instructions would otherwise be optimized with no
                # block context.  Rules that resolve operands via block-local
                # def-use scans (e.g. wide constant reconstruction for the
                # magic-modulo rule) need the owning block, so set it explicitly.
                self.instruction_visitor.blk = blk
                optimization_performed = ins.for_all_insns(self.instruction_visitor)

            if optimization_performed:
                ins.optimize_solo()

                if blk is not None:
                    blk.mark_lists_dirty()
                    safe_verify(
                        blk.mba, "rewriting", logger_func=optimizer_logger.error
                    )

            return bool(optimization_performed)
        except RuntimeError as e:
            optimizer_logger.error(
                "RuntimeError while optimizing ins {0} with {1}: {2}".format(
                    format_minsn_t(ins), self._last_optimizer_tried, e
                )
            )
        except D810Exception as e:
            optimizer_logger.error(
                "D810Exception while optimizing ins {0} with {1}: {2}".format(
                    format_minsn_t(ins), self._last_optimizer_tried, e
                )
            )
        return False

    # statistics are managed centrally via the stats object

    def log_info_on_input(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t):
        mba: ida_hexrays.mbl_array_t = blk.mba

        if (mba is not None) and (mba.maturity != self.current_maturity):
            new_maturity = mba.maturity
            self.current_maturity = new_maturity
            main_logger.update_maturity(maturity_to_string(self.current_maturity))
            if self.event_emitter is not None:
                self.event_emitter.emit(
                    DecompilationEvent.MATURITY_CHANGED, new_maturity
                )
                # ``FLOWGRAPH_READY`` is emitted AFTER ``reset_for_func``
                # below.  See the comment block at the emit site for
                # the ordering rationale.
            if main_logger.debug_on:
                main_logger.debug(
                    "Instruction optimization function called at maturity: %s",
                    maturity_to_string(self.current_maturity),
                )
            self.analyzer.set_maturity(self.current_maturity)
            self.current_blk_serial = None
            # Reset cycle detection on maturity change -- instructions are
            # renumbered / restructured between maturity levels so old hashes
            # are no longer meaningful.
            self.reset_cycle_detection()
            self._active_instruction_rule_names_by_maturity.clear()
            self._drain_run_later_for_maturity(mba)

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
            if self.event_emitter is not None:
                _emit_flowgraph_ready_event(self.event_emitter, mba)
            # ``run_microcode_collectors(mba, ...)`` is now invoked by
            # the ``FLOWGRAPH_READY`` subscriber on ``D810`` (see
            # ``manager.flowgraph_ready.FlowGraphReadySubscriber``).  The
            # event fires immediately above and ``ReconPhase`` dedupes
            # by ``(func_ea, maturity)``, so adding back a direct
            # call here would double-collect.
            if self._recon_phase is not None:
                if self._recon_runtime is not None:
                    try:
                        hints = self._recon_runtime.analyze_and_persist(mba_ea)
                        if hints is not None and self._rule_scope_service is not None:
                            result = self._rule_scope_service.apply_hints(hints)
                            optimizer_logger.info(
                                "Applied recon hints to rule scope for func=0x%x",
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
                            "ReconRuntime analyze_and_persist failed for func=0x%x",
                            mba_ea,
                        )

            for ins_optimizer in self.instruction_optimizers:
                ins_optimizer.cur_maturity = self.current_maturity

            # Pre-compute which optimizers are active at this maturity
            self._active_optimizers = [
                opt
                for opt in self.instruction_optimizers
                if (
                    self.current_maturity in opt.maturities
                    or self._optimizer_has_scheduled_rule(opt)
                )
            ]

            if self.dump_intermediate_microcode:
                dump_microcode_for_debug(
                    mba, self.log_dir, "input_instruction_optimizer"
                )

        if blk.serial != self.current_blk_serial:
            self.current_blk_serial = blk.serial

    def configure(
        self, generate_z3_code=False, dump_intermediate_microcode=False, **kwargs
    ):
        old_scope = (
            self._rule_scope_service,
            self._rule_scope_project_name,
            self._rule_scope_idb_key,
        )
        self.generate_z3_code = generate_z3_code
        self.dump_intermediate_microcode = dump_intermediate_microcode
        self._recon_phase = kwargs.get("recon_phase", self._recon_phase)
        self._recon_runtime = kwargs.get("recon_runtime", self._recon_runtime)
        self._run_later_scheduler = kwargs.get(
            "pass_scheduler",
            self._run_later_scheduler,
        )
        self._rule_scope_service = kwargs.get(
            "rule_scope_service",
            self._rule_scope_service,
        )
        self._rule_scope_project_name = str(
            kwargs.get("rule_scope_project_name", self._rule_scope_project_name)
        )
        self._rule_scope_idb_key = str(
            kwargs.get("rule_scope_idb_key", self._rule_scope_idb_key)
        )
        new_scope = (
            self._rule_scope_service,
            self._rule_scope_project_name,
            self._rule_scope_idb_key,
        )
        if new_scope != old_scope:
            self._rule_scope_func_ea = -1
            self._active_instruction_rule_names_by_maturity.clear()
            # Invalidate compiled rule views on scope change (PR3)
            for optimizer in self.instruction_optimizers:
                if hasattr(optimizer, "invalidate"):
                    optimizer.invalidate()

    @staticmethod
    def _rule_name(rule: object) -> str:
        return str(getattr(rule, "name", rule.__class__.__name__))

    def _optimizer_has_scheduled_rule(self, optimizer: object) -> bool:
        if not self._run_later_rule_names:
            return False
        for rule in getattr(optimizer, "rules", ()) or ():
            if self._rule_name(rule) in self._run_later_rule_names:
                return True
        return False

    def _resolve_active_instruction_rule_names(
        self,
        blk: ida_hexrays.mblock_t,
    ) -> frozenset[str]:
        if self._rule_scope_service is None:
            # FAIL CLOSED: If rule scope service not initialized, run NO rules
            # instead of ALL rules. This prevents expression bloat when optimizer
            # callbacks fire before configure() is called.
            optimizer_logger.warning(
                "Rule scope service not initialized at optimize time - no rules will run. "
                "This may indicate a race condition during initialization."
            )
            return frozenset()
        if blk is None or blk.mba is None or blk.mba.entry_ea is None:
            return frozenset()
        if self.current_maturity is None:
            return frozenset()
        func_ea = int(blk.mba.entry_ea)
        maturity = int(self.current_maturity)
        if func_ea != self._rule_scope_func_ea:
            self._rule_scope_func_ea = func_ea
            self._active_instruction_rule_names_by_maturity.clear()
        cached = self._active_instruction_rule_names_by_maturity.get(maturity)
        if cached is not None:
            return cached
        active_rules = self._rule_scope_service.get_active_rules(
            project_name=self._rule_scope_project_name,
            idb_key=self._rule_scope_idb_key,
            func_ea=func_ea,
            pipeline=PIPELINE_INSTRUCTION,
            maturity=maturity,
        )
        names = (
            frozenset(self._rule_name(rule) for rule in active_rules)
            | self._run_later_rule_names
        )
        self._active_instruction_rule_names_by_maturity[maturity] = names
        return names

    def optimize(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t) -> bool:
        # optimizer_log.info("Trying to optimize {0}".format(format_minsn_t(ins)))
        allowed_rule_names = self._resolve_active_instruction_rule_names(blk)
        scheduled_rule_names = self._run_later_rule_names
        for ins_optimizer in self._active_optimizers:
            self._last_optimizer_tried = ins_optimizer
            new_ins = ins_optimizer.get_optimized_instruction(
                blk,
                ins,
                allowed_rule_names=allowed_rule_names,
                scheduled_rule_names=scheduled_rule_names,
            )

            if new_ins is not None:
                if not check_ins_mop_size_are_ok(new_ins):
                    if check_ins_mop_size_are_ok(ins):
                        main_logger.error(
                            "Invalid optimized instruction (%s) for maturity %s:\n\toptimized: %s\n\toriginal: %s",
                            ins_optimizer.name,
                            maturity_to_string(self.current_maturity),  # type: ignore
                            format_minsn_t(new_ins),
                            format_minsn_t(ins),
                        )
                    else:
                        main_logger.error(
                            "Invalid original instruction (%s) for maturity %s:\n\toptimized: %s\n\toriginal: %s",
                            ins_optimizer.name,
                            maturity_to_string(self.current_maturity),  # type: ignore
                            format_minsn_t(new_ins),
                            format_minsn_t(ins),
                        )
                else:
                    # --- expression size guard ---
                    # Reject replacements that significantly increase expression size.
                    # This is a defense-in-depth measure against rules that cause
                    # expression bloat (e.g., CstSimplificationRule4's 4.24x bloat).
                    # Check BEFORE the cycle detection hash to avoid polluting the
                    # seen-hash set with bloated replacements.
                    original_nodes = count_minsn_nodes(ins)
                    new_nodes = count_minsn_nodes(new_ins)
                    max_allowed_nodes = original_nodes * 2

                    if new_nodes > max_allowed_nodes and original_nodes > 0:
                        optimizer_logger.warning(
                            "Expression bloat detected at %s by %s: "
                            "%d nodes -> %d nodes (%.2fx, max allowed 2x) -- "
                            "rejecting replacement",
                            hex(ins.ea),
                            ins_optimizer.name,
                            original_nodes,
                            new_nodes,
                            new_nodes / original_nodes,
                        )
                        if self.stats is not None:
                            self.stats.record_expression_bloat_rejected(
                                ins_optimizer.name,
                                hex(ins.ea),
                            )
                        return False
                    # --- end expression size guard ---

                    # --- cycle detection guard ---
                    # Compute structural hash of the NEW instruction
                    # (after swap, `ins` holds the new content).
                    ins.swap(new_ins)

                    try:
                        func_ea = blk.mba.entry_ea if blk and blk.mba else 0
                    except Exception:
                        func_ea = 0
                    post_hash = hash_minsn(ins, func_ea)
                    ins_key = ins.ea

                    seen = self._rewrite_seen[ins_key]
                    if post_hash in seen:
                        # Cycle detected: this instruction was already
                        # rewritten to this exact form.  Undo the swap and
                        # refuse the rewrite to break the cycle.
                        ins.swap(new_ins)  # undo
                        optimizer_logger.warning(
                            "Cycle detected for instruction at %s by %s -- "
                            "breaking rewrite loop",
                            hex(ins_key),
                            ins_optimizer.name,
                        )
                        if self.stats is not None:
                            self.stats.record_cycle_detected(
                                ins_optimizer.name,
                                hex(ins_key),
                            )
                        return False

                    seen.add(post_hash)
                    # --- end cycle detection guard ---

                    if self.stats is not None:
                        self.stats.record_optimizer_match(ins_optimizer.name)

                    if self.generate_z3_code:
                        try:
                            z3_script = build_z3_equivalence_proof(new_ins, ins)
                            if z3_script is not None:
                                z3_file_logger.info(z3_script)
                        except KeyError:
                            pass
                    return True

        self.analyzer.analyze(blk, ins)
        return False


class InstructionVisitorManager(ida_hexrays.minsn_visitor_t):
    def __init__(self, optimizer: InstructionOptimizerManager):
        optimizer_logger.debug("Initializing {0}...".format(self.__class__.__name__))
        super().__init__()
        self.instruction_optimizer = optimizer

    def visit_minsn(self) -> bool:
        return self.instruction_optimizer.optimize(self.blk, self.curins)
