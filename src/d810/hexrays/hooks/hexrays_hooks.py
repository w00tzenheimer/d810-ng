from __future__ import annotations

import contextlib
import enum
import math
import pathlib
import sqlite3
import time
from collections import defaultdict

import ida_hexrays
import idaapi

from d810.core import getLogger, typing
from d810.core.cymode import CythonMode
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.core.rule_scope import PIPELINE_FLOW, PIPELINE_INSTRUCTION
from d810.errors import D810Exception
from d810.hexrays.mutation.cfg_verify import safe_verify
from d810.hexrays.mutation.ir_translator import lift as lift_mba_to_flowgraph
from d810.hexrays.utils.hexrays_formatters import (
    count_minsn_nodes,
    dump_microcode_for_debug,
    format_minsn_t,
    maturity_to_string,
)
from d810.hexrays.ir.minsn_utils import build_z3_equivalence_proof
from d810.hexrays.utils.hexrays_helpers import check_ins_mop_size_are_ok
from d810.mba.backend_registry import get_egglog_provider

HEXRAYS_MICROCODE_PROVIDER = "hexrays_microcode"

# ---------------------------------------------------------------------------
# hash_minsn: Cython fast path with pure-Python fallback
# ---------------------------------------------------------------------------
# The Cython version (in speedups/cythxr/_chexrays_api.pyx) hashes the opcode
# and all three operands (l, r, d) at the C level for speed.  When Cython is
# unavailable we fall back to hashing the printed representation of the
# instruction, which is slower but always available.
#
# The OptimizationCache class (in d810.optimizers.caching) was considered for
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
from d810.hexrays.hooks.ctree_hooks import CtreeOptimizerManager

main_logger = getLogger("D810")
optimizer_logger = getLogger("D810.optimizer")
z3_file_logger = getLogger("D810.z3_test")

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
    from d810.optimizers.microcode.instructions.analysis.handler import (
        InstructionAnalyzer,
    )
    from d810.optimizers.microcode.instructions.chain.handler import ChainOptimizer
    from d810.optimizers.microcode.instructions.early.handler import EarlyOptimizer

    # ast-ignore no-hexrays-hook-direct-optimizer-imports
    from d810.optimizers.microcode.instructions.egraph.egglog_handler import (
        EgglogOptimizer,
    )
    from d810.optimizers.microcode.instructions.pattern_matching.handler import (
        PatternOptimizer,
    )
    from d810.optimizers.microcode.instructions.peephole.handler import (
        PeepholeOptimizer,
    )
    from d810.optimizers.microcode.instructions.z3.handler import Z3Optimizer


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

    def func(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t) -> bool:
        self.log_info_on_input(blk, ins)
        try:
            optimization_performed = self.optimize(blk, ins)

            if not optimization_performed:
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
                _emit_flowgraph_ready_event(self.event_emitter, mba)
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
            # E4a: ``run_microcode_collectors(mba, ...)`` is now
            # invoked by the ``FLOWGRAPH_READY`` subscriber on
            # ``D810`` (see ``manager._collect_recon_on_flowgraph_ready``).
            # The event fires earlier in this same maturity gate via
            # ``_emit_flowgraph_ready_event`` (a few lines above),
            # and ``ReconPhase`` dedupes by ``(func_ea, maturity)``,
            # so adding back a direct call here would double-collect.
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
                if self.current_maturity in opt.maturities
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
        names = frozenset(self._rule_name(rule) for rule in active_rules)
        self._active_instruction_rule_names_by_maturity[maturity] = names
        return names

    def optimize(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t) -> bool:
        # optimizer_log.info("Trying to optimize {0}".format(format_minsn_t(ins)))
        allowed_rule_names = self._resolve_active_instruction_rule_names(blk)
        for ins_optimizer in self._active_optimizers:
            self._last_optimizer_tried = ins_optimizer
            new_ins = ins_optimizer.get_optimized_instruction(
                blk,
                ins,
                allowed_rule_names=allowed_rule_names,
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

            # Axis-C end-state event (E1): mirror the
            # ``InstructionOptimizerManager`` site -- emit
            # ``FLOWGRAPH_READY`` so the cross-layer event lands at
            # every existing recon-collection lifecycle point.  When
            # E4 swaps the live-mba ``run_microcode_collectors(...)``
            # path for ``FLOWGRAPH_READY`` subscribers, neither
            # manager silently drops out of the chain.
            _emit_flowgraph_ready_event(self.event_emitter, mba)

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
            # E4a: ``run_microcode_collectors(mba, ...)`` is now
            # invoked by the ``FLOWGRAPH_READY`` subscriber on
            # ``D810`` (see ``manager._collect_recon_on_flowgraph_ready``).
            # The event fires earlier in this same maturity gate via
            # ``_emit_flowgraph_ready_event`` (a few lines above),
            # and ``ReconPhase`` dedupes by ``(func_ea, maturity)``,
            # so a direct call here would double-collect.
            #
            # ``capture_maturity_facts(mba, ...)`` STAYS -- it is a
            # live-MBA fact-capture path (pre_d810), not the
            # microcode-collector path.
            if self._recon_phase is not None:
                provider_phase = ProviderPhaseSnapshot(
                    provider_name=HEXRAYS_MICROCODE_PROVIDER,
                    provider_level=int(mba.maturity),
                    friendly_provider_level=maturity_to_string(mba.maturity),
                )
                if self._recon_runtime is not None:
                    try:
                        self._recon_runtime.capture_maturity_facts(
                            mba,
                            func_ea=mba_ea,
                            provider_phase=provider_phase,
                            phase="pre_d810",
                            snapshot=_pre_snap_ref,
                        )
                    except Exception:
                        optimizer_logger.exception("FactLifecycleRuntime (block) failed")
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
        return rules

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
                    nb_patch = cfg_rule.optimize(blk)
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

    def configure(self, **kwargs):
        self._recon_phase = kwargs.get("recon_phase", self._recon_phase)
        self._recon_runtime = kwargs.get("recon_runtime", self._recon_runtime)
        self._function_priors_provider = kwargs.get(
            "function_priors_provider",
            self._function_priors_provider,
        )
        self._pass_pipeline = kwargs.get("pass_pipeline", self._pass_pipeline)
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


class DecompilationEvent(enum.Enum):
    # Dotted hierarchical event values: domain.object.action.
    # Filter by prefix (e.g. ``decompilation.``) in subscribers / logs.
    # Underscores within a segment are OK (`post_d810`); the SEPARATOR is `.`.
    STARTED = "decompilation.started"
    FINISHED = "decompilation.finished"
    MATURITY_CHANGED = "decompilation.maturity.changed"
    POST_D810_CAPTURE = "decompilation.post_d810.capture"
    # Axis-C end-state event (E1): emitted once per maturity transition
    # with a portable ``FlowGraph`` snapshot.  Recon-side subscribers
    # land in E4 -- E1 only publishes the event; no consumers yet.
    FLOWGRAPH_READY = "decompilation.flowgraph.ready"


def _emit_flowgraph_ready_event(
    event_emitter,
    mba,
) -> None:
    """Lift ``mba`` and emit ``FLOWGRAPH_READY`` (no-op when emitter is None).

    Shared helper invoked at every maturity-transition gate --
    ``InstructionOptimizerManager.log_info_on_input`` and
    ``BlockOptimizerManager.log_info_on_input``.  Both producers
    route through one helper so the cross-layer event fires at
    every recon-collection lifecycle point.

    E4a (now): the ``FLOWGRAPH_READY`` subscriber on ``D810`` (see
    ``manager._collect_recon_on_flowgraph_ready``) is the sole
    invoker of ``ReconPhase.run_microcode_collectors`` for the
    microcode path.  The legacy live-mba direct calls that used to
    live in this same module are gone.

    Lift failures log via ``optimizer_logger.exception`` and return
    cleanly -- the subscriber never runs for the failed transition,
    so recon misses one maturity but decompilation is never gated
    by a lift bug.

    Payload: ``flow_graph`` + ``func_ea`` + ``maturity`` +
    ``maturity_name``.  ``maturity`` and ``maturity_name`` are sourced
    directly from ``flow_graph.metadata`` so the event payload
    mirrors the lifter's metadata contract (E2b) -- the lifter is the
    single source of truth, the event is NOT an alternate convention.
    No ``mba_t`` crosses the boundary.
    """
    if event_emitter is None:
        return
    try:
        flow_graph = lift_mba_to_flowgraph(mba)
    except Exception:
        optimizer_logger.exception(
            "FlowGraph lift failed at maturity %s (func=0x%x); "
            "FLOWGRAPH_READY suppressed for this transition",
            maturity_to_string(int(getattr(mba, "maturity", 0) or 0)),
            int(getattr(mba, "entry_ea", 0) or 0),
        )
        return
    metadata = flow_graph.metadata
    event_emitter.emit(
        DecompilationEvent.FLOWGRAPH_READY,
        flow_graph=flow_graph,
        func_ea=int(mba.entry_ea),
        maturity=metadata["maturity"],
        maturity_name=metadata["maturity_name"],
    )


class HexraysDecompilationHook(ida_hexrays.Hexrays_Hooks):
    def __init__(
        self,
        callback: typing.Callable,
        ctree_optimizer_manager: CtreeOptimizerManager | None = None,
        block_optimizer: BlockOptimizerManager | None = None,
    ):
        super().__init__()
        self.callback = callback
        self.ctree_optimizer_manager = ctree_optimizer_manager
        self._block_optimizer = block_optimizer

    def prolog(
        self, mba: ida_hexrays.mbl_array_t, fc, reachable_blocks, decomp_flags
    ) -> "int":
        fn_name = ""
        with contextlib.suppress(BaseException):
            fn_name = idaapi.get_func_name(mba.entry_ea)
        prologue = f"{fn_name} @ {hex(mba.entry_ea)}"
        main_logger.info("Starting decompilation of function %s", prologue)
        try:
            from d810.core.observability import open_observability_session
            # open_observability_session opens the diag session
            # (idempotent re-installation on re-decompilation) by
            # delegating to the registered backend; nothing here
            # imports d810.core.diag.
            open_observability_session(int(mba.entry_ea))
        except Exception:
            pass  # diagnostic, never gates decompilation
        self.callback(DecompilationEvent.STARTED)
        # self.manager.start_profiling()
        # self.manager.instruction_optimizer.reset_rule_usage_statistic()
        # self.manager.block_optimizer.reset_rule_usage_statistic()
        return 0

    def maturity(self, cfunc, new_maturity: int) -> int:
        """Ctree maturity level is being changed."""
        if self.ctree_optimizer_manager is not None:
            self.ctree_optimizer_manager.on_maturity(cfunc, new_maturity)
        return 0

    def glbopt(self, mba: ida_hexrays.mbl_array_t) -> "int":
        main_logger.info("glbopt finished for function at %s", hex(mba.entry_ea))
        main_logger.reset_maturity()

        # PruneUnreachable: diagnostic-only — logs unreachable BST blocks
        # but does NOT remove them (see _prune_unreachable_bst for rationale).
        self._prune_unreachable_bst(mba)
        return 0

    def _prune_unreachable_bst(self, mba: ida_hexrays.mbl_array_t) -> int:
        """Diagnostic: identify BST blocks proven unreachable by Hodur.

        Reads BST block EAs persisted by HodurUnflattener during optblock pass
        and re-maps them to current serials (IDA renumbers blocks between
        maturities so GLBOPT1 serials are stale by hxe_glbopt time).

        Block removal is currently disabled — see BLOCKED comment near the end.
        Always returns 0.
        """
        if self._block_optimizer is None:
            main_logger.debug("PruneUnreachable: no block_optimizer")
            return 0

        # Find HodurUnflattener instance(s) with stored BST data
        bst_block_eas: set[int] = set()
        dispatcher_ea: int = 0
        for rule in self._block_optimizer.cfg_rules:
            has_attr = hasattr(rule, '_last_bst_block_eas')
            if has_attr:
                main_logger.info(
                    "PruneUnreachable: found rule %s, _last_bst_block_eas=%d, "
                    "_last_func_ea=%s, mba.entry_ea=%s",
                    type(rule).__name__,
                    len(getattr(rule, '_last_bst_block_eas', set())),
                    hex(getattr(rule, '_last_func_ea', 0)),
                    hex(mba.entry_ea),
                )
            if (
                has_attr
                and getattr(rule, '_last_bst_block_eas', set())
                and hasattr(rule, '_last_func_ea')
                and rule._last_func_ea == mba.entry_ea
            ):
                bst_block_eas = rule._last_bst_block_eas
                dispatcher_ea = getattr(rule, '_last_dispatcher_ea', 0)
                # Clear after use (one-shot)
                rule._last_bst_block_eas = set()
                rule._last_dispatcher_ea = 0
                # Also clear legacy serial fields
                rule._last_bst_serials = None
                rule._last_dispatcher_serial = -1
                break

        if not bst_block_eas:
            main_logger.info("PruneUnreachable: no pending BST block EAs for %s", hex(mba.entry_ea))
            return 0

        # Re-map EAs to current block serials
        ea_to_serial: dict[int, int] = {}
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is not None:
                ea_to_serial[blk.start] = i

        current_bst_serials: set[int] = {
            ea_to_serial[ea] for ea in bst_block_eas if ea in ea_to_serial
        }
        current_dispatcher = ea_to_serial.get(dispatcher_ea, -1)

        if not current_bst_serials:
            main_logger.info(
                "PruneUnreachable: EA re-mapping found 0 BST blocks for %s",
                hex(mba.entry_ea),
            )
            return 0

        main_logger.info(
            "PruneUnreachable[glbopt]: re-mapped %d/%d BST block EAs to current serials, "
            "dispatcher EA %s -> serial %s",
            len(current_bst_serials), len(bst_block_eas),
            hex(dispatcher_ea) if dispatcher_ea else "None",
            current_dispatcher if current_dispatcher >= 0 else "None",
        )

        # NOTE: edge severing at hxe_glbopt corrupts IDA (decompilation fails).
        # Only diagnostic BFS follows — no CFG mutations.

        # Forward BFS from block 0 to find reachable blocks
        from collections import deque
        visited: set[int] = set()
        queue = deque([0])
        while queue:
            serial = queue.popleft()
            if serial in visited:
                continue
            visited.add(serial)
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            for si in range(blk.nsucc()):
                succ = blk.succ(si)
                if succ not in visited:
                    queue.append(succ)

        # Intersect unreachable with current BST serials
        all_serials = set(range(mba.qty))
        unreachable_bst = (all_serials - visited) & current_bst_serials

        if not unreachable_bst:
            main_logger.info(
                "PruneUnreachable[glbopt]: no unreachable BST blocks for %s (dispatcher=%s)",
                hex(mba.entry_ea),
                hex(current_dispatcher) if current_dispatcher >= 0 else "None",
            )
            return 0

        main_logger.info(
            "PruneUnreachable[glbopt]: %d/%d blocks reachable, "
            "%d unreachable BST blocks to prune for %s",
            len(visited), mba.qty, len(unreachable_bst), hex(mba.entry_ea),
        )

        # BLOCKED: remove_block requires zero instruction-level references to target
        # block. TAIL_CHASE_FAILED handler exits still have goto instructions pointing
        # to dispatcher/BST. Until all handler exits are resolved via instruction
        # operand redirects (like hrtng's DGM.ChangeGoto), remove_block will fail
        # with INTERR 51920 regardless of hook type (optblock_t or hxe_glbopt).
        # The diagnostic confirms 77/77 BST blocks unreachable via edge-list BFS.
        return 0

    def structural(self, ct: "control_graph_t") -> int:  # type: ignore
        """Structural analysis has been finished.

        @param ct: (control_graph_t *)"""
        main_logger.info("Structural analysis has been finished")
        try:
            from d810.core.observability import close_observability_session
            # close_observability_session unsubscribes event-handler
            # subscribers and closes the diag DB via the registered
            # backend; nothing here imports d810.core.diag.
            close_observability_session()
        except Exception:
            pass  # diagnostic, never gates decompilation
        self.callback(DecompilationEvent.FINISHED)
        return 0

    def func_printed(self, cfunc: "cfunc_t") -> int:
        """Function text has been generated. Plugins may modify the text in cfunc_t::sv. However, it is too late to modify the ctree or microcode. The text uses regular color codes (see lines.hpp) COLOR_ADDR is used to store pointers to ctree items.

        @param cfunc: (cfunc_t *)"""
        main_logger.info("Function text has been generated")
        return 0
