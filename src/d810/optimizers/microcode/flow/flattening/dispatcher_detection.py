"""
Dispatcher Block Detection Cache

This module provides a unified, cached dispatcher detection system that aggregates
multiple detection strategies for identifying state machine dispatcher blocks in
control flow flattened code.

Detection Strategies:
1. High Fan-In: Blocks with ≥N predecessors (typical for dispatchers)
2. State Comparison: Blocks comparing a variable against large constants (>0x10000)
3. Loop Header: Blocks that are natural loop headers (dominator-based)
4. Predecessor Uniformity: Most predecessors are unconditional jumps
5. Constant Frequency: Blocks compared against many unique constants
6. Back-edge Detection: Blocks with incoming back-edges from dominated blocks

Usage:
    cache = DispatcherCache.get_or_create(mba)
    info = cache.analyze()

    # Check if a block is a dispatcher
    if cache.is_dispatcher(blk.serial):
        ...

    # Force refresh
    cache.refresh()
"""
from __future__ import annotations

import weakref
from dataclasses import dataclass, field
from enum import Enum, IntFlag
from typing import TYPE_CHECKING

import ida_hexrays

from d810.core import getLogger

# Optional emulation support
try:
    from d810.expr.emulation_oracle import EmulationOracle, StateTransition
    EMULATION_AVAILABLE = True
except ImportError:
    EMULATION_AVAILABLE = False
    EmulationOracle = None

if TYPE_CHECKING:
    pass

logger = getLogger("D810.dispatcher")


class DispatcherStrategy(IntFlag):
    """Flags indicating which strategies detected a block as a dispatcher."""
    NONE = 0
    HIGH_FAN_IN = 1 << 0           # ≥N predecessors
    STATE_COMPARISON = 1 << 1      # Compares against large constants
    LOOP_HEADER = 1 << 2           # Natural loop header
    PREDECESSOR_UNIFORM = 1 << 3   # Most preds are unconditional jumps
    CONSTANT_FREQUENCY = 1 << 4    # Many unique constants compared
    BACK_EDGE = 1 << 5             # Has incoming back-edges
    NESTED_LOOP = 1 << 6           # Part of nested loop structure
    SMALL_BLOCK = 1 << 7           # Few instructions (dispatchers are typically tight)
    SWITCH_JUMP = 1 << 8           # Contains jtbl or computed goto


class DispatcherType(Enum):
    """
    Classification of control-flow flattening dispatcher mechanisms.

    Different obfuscators use different dispatcher patterns. Identifying the type
    helps select the appropriate unflattening strategy and avoid techniques that
    cause cascading unreachability issues.
    """

    # Unknown or unclassified dispatcher pattern
    UNKNOWN = 0

    # Switch/jump table based dispatcher (jtbl instruction)
    # Used by: O-LLVM, Tigress (switch mode), commercial obfuscators
    # Pattern: Central switch statement dispatches to handler blocks
    # Characteristics: m_jtbl opcode, computed goto, single dispatcher block
    SWITCH_TABLE = 1

    # Conditional chain dispatcher (nested jnz/jz comparisons)
    # Used by: Hodur malware, various C2 frameworks, info stealers
    # Pattern: Nested while(1) loops with sequential state comparisons
    # Characteristics: No jtbl, many jnz/jz blocks, nested loop structure
    # Note: Requires special handling to avoid cascading unreachability
    CONDITIONAL_CHAIN = 2

    # Indirect jump dispatcher (computed address)
    # Used by: Tigress (indirect mode), some VM protectors
    # Pattern: Jump target computed from state variable
    # Characteristics: m_goto with mop_d destination, address arithmetic
    INDIRECT_JUMP = 3


@dataclass
class BlockAnalysis:
    """Analysis results for a single block."""
    serial: int
    strategies: DispatcherStrategy = DispatcherStrategy.NONE
    score: float = 0.0

    # Strategy-specific data
    predecessor_count: int = 0
    unconditional_pred_count: int = 0
    state_constants: set[int] = field(default_factory=set)
    back_edge_sources: list[int] = field(default_factory=list)
    loop_depth: int = 0

    @property
    def is_dispatcher(self) -> bool:
        """True if any strategy flagged this block as a dispatcher."""
        return self.strategies != DispatcherStrategy.NONE

    @property
    def is_strong_dispatcher(self) -> bool:
        """True if multiple strategies agree this is a dispatcher."""
        # Count set bits
        count = bin(self.strategies).count('1')
        return count >= 2


@dataclass
class StateVariableCandidate:
    """A candidate for the state variable."""
    mop: ida_hexrays.mop_t
    mop_type: int = 0  # ida_hexrays.mop_t type (mop_S, mop_r, etc.)
    mop_offset: int = 0  # For mop_S: stack offset; for mop_r: register number
    mop_size: int = 4  # Operand size in bytes
    init_value: int | None = None
    comparison_count: int = 0
    assignment_count: int = 0
    unique_constants: set[int] = field(default_factory=set)
    comparison_blocks: list[int] = field(default_factory=list)
    assignment_blocks: list[int] = field(default_factory=list)
    score: float = 0.0

    def get_native_stack_offset(self, frame_size: int) -> int | None:
        """
        Convert microcode stack offset to native stack offset.

        Microcode stores stack offsets counting UP from the bottom of the frame,
        while native code uses offsets DOWN from RBP/RSP. This converts appropriately.

        Args:
            frame_size: Total frame size from mba_t

        Returns:
            Native stack offset (negative, relative to frame base), or None if not a stack var
        """
        if self.mop_type != ida_hexrays.mop_S:
            return None
        # Convert: display_offset = frame_size - mop.s.off
        # Native offset is typically -(display_offset) from RBP
        display_offset = frame_size - self.mop_offset
        return -display_offset


@dataclass
class DispatcherAnalysis:
    """Complete dispatcher analysis for a function."""
    func_ea: int
    maturity: int

    # Analysis results
    blocks: dict[int, BlockAnalysis] = field(default_factory=dict)
    dispatchers: list[int] = field(default_factory=list)  # Block serials flagged as dispatchers
    state_variable: StateVariableCandidate | None = None
    state_constants: set[int] = field(default_factory=set)

    # Dispatcher classification
    dispatcher_type: DispatcherType = DispatcherType.UNKNOWN
    initial_state: int | None = None
    nested_loop_depth: int = 0

    @property
    def is_conditional_chain(self) -> bool:
        """True if dispatcher uses conditional chain (nested jnz/jz comparisons)."""
        return self.dispatcher_type == DispatcherType.CONDITIONAL_CHAIN

    @property
    def is_switch_table(self) -> bool:
        """True if dispatcher uses switch/jump table."""
        return self.dispatcher_type == DispatcherType.SWITCH_TABLE


# Thresholds for detection strategies
MIN_HIGH_FAN_IN = 5
MIN_STATE_CONSTANT = 0x10000
MIN_UNIQUE_CONSTANTS = 3
MIN_PREDECESSOR_UNIFORMITY_RATIO = 0.8
MIN_BACK_EDGE_RATIO = 0.3
MAX_DISPATCHER_BLOCK_SIZE = 20  # Max instructions in a dispatcher block


class DispatcherCache:
    """
    Per-function cache for dispatcher detection results.

    The cache is keyed by (func_ea, maturity) to handle IDA's multiple decompilation passes.
    """

    # Class-level cache: func_ea -> weakref(DispatcherCache)
    _cache: dict[int, "DispatcherCache"] = {}

    def __init__(self, mba: ida_hexrays.mba_t):
        self.mba = mba
        self.func_ea = mba.entry_ea
        self._analysis: DispatcherAnalysis | None = None
        self._last_maturity: int = -1

        # Statistics for performance tuning
        self.blocks_analyzed = 0
        self.blocks_skipped = 0  # Blocks that didn't match any strategy

    @classmethod
    def get_or_create(cls, mba: ida_hexrays.mba_t) -> "DispatcherCache":
        """Get cached instance or create new one for this function."""
        func_ea = mba.entry_ea

        if func_ea in cls._cache:
            cache = cls._cache[func_ea]
            cache.mba = mba  # Update mba reference
            # Check if maturity changed (need re-analysis)
            if cache._last_maturity != mba.maturity:
                cache._analysis = None  # Invalidate
            return cache

        cache = cls(mba)
        cls._cache[func_ea] = cache
        return cache

    @classmethod
    def clear_cache(cls, func_ea: int | None = None) -> None:
        """Clear cache for a specific function or all functions."""
        if func_ea is None:
            cls._cache.clear()
        elif func_ea in cls._cache:
            del cls._cache[func_ea]

    def refresh(self) -> DispatcherAnalysis:
        """Force re-analysis."""
        self._analysis = None
        return self.analyze()

    def analyze(self) -> DispatcherAnalysis:
        """Analyze the function and return dispatcher information."""
        if self._analysis is not None and self._last_maturity == self.mba.maturity:
            return self._analysis

        logger.debug("Analyzing function 0x%x at maturity %d", self.func_ea, self.mba.maturity)

        analysis = DispatcherAnalysis(
            func_ea=self.func_ea,
            maturity=self.mba.maturity,
        )

        # Quick check: does this function have a switch/jtbl? If so, it's O-LLVM style
        # and we can skip expensive analysis (O-LLVM doesn't need dispatcher skipping)
        has_jtbl = False
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if blk.tail and blk.tail.opcode == ida_hexrays.m_jtbl:
                has_jtbl = True
                break

        if has_jtbl:
            # Switch table style (O-LLVM, Tigress switch mode)
            analysis.dispatcher_type = DispatcherType.SWITCH_TABLE
            self._analysis = analysis
            self._last_maturity = self.mba.maturity
            logger.debug("Detected jtbl - switch table dispatcher")
            return analysis

        # Run all detection strategies for potential conditional chain style
        self._analyze_block_predecessors(analysis)
        self._analyze_state_comparisons(analysis)
        self._analyze_loop_structure(analysis)
        self._analyze_state_assignments(analysis)
        self._analyze_block_sizes(analysis)
        self._analyze_switch_jumps(analysis)
        self._score_blocks(analysis)
        self._classify_dispatcher_type(analysis)

        # Update statistics
        self.blocks_analyzed = self.mba.qty
        self.blocks_skipped = self.mba.qty - len(analysis.blocks)

        # Collect dispatcher blocks
        for serial, block_info in analysis.blocks.items():
            if block_info.is_dispatcher:
                analysis.dispatchers.append(serial)

        self._analysis = analysis
        self._last_maturity = self.mba.maturity

        logger.info(
            "Dispatcher analysis complete: %d dispatchers, %d state constants, type=%s",
            len(analysis.dispatchers),
            len(analysis.state_constants),
            analysis.dispatcher_type.name,
        )

        return analysis

    def is_dispatcher(self, serial: int) -> bool:
        """Check if a block is flagged as a dispatcher."""
        analysis = self.analyze()
        if serial in analysis.blocks:
            return analysis.blocks[serial].is_dispatcher
        return False

    def get_block_info(self, serial: int) -> BlockAnalysis | None:
        """Get analysis info for a specific block."""
        analysis = self.analyze()
        return analysis.blocks.get(serial)

    def get_statistics(self) -> dict:
        """Get analysis statistics for performance tuning.

        Returns:
            Dict with analysis statistics including:
            - blocks_analyzed: Total blocks in function
            - blocks_with_strategies: Blocks matching at least one strategy
            - blocks_skipped: Blocks not matching any strategy
            - skip_rate: Percentage of blocks skipped (0.0-1.0)
            - dispatchers_found: Number of blocks flagged as dispatchers
            - strategies_used: Dict of strategy -> count
        """
        analysis = self.analyze()

        strategies_used: dict[str, int] = {}
        for strategy in DispatcherStrategy:
            if strategy == DispatcherStrategy.NONE:
                continue
            count = sum(
                1 for info in analysis.blocks.values()
                if strategy in info.strategies
            )
            if count > 0:
                strategies_used[strategy.name] = count

        skip_rate = (
            self.blocks_skipped / self.blocks_analyzed
            if self.blocks_analyzed > 0 else 0.0
        )

        return {
            "blocks_analyzed": self.blocks_analyzed,
            "blocks_with_strategies": len(analysis.blocks),
            "blocks_skipped": self.blocks_skipped,
            "skip_rate": skip_rate,
            "dispatchers_found": len(analysis.dispatchers),
            "strategies_used": strategies_used,
            "dispatcher_type": analysis.dispatcher_type.name,
            "state_constants_count": len(analysis.state_constants),
        }

    def validate_with_emulation(
        self,
        initial_state: int | None = None,
        max_transitions: int = 20,
    ) -> list[tuple[int, int]] | None:
        """
        Validate state machine using Unicorn emulation (optional enhancement).

        This method attempts to concretely execute the state machine from
        an initial state to discover actual transitions. This provides
        ground truth validation of pattern-based detection.

        Args:
            initial_state: Starting state value (uses detected initial_state if None)
            max_transitions: Maximum transitions to trace

        Returns:
            List of (from_state, to_state) tuples if successful, None otherwise
        """
        if not EMULATION_AVAILABLE:
            logger.debug("Emulation not available for validation")
            return None

        analysis = self.analyze()
        if not analysis.is_conditional_chain:
            return None

        # Need state variable information for emulation
        if analysis.state_variable is None:
            logger.debug("No state variable detected, cannot emulate")
            return None

        # Use detected initial state if not provided
        if initial_state is None:
            initial_state = analysis.initial_state
            if initial_state is None:
                logger.debug("No initial state available for emulation")
                return None

        try:
            import idc
            import idaapi

            # Create emulation oracle - detect architecture from IDA
            arch = self._detect_architecture()
            oracle = EmulationOracle.create(arch)
            if not oracle.has_unicorn:
                logger.debug("Unicorn not available")
                return None

            # Get function bytes
            func_start = self.func_ea
            func_end = idc.find_func_end(func_start)
            if func_end == idaapi.BADADDR:
                logger.debug("Could not determine function end")
                return None

            code_bytes = idc.get_bytes(func_start, func_end - func_start)
            if not code_bytes:
                logger.debug("Could not read function bytes")
                return None

            # Determine state variable location for Unicorn
            state_var = analysis.state_variable

            if state_var.mop_type == ida_hexrays.mop_S:
                # Stack variable - calculate native offset
                frame_size = self._get_frame_size()
                native_offset = state_var.get_native_stack_offset(frame_size)

                if native_offset is None:
                    logger.debug("Could not determine native stack offset")
                    return None

                logger.info(
                    "State variable: stack offset %d (micro) -> %d (native), size=%d",
                    state_var.mop_offset, native_offset, state_var.mop_size
                )

                # Use oracle's trace_state_variable for stack-based state
                transitions_raw = oracle.trace_state_variable(
                    code_bytes,
                    native_offset,
                    initial_state,
                    func_start,
                )

                # Convert StateTransition objects to tuples
                transitions = [
                    (t.from_value, t.to_value) for t in transitions_raw
                ]

                if transitions:
                    logger.info(
                        "Emulation found %d state transitions: %s",
                        len(transitions),
                        [(hex(f), hex(t)) for f, t in transitions[:5]]  # Log first 5
                    )
                else:
                    logger.debug("Emulation completed but no transitions found")

                return transitions if transitions else None

            elif state_var.mop_type == ida_hexrays.mop_r:
                # Register variable - need different approach
                logger.debug(
                    "State variable in register %d - register tracing not yet implemented",
                    state_var.mop_offset
                )
                return None

            else:
                logger.debug("Unsupported state variable type: %d", state_var.mop_type)
                return None

        except ImportError as e:
            logger.debug("IDA imports not available: %s", e)
            return None
        except Exception as e:
            logger.debug("Emulation validation error: %s", e)
            return None

    def _detect_architecture(self) -> str:
        """Detect architecture from IDA database."""
        try:
            import idaapi
            info = idaapi.get_inf_structure()
            if info.is_64bit():
                # Check if ARM64
                proc_name = idaapi.get_idp_name()
                if proc_name and "arm" in proc_name.lower():
                    return "arm64"
                return "x86_64"
            elif info.is_32bit():
                return "x86"
            return "x86_64"  # Default
        except Exception:
            return "x86_64"

    def _get_frame_size(self) -> int:
        """Get the stack frame size from MBA."""
        # Try various mba_t attributes that store frame size
        for attr in ("stacksize", "frsize", "argsize", "tmpstk_size"):
            val = getattr(self.mba, attr, None)
            if val and val > 0:
                return val
        return 0x100  # Default fallback

    def _get_or_create_block(self, analysis: DispatcherAnalysis, serial: int) -> BlockAnalysis:
        """Get or create BlockAnalysis for a serial."""
        if serial not in analysis.blocks:
            analysis.blocks[serial] = BlockAnalysis(serial=serial)
        return analysis.blocks[serial]

    def _analyze_block_predecessors(self, analysis: DispatcherAnalysis) -> None:
        """Strategy 1: High fan-in detection."""
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            pred_count = blk.npred()

            if pred_count >= MIN_HIGH_FAN_IN:
                block_info = self._get_or_create_block(analysis, i)
                block_info.predecessor_count = pred_count
                block_info.strategies |= DispatcherStrategy.HIGH_FAN_IN

                # Count unconditional predecessors (goto blocks)
                uncond_count = 0
                for pred_serial in blk.predset:
                    pred_blk = self.mba.get_mblock(pred_serial)
                    if pred_blk.tail and pred_blk.tail.opcode == ida_hexrays.m_goto:
                        uncond_count += 1
                    elif pred_blk.nsucc() == 1:
                        uncond_count += 1

                block_info.unconditional_pred_count = uncond_count

                # Check predecessor uniformity
                if pred_count > 0 and uncond_count / pred_count >= MIN_PREDECESSOR_UNIFORMITY_RATIO:
                    block_info.strategies |= DispatcherStrategy.PREDECESSOR_UNIFORM

    def _analyze_state_comparisons(self, analysis: DispatcherAnalysis) -> None:
        """Strategy 2: State comparison detection."""
        # Track which variables are compared against large constants
        comparison_opcodes = [
            ida_hexrays.m_jnz, ida_hexrays.m_jz,
            ida_hexrays.m_jae, ida_hexrays.m_jb,
            ida_hexrays.m_ja, ida_hexrays.m_jbe,
            ida_hexrays.m_jge, ida_hexrays.m_jg,
            ida_hexrays.m_jl, ida_hexrays.m_jle,
        ]

        # var_key -> (mop, list of (block_serial, constant_value))
        var_comparisons: dict[str, tuple[ida_hexrays.mop_t, list[tuple[int, int]]]] = {}

        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if blk.tail and blk.tail.opcode in comparison_opcodes:
                # Check right operand is a large constant
                if blk.tail.r.t == ida_hexrays.mop_n:
                    const_val = blk.tail.r.nnn.value
                    if const_val > MIN_STATE_CONSTANT:
                        # Get variable key from left operand
                        var_key = self._get_mop_key(blk.tail.l)
                        if var_key:
                            if var_key not in var_comparisons:
                                # Store the mop along with comparisons
                                var_comparisons[var_key] = (ida_hexrays.mop_t(blk.tail.l), [])
                            var_comparisons[var_key][1].append((i, const_val))

                            block_info = self._get_or_create_block(analysis, i)
                            block_info.state_constants.add(const_val)
                            analysis.state_constants.add(const_val)

        # Find the state variable (most comparisons)
        best_var_key = None
        best_mop = None
        best_comparisons = []
        for var_key, (mop, comparisons) in var_comparisons.items():
            if len(comparisons) > len(best_comparisons):
                best_var_key = var_key
                best_mop = mop
                best_comparisons = comparisons

        # Mark blocks with state comparisons and create StateVariableCandidate
        if len(best_comparisons) >= MIN_UNIQUE_CONSTANTS and best_mop is not None:
            unique_constants = {c[1] for c in best_comparisons}
            comparison_blocks = [c[0] for c in best_comparisons]

            # Create the state variable candidate
            analysis.state_variable = StateVariableCandidate(
                mop=best_mop,
                mop_type=best_mop.t,
                mop_offset=self._get_mop_offset(best_mop),
                mop_size=best_mop.size,
                comparison_count=len(best_comparisons),
                unique_constants=unique_constants,
                comparison_blocks=comparison_blocks,
            )

            for blk_serial, const_val in best_comparisons:
                block_info = self._get_or_create_block(analysis, blk_serial)
                block_info.strategies |= DispatcherStrategy.STATE_COMPARISON

                # Mark as high constant frequency if many unique constants
                if len(unique_constants) >= MIN_UNIQUE_CONSTANTS:
                    block_info.strategies |= DispatcherStrategy.CONSTANT_FREQUENCY

    def _get_mop_offset(self, mop: ida_hexrays.mop_t) -> int:
        """Get the offset/identifier from an mop_t."""
        if mop.t == ida_hexrays.mop_r:
            return mop.r
        elif mop.t == ida_hexrays.mop_S:
            return mop.s.off
        elif mop.t == ida_hexrays.mop_v:
            return mop.g
        elif mop.t == ida_hexrays.mop_l:
            return mop.l.off
        return 0

    def _analyze_loop_structure(self, analysis: DispatcherAnalysis) -> None:
        """Strategy 3 & 6: Loop header and back-edge detection."""
        # Simple back-edge detection: if block B jumps to block A where A.serial <= B.serial
        # and A dominates B (approximately: A is reachable from entry before B)

        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)

            for succ_serial in blk.succset:
                # Back-edge: jumping to an earlier block
                if succ_serial <= i:
                    target_info = self._get_or_create_block(analysis, succ_serial)
                    target_info.back_edge_sources.append(i)
                    target_info.strategies |= DispatcherStrategy.BACK_EDGE

                    # If many back-edges, likely a loop header
                    if len(target_info.back_edge_sources) >= 2:
                        target_info.strategies |= DispatcherStrategy.LOOP_HEADER

        # Detect nested loop structure (Hodur pattern)
        self._detect_nested_loops(analysis)

    def _detect_nested_loops(self, analysis: DispatcherAnalysis) -> None:
        """Detect nested while(1) loop pattern characteristic of Hodur."""
        # Hodur uses deeply nested while(1) loops
        # Look for blocks that are loop headers at multiple nesting levels

        # Simple heuristic: count blocks with back-edges that are also
        # targets of other back-edge blocks
        loop_headers = [
            serial for serial, info in analysis.blocks.items()
            if DispatcherStrategy.BACK_EDGE in info.strategies
        ]

        if len(loop_headers) >= 3:
            # Check for nesting
            nested_count = 0
            for header in loop_headers:
                header_info = analysis.blocks[header]
                # Check if any back-edge source is also a loop header
                for src in header_info.back_edge_sources:
                    if src in loop_headers:
                        nested_count += 1

            if nested_count >= 2:
                analysis.nested_loop_depth = nested_count
                # Mark deepest loop headers
                for header in loop_headers:
                    analysis.blocks[header].strategies |= DispatcherStrategy.NESTED_LOOP

    def _analyze_state_assignments(self, analysis: DispatcherAnalysis) -> None:
        """Find state variable assignments for Hodur detection."""
        if not analysis.state_constants:
            return

        # Find mov instructions assigning state constants
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            insn = blk.head
            while insn:
                if insn.opcode == ida_hexrays.m_mov:
                    if insn.l.t == ida_hexrays.mop_n:
                        const_val = insn.l.nnn.value
                        if const_val in analysis.state_constants:
                            # This block assigns a state constant
                            block_info = self._get_or_create_block(analysis, i)
                            block_info.state_constants.add(const_val)
                insn = insn.next

    def _analyze_block_sizes(self, analysis: DispatcherAnalysis) -> None:
        """Strategy: Small block detection - dispatchers are typically tight loops."""
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)

            # Count instructions in block
            ins_count = 0
            insn = blk.head
            while insn and ins_count <= MAX_DISPATCHER_BLOCK_SIZE:
                ins_count += 1
                insn = insn.next

            # Small blocks with other dispatcher characteristics get flagged
            if ins_count <= MAX_DISPATCHER_BLOCK_SIZE:
                # Only flag if block has other dispatcher indicators
                if i in analysis.blocks:
                    block_info = analysis.blocks[i]
                    if block_info.strategies != DispatcherStrategy.NONE:
                        block_info.strategies |= DispatcherStrategy.SMALL_BLOCK

    def _analyze_switch_jumps(self, analysis: DispatcherAnalysis) -> None:
        """Strategy: Switch/jtbl detection - computed jumps indicate dispatchers."""
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if not blk.tail:
                continue

            is_switch = False

            # Check for m_jtbl (switch table)
            if blk.tail.opcode == ida_hexrays.m_jtbl:
                is_switch = True

            # Check for computed goto (indirect jump)
            elif blk.tail.opcode == ida_hexrays.m_goto:
                # Check if jump target is computed (not constant block ref)
                if blk.tail.l.t == ida_hexrays.mop_d:  # Computed destination
                    is_switch = True

            if is_switch:
                block_info = self._get_or_create_block(analysis, i)
                block_info.strategies |= DispatcherStrategy.SWITCH_JUMP

    def _score_blocks(self, analysis: DispatcherAnalysis) -> None:
        """Calculate dispatcher likelihood score for each block."""
        for serial, block_info in analysis.blocks.items():
            score = 0.0

            # High fan-in: +10 per predecessor over threshold
            if DispatcherStrategy.HIGH_FAN_IN in block_info.strategies:
                score += (block_info.predecessor_count - MIN_HIGH_FAN_IN + 1) * 10

            # State comparison: +20
            if DispatcherStrategy.STATE_COMPARISON in block_info.strategies:
                score += 20

            # Loop header: +15
            if DispatcherStrategy.LOOP_HEADER in block_info.strategies:
                score += 15

            # Predecessor uniformity: +10
            if DispatcherStrategy.PREDECESSOR_UNIFORM in block_info.strategies:
                score += 10

            # Constant frequency: +5 per unique constant
            if DispatcherStrategy.CONSTANT_FREQUENCY in block_info.strategies:
                score += len(block_info.state_constants) * 5

            # Back-edge: +10 per back-edge
            if DispatcherStrategy.BACK_EDGE in block_info.strategies:
                score += len(block_info.back_edge_sources) * 10

            # Nested loop: +25 (Hodur signature)
            if DispatcherStrategy.NESTED_LOOP in block_info.strategies:
                score += 25

            # Small block: +5 (dispatchers are typically tight)
            if DispatcherStrategy.SMALL_BLOCK in block_info.strategies:
                score += 5

            # Switch/jtbl: +15 (strong dispatcher indicator)
            if DispatcherStrategy.SWITCH_JUMP in block_info.strategies:
                score += 15

            block_info.score = score

    def _classify_dispatcher_type(self, analysis: DispatcherAnalysis) -> None:
        """Classify the dispatcher type based on detected patterns.

        Conditional chain characteristics (Hodur, C2 frameworks, info stealers):
        1. Nested while(1) loops (not switch)
        2. State comparisons using jnz/jz (not jtbl)
        3. Large 32-bit constants
        4. Many state transitions
        """
        conditional_chain_score = 0

        # Nested loops - strong indicator of conditional chain
        if analysis.nested_loop_depth >= 2:
            conditional_chain_score += 30

        # State constants count
        if len(analysis.state_constants) >= MIN_UNIQUE_CONSTANTS:
            conditional_chain_score += len(analysis.state_constants) * 5

        # No jtbl (switch) present - check for absence of jtbl opcode
        has_jtbl = False
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if blk.tail and blk.tail.opcode == ida_hexrays.m_jtbl:
                has_jtbl = True
                break

        if not has_jtbl and len(analysis.state_constants) >= MIN_UNIQUE_CONSTANTS:
            conditional_chain_score += 20

        # Dynamic threshold: lower requirement when nested loops are detected
        # Nested loops are a strong structural indicator even when constants are gone
        min_score = 30 if analysis.nested_loop_depth >= 2 else 50

        # Classify based on score
        if conditional_chain_score >= min_score:
            analysis.dispatcher_type = DispatcherType.CONDITIONAL_CHAIN
            logger.info(
                "Classified as CONDITIONAL_CHAIN dispatcher (score=%d, threshold=%d, maturity=%d)",
                conditional_chain_score,
                min_score,
                self.mba.maturity
            )
            # Find initial state for conditional chain dispatchers
            self._find_initial_state(analysis)
        elif has_jtbl:
            analysis.dispatcher_type = DispatcherType.SWITCH_TABLE
        else:
            analysis.dispatcher_type = DispatcherType.UNKNOWN

    def _find_initial_state(self, analysis: DispatcherAnalysis) -> None:
        """Find the initial state value for conditional chain dispatchers."""
        # Look in early blocks for assignment of a state constant
        for i in range(min(5, self.mba.qty)):
            blk = self.mba.get_mblock(i)
            insn = blk.head
            while insn:
                if insn.opcode == ida_hexrays.m_mov:
                    if insn.l.t == ida_hexrays.mop_n:
                        const_val = insn.l.nnn.value
                        if const_val in analysis.state_constants:
                            analysis.initial_state = const_val
                            # Also update the state variable candidate if we have one
                            if analysis.state_variable is not None:
                                analysis.state_variable.init_value = const_val
                            logger.debug("Found initial state: 0x%x in block %d", const_val, i)
                            return
                insn = insn.next

    def _get_mop_key(self, mop: ida_hexrays.mop_t) -> str | None:
        """Get a unique key for an mop_t for comparison."""
        if mop.t == ida_hexrays.mop_r:
            return f"r{mop.r}"
        elif mop.t == ida_hexrays.mop_S:
            return f"S{mop.s.off}"
        elif mop.t == ida_hexrays.mop_v:
            return f"v{mop.g}"
        elif mop.t == ida_hexrays.mop_l:
            return f"l{mop.l.off}"
        return None


def should_skip_dispatcher(mba: ida_hexrays.mba_t, blk: ida_hexrays.mblock_t) -> bool:
    """
    Check if a block should be skipped for switch-table style patching.

    This is used by FixPredecessorOfConditionalJumpBlock to avoid cascading unreachability
    when dealing with conditional chain dispatchers (nested jnz/jz comparisons).

    IMPORTANT: Only returns True for CONDITIONAL_CHAIN dispatchers, NOT for SWITCH_TABLE.
    Switch-table patching requires modifying dispatcher blocks, so we must not skip them.

    Returns:
        True if this is a conditional chain dispatcher block that should be skipped
        to avoid cascading unreachability.
    """
    cache = DispatcherCache.get_or_create(mba)
    analysis = cache.analyze()

    # Only skip if this is conditional chain style (nested while loops, no switch/jtbl)
    # Switch-table style should NOT be skipped - it needs the predecessor patching
    if not analysis.is_conditional_chain:
        return False

    # For conditional chain style, skip blocks flagged as dispatchers
    if cache.is_dispatcher(blk.serial):
        return True

    return False
