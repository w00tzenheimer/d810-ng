from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import ida_hexrays

from d810.core import getLogger
from d810.expr.emulator import MicroCodeEnvironment, MicroCodeInterpreter
from d810.hexrays.cfg_utils import (
    change_1way_block_successor,
    change_2way_block_conditional_successor,
    duplicate_block,
)
from d810.hexrays.hexrays_formatters import (
    format_minsn_t,
    format_mop_t,
    mop_type_to_string,
)
from d810.hexrays.hexrays_helpers import (
    append_mop_if_not_in_list,
    equal_mops_ignore_size,
    get_blk_index,
    get_mop_index,
)

if TYPE_CHECKING:
    from typing import Union

# This module can be use to find the instruction that define the value of a mop. Basically, you:
# 1 - Create a MopTracker object with the list of mops to search
# 2 - Call search_backward while specifying the instruction where the search should start
# It will return a list if MopHistory, each MopHistory object of this list:
# * Represents one possible path to compute the searched mops
# * Stores all instructions used to compute the searched mops
#
# You can get the value of one of the searched mop by calling the get_mop_constant_value API of a MopHistory object.
# Behind the scene, it will emulate all microcode instructions on the MopHistory path.
#
# Finally the duplicate_histories API can be used to duplicate microcode blocks so that for each microcode block,
# the searched mops have only one possible values. For instance, this is a preliminary step used in code unflattening.


logger = getLogger(__name__, logging.WARNING)


class InstructionDefUseCollector(ida_hexrays.mop_visitor_t):
    def __init__(self):
        super().__init__()
        self.unresolved_ins_mops = []
        self.memory_unresolved_ins_mops = []
        self.target_mops = []

    def visit_mop(self, op: ida_hexrays.mop_t, op_type: int, is_target: bool):
        # Skip mops with invalid sizes (e.g., function references with size=-1)
        if op.size < 0:
            return 0

        if is_target:
            append_mop_if_not_in_list(op, self.target_mops)
        else:
            # TODO whatever the case, in the end we will always return 0. May be this code can be better optimized.
            # TODO handle other special case (e.g. ldx ins, ...)
            if op.t == ida_hexrays.mop_S:
                append_mop_if_not_in_list(op, self.unresolved_ins_mops)
            elif op.t == ida_hexrays.mop_r:
                append_mop_if_not_in_list(op, self.unresolved_ins_mops)
            elif op.t == ida_hexrays.mop_v:
                append_mop_if_not_in_list(op, self.memory_unresolved_ins_mops)
            elif op.t == ida_hexrays.mop_a:
                if op.a.t == ida_hexrays.mop_v:
                    return 0
                elif op.a.t == ida_hexrays.mop_S:
                    return 0
                logger.warning(
                    "op.t == mop_a: Calling visit_mop with unsupported mop type %s - %s: '%s'",
                    mop_type_to_string(op.t),
                    mop_type_to_string(op.a.t),
                    format_mop_t(op),
                )
                return 0
            elif op.t == ida_hexrays.mop_n:
                return 0
            elif op.t == ida_hexrays.mop_d:
                return 0
            elif op.t == ida_hexrays.mop_h:
                return 0
            elif op.t == ida_hexrays.mop_b:
                return 0
            elif op.t == ida_hexrays.mop_str:
                return 0
            else:
                logger.warning(
                    "op.t == else: Calling visit_mop with unsupported mop type %s: '%s'",
                    mop_type_to_string(op.t),
                    format_mop_t(op),
                )
        return 0


class BlockInfo(object):
    """Immutable block info for structural sharing.

    Uses tuple for ins_list to enable copy-free sharing between MopHistory instances.
    When mutation is needed, use with_prepended_ins/with_appended_ins to create
    a new BlockInfo with the change.

    The serial is cached to avoid repeated SWIG attribute access overhead
    (profiled at 1.9M accesses taking 0.39s in generator expressions).
    """
    __slots__ = ('blk', 'ins_list', 'serial')

    def __init__(self, blk: ida_hexrays.mblock_t, ins=None):
        self.blk = blk
        self.serial: int = blk.serial  # Cache serial to avoid SWIG overhead
        self.ins_list: tuple[ida_hexrays.minsn_t, ...] = (ins,) if ins is not None else ()

    def with_prepended_ins(self, ins: ida_hexrays.minsn_t) -> BlockInfo:
        """Return new BlockInfo with instruction prepended (copy-on-write)."""
        new_info = BlockInfo.__new__(BlockInfo)
        new_info.blk = self.blk
        new_info.serial = self.serial
        new_info.ins_list = (ins,) + self.ins_list
        return new_info

    def with_appended_ins(self, ins: ida_hexrays.minsn_t) -> BlockInfo:
        """Return new BlockInfo with instruction appended (copy-on-write)."""
        new_info = BlockInfo.__new__(BlockInfo)
        new_info.blk = self.blk
        new_info.serial = self.serial
        new_info.ins_list = self.ins_list + (ins,)
        return new_info

    def with_new_blk(self, new_blk: ida_hexrays.mblock_t) -> BlockInfo:
        """Return new BlockInfo with different block (copy-on-write)."""
        new_info = BlockInfo.__new__(BlockInfo)
        new_info.blk = new_blk
        new_info.serial = new_blk.serial  # Update serial for new block
        new_info.ins_list = self.ins_list
        return new_info

    def get_copy(self) -> BlockInfo:
        """For backwards compatibility - returns self since BlockInfo is now immutable."""
        return self


class MopHistory(object):
    def __init__(self, searched_mop_list: list[ida_hexrays.mop_t]):
        self.searched_mop_list = [ida_hexrays.mop_t(x) for x in searched_mop_list]
        self.history = []
        self.unresolved_mop_list = []

        # Don't use symbolic mode for tracking - we need to know when variables are unresolved
        self._mc_interpreter = MicroCodeInterpreter(symbolic_mode=False)
        self._mc_initial_environment = MicroCodeEnvironment()
        self._mc_current_environment = self._mc_initial_environment.get_copy()
        self._is_dirty = True

        # Cached serial path for O(1) lookup - invalidated on history changes
        self._serial_cache: tuple[int, ...] | None = None
        self._serial_set_cache: frozenset[int] | None = None

    def _invalidate_serial_cache(self) -> None:
        """Invalidate the serial path cache after history changes."""
        self._serial_cache = None
        self._serial_set_cache = None

    def add_mop_initial_value(self, mop: ida_hexrays.mop_t, value: int):
        self._is_dirty = True
        self._mc_initial_environment.define(mop, value)

    def get_copy(self) -> MopHistory:
        new_mop_history = MopHistory(self.searched_mop_list)
        # Shallow copy of history list - BlockInfo objects are immutable and can be shared
        new_mop_history.history = self.history.copy()
        new_mop_history.unresolved_mop_list = [x for x in self.unresolved_mop_list]
        new_mop_history._mc_initial_environment = (
            self._mc_initial_environment.get_copy()
        )
        new_mop_history._mc_current_environment = (
            new_mop_history._mc_initial_environment.get_copy()
        )
        # Copy the serial cache if valid (same history structure)
        new_mop_history._serial_cache = self._serial_cache
        new_mop_history._serial_set_cache = self._serial_set_cache
        return new_mop_history

    def is_resolved(self) -> bool:
        if len(self.unresolved_mop_list) == 0:
            return True
        for x in self.unresolved_mop_list:
            x_value = self._mc_initial_environment.lookup(x, raise_exception=False)
            if x_value is None:
                return False
        return True

    @property
    def block_path(self) -> list[ida_hexrays.mblock_t]:
        return [blk_info.blk for blk_info in self.history]

    @property
    def block_serial_path(self) -> list[int]:
        """Get list of block serials (cached).

        Uses cached serial from BlockInfo to avoid SWIG attribute access overhead.
        """
        if self._serial_cache is None:
            # Use cached serial from BlockInfo (avoids 1.9M SWIG calls)
            self._serial_cache = tuple(blk_info.serial for blk_info in self.history)
        return list(self._serial_cache)

    @property
    def block_serial_set(self) -> frozenset[int]:
        """Get frozenset of block serials for O(1) membership testing (cached).

        Uses cached serial from BlockInfo to avoid SWIG attribute access overhead.
        """
        if self._serial_set_cache is None:
            # Ensure serial_cache is populated first
            if self._serial_cache is None:
                # Use cached serial from BlockInfo (avoids 1.9M SWIG calls)
                self._serial_cache = tuple(blk_info.serial for blk_info in self.history)
            self._serial_set_cache = frozenset(self._serial_cache)
        return self._serial_set_cache

    def contains_block_serial(self, serial: int) -> bool:
        """O(1) check if path contains a block serial."""
        return serial in self.block_serial_set

    def replace_block_in_path(self, old_blk: ida_hexrays.mblock_t, new_blk: ida_hexrays.mblock_t) -> bool:
        blk_index = get_blk_index(old_blk, self.block_path)
        if blk_index > 0:
            # Use copy-on-write: create new BlockInfo with new block
            self.history[blk_index] = self.history[blk_index].with_new_blk(new_blk)
            self._is_dirty = True
            self._invalidate_serial_cache()
            return True
        else:
            logger.error("replace_block_in_path: should not happen")
            return False

    def insert_block_in_path(self, blk: ida_hexrays.mblock_t, where_index: int):
        self.history = (
            self.history[:where_index] + [BlockInfo(blk)] + self.history[where_index:]
        )
        self._is_dirty = True
        self._invalidate_serial_cache()

    def insert_ins_in_block(self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t, before=True):
        blk_index = get_blk_index(blk, self.block_path)
        if blk_index < 0:
            return False
        # Use copy-on-write: create new BlockInfo with new instruction
        old_info = self.history[blk_index]
        if before:
            self.history[blk_index] = old_info.with_prepended_ins(ins)
        else:
            self.history[blk_index] = old_info.with_appended_ins(ins)
        self._is_dirty = True

    def _execute_microcode(self) -> bool:
        if not self._is_dirty:
            if logger.debug_on:
                logger.debug("_execute_microcode: already clean, using cached results")
            return True
        if logger.debug_on:
            formatted_mop_searched_list = (
                "['" + "', '".join([format_mop_t(x) for x in self.searched_mop_list]) + "']"
            )
            logger.debug(
                "Computing: %s for path %s", formatted_mop_searched_list, self.block_serial_path
            )
            logger.debug(
                "History has %d blocks with total %d instructions",
                len(self.history),
                sum(len(blk_info.ins_list) for blk_info in self.history),
            )
        self._mc_current_environment = self._mc_initial_environment.get_copy()
        for blk_info in self.history:
            for blk_ins in blk_info.ins_list:
                if logger.debug_on:
                    logger.debug(
                        "Executing: %d.%s", blk_info.serial, format_minsn_t(blk_ins)
                    )
                if not self._mc_interpreter.eval_instruction(
                    blk_info.blk, blk_ins, self._mc_current_environment
                ):
                    self._is_dirty = False
                    return False
        self._is_dirty = False
        # Debug: dump environment after execution
        if logger.debug_on:
            self._mc_current_environment.dump(
                "Tracker environment after _execute_microcode"
            )
        return True

    def get_mop_constant_value(self, searched_mop: ida_hexrays.mop_t) -> Union[None, int]:
        if logger.debug_on:
            logger.debug(
                "get_mop_constant_value called for {0}, _is_dirty={1}, history_len={2}".format(
                    format_mop_t(searched_mop), self._is_dirty, len(self.history)
                )
            )
        if not self._execute_microcode():
            logger.debug("get_mop_constant_value: _execute_microcode returned False")
            return None
        if logger.debug_on:
            self._mc_current_environment.dump(
                f"Tracker environment before eval_mop for {format_mop_t(searched_mop)}"
            )
        return self._mc_interpreter.eval_mop(searched_mop, self._mc_current_environment)

    def print_info(self, detailed_info=False):
        formatted_mop_searched_list = [format_mop_t(x) for x in self.searched_mop_list]
        tmp = ", ".join(
            [
                "{0}={1}".format(formatted_mop, self.get_mop_constant_value(mop))
                for formatted_mop, mop in zip(
                    formatted_mop_searched_list, self.searched_mop_list
                )
            ]
        )
        logger.info(
            "MopHistory: resolved={0}, path={1}, mops={2}".format(
                self.is_resolved(), self.block_serial_path, tmp
            )
        )
        if detailed_info:
            str_mop_list = "['" + "', '".join(formatted_mop_searched_list) + "']"
            if len(self.block_path) == 0:
                logger.info("MopHistory for {0} => nothing".format(str_mop_list))
                return

            end_blk = self.block_path[-1]
            end_ins = end_blk.tail
            if self.history[-1].ins_list:
                end_ins = self.history[-1].ins_list[-1]

            if end_ins:
                logger.info(
                    "MopHistory for {0} {1}.{2}".format(
                        str_mop_list, end_blk.serial, format_minsn_t(end_ins)
                    )
                )
            else:
                logger.info(
                    "MopHistory for '{0}' {1}.tail".format(str_mop_list, end_blk.serial)
                )
            logger.info("  path {0}".format(self.block_serial_path))
            for blk_info in self.history:
                for blk_ins in blk_info.ins_list:
                    logger.info(
                        "   {0}.{1}".format(
                            blk_info.serial, format_minsn_t(blk_ins)
                        )
                    )


def get_standard_and_memory_mop_lists(mop_in: ida_hexrays.mop_t) -> tuple[list[ida_hexrays.mop_t], list[ida_hexrays.mop_t]]:
    # Filter out mops with invalid sizes (e.g., function references with size=-1)
    # These cannot be tracked or evaluated as variables
    if mop_in.size < 0:
        if logger.debug_on:
            logger.debug(
                "Skipping mop with invalid size (%d): %s",
                mop_in.size,
                format_mop_t(mop_in),
            )
        return [], []

    if mop_in.t in [ida_hexrays.mop_r, ida_hexrays.mop_S]:
        return [mop_in], []
    elif mop_in.t == ida_hexrays.mop_v:
        return [], [mop_in]
    elif mop_in.t == ida_hexrays.mop_d:
        ins_mop_info = InstructionDefUseCollector()
        mop_in.d.for_all_ops(ins_mop_info)
        return (
            remove_segment_registers(ins_mop_info.unresolved_ins_mops),
            ins_mop_info.memory_unresolved_ins_mops,
        )
    else:
        logger.warning(
            "Calling get_standard_and_memory_mop_lists with unsupported mop type {0}: '{1}'".format(
                mop_in.t, format_mop_t(mop_in)
            )
        )
        return [], []


# A MopTracker will create new MopTracker to recursively track variable when multiple paths are possible,
# The cur_mop_tracker_nb_path global variable is used to limit the number of MopTracker created
cur_mop_tracker_nb_path = 0


class SearchContext:
    """Context for a single search_backward operation with memoization.

    This class manages state across recursive search_backward calls to:
    1. Track visited (block, state) pairs to avoid redundant exploration
    2. Cache results for memoization
    3. Track statistics for debugging

    The key insight is that path explosion happens when the same (block, unresolved_mops)
    state is explored via multiple paths. By caching these, we avoid the 113x amplification.
    """
    __slots__ = ('visited_states', 'result_cache', 'stats_hits', 'stats_misses', 'stats_skipped')

    def __init__(self):
        # Set of (block_serial, unresolved_state_hash) that have been visited
        self.visited_states: set[tuple[int, int]] = set()
        # Cache: (block_serial, unresolved_state_hash) -> list of histories
        self.result_cache: dict[tuple[int, int], list] = {}
        # Statistics
        self.stats_hits = 0
        self.stats_misses = 0
        self.stats_skipped = 0

    def make_state_hash(self, unresolved_mops: list, memory_unresolved_mops: list) -> int:
        """Create a hashable representation of the unresolved state.

        Uses the mop type and value for hashing to identify equivalent states.
        """
        # Build tuple of (mop_type, mop_repr) for each unresolved mop
        state_parts = []
        for mop in unresolved_mops:
            # Use type and string representation for uniqueness
            state_parts.append((mop.t, format_mop_t(mop)))
        for mop in memory_unresolved_mops:
            state_parts.append((-1, format_mop_t(mop)))  # -1 to distinguish memory mops
        return hash(tuple(sorted(state_parts)))

    def check_and_mark_visited(self, blk_serial: int, state_hash: int) -> bool:
        """Check if state was visited; if not, mark it visited.

        Returns True if this is a new state (should explore).
        Returns False if already visited (should skip).
        """
        key = (blk_serial, state_hash)
        if key in self.visited_states:
            self.stats_skipped += 1
            return False
        self.visited_states.add(key)
        return True

    def get_cached(self, blk_serial: int, state_hash: int) -> list | None:
        """Get cached result if available."""
        key = (blk_serial, state_hash)
        result = self.result_cache.get(key)
        if result is not None:
            self.stats_hits += 1
        else:
            self.stats_misses += 1
        return result

    def cache_result(self, blk_serial: int, state_hash: int, histories: list) -> None:
        """Cache the result for future lookups."""
        key = (blk_serial, state_hash)
        self.result_cache[key] = histories


# Global search context for the current search operation
_current_search_context: SearchContext | None = None


def get_search_statistics() -> dict[str, int]:
    """Get statistics from the most recent search_backward operation.

    Returns a dict with:
    - visited_states: Number of unique (block, state) pairs explored
    - skipped: Number of states skipped due to memoization
    - cache_hits: Number of times cached results were used
    - cache_misses: Number of times cache lookup failed
    - reduction_factor: Ratio of skipped to total (higher = more savings)

    This is useful for profiling and debugging search performance.
    """
    if _current_search_context is None:
        return {
            'visited_states': 0,
            'skipped': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'reduction_factor': 0.0,
        }

    ctx = _current_search_context
    total = len(ctx.visited_states) + ctx.stats_skipped
    reduction = ctx.stats_skipped / total if total > 0 else 0.0

    return {
        'visited_states': len(ctx.visited_states),
        'skipped': ctx.stats_skipped,
        'cache_hits': ctx.stats_hits,
        'cache_misses': ctx.stats_misses,
        'reduction_factor': reduction,
    }


class MopTracker(object):
    def __init__(
        self,
        searched_mop_list: list[ida_hexrays.mop_t],
        max_nb_block=-1,
        max_path=-1,
        dispatcher_info=None,
        _search_context: SearchContext | None = None,
    ):
        self.mba: ida_hexrays.mba_t
        self._unresolved_mops = []
        self._memory_unresolved_mops = []
        for searched_mop in searched_mop_list:
            a, b = get_standard_and_memory_mop_lists(searched_mop)
            self._unresolved_mops += a
            self._memory_unresolved_mops += b
        self.history = MopHistory(searched_mop_list)
        self.max_nb_block = max_nb_block
        self.max_path = max_path
        self.avoid_list = []
        self.call_detected = False
        self.constant_mops = []
        self.dispatcher_info = dispatcher_info
        # Search context for memoization (shared across recursive calls)
        self._search_context = _search_context

    @staticmethod
    def reset():
        global cur_mop_tracker_nb_path, _current_search_context
        cur_mop_tracker_nb_path = 0
        _current_search_context = None

    def add_mop_definition(self, mop: ida_hexrays.mop_t, cst_value: int):
        self.constant_mops.append([mop, cst_value])
        self.history.add_mop_initial_value(mop, cst_value)

    def get_copy(self) -> MopTracker:
        global cur_mop_tracker_nb_path
        new_mop_tracker = MopTracker(
            self._unresolved_mops, self.max_nb_block, self.max_path,
            _search_context=self._search_context  # Share context across copies
        )
        new_mop_tracker._memory_unresolved_mops = [
            x for x in self._memory_unresolved_mops
        ]
        new_mop_tracker.constant_mops = [[x[0], x[1]] for x in self.constant_mops]
        new_mop_tracker.history = self.history.get_copy()
        cur_mop_tracker_nb_path += 1
        return new_mop_tracker

    def search_backward(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t | None = None,
        avoid_list=None,
        must_use_pred=None,
        stop_at_first_duplication=False,
    ) -> list[MopHistory]:
        global _current_search_context

        # Initialize search context for top-level call
        is_top_level = self._search_context is None
        if is_top_level:
            self._search_context = SearchContext()
            _current_search_context = self._search_context

        if logger.debug_on:
            logger.debug(
                "Searching backward (reg): %s",
                [format_mop_t(x) for x in self._unresolved_mops]
            )
            logger.debug(
                "Searching backward (mem): %s",
                [format_mop_t(x) for x in self._memory_unresolved_mops]
            )
            logger.debug(
                "Searching backward (cst): %s",
                [f"{format_mop_t(x[0])}: {x[1]:x}" for x in self.constant_mops]
            )
        self.mba = blk.mba
        self.avoid_list = avoid_list if avoid_list else []

        # Compute state hash for memoization
        state_hash = self._search_context.make_state_hash(
            self._unresolved_mops, self._memory_unresolved_mops
        )

        # Check if we've already visited this (block, state) pair
        if not self._search_context.check_and_mark_visited(blk.serial, state_hash):
            if logger.debug_on:
                logger.debug(
                    "Skipping already-visited state: block %d, state_hash %d",
                    blk.serial, state_hash
                )
            # Return empty list since this state was already explored
            return []

        blk_with_multiple_pred = self.search_until_multiple_predecessor(blk, ins)
        if self.is_resolved():
            if logger.debug_on:
                logger.debug("MopTracker is resolved: %s", self.history.block_serial_path)
            self.history.unresolved_mop_list = [x for x in self._unresolved_mops]
            return [self.history]
        elif blk_with_multiple_pred is None:
            if logger.debug_on:
                logger.debug(
                    "MopTracker unresolved: (blk_with_multiple_pred): %s",
                    self.history.block_serial_path
                )
            self.history.unresolved_mop_list = [x for x in self._unresolved_mops]
            return [self.history]
        elif (
            self.max_nb_block != -1
            and len(self.history.block_serial_path) > self.max_nb_block
        ):
            if logger.debug_on:
                logger.debug(
                    "MopTracker unresolved: (max_nb_block): %s",
                    self.history.block_serial_path
                )
            self.history.unresolved_mop_list = [x for x in self._unresolved_mops]
            return [self.history]
        elif self.max_path != -1 and cur_mop_tracker_nb_path > self.max_path:
            if logger.debug_on:
                logger.debug("MopTracker unresolved: (max_path: %d", cur_mop_tracker_nb_path)
            self.history.unresolved_mop_list = [x for x in self._unresolved_mops]
            return [self.history]
        elif self.call_detected:
            if logger.debug_on:
                logger.debug(
                    "MopTracker unresolved: (call): %s", self.history.block_serial_path
                )
            self.history.unresolved_mop_list = [x for x in self._unresolved_mops]
            return [self.history]

        if stop_at_first_duplication:
            self.history.unresolved_mop_list = [x for x in self._unresolved_mops]
            return [self.history]

        if (
            self.dispatcher_info
            and blk_with_multiple_pred.serial
            == self.dispatcher_info.outmost_dispatch_num
        ):
            if logger.debug_on:
                logger.debug(
                    "MopTracker unresolved: reached to the dispatcher %d",
                    blk_with_multiple_pred.serial
                )
            if self.dispatcher_info.last_num_in_first_blks > 0:
                if logger.debug_on:
                    logger.debug(
                        "Tracking again from the last block %d in first blocks before the dispatcher",
                        self.dispatcher_info.last_num_in_first_blks
                    )
                new_tracker = self.get_copy()
                return new_tracker.search_backward(
                    self.mba.get_mblock(self.dispatcher_info.last_num_in_first_blks),
                    None,
                    self.avoid_list,
                    must_use_pred,
                )
        if logger.debug_on:
            logger.debug(
                "MopTracker creating child because multiple pred: %s",
                self.history.block_serial_path
            )
        possible_histories = []
        if (
            must_use_pred is not None
            and must_use_pred.serial in blk_with_multiple_pred.predset
        ):
            new_tracker = self.get_copy()
            possible_histories += new_tracker.search_backward(
                must_use_pred, None, self.avoid_list, must_use_pred
            )
        else:
            for blk_pred_serial in blk_with_multiple_pred.predset:
                new_tracker = self.get_copy()
                possible_histories += new_tracker.search_backward(
                    self.mba.get_mblock(blk_pred_serial),
                    None,
                    self.avoid_list,
                    must_use_pred,
                )
        return possible_histories

    def search_until_multiple_predecessor(
        self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t | None = None
    ) -> Union[None, ida_hexrays.mblock_t]:
        # By default, we start searching from block tail
        cur_ins = ins if ins else blk.tail
        cur_blk = blk

        while not self.is_resolved():
            # Explore one block
            # Use O(1) lookup via block_serial_set instead of O(n) list search
            if self.history.contains_block_serial(cur_blk.serial):
                self.history.insert_block_in_path(cur_blk, 0)
                # Check if the looped block is the dispatcher - if so, return it
                # so search_backward can resume tracking from the first blocks
                if (
                    self.dispatcher_info
                    and cur_blk.serial == self.dispatcher_info.outmost_dispatch_num
                ):
                    if logger.debug_on:
                        logger.debug(
                            "Loop detected back to dispatcher block %d",
                            cur_blk.serial
                        )
                    return cur_blk
                return None
            if cur_blk.serial in self.avoid_list:
                self.history.insert_block_in_path(cur_blk, 0)
                return None
            self.history.insert_block_in_path(cur_blk, 0)
            cur_ins = self.blk_find_def_backward(cur_blk, cur_ins)
            while cur_ins:
                cur_ins = self.blk_find_def_backward(cur_blk, cur_ins)
            if cur_blk.npred() > 1:
                return cur_blk
            elif cur_blk.npred() == 0:
                return None
            else:
                cur_blk = self.mba.get_mblock(cur_blk.predset[0])
                cur_ins = cur_blk.tail

        # We want to handle cases where the self.is_resolved() is True without doing anything
        if len(self.history.block_serial_path) == 0:
            self.history.insert_block_in_path(cur_blk, 0)
        return None

    def is_resolved(self) -> bool:
        if (len(self._unresolved_mops) == 0) and (
            len(self._memory_unresolved_mops) == 0
        ):
            return True

        for x in self._unresolved_mops:
            x_index = get_mop_index(x, [y[0] for y in self.constant_mops])
            if x_index == -1:
                return False
        return True

    def _build_ml_list(self, blk: ida_hexrays.mblock_t) -> Union[None, ida_hexrays.mlist_t]:
        ml = ida_hexrays.mlist_t()
        for unresolved_mop in self._unresolved_mops:
            if unresolved_mop.t not in [ida_hexrays.mop_r, ida_hexrays.mop_S]:
                logger.warning(
                    "_build_ml_list: Not supported mop type '{0}'".format(
                        unresolved_mop.t
                    )
                )
                return None
            blk.append_use_list(ml, unresolved_mop, ida_hexrays.MUST_ACCESS)
        return ml

    def blk_find_def_backward(
        self, blk: ida_hexrays.mblock_t, ins_start: ida_hexrays.minsn_t
    ) -> Union[None, ida_hexrays.minsn_t]:
        if self.is_resolved():
            return None
        ml = self._build_ml_list(blk)
        if not ml:
            logger.warning("blk_find_def_backward: _build_ml_list failed")
            return None
        ins_def = self._blk_find_ins_def_backward(blk, ins_start, ml)
        if ins_def:
            is_ok = self.update_history(blk, ins_def)
            if not is_ok:
                return None
            ins_def = ins_def.prev
        return ins_def

    def update_history(self, blk: ida_hexrays.mblock_t, ins_def: ida_hexrays.minsn_t) -> bool:
        if logger.debug_on:
            logger.debug("Updating history with %d.%s", blk.serial, format_minsn_t(ins_def))
        self.history.insert_ins_in_block(blk, ins_def, before=True)
        if ins_def.opcode == ida_hexrays.m_call:
            self.call_detected = True
            return False
        ins_mop_info = InstructionDefUseCollector()
        ins_def.for_all_ops(ins_mop_info)

        for target_mop in ins_mop_info.target_mops:
            resolved_mop_index = get_mop_index(target_mop, self._unresolved_mops)
            if resolved_mop_index != -1:
                if logger.debug_on:
                    logger.debug("Removing %s from unresolved mop", format_mop_t(target_mop))
                self._unresolved_mops.pop(resolved_mop_index)
        cleaned_unresolved_ins_mops = remove_segment_registers(
            ins_mop_info.unresolved_ins_mops
        )
        for ins_def_mop in cleaned_unresolved_ins_mops:
            ins_def_mop_index = get_mop_index(ins_def_mop, self._unresolved_mops)
            if ins_def_mop_index == -1:
                if logger.debug_on:
                    logger.debug("Adding %s in unresolved mop", format_mop_t(ins_def_mop))
                self._unresolved_mops.append(ins_def_mop)

        for target_mop in ins_mop_info.target_mops:
            resolved_mop_index = get_mop_index(target_mop, self._memory_unresolved_mops)
            if resolved_mop_index != -1:
                if logger.debug_on:
                    logger.debug("Removing %s from memory unresolved mop", format_mop_t(target_mop))
                self._memory_unresolved_mops.pop(resolved_mop_index)
        for ins_def_mem_mop in ins_mop_info.memory_unresolved_ins_mops:
            ins_def_mop_index = get_mop_index(
                ins_def_mem_mop, self._memory_unresolved_mops
            )
            if ins_def_mop_index == -1:
                if logger.debug_on:
                    logger.debug("Adding %s in memory unresolved mop", format_mop_t(ins_def_mem_mop))
                self._memory_unresolved_mops.append(ins_def_mem_mop)
        return True

    def _blk_find_ins_def_backward(
        self, blk: ida_hexrays.mblock_t, ins_start: ida_hexrays.minsn_t, ml: ida_hexrays.mlist_t
    ) -> Union[None, ida_hexrays.minsn_t]:
        cur_ins = ins_start
        while cur_ins is not None:
            def_list = blk.build_def_list(cur_ins, ida_hexrays.MAY_ACCESS | ida_hexrays.FULL_XDSU)
            if ml.has_common(def_list):
                return cur_ins
            for mem_mop in self._memory_unresolved_mops:
                if equal_mops_ignore_size(cur_ins.d, mem_mop):
                    return cur_ins
            cur_ins = cur_ins.prev
        return None


def get_block_with_multiple_predecessors(
    var_histories: list[MopHistory],
) -> tuple[None | ida_hexrays.mblock_t, None | dict[int, list[MopHistory]]]:
    for i, var_history in enumerate(var_histories):
        pred_blk = var_history.block_path[0]
        for block in var_history.block_path[1:]:
            tmp_dict = {pred_blk.serial: [var_history]}
            for j in range(i + 1, len(var_histories)):
                blk_index = get_blk_index(block, var_histories[j].block_path)
                if (blk_index - 1) >= 0:
                    other_pred = var_histories[j].block_path[blk_index - 1]
                    if other_pred.serial not in tmp_dict.keys():
                        tmp_dict[other_pred.serial] = []
                    tmp_dict[other_pred.serial].append(var_histories[j])
            if len(tmp_dict) > 1:
                return block, tmp_dict
            pred_blk = block
    return None, None


def try_to_duplicate_one_block(var_histories: list[MopHistory]) -> tuple[int, int]:
    nb_duplication = 0
    nb_change = 0
    if (len(var_histories) == 0) or (len(var_histories[0].block_path) == 0):
        return nb_duplication, nb_change
    mba = var_histories[0].block_path[0].mba
    block_to_duplicate, pred_dict = get_block_with_multiple_predecessors(var_histories)
    if block_to_duplicate is None or pred_dict is None:
        return nb_duplication, nb_change
    logger.debug(
        "Block to duplicate found: {0} with {1} successors".format(
            block_to_duplicate.serial, block_to_duplicate.nsucc()
        )
    )
    i = 0
    for pred_serial, pred_history_group in pred_dict.items():
        # We do not duplicate first group
        if i >= 1:
            logger.debug(
                "  Before {0}: {1}".format(
                    pred_serial,
                    [
                        var_history.block_serial_path
                        for var_history in pred_history_group
                    ],
                )
            )
            pred_block = mba.get_mblock(pred_serial)
            duplicated_blk_jmp, duplicated_blk_default = duplicate_block(
                block_to_duplicate
            )
            nb_duplication += 1 if duplicated_blk_jmp is not None else 0
            nb_duplication += 1 if duplicated_blk_default is not None else 0
            logger.debug(
                "  Making {0} goto {1}".format(
                    pred_block.serial, duplicated_blk_jmp.serial
                )
            )
            if (pred_block.tail is None) or (
                not ida_hexrays.is_mcode_jcond(pred_block.tail.opcode)
            ):
                change_1way_block_successor(pred_block, duplicated_blk_jmp.serial)
                nb_change += 1
            else:
                if block_to_duplicate.serial == pred_block.tail.d.b:
                    change_2way_block_conditional_successor(
                        pred_block, duplicated_blk_jmp.serial
                    )
                    nb_change += 1
                else:
                    logger.warning(" not sure this is suppose to happen")
                    change_1way_block_successor(
                        pred_block.mba.get_mblock(pred_block.serial + 1),
                        duplicated_blk_jmp.serial,
                    )
                    nb_change += 1

            block_to_duplicate_default_successor = mba.get_mblock(
                block_to_duplicate.serial + 1
            )
            logger.debug("  Now, we fix var histories...")
            for var_history in pred_history_group:
                var_history.replace_block_in_path(
                    block_to_duplicate, duplicated_blk_jmp
                )
                if block_to_duplicate.tail is not None and ida_hexrays.is_mcode_jcond(
                    block_to_duplicate.tail.opcode
                ):
                    index_jump_block = get_blk_index(
                        duplicated_blk_jmp, var_history.block_path
                    )
                    if index_jump_block + 1 < len(var_history.block_path):
                        original_jump_block_successor = var_history.block_path[
                            index_jump_block + 1
                        ]
                        if (
                            original_jump_block_successor.serial
                            == block_to_duplicate_default_successor.serial
                        ):
                            var_history.insert_block_in_path(
                                duplicated_blk_default, index_jump_block + 1
                            )
        i += 1
        logger.debug(
            "  After {0}: {1}".format(
                pred_serial,
                [var_history.block_serial_path for var_history in pred_history_group],
            )
        )
    for i, var_history in enumerate(var_histories):
        logger.debug(
            " internal_pass_end.{0}: {1}".format(i, var_history.block_serial_path)
        )
    return nb_duplication, nb_change


def duplicate_histories(
    var_histories: list[MopHistory], max_nb_pass: int = 10
) -> tuple[int, int]:
    cur_pass = 0
    total_nb_duplication = 0
    total_nb_change = 0
    logger.info("Trying to fix new var_history...")
    for i, var_history in enumerate(var_histories):
        logger.info(" start.{0}: {1}".format(i, var_history.block_serial_path))
    while cur_pass < max_nb_pass:
        logger.debug("Current path {0}".format(cur_pass))
        nb_duplication, nb_change = try_to_duplicate_one_block(var_histories)
        if nb_change == 0 and nb_duplication == 0:
            break
        total_nb_duplication += nb_duplication
        total_nb_change += nb_change
        cur_pass += 1
    for i, var_history in enumerate(var_histories):
        logger.info(" end.{0}: {1}".format(i, var_history.block_serial_path))
    return total_nb_duplication, total_nb_change


def get_segment_register_indexes(mop_list: list[ida_hexrays.mop_t]) -> list[int]:
    # This is a very dirty and probably buggy
    segment_register_indexes = []
    for i, mop in enumerate(mop_list):
        if mop.t == ida_hexrays.mop_r:
            formatted_mop = format_mop_t(mop)
            if formatted_mop in ["ds.2", "cs.2", "es.2", "ss.2"]:
                segment_register_indexes.append(i)
    return segment_register_indexes


def remove_segment_registers(mop_list: list[ida_hexrays.mop_t]) -> list[ida_hexrays.mop_t]:
    # TODO: instead of doing that, we should add the segment registers to the (global?) emulation environment
    segment_register_indexes = get_segment_register_indexes(mop_list)
    if len(segment_register_indexes) == 0:
        return mop_list
    new_mop_list = []
    for i, mop in enumerate(mop_list):
        if i in segment_register_indexes:
            pass
        else:
            new_mop_list.append(mop)
    return new_mop_list
