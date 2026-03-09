try:
    from d810.evaluator.hexrays_microcode.tracker import (
        BlockInfo,
        InstructionDefUseCollector,
        MopHistory,
        MopTracker,
        duplicate_histories,
        remove_segment_registers,
    )
    from d810.evaluator.hexrays_microcode.emulator import (
        MicroCodeEnvironment,
        MicroCodeInterpreter,
        SyntheticCallReturnCache
    )
except ImportError:
    # IDA-dependent modules are unavailable (e.g. unit-test environment).
    pass

from d810.evaluator.hexrays_microcode.forward_dataflow import (
    FixpointResult,
    run_forward_fixpoint,
    run_forward_fixpoint_on_mba,
    transfer_block_insnwise,
    # Reaching-definitions domain
    DefSite,
    ReachingDefEnv,
    ReachingDefValue,
    VarKey,
    build_reaching_defs_entry_state,
    get_written_var_key,
    reaching_defs_meet,
    reaching_defs_transfer_block,
    reaching_defs_transfer_single,
    # Constant-propagation domain
    ConstMap,
    build_constant_entry_state,
    collect_universe,
    constant_transfer_block,
    constant_transfer_single,
)
from d810.evaluator.hexrays_microcode.chains import (
    DefSite as ChainDefSite,
    UseSite,
    collect_pred_defs_for_block,
    ensure_graph_and_lists_ready,
    find_all_uses_of_stkvar,
    find_reaching_defs_for_reg,
    find_reaching_defs_for_stkvar,
    get_ud_du_chains,
    is_passthru_chain,
    is_phi_like_merge,
)
from d810.evaluator.hexrays_microcode.valranges import (
    ValrangeLocation,
    ValrangeLocationKind,
    ValrangeRecord,
    collect_block_valrange_record_for_location,
    collect_block_valrange_records,
    collect_block_valranges,
    collect_instruction_valrange_record_for_location,
    collect_instruction_valrange_records,
    collect_instruction_valranges,
    collect_mba_valrange_records,
    collect_mba_valranges,
)
from d810.evaluator.hexrays_microcode.terminal_return_valranges import (
    TerminalReturnValrangeGroup,
    TerminalReturnValrangeReport,
    TerminalValrangeMergeKind,
    TerminalValrangeSnapshot,
    build_terminal_return_valrange_report,
    build_terminal_return_valrange_report_from_mba,
)

try:
    from d810.evaluator.hexrays_microcode.liveness import (
        ensure_lists_ready,
        get_dead_at_start,
        get_defined_not_used,
        get_may_def,
        get_may_use,
        get_must_def,
        get_must_use,
        is_dead_at_entry,
        is_defined_not_used,
        is_var_live_at_block_entry,
        is_var_live_at_block_exit,
    )
except ImportError:
    pass

try:
    from d810.evaluator.hexrays_microcode.def_search import (
        operand_to_mlist,
        instruction_uses,
        instruction_defs,
    )
except ImportError:
    pass

__all__ = [
    "BlockInfo",
    "InstructionDefUseCollector",
    "MopHistory",
    "MopTracker",
    "duplicate_histories",
    "remove_segment_registers",
    "MicroCodeEnvironment",
    "MicroCodeInterpreter",
    "SyntheticCallReturnCache",
    "FixpointResult",
    "run_forward_fixpoint",
    "run_forward_fixpoint_on_mba",
    "transfer_block_insnwise",
    # Reaching-definitions domain
    "DefSite",
    "ReachingDefEnv",
    "ReachingDefValue",
    "VarKey",
    "build_reaching_defs_entry_state",
    "get_written_var_key",
    "reaching_defs_meet",
    "reaching_defs_transfer_block",
    "reaching_defs_transfer_single",
    # Constant-propagation domain
    "ConstMap",
    "build_constant_entry_state",
    "collect_universe",
    "constant_transfer_block",
    "constant_transfer_single",
    # Chains
    "ChainDefSite",
    "UseSite",
    "collect_pred_defs_for_block",
    "ensure_graph_and_lists_ready",
    "find_all_uses_of_stkvar",
    "find_reaching_defs_for_reg",
    "find_reaching_defs_for_stkvar",
    "get_ud_du_chains",
    "is_passthru_chain",
    "is_phi_like_merge",
    # Valranges
    "ValrangeLocation",
    "ValrangeLocationKind",
    "ValrangeRecord",
    "collect_block_valrange_record_for_location",
    "collect_block_valrange_records",
    "collect_block_valranges",
    "collect_instruction_valrange_record_for_location",
    "collect_instruction_valrange_records",
    "collect_instruction_valranges",
    "collect_mba_valrange_records",
    "collect_mba_valranges",
    # Terminal return valranges
    "TerminalValrangeMergeKind",
    "TerminalValrangeSnapshot",
    "TerminalReturnValrangeGroup",
    "TerminalReturnValrangeReport",
    "build_terminal_return_valrange_report",
    "build_terminal_return_valrange_report_from_mba",
    # Liveness
    "ensure_lists_ready",
    "get_dead_at_start",
    "get_defined_not_used",
    "get_may_def",
    "get_may_use",
    "get_must_def",
    "get_must_use",
    "is_dead_at_entry",
    "is_defined_not_used",
    "is_var_live_at_block_entry",
    "is_var_live_at_block_exit",
    # Def-search helpers
    "operand_to_mlist",
    "instruction_uses",
    "instruction_defs",
]
