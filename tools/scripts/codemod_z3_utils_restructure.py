#!/usr/bin/env python3
"Rewrite z3_utils imports to new module locations.\n\nThis codemod was superseded by manual edits due to the complexity of\nrewriting free-function calls to instance-method calls on Z3MopProver.\n\nPreserved for reference. The actual migration was done manually in:\n  refactor: update all consumers to use Z3MopProver\n\nImport mapping:\n  z3_check_mop_equality    -> Z3MopProver().are_equal\n  z3_check_mop_inequality  -> Z3MopProver().are_unequal\n  z3_check_always_zero     -> Z3MopProver(blk=..., ins=...).is_always_zero\n  z3_check_always_nonzero  -> Z3MopProver(blk=..., ins=...).is_always_nonzero\n  clear_z3_caches          -> Z3MopProver().clear_caches\n  log_z3_instructions      -> format_z3_equivalence_script\n  _find_def_in_block       -> find_def_in_block (from preanalysis.flow.def_search)\n  _resolve_mop_via_predecessors -> resolve_mop_via_predecessors\n  _recursively_resolve_ast -> recursively_resolve_ast\n"
from __future__ import annotations


def main() -> int:
    print("This codemod was superseded by manual edits.")
    print("See git log for the actual migration commit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
