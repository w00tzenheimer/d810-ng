#!/usr/bin/env python3
"""Rewrite z3_utils imports to new module locations.

This codemod was superseded by manual edits due to the complexity of
rewriting free-function calls to instance-method calls on Z3MopProver.

Preserved for reference. The actual migration was done manually in:
  refactor: update all consumers to use Z3MopProver

Import mapping:
  z3_check_mop_equality    -> Z3MopProver().are_equal
  z3_check_mop_inequality  -> Z3MopProver().are_unequal
  z3_check_always_zero     -> Z3MopProver(blk=..., ins=...).is_always_zero
  z3_check_always_nonzero  -> Z3MopProver(blk=..., ins=...).is_always_nonzero
  clear_z3_caches          -> Z3MopProver().clear_caches
  log_z3_instructions      -> format_z3_equivalence_script
  _find_def_in_block       -> find_def_in_block (from recon.flow.def_search)
  _resolve_mop_via_predecessors -> resolve_mop_via_predecessors
  _recursively_resolve_ast -> recursively_resolve_ast
"""
from __future__ import annotations


def main() -> int:
    print("This codemod was superseded by manual edits.")
    print("See git log for the actual migration commit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
