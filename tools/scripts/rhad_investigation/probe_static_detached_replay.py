"""Run the static computed-goto fixpoint from one native entry with seed regs."""

from __future__ import annotations

import argparse
from pathlib import Path

import idapro


parser = argparse.ArgumentParser()
parser.add_argument("binary", type=Path)
parser.add_argument("entry", type=lambda value: int(value, 0))
parser.add_argument(
    "register",
    nargs="*",
    help="resolver-native register assignment, for example ebx=0x1234",
)
args = parser.parse_args()
registers = tuple(
    (name.strip().lower(), int(value, 0))
    for item in args.register
    for name, value in (item.split("=", 1),)
)

assert idapro.open_database(str(args.binary.resolve()), True) == 0
try:
    import idaapi

    from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
        _static_resolver_fixpoint,
    )

    idaapi.auto_wait()
    entry_state, resolved, unresolved, block_entry_of, steps = (
        _static_resolver_fixpoint(
            int(args.entry),
            initial_register_values=registers,
            follow_indirect_targets=False,
        )
    )
    print("steps", steps)
    print(
        "resolved",
        {
            hex(int(source)): [hex(int(target)) for target in targets]
            for source, targets in sorted(resolved.items())
        },
    )
    print("unresolved", {hex(int(ea)): reason for ea, reason in unresolved.items()})
    print(
        "block_entry_of",
        {hex(int(ea)): hex(int(entry)) for ea, entry in block_entry_of.items()},
    )
    print(
        "entry_state",
        {
            hex(int(ea)): {
                name: None if values is None else [hex(int(value)) for value in values]
                for name, values in state.items()
            }
            for ea, state in sorted(entry_state.items())
        },
    )
finally:
    idapro.close_database(False)
