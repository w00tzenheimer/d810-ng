"""Print native conditional-state choices and their dispatcher bindings."""
from __future__ import annotations

import os

import idapro


def main() -> int:
    binary = os.environ["RHAD_CHOICE_BIN"]
    function_ea = int(os.environ.get("RHAD_CHOICE_FUNC", "0x40D200"), 0)
    idapro.open_database(binary, True)
    try:
        from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
            _static_branch_state_choices,
            _static_prepatch_union_source_transfers,
            _static_register_state_before_jmp,
            _static_resolver_fixpoint,
            resolve_computed_gotos_static,
        )

        resolution = resolve_computed_gotos_static(function_ea)
        print("resolution", resolution is not None)
        if resolution is None:
            return 1
        print("choices", len(resolution.conditional_state_choices))
        for choice in resolution.conditional_state_choices:
            print(
                "CHOICE",
                hex(choice.source_block_ea),
                [hex(ea) for ea in choice.materialized_anchor_eas],
                choice.condition_code,
                choice.predicate_register,
                hex(choice.predicate_compare_constant or 0),
                hex(choice.predicate_true_state or 0),
                hex(choice.predicate_false_state or 0),
            )
        for transfer in _static_prepatch_union_source_transfers(resolution):
            if transfer.resolver_kind != "static_conditional_state_choice_bridge":
                continue
            print(
                "BRIDGE",
                hex(transfer.source_block_ea),
                hex(transfer.source_jmp_ea),
                [hex(ea) for ea in transfer.target_eas],
                hex(transfer.predicate_true_state or 0),
                hex(transfer.predicate_false_state or 0),
            )
        debug_range = os.environ.get("RHAD_CHOICE_DEBUG_RANGE")
        if debug_range:
            start_text, end_text = debug_range.split(":", 1)
            start_ea = int(start_text, 0)
            end_ea = int(end_text, 0)
            entry_state, resolved, unresolved, block_entry_of, _steps = (
                _static_resolver_fixpoint(function_ea)
            )
            print("DEBUG_ENTRIES")
            for entry_ea, state in sorted(entry_state.items()):
                if start_ea <= int(entry_ea) < end_ea:
                    print(
                        hex(int(entry_ea)),
                        {
                            name: (
                                None
                                if values is None
                                else [hex(int(value)) for value in sorted(values)]
                            )
                            for name, values in sorted(state.items())
                        },
                    )
            print(
                "DEBUG_FRONTIERS",
                {
                    hex(int(jmp_ea)): {
                        "entry": hex(int(block_entry_of[jmp_ea])),
                        "targets": [hex(int(target)) for target in targets],
                    }
                    for jmp_ea, targets in sorted(resolved.items())
                    if start_ea <= int(jmp_ea) < end_ea
                },
            )
            print(
                "DEBUG_UNRESOLVED",
                {
                    hex(int(jmp_ea)): reason
                    for jmp_ea, reason in sorted(unresolved.items())
                    if start_ea <= int(jmp_ea) < end_ea
                },
            )
            print(
                "DEBUG_BRANCH_CHOICES",
                [
                    {
                        "source": hex(int(choice.source_block_ea)),
                        "predicate": hex(int(choice.source_jmp_ea)),
                        "state_reg": choice.selector_state_var_reg,
                        "taken": hex(int(choice.predicate_true_state or 0)),
                        "fallthrough": hex(
                            int(choice.predicate_false_state or 0)
                        ),
                    }
                    for choice in _static_branch_state_choices(
                        entry_state,
                    )
                ],
            )
            debug_branch = os.environ.get("RHAD_CHOICE_DEBUG_BRANCH")
            if debug_branch:
                source_text, predicate_text, taken_text, fallthrough_text = (
                    debug_branch.split(":", 3)
                )
                source_ea = int(source_text, 0)
                predicate_ea = int(predicate_text, 0)
                source_state = _static_register_state_before_jmp(
                    source_ea,
                    entry_state.get(source_ea, {}),
                    predicate_ea,
                )
                print(
                    "DEBUG_BRANCH_SOURCE_STATE",
                    {
                        name: (
                            None
                            if values is None
                            else [hex(int(value)) for value in sorted(values)]
                        )
                        for name, values in sorted(source_state.items())
                    },
                )
                initial_values = tuple(
                    sorted(
                        (name, next(iter(values)))
                        for name, values in source_state.items()
                        if values is not None and len(values) == 1
                    )
                )
                for arm_name, arm_ea in (
                    ("taken", int(taken_text, 0)),
                    ("fallthrough", int(fallthrough_text, 0)),
                ):
                    arm_fixpoint = _static_resolver_fixpoint(
                        arm_ea,
                        initial_register_values=initial_values,
                        follow_indirect_targets=False,
                    )
                    print(
                        "DEBUG_BRANCH_ARM",
                        arm_name,
                        hex(arm_ea),
                        {
                            "resolved": {
                                hex(int(jmp_ea)): [
                                    hex(int(target)) for target in targets
                                ]
                                for jmp_ea, targets in sorted(
                                    arm_fixpoint[1].items()
                                )
                            },
                            "unresolved": {
                                hex(int(jmp_ea)): reason
                                for jmp_ea, reason in sorted(
                                    arm_fixpoint[2].items()
                                )
                            },
                            "block_entry_of": {
                                hex(int(jmp_ea)): hex(int(block_ea))
                                for jmp_ea, block_ea in sorted(
                                    arm_fixpoint[3].items()
                                )
                            },
                        },
                    )
        return 0
    finally:
        idapro.close_database(False)


if __name__ == "__main__":
    raise SystemExit(main())
