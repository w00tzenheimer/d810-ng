"""Native Egglog regression for the MASM-extracted Hodur MBA residual."""

from __future__ import annotations

import os

import ida_entry
import ida_funcs
import idaapi
import idc
import pytest

from d810.optimizers.microcode.instructions.egraph.egglog_handler import (
    EgglogOptimizer,
)


_PROBE_BINARY = "/work/.tmp/disposable-mmorpg-mba-probe/mmorpg_mba_probe.dll"
_FUNCTION_NAME = "sub_7FF85A13D930"


def _function_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea != idaapi.BADADDR:
        return ea
    for index in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(index)
        if ida_entry.get_entry_name(ordinal) == name:
            ea = ida_entry.get_entry(ordinal)
            ida_funcs.add_func(ea)
            assert ida_funcs.get_func(ea) is not None
            return ea
    return idaapi.BADADDR


@pytest.mark.usefixtures("configure_hexrays", "setup_libobfuscated_funcs")
class TestHodurEgglogWithoutFcp:
    binary_name = os.environ.get("D810_TEST_BINARY", _PROBE_BINARY)

    def test_interactive_egglog_reduces_the_real_mba_residual_after_fcp_is_removed(
        self, ida_database, d810_state, pseudocode_to_string, monkeypatch
    ) -> None:
        """The real residual mutates only through the certified native-Z3 path."""
        ea = _function_ea(_FUNCTION_NAME)
        assert ea != idaapi.BADADDR

        with d810_state() as state:
            with state.for_project(
                "hodur_flag2_s1a_config_v2_canary_constant_simplification.json"
            ) as context:
                context.remove_rule("ForwardConstantPropagationRule")
                context.add_rule(EgglogOptimizer)
                egglog = next(
                    rule
                    for rule in state.current_ins_rules
                    if isinstance(rule, EgglogOptimizer)
                )
                egglog.configure(
                    {
                        "families": [
                            "add",
                            "and",
                            "bnot",
                            "mul",
                            "neg",
                            "or",
                            "sub",
                            "xor",
                        ],
                        "maturities": ["GLOBAL_ANALYZED", "GLOBAL_OPTIMIZED"],
                        "max_leaves": 2,
                        "max_operator_nodes": 24,
                        "max_degree": 2,
                        "saturation_rounds": 2,
                        "max_eclasses": 64,
                        "max_enodes": 128,
                        "max_rule_firings": 32,
                        "cross_block_constant_preparation": False,
                        "cross_block_def_use_preparation": False,
                        "time_budget_ms": 1000,
                        "require_proof": True,
                    }
                )
                state.start_d810()
                # The Hodur config-v2 pipeline deliberately does not schedule
                # Egglog. This test isolates the interactive experiment by
                # making the already-configured rule eligible without changing
                # the checked-in production profile. The run-later scheduler
                # clears its own temporary allow-list on every maturity, so
                # wrap the scope resolver rather than faking a scheduler event.
                optimizer = state.manager.instruction_optimizer
                resolve_allowed = optimizer._resolve_active_instruction_rule_names
                optimizer._resolve_active_instruction_rule_names = lambda blk: (
                    resolve_allowed(blk) | frozenset({egglog.name})
                )
                accepted_receipts = []
                accept_mutation = egglog.record_mutation_accepted

                def record_accepted_mutation() -> None:
                    accepted_receipts.append(
                        (
                            egglog.last_rule_provenance,
                            egglog.last_extraction_receipt,
                        )
                    )
                    accept_mutation()

                monkeypatch.setattr(
                    egglog, "record_mutation_accepted", record_accepted_mutation
                )
                try:
                    cfunc = idaapi.decompile(ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    text = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    state.stop_d810()

        assert text
        assert any(
            provenance == ("Sub_ComplementMaskHodurRule_1",)
            and receipt is not None
            and receipt.skip_reason is None
            and receipt.input_cost == (21, 39)
            and receipt.extracted_cost == (1, 3)
            for provenance, receipt in accepted_receipts
        )
