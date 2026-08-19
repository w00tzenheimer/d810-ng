"""IDA acceptance coverage for the constant-simplification stage contract.

The fixture is deliberately small, but the assertions are not eligibility
checks. Every case must have a real PE export, a semantic pseudocode result,
and the typed schedule/receipt evidence that explains that result.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest
import idaapi
import ida_hexrays
import idc
from d810.core.typing import Any


ROOT = Path(__file__).parents[3]
MASM_SOURCE = ROOT / "samples" / "src" / "masm" / "constant_stage_controls.asm"
CANARY = ROOT / "src" / "d810" / "conf" / "constant_stage_controls_config_v2_canary.json"

FIXTURE_FUNCTIONS = (
    "const_prepare_without_fold",
    "readonly_fold_without_prepare",
    "readonly_then_subtree",
    "forward_selected_maturity",
    "bounded_table_next_round",
    "bounded_setz",
    "bounded_setnz",
    "bounded_lnot",
)

_STAGE_IDS = (
    "fold-readonly-data",
    "fold-constant-subtree",
    "forward-constants",
)
_EXPECTED_SUPPORTED = {
    "fold-readonly-data": (
        "CANONICAL", "LOCAL_OPTIMIZED", "CALL_MODELED", "GLOBAL_ANALYZED", "STRUCTURED"
    ),
    "fold-constant-subtree": (
        "LOCAL_OPTIMIZED", "CALL_MODELED", "GLOBAL_ANALYZED", "GLOBAL_OPTIMIZED", "STRUCTURED"
    ),
    "forward-constants": (
        "CALL_MODELED", "GLOBAL_ANALYZED", "GLOBAL_OPTIMIZED", "STRUCTURED"
    ),
}
_RULE_FOR_STAGE = {
    "fold-readonly-data": "FoldReadonlyDataRule",
    "fold-constant-subtree": "ConstantSubtreeFoldRule",
    "forward-constants": "ForwardConstantPropagationRule",
}


def _source_text() -> str:
    return MASM_SOURCE.read_text(encoding="utf-8")


def _fixture_ea(name: str, idc: Any, idaapi: Any) -> int:
    for candidate in (name, f"_{name}"):
        ea = int(idc.get_name_ea_simple(candidate))
        if ea != int(idaapi.BADADDR):
            return ea
    pytest.fail(f"constant-stage fixture export is absent: {name}")


def _load_canary(state):
    index = next(
        index
        for index, project in enumerate(state.project_manager.projects())
        if Path(project.path).name == CANARY.name
    )
    state.load_project(index)
    assert state.current_runtime_project is not None
    return state.current_runtime_project


def _pipeline_entry(project, pass_id: str) -> dict[str, object]:
    return next(
        entry
        for entry in project.additional_configuration["pipeline_v2"]
        if entry["pass_id"] == pass_id
    )


def _constant_pass(project) -> dict[str, object]:
    return _pipeline_entry(project, "constant-simplification")


def _mba_pass(project) -> dict[str, object]:
    return _pipeline_entry(project, "mba-simplify")


def _activate_runtime_project(state, project) -> None:
    # Project activation mutates the manager's rule worklists.  Replacing
    # those lists while the native hooks are live can leave the already-built
    # instruction optimizer with the previous project's rule set.  Always
    # perform the replacement while stopped; callers start the manager after
    # this helper returns.
    if state.manager.started:
        state.stop_d810()
    state._activate_runtime_project(
        project_index=state.current_project_index,
        source_project=state.current_project,
        runtime_project=project,
        default_selection=state.last_config_v2_default_selection,
    )


def _live_instruction_rule_names(state) -> tuple[str, ...]:
    rules = getattr(state.manager, "instruction_optimizer_rules", ())
    return tuple(
        str(getattr(rule, "name", rule.__class__.__name__))
        for rule in rules
    )


def _decompile(state, ea: int, idaapi, *, eager: bool = False):
    manager = state.manager
    controlled = getattr(manager, "decompile_with_native_preanalysis", None)
    assert callable(controlled), "managed native-preanalysis entry point is required"
    # This is deliberately the only normal E2E entry point.  The manager owns
    # preparation, CALLS observation, and any bounded natural retry; calling
    # Hex-Rays first would bypass the lifecycle contract under test.
    result = controlled(
        ea,
        lambda: idaapi.decompile(ea, flags=idaapi.DECOMP_NO_CACHE),
        ida_hexrays.clear_cached_cfuncs,
        eager_native_preanalysis=eager,
    )
    assert result is not None, f"decompilation failed at 0x{ea:X}"
    return result


def _render(result, pseudocode_to_string) -> str:
    return pseudocode_to_string(result.get_pseudocode())


def _entries(state, *names: str, start: int = 0):
    wanted = set(names)
    return [
        entry
        for entry in state.stats.rule_execution_log[start:]
        if entry.rule_name in wanted and entry.match_count > 0
    ]


def _assert_rule_receipt(entry) -> None:
    assert type(entry).__name__ == "RuleExecution"
    assert entry.rule_name
    assert entry.match_count > 0
    assert isinstance(entry.metadata, dict)
    actual_maturity = entry.metadata.get("maturity")
    assert actual_maturity is not None, entry
    configured_maturities = tuple(getattr(entry.rule, "maturities", ()))
    assert configured_maturities, entry
    assert actual_maturity in configured_maturities, entry


def _contains_value(rendered: str, value: int) -> bool:
    """Accept Hex-Rays' decimal or hexadecimal spelling of a value."""

    return str(int(value)) in rendered or f"0x{int(value):X}".upper() in rendered.upper()


def _return_literal(rendered: str) -> bool | None:
    """Return the semantic boolean literal, if pseudocode reduced to one."""

    match = re.search(r"\breturn\s+(true|false|1|0)\s*;", rendered, re.IGNORECASE)
    if match is None:
        return None
    return match.group(1).lower() in {"true", "1"}


def _run_entries(state, start: int, *names: str):
    """Return accepted mutation receipts from one controlled decompile."""

    return _entries(state, *names, start=start)


def _cfg_patch_receipts(state, rule_name: str, before: int = 0) -> tuple[int, ...]:
    """Return positive CFG mutation counts appended after ``before``."""

    return tuple(
        int(count)
        for count in state.stats.cfg_rule_usages.get(rule_name, ())[before:]
        if int(count) > 0
    )


def _database_identity(state) -> str:
    preparation = state.manager.pre_hex_preparation
    assert preparation is not None
    return preparation.database_identity


def _pending_proposals(state):
    from d810.backends.hexrays.global_const_annotation import (
        pending_global_const_proposals,
    )

    return pending_global_const_proposals(database_identity=_database_identity(state))


def _journal_deltas(state, transaction_id):
    journal = state.manager._idb_preparation_journal
    assert journal is not None
    return journal.type_deltas(transaction_id)


def _type_snapshot(function_ea: int):
    from d810.backends.hexrays.global_const_annotation import referenced_global_items

    return tuple(
        (item.evidence.item_head, _capture_type(item.evidence.item_head))
        for item in referenced_global_items(function_ea)
    )


def _capture_type(item_ea: int):
    from d810.capabilities.idb_preparation import SerializedTypeSnapshot
    from d810.backends.ida.type_serialization import capture_serialized_tinfo

    parts = capture_serialized_tinfo(int(item_ea))
    if parts is None:
        return SerializedTypeSnapshot.absent()
    return SerializedTypeSnapshot.from_parts(
        parts.type_bytes,
        parts.field_bytes,
        parts.field_comment_bytes,
    )


def _apply_nonconst_qword_array(item_ea: int, count: int):
    """Install the fixture's exact non-const table baseline in the disposable IDB."""

    import ida_typeinf

    element = ida_typeinf.tinfo_t()
    assert element.create_simple_type(ida_typeinf.BTF_UINT64)
    table = ida_typeinf.tinfo_t()
    assert table.create_array(element, int(count), 0)
    assert ida_typeinf.apply_tinfo(item_ea, table, ida_typeinf.TINFO_DEFINITE)
    return _capture_type(item_ea)


def _apply_const_qword(item_ea: int):
    """Give the readonly pointer its deterministic fixture baseline type."""

    import ida_typeinf

    qword = ida_typeinf.tinfo_t()
    assert qword.create_simple_type(ida_typeinf.BTF_UINT64)
    qword.set_const()
    assert ida_typeinf.apply_tinfo(item_ea, qword, ida_typeinf.TINFO_DEFINITE)
    return _capture_type(item_ea)


def _apply_bool_predicate_prototype(function_ea: int, function_name: str) -> str:
    """Make the setcc carrier a one-byte bool in the disposable IDB.

    The MASM bytes are intentionally ordinary x64 ``setcc`` plus a stack
    carrier.  Without a function prototype, Hex-Rays widens the returned byte
    through an ``xdu`` node and hides the setcc root inside that expression;
    the optimizer cannot legitimately claim a live generic predicate receipt.
    Applying the exact prototype in ``copy_of_idb`` is therefore fixture setup,
    not a production or canonical-database mutation.
    """

    import ida_nalt
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    declaration = f"bool __fastcall {function_name}(unsigned int a1);"
    assert ida_typeinf.parse_decl(tif, None, declaration, ida_typeinf.PT_SIL), declaration
    assert ida_typeinf.apply_tinfo(function_ea, tif, ida_typeinf.TINFO_DEFINITE), declaration
    observed = ida_typeinf.tinfo_t()
    assert ida_nalt.get_tinfo(observed, function_ea)
    rendered = str(observed)
    assert "bool" in rendered.lower(), rendered
    return rendered


def _event_for(events, transform_id: str, function_ea: int):
    matching = [
        event
        for event in events
        if event.transform_id == transform_id and int(event.func_ea) == int(function_ea)
    ]
    assert matching, f"no typed Z3 receipt for {transform_id}"
    return matching


def _replace_transform_policy(project, transform_id: str, **values: int) -> None:
    options = _mba_pass(project)["options"]
    transform_options = options.setdefault("transform_options", {})
    transform_options[transform_id] = {
        **transform_options.get(transform_id, {}),
        **values,
    }


def _set_constant_stages(
    project, *, preparation: bool, readonly: bool, subtree: bool, forward: bool
) -> None:
    options = _constant_pass(project)["options"]
    options["preparation"]["global_const_types"]["enabled"] = preparation
    stages = options["stages"]
    stages["fold-readonly-data"]["enabled"] = readonly
    stages["fold-constant-subtree"]["enabled"] = subtree
    stages["forward-constants"]["enabled"] = forward


def _assert_fixture_semantics() -> None:
    """Pure oracle for constants used by the MASM manifest and registry."""

    mask32 = 0xFFFFFFFF
    readonly = 0x13579BDF
    rotated = ((readonly << 13) | (readonly >> (32 - 13))) & mask32
    assert rotated == 0xF37BE26A

    forward = 0x01234567
    assert (forward + forward) & mask32 == 0x02468ACE

    mask = 0x55AA55AA
    for value in (0, 1, mask32, 0x89ABCDEF):
        identity = ((value ^ mask) + 2 * (value & mask) - value - mask) & mask32
        assert identity == 0
        square_mod_four = ((value * value) & mask32) & 3
        assert (square_mod_four ^ 2) != 0


class TestConstantStageControls:
    binary_name = "libobfuscated.dll"

    def test_fixture_manifest_and_semantic_oracle(self, copy_of_idb):
        _assert_fixture_semantics()
        source = _source_text()
        assert CANARY.is_file(), CANARY
        assert "PUBLIC constant_stage_controls" in source
        document = json.loads(CANARY.read_text(encoding="utf-8"))
        pipeline = document["additional_configuration"]["pipeline_v2"]
        constant = next(item for item in pipeline if item["pass_id"] == "constant-simplification")
        options = constant["options"]
        assert set(options) == {"preparation", "stages"}
        assert set(options["stages"]) == set(_STAGE_IDS)
        for function in FIXTURE_FUNCTIONS:
            assert f"PUBLIC {function}" in source
            assert f"{function}:" in source
            _fixture_ea(function, idc, idaapi)

    def test_compiled_schedule_and_callback_order(
        self, copy_of_idb, d810_state, pseudocode_to_string
    ) -> None:
        from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation

        with d810_state() as state:
            project = _load_canary(state)
            activation = pipeline_v2_hook_activation(project)
            schedule = activation.constant_simplification_schedule
            assert schedule is not None
            by_id = {stage.stage_id: stage for stage in schedule.stages}
            assert tuple(by_id) == _STAGE_IDS
            for stage_id in _STAGE_IDS:
                stage = by_id[stage_id]
                assert tuple(item.name for item in stage.supported_maturities) == _EXPECTED_SUPPORTED[stage_id]
                assert stage.requested_maturities == stage.supported_maturities
                assert stage.pass_maturity_gates == ()
                assert stage.effective_maturities == stage.requested_maturities
            assert [rule.name for rule in activation.instruction_rules[:2]] == [
                "FoldReadonlyDataRule", "ConstantSubtreeFoldRule"
            ]
            assert [rule.name for rule in activation.block_rules[:1]] == [
                "ForwardConstantPropagationRule"
            ]
            assert all(
                "maturities" in rule.config
                for rule in (*activation.instruction_rules[:2], *activation.block_rules[:1])
            )

            original = copy.deepcopy(_constant_pass(project)["options"])
            try:
                for stage in _constant_pass(project)["options"]["stages"].values():
                    stage["enabled"] = False
                disabled = pipeline_v2_hook_activation(project)
                assert all(not stage.enabled for stage in disabled.constant_simplification_schedule.stages)
                assert not {
                    rule.name for rule in (*disabled.instruction_rules, *disabled.block_rules)
                }.intersection(_RULE_FOR_STAGE.values())
                _activate_runtime_project(state, project)
                state.stop_d810()
                state.start_d810()
                ea = _fixture_ea("readonly_fold_without_prepare", idc, idaapi)
                before_log = len(state.stats.rule_execution_log)
                rendered = _render(_decompile(state, ea, idaapi), pseudocode_to_string)
                assert not _contains_value(rendered, 0x13579BDF), rendered
                assert "dword_" in rendered, rendered
                assert not _run_entries(
                    state,
                    before_log,
                    "FoldReadonlyDataRule",
                    "ConstantSubtreeFoldRule",
                    "ForwardConstantPropagationRule",
                )
            finally:
                _constant_pass(project)["options"] = original

    def test_preparation_without_readonly_fold_is_reversible(
        self, copy_of_idb, d810_state, pseudocode_to_string
    ) -> None:
        from d810.capabilities.idb_preparation import PreparationState

        with d810_state() as state:
            project = _load_canary(state)
            _set_constant_stages(project, preparation=True, readonly=False, subtree=False, forward=False)
            _activate_runtime_project(state, project)
            state.start_d810()
            ea = _fixture_ea("const_prepare_without_fold", idc, idaapi)
            before_types = _type_snapshot(ea)
            before_log = len(state.stats.rule_execution_log)
            rendered = _render(_decompile(state, ea, idaapi), pseudocode_to_string)
            assert _contains_value(rendered, 0x12345678), rendered
            assert not _run_entries(state, before_log, "FoldReadonlyDataRule")
            assert state.manager.preparation_status().applied
            before_by_item = dict(before_types)
            records = state.manager.pre_hex_preparation._prepared_records(
                _database_identity(state)
            )
            prepared = [
                record
                for record in records
                if record.state is PreparationState.IDB_PREPARED
                and int(record.anchor_function_ea) == ea
            ]
            assert len(prepared) == 1, records
            transaction = prepared[0]
            deltas = _journal_deltas(state, transaction.transaction_id)
            assert deltas
            for delta in deltas:
                assert before_by_item[delta.item_ea] == delta.before
                assert delta.before != delta.after
                assert _capture_type(delta.item_ea) == delta.after
            restored = state.manager.restore_idb_preparation(transaction.transaction_id)
            assert restored.ok, restored
            assert state.manager.preparation_status().restored
            assert _type_snapshot(ea) == before_types
            for delta in deltas:
                assert _capture_type(delta.item_ea) == delta.before

    def test_readonly_folds_without_preparation(
        self, copy_of_idb, d810_state, pseudocode_to_string
    ) -> None:
        with d810_state() as state:
            project = _load_canary(state)
            _set_constant_stages(project, preparation=False, readonly=True, subtree=False, forward=False)
            _activate_runtime_project(state, project)
            state.start_d810()
            ea = _fixture_ea("readonly_fold_without_prepare", idc, idaapi)
            before_log = len(state.stats.rule_execution_log)
            before_types = _type_snapshot(ea)
            rendered = _render(_decompile(state, ea, idaapi), pseudocode_to_string)
            assert _contains_value(rendered, 0x13579BDF), rendered
            receipts = _run_entries(state, before_log, "FoldReadonlyDataRule")
            assert receipts
            for entry in receipts:
                _assert_rule_receipt(entry)
            assert not state.manager.preparation_status().applied
            assert not state.manager.preparation_status().pending
            assert not _pending_proposals(state)
            records = state.manager.pre_hex_preparation._prepared_records(
                _database_identity(state)
            )
            assert not any(
                int(record.anchor_function_ea) == ea for record in records
            ), records
            assert _type_snapshot(ea) == before_types

    def test_readonly_receipt_precedes_native_subtree_semantics(
        self, copy_of_idb, d810_state, pseudocode_to_string
    ) -> None:
        with d810_state() as state:
            project = _load_canary(state)
            _set_constant_stages(project, preparation=False, readonly=True, subtree=True, forward=True)
            _activate_runtime_project(state, project)
            state.start_d810()
            ea = _fixture_ea("readonly_then_subtree", idc, idaapi)
            before_log = len(state.stats.rule_execution_log)
            rendered = _render(_decompile(state, ea, idaapi), pseudocode_to_string)
            assert _contains_value(rendered, 0xF37BE26A), rendered
            assert "a1" in rendered and "^" in rendered, rendered
            # Hex-Rays consumes the rotated constant between native callbacks,
            # so the dependent ConstantSubtreeFoldRule is covered by the
            # direct native rule-order test rather than claimed as a live
            # same-run receipt here.
            receipts = _run_entries(state, before_log, "FoldReadonlyDataRule")
            assert receipts
            for entry in receipts:
                _assert_rule_receipt(entry)

    def test_forward_selected_maturity_mutates_with_receipt(
        self, copy_of_idb, d810_state, pseudocode_to_string
    ) -> None:
        from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation

        with d810_state() as state:
            project = _load_canary(state)
            _set_constant_stages(project, preparation=False, readonly=False, subtree=False, forward=True)
            _activate_runtime_project(state, project)
            activation = pipeline_v2_hook_activation(project)
            forward = next(stage for stage in activation.constant_simplification_schedule.stages if stage.stage_id == "forward-constants")
            assert forward.effective_maturities
            state.start_d810()
            ea = _fixture_ea("forward_selected_maturity", idc, idaapi)
            before_log = len(state.stats.rule_execution_log)
            before_cfg = len(
                state.stats.cfg_rule_usages.get("ForwardConstantPropagationRule", ())
            )
            rendered = _render(_decompile(state, ea, idaapi), pseudocode_to_string)
            assert _contains_value(rendered, 0x02468ACE), rendered
            assert "a1" in rendered and "^" in rendered, rendered
            assert "+ 1" in rendered and "= 2" in rendered, rendered
            # CFG rules have a separate accepted-mutation receipt surface from
            # instruction rules.  A positive patch count is the mutation
            # receipt; invocation/eligibility alone is not sufficient.
            assert not _run_entries(
                state, before_log, "ForwardConstantPropagationRule"
            )
            assert _cfg_patch_receipts(
                state, "ForwardConstantPropagationRule", before_cfg
            )

    def test_forward_gated_maturity_keeps_semantics_and_has_no_receipt(
        self, copy_of_idb, d810_state, pseudocode_to_string
    ) -> None:
        from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation

        with d810_state() as state:
            project = _load_canary(state)
            _set_constant_stages(project, preparation=False, readonly=False, subtree=False, forward=True)
            # Keep a non-empty intersection while excluding the CALLS maturity
            # at which this tiny forward chain is observed.  An enabled stage
            # with an empty intersection is intentionally a configuration
            # error, so this exercises gating rather than that rejection path.
            _constant_pass(project)["maturity_gates"] = ["GLOBAL_OPTIMIZED"]
            _activate_runtime_project(state, project)
            activation = pipeline_v2_hook_activation(project)
            forward = next(stage for stage in activation.constant_simplification_schedule.stages if stage.stage_id == "forward-constants")
            assert forward.enabled
            assert tuple(item.name for item in forward.effective_maturities) == (
                "GLOBAL_OPTIMIZED",
            )
            assert tuple(item.name for item in forward.pass_maturity_gates) == (
                "GLOBAL_OPTIMIZED",
            )
            assert forward.inactive_reason is None
            assert any(
                rule.name == "ForwardConstantPropagationRule"
                for rule in activation.block_rules
            )
            state.start_d810()
            ea = _fixture_ea("forward_selected_maturity", idc, idaapi)
            before_log = len(state.stats.rule_execution_log)
            before_cfg = len(
                state.stats.cfg_rule_usages.get("ForwardConstantPropagationRule", ())
            )
            rendered = _render(_decompile(state, ea, idaapi), pseudocode_to_string)
            assert _contains_value(rendered, 0x02468ACE), rendered
            assert "a1" in rendered and "^" in rendered, rendered
            assert "+ 1" in rendered and "= 2" in rendered, rendered
            assert not _run_entries(
                state, before_log, "ForwardConstantPropagationRule"
            )
            assert not _cfg_patch_receipts(
                state, "ForwardConstantPropagationRule", before_cfg
            )

    def test_bounded_table_queues_then_applies_next_round_and_restores(
        self, copy_of_idb, d810_state, pseudocode_to_string
    ) -> None:
        from d810.capabilities.idb_preparation import PreparationState

        with d810_state() as state:
            project = _load_canary(state)
            _set_constant_stages(project, preparation=True, readonly=True, subtree=False, forward=False)
            _activate_runtime_project(state, project)
            table_ea = int(idc.get_name_ea_simple("csc_bounded_table"))
            assert table_ea != int(idaapi.BADADDR), "bounded table symbol is absent"
            baseline_type = _apply_nonconst_qword_array(table_ea, 128)
            assert baseline_type.present
            pointer_ea = table_ea + 128 * 8
            assert int(idc.get_qword(pointer_ea)) == table_ea
            pointer_type = _apply_const_qword(pointer_ea)
            assert pointer_type.present
            state.start_d810()
            ea = _fixture_ea("bounded_table_next_round", idc, idaapi)
            observer = state.manager._ensure_post_d810_runtime().global_const_observer
            assert observer.preparation_options.enabled is True
            assert observer.preparation_options.discover_bounded_tables is True
            from d810.core.decompilation_session import DecompilationEvent
            calls_post_d810_events = []

            def _record_calls_post_d810(mba, maturity):
                if int(getattr(mba, "entry_ea", 0) or 0) == ea:
                    calls_post_d810_events.append(
                        (int(maturity), int(getattr(mba, "maturity", -1)))
                    )

            state.manager.event_emitter.on(
                DecompilationEvent.HEXRAYS_CALLS_POST_D810,
                _record_calls_post_d810,
            )
            first = _decompile(state, ea, idaapi)
            assert first is not None
            first_rendered = _render(first, pseudocode_to_string)
            assert "a1" in first_rendered and "[" in first_rendered, first_rendered
            assert calls_post_d810_events == [
                (int(ida_hexrays.MMAT_CALLS), int(ida_hexrays.MMAT_CALLS))
            ]
            assert observer.restart_requested is False
            assert observer.pending_identities
            assert observer.pending_reason == "next preparation round"
            assert state.manager.preparation_status().pending
            pending = _pending_proposals(state)
            assert len(pending) == 1, pending
            proposal = pending[0]
            assert proposal.function_ea == ea
            assert proposal.item_end > proposal.item_head
            assert proposal.before != proposal.after
            assert proposal.item_head == table_ea
            assert proposal.before == baseline_type
            # A second normal managed decompile is the natural preparation
            # round that consumes the exact queued proposal.
            second = _decompile(state, ea, idaapi)
            assert second is not None
            second_rendered = _render(second, pseudocode_to_string)
            assert "a1" in second_rendered and "[" in second_rendered, second_rendered
            assert "0x7F" in second_rendered or "127" in second_rendered, second_rendered
            assert not _pending_proposals(state)
            assert state.manager.preparation_status().applied
            assert not state.manager.preparation_status().pending
            records = state.manager.pre_hex_preparation._prepared_records(
                _database_identity(state)
            )
            applied = [
                record
                for record in records
                if record.state is PreparationState.IDB_PREPARED
                and int(record.anchor_function_ea) == ea
            ]
            assert len(applied) == 1, records
            transaction = applied[0]
            deltas = _journal_deltas(state, transaction.transaction_id)
            assert deltas == (proposal.type_delta,)
            assert _capture_type(proposal.item_head) == proposal.after
            restored = state.manager.restore_idb_preparation(transaction.transaction_id)
            assert restored.ok, restored
            assert state.manager.preparation_status().restored
            restored_records = state.manager.pre_hex_preparation._prepared_records(
                _database_identity(state)
            )
            assert any(
                record.transaction_id == transaction.transaction_id
                and record.state is PreparationState.RESTORED
                for record in restored_records
            )
            assert _capture_type(proposal.item_head) == proposal.before

    @pytest.mark.parametrize(
        ("function", "transform_id", "expected_return"),
        (
        ("bounded_setz", "z-3-setz-generic", "return 1"),
        ("bounded_setnz", "z-3-setnz-generic", "return 0"),
        ("bounded_lnot", "z-3-lnot-generic", "return 1"),
        ),
    )
    def test_bounded_predicates_have_independent_proof_receipts(
        self,
        function,
        transform_id,
        expected_return,
        copy_of_idb,
        d810_state,
        pseudocode_to_string,
    ) -> None:
        from d810.backends.ast.z3_proof_policy import Z3ProofStatus
        from d810.core.observability import subscribe, unsubscribe
        from d810.core.observability_events import Z3PredicateProofObserved

        events: list[Z3PredicateProofObserved] = []
        subscribed = False
        try:
            with d810_state() as state:
                project = _load_canary(state)
                _set_constant_stages(
                    project,
                    preparation=False,
                    readonly=False,
                    subtree=False,
                    forward=False,
                )
                mba_options = _mba_pass(project)["options"]
                ea = _fixture_ea(function, idc, idaapi)
                prototype = _apply_bool_predicate_prototype(ea, function)
                assert "bool" in prototype.lower(), prototype
                source_transform_options = copy.deepcopy(
                    mba_options["transform_options"]
                )
                assert set(source_transform_options) == {
                    "z-3-setz-generic",
                    "z-3-setnz-generic",
                    "z-3-lnot-generic",
                }
                # Exercise exactly one generic predicate transform per case.
                # Hex-Rays lowers setcc/lnot through a flag producer; leaving
                # all three rules active lets an earlier setz rule consume that
                # producer before the target rule can observe its candidate.
                mba_options["transforms"] = [transform_id]
                mba_options["transform_options"] = {
                    transform_id: copy.deepcopy(source_transform_options[transform_id])
                }
                rule_name = {
                    "z-3-setz-generic": "Z3setzRuleGeneric",
                    "z-3-setnz-generic": "Z3setnzRuleGeneric",
                    "z-3-lnot-generic": "Z3lnotRuleGeneric",
                }[transform_id]
                _activate_runtime_project(state, project)
                state.start_d810()
                live_rule_names = set(_live_instruction_rule_names(state))
                assert rule_name in live_rule_names, live_rule_names
                sibling_rule_names = {
                    "Z3setzRuleGeneric",
                    "Z3setnzRuleGeneric",
                    "Z3lnotRuleGeneric",
                } - {rule_name}
                assert not live_rule_names.intersection(sibling_rule_names), (
                    rule_name,
                    live_rule_names,
                )
                # Subscribe after the manager is live.  Do not reset the
                # process-wide diagnostic bus between rounds: that would
                # remove the production sink and this subscriber.
                subscribe(Z3PredicateProofObserved, events.append)
                subscribed = True
                before_log = len(state.stats.rule_execution_log)
                rendered = _render(
                    _decompile(state, ea, idaapi), pseudocode_to_string
                )
                expected_boolean = expected_return == "return 1"
                assert _return_literal(rendered) is expected_boolean, rendered
                sufficient = _event_for(events, transform_id, ea)
                proved = [
                    event
                    for event in sufficient
                    if event.status is Z3ProofStatus.PROVED
                ]
                assert proved, sufficient
                for event in proved:
                    assert event.transform_id == transform_id
                    assert event.max_expression_nodes == 256
                    assert event.proof_timeout_ms == 50
                    assert event.observed_expression_nodes is not None
                    assert event.elapsed_ms >= 0
                    assert event.reason is None
                rule_receipts = _run_entries(state, before_log, rule_name)
                assert rule_receipts
                for entry in rule_receipts:
                    _assert_rule_receipt(entry)

                events.clear()
                state.stop_d810()
                project = _load_canary(state)
                _set_constant_stages(
                    project,
                    preparation=False,
                    readonly=False,
                    subtree=False,
                    forward=False,
                )
                mba_options = _mba_pass(project)["options"]
                assert mba_options["transforms"] == [transform_id]
                assert mba_options["transform_options"] == {
                    transform_id: source_transform_options[transform_id]
                }
                _replace_transform_policy(
                    project,
                    transform_id,
                    max_expression_nodes=1,
                    proof_timeout_ms=50,
                )
                for other_id in (
                    "z-3-setz-generic",
                    "z-3-setnz-generic",
                    "z-3-lnot-generic",
                ):
                    if other_id == transform_id:
                        continue
                    assert source_transform_options[other_id] == {
                        "max_expression_nodes": 256,
                        "proof_timeout_ms": 50,
                    }
                    assert other_id not in mba_options["transform_options"]
                _activate_runtime_project(state, project)
                state.start_d810()
                low_live_rule_names = set(_live_instruction_rule_names(state))
                assert rule_name in low_live_rule_names, low_live_rule_names
                assert not low_live_rule_names.intersection(sibling_rule_names), (
                    rule_name,
                    low_live_rule_names,
                )
                low_rendered = _render(
                    _decompile(state, ea, idaapi), pseudocode_to_string
                )
                assert low_rendered != rendered
                assert _return_literal(low_rendered) is None, low_rendered
                assert "a1" in low_rendered, low_rendered
                if function in {"bounded_setz", "bounded_setnz"}:
                    assert all(
                        token in low_rendered for token in ("^", "&", "-")
                    ), low_rendered
                    expected_mask = (
                        0x55AA55AA
                        if function == "bounded_setz"
                        else 0x33CC33CC
                    )
                    assert _contains_value(low_rendered, expected_mask), low_rendered
                else:
                    assert all(
                        token in low_rendered for token in ("*", "&", "^", "+")
                    ), low_rendered
                    assert "==" in low_rendered or "!=" in low_rendered, low_rendered
                    assert _contains_value(low_rendered, 2), low_rendered
                    assert _contains_value(low_rendered, 0x0F0F3C3C), low_rendered
                low_events = _event_for(events, transform_id, ea)
                abstained = [
                    event
                    for event in low_events
                    if event.status is Z3ProofStatus.ABSTAINED
                ]
                assert abstained, low_events
                assert all(event.max_expression_nodes == 1 for event in abstained)
                assert all(event.proof_timeout_ms == 50 for event in abstained)
                assert all(event.reason is not None for event in abstained)
        finally:
            if subscribed:
                unsubscribe(Z3PredicateProofObserved, events.append)
