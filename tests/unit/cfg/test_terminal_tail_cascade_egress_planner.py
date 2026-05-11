"""Tests for read-only terminal-tail cascade egress planning."""
from __future__ import annotations

from d810.cfg.terminal_tail_cascade_egress_planner import (
    AMBIGUOUS_STATE_UPDATE,
    NEEDS_STATE_WRITE,
    SAFE_STATE_ALREADY_SET,
    SAFE_TARGET_POST_GUARD,
    TerminalByteEmitSite,
    TerminalTailBlock,
    TerminalTailCascadeEgressPlanner,
    format_cascade_egress_plan,
    terminal_byte_emit_site_from_payload,
)


def _block(
    serial: int,
    succs: tuple[int, ...],
    *,
    text: tuple[str, ...] = (),
) -> TerminalTailBlock:
    return TerminalTailBlock(
        serial=serial,
        succs=succs,
        insn_opcodes=("m_stx", "m_jnz") if serial < 10 else ("m_mov",),
        insn_text=text,
    )


def _site(
    byte_index: int,
    block: int,
    *,
    continuation: int | None,
    return_edge: int | None,
    role: str = "memory_store",
    opcode: str = "m_stx",
    destination: str = "[ds.2:(%var_190+#1.8)]",
) -> TerminalByteEmitSite:
    return TerminalByteEmitSite(
        byte_index=byte_index,
        block_serial=block,
        opcode=opcode,
        emitter_role=role,
        corridor_role="terminal_tail",
        destination=destination,
        return_edge=return_edge,
        continuation_edge=continuation,
        confidence=0.7,
    )


class TestTerminalTailCascadeEgressPlanner:
    def test_plans_cascade_redirect_that_reduces_source_scc(self) -> None:
        blocks = {
            0: _block(0, (20, 1)),
            1: _block(1, (11, 90)),
            2: _block(2, (12,)),
            3: _block(3, (13, 90)),
            4: _block(4, (14, 90)),
            5: _block(5, (15, 90)),
            6: _block(6, (91,)),
            11: _block(11, ()),
            12: _block(12, ()),
            13: _block(13, ()),
            14: _block(14, ()),
            15: _block(15, ()),
            20: _block(20, ()),
            90: _block(90, (1,)),
            91: _block(91, ()),
        }
        sites = [
            _site(0, 0, continuation=1, return_edge=20, role="guard_only", opcode="op_43"),
            _site(1, 1, continuation=90, return_edge=11),
            _site(2, 2, continuation=90, return_edge=12),
            _site(3, 3, continuation=90, return_edge=13),
            _site(4, 4, continuation=90, return_edge=14),
            _site(5, 5, continuation=90, return_edge=15),
            _site(6, 6, continuation=91, return_edge=None),
        ]

        plan = TerminalTailCascadeEgressPlanner(blocks, sites).build_plan()

        row1 = plan.rows[1]
        assert row1.source_block == 1
        assert row1.current_continuation_target == 90
        assert row1.intended_target == 2
        assert row1.early_return_target == 11
        assert row1.preserves_early_return
        assert row1.removes_from_scc
        assert row1.source_scc_size_before == 2
        assert row1.source_scc_size_after == 1

        row0 = plan.rows[0]
        assert row0.reason == "guard_only_byte0_collector_gap"
        row6 = plan.rows[6]
        assert row6.reason == "terminal_byte_has_no_next_emit_target"
        assert 6 in plan.gap_bytes

    def test_selects_real_store_over_counter_increment_noise(self) -> None:
        blocks = {
            1: _block(1, (10, 90)),
            2: _block(2, ()),
            10: _block(10, ()),
            90: _block(90, (1,)),
        }
        noisy_counter_store = _site(
            1,
            1,
            continuation=90,
            return_edge=10,
            destination="%var_178.8",
        )
        real_byte_store = _site(
            1,
            1,
            continuation=90,
            return_edge=10,
            destination="[ds.2:((%var_190+#1.8)+%var_188.8)]",
        )
        plan = TerminalTailCascadeEgressPlanner(
            blocks,
            [noisy_counter_store, real_byte_store, _site(2, 2, continuation=None, return_edge=None)],
        ).build_plan()

        assert plan.rows[1].explicit_store
        assert plan.rows[1].confidence == 0.82

    def test_same_block_next_byte_is_reported_as_split_requirement(self) -> None:
        blocks = {
            3: _block(3, (30, 31)),
            30: _block(30, ()),
            31: _block(31, ()),
        }
        sites = [
            _site(3, 3, continuation=30, return_edge=31),
            _site(4, 3, continuation=30, return_edge=31),
        ]

        plan = TerminalTailCascadeEgressPlanner(blocks, sites).build_plan()

        assert plan.rows[3].intended_target == 3
        assert plan.rows[3].reason == "next_byte_emit_resolves_to_same_block_split_required"
        assert not plan.rows[3].removes_from_scc

    def test_state_proof_marks_post_guard_target_safe(self) -> None:
        blocks = {
            5: _block(5, (50, 6)),
            6: _block(6, ()),
            50: _block(50, ()),
        }
        sites = [
            _site(5, 5, continuation=6, return_edge=50),
            _site(6, 6, continuation=None, return_edge=None),
        ]

        plan = TerminalTailCascadeEgressPlanner(blocks, sites).build_plan()

        assert plan.rows[5].state_update_verdict == SAFE_TARGET_POST_GUARD

    def test_state_proof_marks_source_write_safe(self) -> None:
        blocks = {
            1: _block(1, (10, 2), text=("mov    #2.8, %var_198.8",)),
            2: _block(2, (), text=("jnz    %var_198.8, #2.8, @20",)),
            10: _block(10, ()),
        }
        sites = [
            _site(1, 1, continuation=2, return_edge=10),
            _site(2, 2, continuation=None, return_edge=None),
        ]

        plan = TerminalTailCascadeEgressPlanner(blocks, sites).build_plan()

        assert plan.rows[1].state_update_verdict == SAFE_STATE_ALREADY_SET
        assert plan.rows[1].state_write_block == 1

    def test_state_proof_marks_bypassed_dispatcher_write_needed(self) -> None:
        blocks = {
            1: _block(1, (10, 90)),
            2: _block(2, (), text=("jnz    %var_198.8, #2.8, @20",)),
            10: _block(10, ()),
            90: _block(90, (2,), text=("mov    #2.8, %var_198.8",)),
        }
        sites = [
            _site(1, 1, continuation=90, return_edge=10),
            _site(2, 2, continuation=None, return_edge=None),
        ]

        plan = TerminalTailCascadeEgressPlanner(blocks, sites).build_plan()

        assert plan.rows[1].state_update_verdict == NEEDS_STATE_WRITE
        assert plan.rows[1].state_write_block == 90
        assert plan.rows[1].state_write_bypassed

    def test_state_proof_marks_missing_write_ambiguous(self) -> None:
        blocks = {
            1: _block(1, (10, 90)),
            2: _block(2, (), text=("jnz    %var_198.8, #2.8, @20",)),
            10: _block(10, ()),
            90: _block(90, (2,)),
        }
        sites = [
            _site(1, 1, continuation=90, return_edge=10),
            _site(2, 2, continuation=None, return_edge=None),
        ]

        plan = TerminalTailCascadeEgressPlanner(blocks, sites).build_plan()

        assert plan.rows[1].state_update_verdict == AMBIGUOUS_STATE_UPDATE

    def test_payload_adapter_rejects_incomplete_payloads(self) -> None:
        assert terminal_byte_emit_site_from_payload("f", {}) is None

        site = terminal_byte_emit_site_from_payload(
            "fact",
            {
                "byte_index": 5,
                "block_serial": 101,
                "opcode": "m_stx",
                "emitter_role": "memory_store",
                "corridor_role": "terminal_tail",
                "return_edge": 103,
                "continuation_edge": 102,
                "successor_blocks": [102, 103],
            },
            source_ea_hex="0x180014c61",
            confidence=0.72,
        )

        assert site is not None
        assert site.byte_index == 5
        assert site.block_serial == 101
        assert site.successor_blocks == (102, 103)
        assert site.explicit_store

    def test_format_renders_required_table_columns(self) -> None:
        blocks = {1: _block(1, (10,)), 10: _block(10, ())}
        sites = [_site(1, 1, continuation=10, return_edge=None)]
        plan = TerminalTailCascadeEgressPlanner(blocks, sites).build_plan()

        rendered = format_cascade_egress_plan(plan)

        assert "Terminal tail cascade egress plan" in rendered
        assert "| byte | source block | current continuation | intended target |" in rendered
        assert "state verdict" in rendered
        assert "terminal_byte_has_no_next_emit_target" in rendered
