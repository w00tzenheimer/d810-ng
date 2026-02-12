"""Integration tests for resolve_dispatcher_father method behavior.

These tests verify that resolve_dispatcher_father correctly chooses between
queue_convert_to_goto, queue_goto_change, and queue_create_and_redirect based on
the dispatcher father type and side-effect presence.

Requires mocked IDA modules to instantiate GenericDispatcherUnflatteningRule.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch


@pytest.fixture(autouse=True)
def mock_ida_modules():
    """Mock IDA modules needed for testing."""

    # Create a real class for mop_t (needed for singledispatch.register)
    class mop_t:
        """Mock mop_t class for testing."""
        def __init__(self):
            self.t = 0
            self.r = 0
            self.s = None
            self.size = 4

    mock_hexrays = MagicMock()
    mock_idaapi = MagicMock()

    # Replace mop_t MagicMock with real class
    mock_hexrays.mop_t = mop_t

    # Mock essential block type constants
    mock_hexrays.BLT_0WAY = 0
    mock_hexrays.BLT_1WAY = 1
    mock_hexrays.BLT_2WAY = 2

    # Mock control flow opcodes used in tests
    mock_hexrays.m_goto = 0x40
    mock_hexrays.m_jnz = 0x30
    mock_hexrays.m_jz = 0x2C

    # Mock MMAT_ constants (maturity levels) to prevent sorting errors
    mock_hexrays.MMAT_GENERATED = 0
    mock_hexrays.MMAT_PREOPTIMIZED = 1
    mock_hexrays.MMAT_LOCOPT = 2
    mock_hexrays.MMAT_CALLS = 3
    mock_hexrays.MMAT_GLBOPT1 = 4
    mock_hexrays.MMAT_GLBOPT2 = 5
    mock_hexrays.MMAT_GLBOPT3 = 6
    mock_hexrays.MMAT_LVARS = 7

    # Mock mop_ constants (operand types)
    mock_hexrays.mop_z = 0
    mock_hexrays.mop_r = 1
    mock_hexrays.mop_n = 2
    mock_hexrays.mop_str = 3
    mock_hexrays.mop_d = 4
    mock_hexrays.mop_S = 5
    mock_hexrays.mop_v = 6
    mock_hexrays.mop_b = 7
    mock_hexrays.mop_f = 8
    mock_hexrays.mop_l = 9
    mock_hexrays.mop_a = 10
    mock_hexrays.mop_h = 11
    mock_hexrays.mop_c = 12

    # Mock m_ constants (opcodes)
    mock_hexrays.m_nop = 0x00
    mock_hexrays.m_stx = 0x01
    mock_hexrays.m_ldx = 0x02
    mock_hexrays.m_ldc = 0x03
    mock_hexrays.m_mov = 0x04
    mock_hexrays.m_neg = 0x05
    mock_hexrays.m_lnot = 0x06
    mock_hexrays.m_bnot = 0x07
    mock_hexrays.m_xds = 0x08
    mock_hexrays.m_xdu = 0x09
    mock_hexrays.m_low = 0x0A
    mock_hexrays.m_high = 0x0B
    mock_hexrays.m_add = 0x0C
    mock_hexrays.m_sub = 0x0D
    mock_hexrays.m_mul = 0x0E
    mock_hexrays.m_udiv = 0x0F
    mock_hexrays.m_sdiv = 0x10
    mock_hexrays.m_umod = 0x11
    mock_hexrays.m_smod = 0x12
    mock_hexrays.m_or = 0x13
    mock_hexrays.m_and = 0x14
    mock_hexrays.m_xor = 0x15
    mock_hexrays.m_shl = 0x16
    mock_hexrays.m_shr = 0x17
    mock_hexrays.m_sar = 0x18
    mock_hexrays.m_cfadd = 0x19
    mock_hexrays.m_ofadd = 0x1A
    mock_hexrays.m_cfshl = 0x1B
    mock_hexrays.m_cfshr = 0x1C
    mock_hexrays.m_sets = 0x1D
    mock_hexrays.m_seto = 0x1E
    mock_hexrays.m_setp = 0x1F
    mock_hexrays.m_setnz = 0x20
    mock_hexrays.m_setz = 0x21
    mock_hexrays.m_setae = 0x22
    mock_hexrays.m_setb = 0x23
    mock_hexrays.m_seta = 0x24
    mock_hexrays.m_setbe = 0x25
    mock_hexrays.m_setg = 0x26
    mock_hexrays.m_setge = 0x27
    mock_hexrays.m_setl = 0x28
    mock_hexrays.m_setle = 0x29
    mock_hexrays.m_jcnd = 0x2A
    mock_hexrays.m_jnz = 0x2B
    mock_hexrays.m_jz = 0x2C
    mock_hexrays.m_jae = 0x2D
    mock_hexrays.m_jb = 0x2E
    mock_hexrays.m_ja = 0x2F
    mock_hexrays.m_jbe = 0x30
    mock_hexrays.m_jg = 0x31
    mock_hexrays.m_jge = 0x32
    mock_hexrays.m_jl = 0x33
    mock_hexrays.m_jle = 0x34
    mock_hexrays.m_jtbl = 0x35
    mock_hexrays.m_ijmp = 0x36
    mock_hexrays.m_goto = 0x37
    mock_hexrays.m_call = 0x38
    mock_hexrays.m_icall = 0x39
    mock_hexrays.m_ret = 0x3A
    mock_hexrays.m_push = 0x3B
    mock_hexrays.m_pop = 0x3C
    mock_hexrays.m_und = 0x3D
    mock_hexrays.m_ext = 0x3E
    mock_hexrays.m_f2i = 0x3F
    mock_hexrays.m_f2u = 0x40
    mock_hexrays.m_i2f = 0x41
    mock_hexrays.m_u2f = 0x42
    mock_hexrays.m_f2f = 0x43
    mock_hexrays.m_fneg = 0x44
    mock_hexrays.m_fadd = 0x45
    mock_hexrays.m_fsub = 0x46
    mock_hexrays.m_fmul = 0x47
    mock_hexrays.m_fdiv = 0x48

    # Mock the __dir__ method to return our constants
    def mock_dir(self):
        return [attr for attr in dir(type(self)) if not attr.startswith('_')]

    type(mock_hexrays).__dir__ = mock_dir

    mock_idc = MagicMock()
    mock_ida_ida = MagicMock()
    mock_ida_idp = MagicMock()
    mock_ida_bytes = MagicMock()

    with patch.dict('sys.modules', {
        'ida_hexrays': mock_hexrays,
        'idaapi': mock_idaapi,
        'idc': mock_idc,
        'ida_ida': mock_ida_ida,
        'ida_idp': mock_ida_idp,
        'ida_bytes': mock_ida_bytes,
    }):
        yield mock_hexrays


@pytest.mark.ida_required
class TestDispatcherFatherResolveIntegration:
    """Integration tests for resolve_dispatcher_father deferred modifier queueing."""

    def test_resolve_dispatcher_father_uses_convert_for_2way_conditional(self, mock_ida_modules):
        """2-way conditional fathers must queue convert_to_goto, not goto_change."""
        from d810.optimizers.microcode.flow.flattening.generic import (
            GenericDispatcherUnflatteningRule
        )

        class TestDispatcherRule(GenericDispatcherUnflatteningRule):
            @property
            def DISPATCHER_COLLECTOR_CLASS(self):
                return Mock

        rule = TestDispatcherRule()
        rule.mba = Mock()
        rule.mba.qty = 10

        dispatcher_father = Mock()
        dispatcher_father.serial = 3
        dispatcher_father.nsucc.return_value = 2
        dispatcher_father.tail = Mock()
        dispatcher_father.tail.opcode = mock_ida_modules.m_jz

        target_blk = Mock()
        target_blk.serial = 137
        target_blk.type = mock_ida_modules.BLT_1WAY

        dispatcher_info = Mock()
        dispatcher_info.entry_block = Mock()
        dispatcher_info.entry_block.use_before_def_list = []
        dispatcher_info.dispatcher_internal_blocks = []
        dispatcher_info.emulate_dispatcher_with_father_history = Mock(
            return_value=(target_blk, [])
        )

        rule.get_dispatcher_father_histories = Mock(return_value=[Mock()])
        rule.check_if_histories_are_resolved = Mock(return_value=True)

        deferred_modifier = Mock()

        with patch(
            "d810.optimizers.microcode.flow.flattening.generic.get_all_possibles_values",
            return_value=[[1]],
        ), patch(
            "d810.optimizers.microcode.flow.flattening.generic.check_if_all_values_are_found",
            return_value=True,
        ), patch(
            "d810.optimizers.microcode.flow.flattening.generic.classify_exit_block",
            return_value=None,
        ):
            result = rule.resolve_dispatcher_father(
                dispatcher_father, dispatcher_info, deferred_modifier
            )

        assert result == 2
        deferred_modifier.queue_convert_to_goto.assert_called_once()
        deferred_modifier.queue_goto_change.assert_not_called()
        deferred_modifier.queue_create_and_redirect.assert_not_called()

    def test_resolve_dispatcher_father_skips_non_1way_create_and_redirect(self, mock_ida_modules):
        """When side-effect copies exist, non-1way fathers should be skipped safely."""
        from d810.optimizers.microcode.flow.flattening.generic import (
            GenericDispatcherUnflatteningRule
        )

        class TestDispatcherRule(GenericDispatcherUnflatteningRule):
            @property
            def DISPATCHER_COLLECTOR_CLASS(self):
                return Mock

        rule = TestDispatcherRule()
        rule.mba = Mock()
        rule.mba.qty = 10

        dispatcher_father = Mock()
        dispatcher_father.serial = 77
        dispatcher_father.nsucc.return_value = 2
        dispatcher_father.tail = Mock()
        dispatcher_father.tail.opcode = mock_ida_modules.m_jz

        target_blk = Mock()
        target_blk.serial = 120
        target_blk.type = mock_ida_modules.BLT_1WAY

        fake_side_effect = Mock()
        fake_side_effect.opcode = 0x1234  # non-control-flow opcode for this test

        dispatcher_info = Mock()
        dispatcher_info.entry_block = Mock()
        dispatcher_info.entry_block.use_before_def_list = []
        dispatcher_info.dispatcher_internal_blocks = []
        dispatcher_info.emulate_dispatcher_with_father_history = Mock(
            return_value=(target_blk, [fake_side_effect])
        )

        rule.get_dispatcher_father_histories = Mock(return_value=[Mock()])
        rule.check_if_histories_are_resolved = Mock(return_value=True)

        deferred_modifier = Mock()

        with patch(
            "d810.optimizers.microcode.flow.flattening.generic.get_all_possibles_values",
            return_value=[[1]],
        ), patch(
            "d810.optimizers.microcode.flow.flattening.generic.check_if_all_values_are_found",
            return_value=True,
        ), patch(
            "d810.optimizers.microcode.flow.flattening.generic.classify_exit_block",
            return_value=None,
        ):
            result = rule.resolve_dispatcher_father(
                dispatcher_father, dispatcher_info, deferred_modifier
            )

        assert result == 0
        deferred_modifier.queue_create_and_redirect.assert_not_called()
        deferred_modifier.queue_goto_change.assert_not_called()
        deferred_modifier.queue_convert_to_goto.assert_not_called()
