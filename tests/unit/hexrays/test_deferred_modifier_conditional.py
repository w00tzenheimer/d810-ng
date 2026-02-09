"""Unit tests for BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT modification type.

Tests the new ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT feature
added to DeferredGraphModifier. This modification creates a 2-way conditional
block with two wired successors (conditional target + fallthrough via NOP-goto).

Note: These tests verify the enum exists and the basic queueing logic.
Full integration tests with real MBA are in system tests.
"""

import pytest


class TestModificationTypeEnum:
    """Test that the new enum value exists."""

    def test_modification_type_enum_has_new_value(self):
        """Verify BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT exists in ModificationType enum."""
        # Import here to allow module-level mocking if needed
        from unittest.mock import MagicMock
        import sys

        # Mock IDA modules before importing
        sys.modules['ida_hexrays'] = MagicMock()
        sys.modules['idaapi'] = MagicMock()

        # Mock constants that are used during module import
        ida_hex = sys.modules['ida_hexrays']
        ida_hex.BLT_NONE = 0
        ida_hex.BLT_STOP = 1
        ida_hex.BLT_0WAY = 2
        ida_hex.BLT_1WAY = 3
        ida_hex.BLT_2WAY = 4
        ida_hex.BLT_NWAY = 5
        ida_hex.BLT_XTRN = 6
        ida_hex.m_goto = 1
        ida_hex.m_jnz = 2
        ida_hex.m_jz = 3
        ida_hex.m_jae = 4
        ida_hex.m_jb = 5
        ida_hex.m_ja = 6
        ida_hex.m_jbe = 7
        ida_hex.m_jg = 8
        ida_hex.m_jge = 9
        ida_hex.m_jl = 10
        ida_hex.m_jle = 11
        ida_hex.m_jtbl = 12
        ida_hex.m_ijmp = 13
        ida_hex.m_call = 14
        ida_hex.m_nop = 15
        ida_hex.mop_b = 1
        ida_hex.mop_n = 2
        ida_hex.mop_c = 3
        ida_hex.mop_v = 4
        ida_hex.MBL_GOTO = 1
        ida_hex.MMAT_CALLS = 1
        ida_hex.is_mcode_jcond = MagicMock(return_value=True)

        # Import after mocking
        from d810.hexrays.deferred_modifier import ModificationType

        assert hasattr(ModificationType, "BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT")
        assert isinstance(
            ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT,
            ModificationType
        )


class TestQueueCreateConditionalRedirect:
    """Test the queue_create_conditional_redirect() method."""

    @pytest.fixture
    def mock_ida_and_import(self):
        """Setup mocks and import modules."""
        from unittest.mock import MagicMock
        import sys

        # Mock IDA modules
        sys.modules['ida_hexrays'] = MagicMock()
        sys.modules['idaapi'] = MagicMock()

        # Mock constants
        ida_hex = sys.modules['ida_hexrays']
        ida_hex.BLT_NONE = 0
        ida_hex.BLT_STOP = 1
        ida_hex.BLT_0WAY = 2
        ida_hex.BLT_1WAY = 3
        ida_hex.BLT_2WAY = 4
        ida_hex.BLT_NWAY = 5
        ida_hex.BLT_XTRN = 6
        ida_hex.m_goto = 1
        ida_hex.m_jnz = 2
        ida_hex.m_jz = 3
        ida_hex.m_jae = 4
        ida_hex.m_jb = 5
        ida_hex.m_ja = 6
        ida_hex.m_jbe = 7
        ida_hex.m_jg = 8
        ida_hex.m_jge = 9
        ida_hex.m_jl = 10
        ida_hex.m_jle = 11
        ida_hex.m_jtbl = 12
        ida_hex.m_ijmp = 13
        ida_hex.m_call = 14
        ida_hex.m_nop = 15
        ida_hex.mop_b = 1
        ida_hex.mop_n = 2
        ida_hex.mop_c = 3
        ida_hex.mop_v = 4
        ida_hex.MBL_GOTO = 1
        ida_hex.MMAT_CALLS = 1
        ida_hex.is_mcode_jcond = MagicMock(return_value=True)

        # Import modules
        from d810.hexrays.deferred_modifier import (
            DeferredGraphModifier,
            GraphModification,
            ModificationType,
        )

        return DeferredGraphModifier, GraphModification, ModificationType

    def test_queue_creates_graph_modification(self, mock_ida_and_import):
        """Verify that calling queue_create_conditional_redirect adds a GraphModification."""
        DeferredGraphModifier, GraphModification, ModificationType = mock_ida_and_import
        from unittest.mock import MagicMock

        mock_mba = MagicMock()
        modifier = DeferredGraphModifier(mock_mba)

        # Queue a conditional redirect
        modifier.queue_create_conditional_redirect(
            source_blk_serial=10,
            ref_blk_serial=20,
            conditional_target_serial=30,
            fallthrough_target_serial=40,
            description="test conditional redirect"
        )

        # Verify modification was queued
        assert len(modifier.modifications) == 1
        mod = modifier.modifications[0]
        assert isinstance(mod, GraphModification)
        assert mod.mod_type == ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT

    def test_queue_stores_all_parameters(self, mock_ida_and_import):
        """Verify all parameters are stored correctly in the GraphModification."""
        DeferredGraphModifier, _, _ = mock_ida_and_import
        from unittest.mock import MagicMock

        mock_mba = MagicMock()
        modifier = DeferredGraphModifier(mock_mba)

        source = 10
        ref = 20
        cond_target = 30
        ft_target = 40
        desc = "test description"

        modifier.queue_create_conditional_redirect(
            source_blk_serial=source,
            ref_blk_serial=ref,
            conditional_target_serial=cond_target,
            fallthrough_target_serial=ft_target,
            description=desc
        )

        mod = modifier.modifications[0]
        assert mod.block_serial == source
        assert mod.new_target == ref  # Reference block stored in new_target
        assert mod.conditional_target == cond_target
        assert mod.fallthrough_target == ft_target
        assert mod.description == desc

    def test_queue_sets_high_priority(self, mock_ida_and_import):
        """Verify that conditional redirect has high priority (5)."""
        DeferredGraphModifier, _, _ = mock_ida_and_import
        from unittest.mock import MagicMock

        mock_mba = MagicMock()
        modifier = DeferredGraphModifier(mock_mba)

        modifier.queue_create_conditional_redirect(
            source_blk_serial=10,
            ref_blk_serial=20,
            conditional_target_serial=30,
            fallthrough_target_serial=40,
        )

        mod = modifier.modifications[0]
        assert mod.priority == 5  # Very high priority

    def test_queue_generates_default_description(self, mock_ida_and_import):
        """Verify that a default description is generated if not provided."""
        DeferredGraphModifier, _, _ = mock_ida_and_import
        from unittest.mock import MagicMock

        mock_mba = MagicMock()
        modifier = DeferredGraphModifier(mock_mba)

        modifier.queue_create_conditional_redirect(
            source_blk_serial=10,
            ref_blk_serial=20,
            conditional_target_serial=30,
            fallthrough_target_serial=40,
        )

        mod = modifier.modifications[0]
        assert "10" in mod.description
        assert "30" in mod.description
        assert "40" in mod.description
        assert "conditional" in mod.description.lower()

    def test_multiple_queued_modifications(self, mock_ida_and_import):
        """Verify that multiple conditional redirects can be queued."""
        DeferredGraphModifier, _, ModificationType = mock_ida_and_import
        from unittest.mock import MagicMock

        mock_mba = MagicMock()
        modifier = DeferredGraphModifier(mock_mba)

        modifier.queue_create_conditional_redirect(10, 20, 30, 40)
        modifier.queue_create_conditional_redirect(11, 21, 31, 41)
        modifier.queue_create_conditional_redirect(12, 22, 32, 42)

        assert len(modifier.modifications) == 3
        assert all(
            m.mod_type == ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT
            for m in modifier.modifications
        )


class TestApplyDispatchesToHandler:
    """Test that _apply_single dispatches to the correct handler."""

    @pytest.fixture
    def mock_ida_and_import(self):
        """Setup mocks and import modules."""
        from unittest.mock import MagicMock, patch
        import sys

        # Mock IDA modules
        sys.modules['ida_hexrays'] = MagicMock()
        sys.modules['idaapi'] = MagicMock()

        # Mock constants
        ida_hex = sys.modules['ida_hexrays']
        ida_hex.BLT_NONE = 0
        ida_hex.BLT_STOP = 1
        ida_hex.BLT_0WAY = 2
        ida_hex.BLT_1WAY = 3
        ida_hex.BLT_2WAY = 4
        ida_hex.BLT_NWAY = 5
        ida_hex.BLT_XTRN = 6
        ida_hex.m_goto = 1
        ida_hex.m_jnz = 2
        ida_hex.m_jz = 3
        ida_hex.m_jae = 4
        ida_hex.m_jb = 5
        ida_hex.m_ja = 6
        ida_hex.m_jbe = 7
        ida_hex.m_jg = 8
        ida_hex.m_jge = 9
        ida_hex.m_jl = 10
        ida_hex.m_jle = 11
        ida_hex.m_jtbl = 12
        ida_hex.m_ijmp = 13
        ida_hex.m_call = 14
        ida_hex.m_nop = 15
        ida_hex.mop_b = 1
        ida_hex.mop_n = 2
        ida_hex.mop_c = 3
        ida_hex.mop_v = 4
        ida_hex.MBL_GOTO = 1
        ida_hex.MMAT_CALLS = 1
        ida_hex.is_mcode_jcond = MagicMock(return_value=True)

        # Import modules
        from d810.hexrays.deferred_modifier import (
            DeferredGraphModifier,
            GraphModification,
            ModificationType,
        )

        return DeferredGraphModifier, GraphModification, ModificationType

    def test_apply_dispatches_to_handler(self, mock_ida_and_import):
        """Verify _apply_single routes to _apply_create_conditional_redirect."""
        DeferredGraphModifier, GraphModification, ModificationType = mock_ida_and_import
        from unittest.mock import MagicMock, patch

        with patch.object(DeferredGraphModifier, '_apply_create_conditional_redirect') as mock_handler:
            mock_mba = MagicMock()
            mock_mba.get_mblock.return_value = MagicMock()
            mock_handler.return_value = True

            modifier = DeferredGraphModifier(mock_mba)

            # Create a modification
            mod = GraphModification(
                mod_type=ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT,
                block_serial=10,
                new_target=20,
                conditional_target=30,
                fallthrough_target=40,
                priority=5,
                description="test"
            )

            # Call _apply_single
            result = modifier._apply_single(mod)

            # Verify handler was called
            assert mock_handler.called
            assert result is True

            # Verify handler was called with correct arguments
            call_args = mock_handler.call_args
            assert call_args is not None
            args = call_args[0]
            assert len(args) == 4
            assert args[1] == 20  # ref_blk_serial
            assert args[2] == 30  # conditional_target
            assert args[3] == 40  # fallthrough_target

    def test_apply_handles_missing_block(self, mock_ida_and_import):
        """Verify _apply_single handles missing source block gracefully."""
        DeferredGraphModifier, GraphModification, ModificationType = mock_ida_and_import
        from unittest.mock import MagicMock, patch

        with patch.object(DeferredGraphModifier, '_apply_create_conditional_redirect') as mock_handler:
            mock_mba = MagicMock()
            mock_mba.get_mblock.return_value = None  # Block not found

            modifier = DeferredGraphModifier(mock_mba)

            mod = GraphModification(
                mod_type=ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT,
                block_serial=10,
                new_target=20,
                conditional_target=30,
                fallthrough_target=40,
                priority=5,
            )

            result = modifier._apply_single(mod)

            # Handler should not be called
            assert not mock_handler.called
            # Result should be False
            assert result is False


class TestHasModifications:
    """Test has_modifications() with conditional redirects."""

    @pytest.fixture
    def mock_ida_and_import(self):
        """Setup mocks and import modules."""
        from unittest.mock import MagicMock
        import sys

        # Mock IDA modules
        sys.modules['ida_hexrays'] = MagicMock()
        sys.modules['idaapi'] = MagicMock()

        # Mock constants
        ida_hex = sys.modules['ida_hexrays']
        ida_hex.BLT_NONE = 0
        ida_hex.BLT_STOP = 1
        ida_hex.BLT_0WAY = 2
        ida_hex.BLT_1WAY = 3
        ida_hex.BLT_2WAY = 4
        ida_hex.BLT_NWAY = 5
        ida_hex.BLT_XTRN = 6
        ida_hex.m_goto = 1
        ida_hex.m_jnz = 2
        ida_hex.m_jz = 3
        ida_hex.m_jae = 4
        ida_hex.m_jb = 5
        ida_hex.m_ja = 6
        ida_hex.m_jbe = 7
        ida_hex.m_jg = 8
        ida_hex.m_jge = 9
        ida_hex.m_jl = 10
        ida_hex.m_jle = 11
        ida_hex.m_jtbl = 12
        ida_hex.m_ijmp = 13
        ida_hex.m_call = 14
        ida_hex.m_nop = 15
        ida_hex.mop_b = 1
        ida_hex.mop_n = 2
        ida_hex.mop_c = 3
        ida_hex.mop_v = 4
        ida_hex.MBL_GOTO = 1
        ida_hex.MMAT_CALLS = 1
        ida_hex.is_mcode_jcond = MagicMock(return_value=True)

        # Import modules
        from d810.hexrays.deferred_modifier import DeferredGraphModifier

        return DeferredGraphModifier

    def test_has_modifications_returns_true_when_queued(self, mock_ida_and_import):
        """Verify has_modifications() returns True after queueing."""
        DeferredGraphModifier = mock_ida_and_import
        from unittest.mock import MagicMock

        mock_mba = MagicMock()
        modifier = DeferredGraphModifier(mock_mba)

        assert not modifier.has_modifications()

        modifier.queue_create_conditional_redirect(10, 20, 30, 40)

        assert modifier.has_modifications()

    def test_has_modifications_returns_false_when_empty(self, mock_ida_and_import):
        """Verify has_modifications() returns False when empty."""
        DeferredGraphModifier = mock_ida_and_import
        from unittest.mock import MagicMock

        mock_mba = MagicMock()
        modifier = DeferredGraphModifier(mock_mba)

        assert not modifier.has_modifications()


class TestCoalesceWithConditionalRedirect:
    """Test coalesce() behavior with conditional redirects."""

    @pytest.fixture
    def mock_ida_and_import(self):
        """Setup mocks and import modules."""
        from unittest.mock import MagicMock
        import sys

        # Mock IDA modules
        sys.modules['ida_hexrays'] = MagicMock()
        sys.modules['idaapi'] = MagicMock()

        # Mock constants
        ida_hex = sys.modules['ida_hexrays']
        ida_hex.BLT_NONE = 0
        ida_hex.BLT_STOP = 1
        ida_hex.BLT_0WAY = 2
        ida_hex.BLT_1WAY = 3
        ida_hex.BLT_2WAY = 4
        ida_hex.BLT_NWAY = 5
        ida_hex.BLT_XTRN = 6
        ida_hex.m_goto = 1
        ida_hex.m_jnz = 2
        ida_hex.m_jz = 3
        ida_hex.m_jae = 4
        ida_hex.m_jb = 5
        ida_hex.m_ja = 6
        ida_hex.m_jbe = 7
        ida_hex.m_jg = 8
        ida_hex.m_jge = 9
        ida_hex.m_jl = 10
        ida_hex.m_jle = 11
        ida_hex.m_jtbl = 12
        ida_hex.m_ijmp = 13
        ida_hex.m_call = 14
        ida_hex.m_nop = 15
        ida_hex.mop_b = 1
        ida_hex.mop_n = 2
        ida_hex.mop_c = 3
        ida_hex.mop_v = 4
        ida_hex.MBL_GOTO = 1
        ida_hex.MMAT_CALLS = 1
        ida_hex.is_mcode_jcond = MagicMock(return_value=True)

        # Import modules
        from d810.hexrays.deferred_modifier import DeferredGraphModifier

        return DeferredGraphModifier

    def test_coalesce_removes_duplicates(self, mock_ida_and_import):
        """Verify coalesce() removes duplicate conditional redirects."""
        DeferredGraphModifier = mock_ida_and_import
        from unittest.mock import MagicMock

        mock_mba = MagicMock()
        modifier = DeferredGraphModifier(mock_mba)

        # Queue same modification twice
        modifier.queue_create_conditional_redirect(10, 20, 30, 40, "first")
        modifier.queue_create_conditional_redirect(10, 20, 30, 40, "duplicate")

        assert len(modifier.modifications) == 2

        removed = modifier.coalesce()

        assert removed == 1
        assert len(modifier.modifications) == 1

    def test_coalesce_keeps_different_targets(self, mock_ida_and_import):
        """Verify coalesce() keeps modifications with different targets."""
        DeferredGraphModifier = mock_ida_and_import
        from unittest.mock import MagicMock

        mock_mba = MagicMock()
        modifier = DeferredGraphModifier(mock_mba)

        # Queue different modifications
        modifier.queue_create_conditional_redirect(10, 20, 30, 40)
        modifier.queue_create_conditional_redirect(10, 20, 31, 41)  # Different targets

        assert len(modifier.modifications) == 2

        removed = modifier.coalesce()

        assert removed == 0
        assert len(modifier.modifications) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
