"""Tests for ProjectContext rule filtering API."""
import pytest
from unittest.mock import MagicMock, patch

from d810.core.project import ProjectContext


class TestProjectContext:
    """Tests for ProjectContext class."""

    def test_remove_rule_by_string(self):
        """Test removing a rule by name string."""

        # Create mock state
        mock_state = MagicMock()
        mock_rule1 = MagicMock()
        mock_rule1.name = "Rule1"
        mock_rule2 = MagicMock()
        mock_rule2.name = "Rule2"

        mock_state.current_ins_rules = [mock_rule1, mock_rule2]
        mock_state.current_blk_rules = []

        ctx = ProjectContext(state=mock_state, project_index=0)

        # Remove by string (case-insensitive)
        result = ctx.remove_rule("rule1")

        assert result is ctx  # Chainable
        assert len(mock_state.current_ins_rules) == 1
        assert mock_state.current_ins_rules[0].name == "Rule2"

    def test_remove_rule_by_class(self):
        """Test removing a rule by class."""
        mock_state = MagicMock()
        mock_rule = MagicMock()
        mock_rule.name = "TestRule"
        mock_state.current_ins_rules = [mock_rule]
        mock_state.current_blk_rules = []

        ctx = ProjectContext(state=mock_state, project_index=0)

        # Create a mock class
        class TestRule:
            pass

        ctx.remove_rule(TestRule)

        assert len(mock_state.current_ins_rules) == 0

    def test_remove_blk_rule(self):
        """Test removing a block rule."""
        mock_state = MagicMock()
        mock_rule = MagicMock()
        mock_rule.name = "FixPredecessorOfConditionalJumpBlock"
        mock_state.current_ins_rules = []
        mock_state.current_blk_rules = [mock_rule]

        ctx = ProjectContext(state=mock_state, project_index=0)

        ctx.remove_rule("FixPredecessorOfConditionalJumpBlock")

        assert len(mock_state.current_blk_rules) == 0

    def test_add_rule_instruction(self):
        """Test adding an instruction rule."""
        mock_state = MagicMock()
        mock_known_rule = MagicMock()
        mock_known_rule.name = "NewRule"

        mock_state.current_ins_rules = []
        mock_state.current_blk_rules = []
        mock_state.known_ins_rules = [mock_known_rule]
        mock_state.known_blk_rules = []

        ctx = ProjectContext(state=mock_state, project_index=0)

        result = ctx.add_rule("newrule")

        assert result is ctx  # Chainable
        assert mock_known_rule in mock_state.current_ins_rules

    def test_add_rule_not_found(self):
        """Test that add_rule raises ValueError for unknown rules."""
        mock_state = MagicMock()
        mock_state.current_ins_rules = []
        mock_state.current_blk_rules = []
        mock_state.known_ins_rules = []
        mock_state.known_blk_rules = []

        ctx = ProjectContext(state=mock_state, project_index=0)

        with pytest.raises(ValueError, match="not found in known rules"):
            ctx.add_rule("NonExistentRule")

    def test_restore(self):
        """Test that restore brings back original rules."""
        mock_state = MagicMock()
        mock_rule1 = MagicMock()
        mock_rule1.name = "Rule1"
        mock_rule2 = MagicMock()
        mock_rule2.name = "Rule2"

        original_ins = [mock_rule1, mock_rule2]
        original_blk = []
        mock_state.current_ins_rules = list(original_ins)
        mock_state.current_blk_rules = list(original_blk)

        ctx = ProjectContext(state=mock_state, project_index=0)

        # Remove a rule
        ctx.remove_rule("Rule1")
        assert len(mock_state.current_ins_rules) == 1

        # Restore
        ctx.restore()
        assert mock_state.current_ins_rules == original_ins
        assert mock_state.current_blk_rules == original_blk

    def test_backward_compatible_as_int(self):
        """Test that ProjectContext can be used as an integer."""
        mock_state = MagicMock()
        mock_state.current_ins_rules = []
        mock_state.current_blk_rules = []

        ctx = ProjectContext(state=mock_state, project_index=42)

        # Should work as int
        assert int(ctx) == 42
        assert ctx == 42
        assert ctx != 0

    def test_chaining(self):
        """Test method chaining."""
        mock_state = MagicMock()
        mock_rule1 = MagicMock()
        mock_rule1.name = "Rule1"
        mock_rule2 = MagicMock()
        mock_rule2.name = "Rule2"

        mock_state.current_ins_rules = [mock_rule1, mock_rule2]
        mock_state.current_blk_rules = []
        mock_state.known_ins_rules = []
        mock_state.known_blk_rules = []

        ctx = ProjectContext(state=mock_state, project_index=0)

        # Chain removal
        result = ctx.remove_rule("Rule1").remove_rule("Rule2")

        assert result is ctx
        assert len(mock_state.current_ins_rules) == 0


class TestRegistrantFind:
    """Tests for Registrant.find() method."""

    def test_find_existing(self):
        """Test finding an existing registered class."""
        from d810.core.registry import Registrant

        # Create a test registry
        class TestBase(Registrant):
            pass

        class TestImpl(TestBase):
            pass

        # find() should return the class
        result = TestBase.find("TestImpl")
        assert result is TestImpl

    def test_find_nonexistent(self):
        """Test finding a non-existent class returns None."""
        from d810.core.registry import Registrant

        class TestBase(Registrant):
            pass

        result = TestBase.find("NonExistent")
        assert result is None

    def test_find_case_insensitive(self):
        """Test that find() is case-insensitive."""
        from d810.core.registry import Registrant

        class TestBase2(Registrant):
            pass

        class MyTestRule(TestBase2):
            pass

        result = TestBase2.find("mytestrule")
        assert result is MyTestRule

        result = TestBase2.find("MYTESTRULE")
        assert result is MyTestRule
